"""FastAPI server: start runs, stream events over SSE, replay recorded runs."""
import asyncio
import collections
import json
import logging
import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

from . import config, sources
from .agent import PIN, Agent

app = FastAPI(title="PatchPilot")
RUNS = {}  # run_id -> {"events": [...], "done": bool}
MAX_RUNS = 50
RATE_LIMIT, RATE_WINDOW = 5, 60.0
_hits = collections.defaultdict(collections.deque)
_lock = threading.Lock()
RUN_ID = re.compile(r"[\w.-]+")
REPO = re.compile(r"https://github\.com/[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}?(?:\.git)?/?")
log = logging.getLogger(__name__)
config.RUNS_DIR.mkdir(exist_ok=True)


class RunRequest(BaseModel):
    repo: str = ""

    @field_validator("repo")
    @classmethod
    def _repo(cls, v):
        v = v.strip()
        if v and (len(v) > 200 or not REPO.fullmatch(v)):
            raise ValueError("repo must be empty or https://github.com/owner/repo")
        return v


def _evict():
    done = [k for k, v in RUNS.items() if v["done"]]
    for k in done[:max(0, len(RUNS) - MAX_RUNS)]:
        del RUNS[k]


def _rate_ok(ip, now=None):
    now = time.monotonic() if now is None else now
    with _lock:
        q = _hits[ip]
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return False
        q.append(now)
        return True


def _read_events(path):
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if isinstance(ev, dict):
            out.append(ev)
    return out


def _record(run_id):
    path = config.RUNS_DIR / f"{run_id}.jsonl"

    def emit(ev):
        RUNS[run_id]["events"].append(ev)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
        if ev["type"] == "done":
            RUNS[run_id]["done"] = True
    return emit


@app.get("/api/health")
def health():
    return {"nebius": bool(config.NEBIUS_API_KEY), "provider": config.provider_name(), "tavily": bool(config.TAVILY_API_KEY),
            "github": bool(config.GITHUB_TOKEN), "base_url": config.NEBIUS_BASE_URL,
            "remote_repos": config.ALLOW_REMOTE_REPOS}


@app.get("/api/cases")
def cases():
    out = []
    for d in sorted(config.CASES_DIR.iterdir()):
        req = d / "requirements.txt"
        if req.exists():
            pins = [l.strip() for l in req.read_text().splitlines() if "==" in l and not l.startswith("pytest")]
            out.append({"id": d.name, "pins": pins})
    return out


@app.get("/api/bench")
def bench():
    p = config.RUNS_DIR / "batch-summary.json"
    return json.loads(p.read_text()) if p.exists() else []


@app.get("/api/org/{owner}")
def org_scan(owner: str):
    """Scan every public repo of a GitHub user/org: pinned requirements.txt -> OSV advisories."""
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", owner):
        raise HTTPException(400, "Invalid GitHub owner")
    with httpx.Client(timeout=20, headers={"Accept": "application/vnd.github+json",
                      **({"Authorization": f"Bearer {config.GITHUB_TOKEN}"} if config.GITHUB_TOKEN else {})}) as gh:
        return _org_scan(gh, owner)


def _org_scan(gh, owner):
    r = gh.get(f"https://api.github.com/users/{owner}/repos", params={"per_page": 40, "sort": "pushed"})
    if r.status_code == 404:
        raise HTTPException(404, f"No GitHub user or org named '{owner}'")
    if r.status_code == 403:
        raise HTTPException(429, "GitHub rate limit hit. Set GITHUB_TOKEN in .env to raise it")
    r.raise_for_status()
    repos = [x for x in r.json() if not x.get("fork") and not x.get("archived") and x.get("language") in ("Python", None)]

    def scan(repo):
        raw = gh.get(f"https://raw.githubusercontent.com/{repo['full_name']}/{repo['default_branch']}/requirements.txt")
        row = {"name": repo["name"], "url": repo["html_url"], "stars": repo.get("stargazers_count", 0),
               "pins": 0, "packages": [], "critical": 0, "high": 0, "other": 0, "has_reqs": raw.status_code == 200}
        if raw.status_code != 200:
            return row
        for line in raw.text.splitlines()[:60]:
            m = PIN.match(line.split("#")[0])
            if not m:
                continue
            row["pins"] += 1
            try:
                vulns = sources.osv_vulns(m.group(1), m.group(2))
            except Exception:
                log.warning("OSV lookup failed for %s", m.group(1), exc_info=True)
                continue
            if vulns:
                row["packages"].append({"package": m.group(1), "version": m.group(2), "count": len(vulns)})
            for v in vulns:
                key = {"CRITICAL": "critical", "HIGH": "high"}.get(v.get("severity"), "other")
                row[key] += 1
        return row

    with ThreadPoolExecutor(8) as pool:
        rows = list(pool.map(scan, repos))
    rows.sort(key=lambda x: (x["critical"], x["high"], x["other"]), reverse=True)
    return {"owner": owner, "scanned": len(rows), "repos": rows}


@app.post("/api/runs")
def start_run(req: RunRequest, request: Request):
    token = os.getenv("PATCHPILOT_TOKEN", "")
    if token and request.headers.get("authorization", "") != f"Bearer {token}":
        raise HTTPException(401, "Missing or invalid bearer token")
    if not _rate_ok(request.client.host if request.client else "?"):
        raise HTTPException(429, "Too many runs; try again in a minute")
    if not config.NEBIUS_API_KEY:
        raise HTTPException(400, "NEBIUS_API_KEY is not configured on the server")
    run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
    RUNS[run_id] = {"events": [], "done": False}
    _evict()
    emit = _record(run_id)
    emit({"type": "start", "repo": req.repo or f"case:{config.DEFAULT_CASE}", "t": 0})
    threading.Thread(target=Agent(run_id, req.repo, emit).run, daemon=True).start()
    return {"id": run_id}


@app.get("/api/runs")
def list_runs():
    out = []
    for p in sorted(config.RUNS_DIR.glob("*.jsonl"), reverse=True):
        try:
            evs = _read_events(p)
        except OSError:
            continue
        if not evs:
            continue
        first, last = evs[0], evs[-1]
        out.append({"id": p.stem, "repo": first.get("repo"), "ok": last.get("ok") if last.get("type") == "done" else None})
    return out[:30]


@app.get("/api/runs/{run_id}/events")
async def events(run_id: str, replay: float = 0):
    if run_id not in RUNS:
        if not RUN_ID.fullmatch(run_id):
            raise HTTPException(404)
        path = config.RUNS_DIR / f"{run_id}.jsonl"
        if not path.exists():
            raise HTTPException(404)
        RUNS[run_id] = {"events": _read_events(path), "done": True}
        _evict()

    async def gen():
        i, last_t = 0, 0.0
        while True:
            evs = RUNS[run_id]["events"]
            while i < len(evs):
                ev = evs[i]
                if replay:  # re-play a recorded run at accelerated real-time pace
                    await asyncio.sleep(min(max(ev.get("t", 0) - last_t, 0) / replay, 1.5))
                    last_t = ev.get("t", last_t)
                yield f"data: {json.dumps(ev)}\n\n"
                i += 1
            if RUNS[run_id]["done"] and i >= len(RUNS[run_id]["events"]):
                break
            await asyncio.sleep(0.25)
    return StreamingResponse(gen(), media_type="text/event-stream")


app.mount("/static", StaticFiles(directory=config.ROOT / "web"), name="static")


@app.get("/api/runs/{run_id}/vex")
def run_vex(run_id: str):
    evs = RUNS.get(run_id, {}).get("events")
    if evs is None:
        if not RUN_ID.fullmatch(run_id):
            raise HTTPException(404, "unknown run")
        path = config.RUNS_DIR / f"{run_id}.jsonl"
        if not path.exists():
            raise HTTPException(404, "unknown run")
        evs = _read_events(path)
    doc = next((e["document"] for e in reversed(evs) if e.get("type") == "vex"), None)
    if doc is None:
        raise HTTPException(404, "no OpenVEX document for this run")
    return doc


PAGES = {"": "landing", "console": "console", "app": "console", "runs": "runs", "how": "how", "org": "org"}


@app.get("/{page}")
@app.get("/", include_in_schema=False)
def page(page: str = ""):
    if page not in PAGES:
        raise HTTPException(404)
    return FileResponse(config.ROOT / "web" / f"{PAGES[page]}.html")
