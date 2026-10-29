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
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

from . import config, sources
from .agent import PIN, Agent

app = FastAPI(title="PatchPilot")
app.add_middleware(GZipMiddleware, minimum_size=1000)
RUNS = {}  # run_id -> {"events": [...], "done": bool}
MAX_RUNS = 50
MAX_ACTIVE_RUNS = 3
IDLE_TIMEOUT = 600.0  # seconds an SSE stream may go without new events before it is closed
ORG_TTL, ORG_MAX_OSV = 600.0, 300
RATE_LIMIT, RATE_WINDOW = 5, 60.0
_hits = collections.defaultdict(collections.deque)
_lock = threading.Lock()
_runs_lock = threading.RLock()
_org_cache = {}  # owner.lower() -> (monotonic time, result)
RUN_ID = re.compile(r"[\w.-]+")
REPO = re.compile(r"https://github\.com/[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}?(?:\.git)?/?")
CSP = ("default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
       "img-src 'self' data:; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
SECURITY_HEADERS = {"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                    "Referrer-Policy": "strict-origin-when-cross-origin"}
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


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


class CachedStatic(StaticFiles):
    async def get_response(self, path, scope):
        resp = await super().get_response(path, scope)
        if resp.status_code == 200:
            resp.headers.setdefault("Cache-Control", "public, max-age=3600")
        return resp


def _evict():
    with _runs_lock:
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


def _check_token(request):
    token = os.getenv("PATCHPILOT_TOKEN", "")
    if token and request.headers.get("authorization", "") != f"Bearer {token}":
        raise HTTPException(401, "Missing or invalid bearer token")


def _ip(request):
    return request.client.host if request.client else "?"


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
        with _runs_lock:
            run = RUNS.get(run_id)
            if run is not None:
                run["events"].append(ev)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
        if ev["type"] == "done":
            with _runs_lock:
                if run_id in RUNS:
                    RUNS[run_id]["done"] = True
    return emit


def _run_agent(run_id, repo, emit):
    """Thread target: whatever happens inside the agent, the stream always ends with a done event."""
    err = "agent exited without finishing"
    try:
        Agent(run_id, repo, emit).run()
    except Exception as e:  # surfaced to the client as the run's error
        log.exception("agent run %s crashed", run_id)
        err = f"{type(e).__name__}: {e}"
    finally:
        with _runs_lock:
            finished = RUNS.get(run_id, {}).get("done", True)
        if not finished:
            emit({"type": "done", "ok": False, "error": err})


@app.api_route("/api/health", methods=["GET", "HEAD"])
def health():
    return {"nebius": bool(config.NEBIUS_API_KEY), "provider": config.provider_name(), "tavily": bool(config.TAVILY_API_KEY),
            "github": bool(config.GITHUB_TOKEN), "remote_repos": config.ALLOW_REMOTE_REPOS}


@app.get("/api/cases")
def cases():
    try:
        dirs = sorted(config.CASES_DIR.iterdir())
    except OSError:
        return []
    out = []
    for d in dirs:
        req = d / "requirements.txt"
        try:
            text = req.read_text(encoding="utf-8") if req.exists() else None
        except (OSError, UnicodeDecodeError):
            continue
        if text is not None:
            pins = [l.strip() for l in text.splitlines() if "==" in l and not l.startswith("pytest")]
            out.append({"id": d.name, "pins": pins})
    return out


@app.get("/api/bench")
def bench():
    p = config.RUNS_DIR / "batch-summary.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


@app.get("/api/org/{owner}")
def org_scan(owner: str, request: Request):
    """Scan every public repo of a GitHub user/org: pinned requirements.txt -> OSV advisories."""
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", owner):
        raise HTTPException(400, "Invalid GitHub owner")
    _check_token(request)
    key = owner.lower()
    with _lock:
        hit = _org_cache.get(key)
    if hit and time.monotonic() - hit[0] < ORG_TTL:
        return hit[1]
    if not _rate_ok("org:" + _ip(request)):
        raise HTTPException(429, "Too many scans; try again in a minute")
    try:
        with httpx.Client(timeout=20, headers={"Accept": "application/vnd.github+json",
                          **({"Authorization": f"Bearer {config.GITHUB_TOKEN}"} if config.GITHUB_TOKEN else {})}) as gh:
            result = _org_scan(gh, owner)
    except httpx.HTTPError:
        log.warning("GitHub request failed for %s", owner, exc_info=True)
        raise HTTPException(502, "GitHub unreachable")
    now = time.monotonic()
    with _lock:
        for k in [k for k, (t, _) in _org_cache.items() if now - t >= ORG_TTL]:
            del _org_cache[k]
        _org_cache[key] = (now, result)
    return result


def _org_scan(gh, owner):
    r = gh.get(f"https://api.github.com/users/{owner}/repos", params={"per_page": 40, "sort": "pushed"})
    if r.status_code == 404:
        raise HTTPException(404, f"No GitHub user or org named '{owner}'")
    if r.status_code in (403, 429) and r.headers.get("X-RateLimit-Remaining") == "0":
        raise HTTPException(429, "GitHub rate limit hit. Set GITHUB_TOKEN in .env to raise it")
    if not 200 <= r.status_code < 300:
        raise HTTPException(502, f"GitHub returned HTTP {r.status_code}")
    repos = [x for x in r.json() if not x.get("fork") and not x.get("archived") and x.get("language") in ("Python", None)]
    budget, budget_lock = [ORG_MAX_OSV], threading.Lock()  # cap total OSV calls per scan

    def take():
        with budget_lock:
            if budget[0] <= 0:
                return False
            budget[0] -= 1
            return True

    def scan(repo):
        row = {"name": repo["name"], "url": repo["html_url"], "stars": repo.get("stargazers_count", 0),
               "pins": 0, "packages": [], "critical": 0, "high": 0, "other": 0, "has_reqs": False}
        try:
            raw = gh.get(f"https://raw.githubusercontent.com/{repo['full_name']}/{repo['default_branch']}/requirements.txt")
        except httpx.HTTPError as e:
            row["error"] = f"requirements.txt fetch failed ({type(e).__name__})"
            return row
        row["has_reqs"] = raw.status_code == 200
        if raw.status_code != 200:
            return row
        for line in raw.text.splitlines()[:60]:
            m = PIN.match(line.split("#")[0])
            if not m:
                continue
            row["pins"] += 1
            if not take():
                row["truncated"] = True
                continue
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
    return {"owner": owner, "scanned": len(rows), "repos": rows, "osv_capped": budget[0] <= 0,
            "reason": _org_reason(rows, budget[0] <= 0)}


def _org_reason(rows, capped):
    """Short human explanation of why an org scan shows little or nothing (None when there is nothing to explain)."""
    if not rows:
        return "no public python repos"
    if not any(r["has_reqs"] for r in rows):
        return "no requirements.txt found"
    if not any(r["pins"] for r in rows):
        return "no pinned requirements (pkg==x.y.z)"
    if capped:
        return "osv lookup limit reached; results partial"
    if any(r.get("error") for r in rows):
        return "some repos could not be fetched"
    return None


@app.post("/api/runs")
def start_run(req: RunRequest, request: Request):
    _check_token(request)
    if not config.NEBIUS_API_KEY:
        raise HTTPException(400, "NEBIUS_API_KEY is not configured on the server")
    with _runs_lock:
        if sum(1 for v in RUNS.values() if not v["done"]) >= MAX_ACTIVE_RUNS:
            raise HTTPException(429, "Too many runs in progress; try again shortly")
    if not _rate_ok(_ip(request)):
        raise HTTPException(429, "Too many runs; try again in a minute")
    run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
    with _runs_lock:
        RUNS[run_id] = {"events": [], "done": False}
    _evict()
    emit = _record(run_id)
    emit({"type": "start", "repo": req.repo or f"case:{config.DEFAULT_CASE}", "t": 0})
    threading.Thread(target=_run_agent, args=(run_id, req.repo, emit), daemon=True).start()
    return {"id": run_id}


@app.api_route("/api/runs", methods=["GET", "HEAD"])
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
        done = last.get("type") == "done"
        row = {"id": p.stem, "repo": first.get("repo"), "ok": last.get("ok") if done else None}
        if done and last.get("ok") is False:
            # failure reason: the done event's error, else the last error event's msg (older recordings)
            err = last.get("error") or next((e.get("msg") for e in reversed(evs) if e.get("type") == "error" and e.get("msg")), None)
            row["error"] = str(err)[:300] if err else None
        out.append(row)
    return out[:30]


@app.get("/api/runs/{run_id}/events")
async def events(run_id: str, replay: float = Query(0, ge=0, le=100, allow_inf_nan=False)):
    run = RUNS.get(run_id)
    if run is None:
        if not RUN_ID.fullmatch(run_id):
            raise HTTPException(404)
        path = config.RUNS_DIR / f"{run_id}.jsonl"
        if not path.exists():
            raise HTTPException(404)
        evs = _read_events(path)
        with _runs_lock:
            run = RUNS.setdefault(run_id, {"events": evs, "done": True})
        _evict()

    async def gen():
        i, last_t, idle_since = 0, 0.0, time.monotonic()
        while True:
            evs = run["events"]
            if i < len(evs):
                idle_since = time.monotonic()
            while i < len(evs):
                ev = evs[i]
                if replay:  # re-play a recorded run at accelerated real-time pace
                    await asyncio.sleep(min(max(ev.get("t", 0) - last_t, 0) / replay, 1.5))
                    last_t = ev.get("t", last_t)
                yield f"data: {json.dumps(ev)}\n\n"
                i += 1
            if run["done"] and i >= len(run["events"]):
                break
            if time.monotonic() - idle_since > IDLE_TIMEOUT:
                yield f"data: {json.dumps({'type': 'error', 'msg': 'Stream idle: no new events for too long'})}\n\n"
                break
            await asyncio.sleep(0.25)
    return StreamingResponse(gen(), media_type="text/event-stream")


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


@app.api_route("/robots.txt", methods=["GET", "HEAD"], include_in_schema=False)
def robots():
    return PlainTextResponse("User-agent: *\nAllow: /\n", headers={"Cache-Control": "public, max-age=86400"})


@app.api_route("/favicon.svg", methods=["GET", "HEAD"], include_in_schema=False)
def favicon():
    return FileResponse(config.ROOT / "web" / "favicon.svg", media_type="image/svg+xml",
                        headers={"Cache-Control": "public, max-age=86400"})


app.mount("/static", CachedStatic(directory=config.ROOT / "web"), name="static")

PAGES = {"": "landing", "console": "console", "app": "console", "runs": "runs", "how": "how", "org": "org"}


@app.api_route("/{page}", methods=["GET", "HEAD"])
@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
def page(page: str = ""):
    if page not in PAGES:
        raise HTTPException(404)
    return FileResponse(config.ROOT / "web" / f"{PAGES[page]}.html")
