"""FastAPI server: start runs, stream events over SSE, replay recorded runs."""
import asyncio
import collections
import contextlib
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import (FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response,
                               StreamingResponse)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from . import auth, config, db, export, manifests, notify, sandbox, scanner, scheduler, settings, sources
from .agent import PIN, Agent


class _GZipExceptSSE(GZipMiddleware):
    """gzip buffers a streamed body until its compressor flushes, which stalls Server-Sent Events in browsers."""
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"].endswith("/events"):
            await self.app(scope, receive, send)
        else:
            await super().__call__(scope, receive, send)


@contextlib.asynccontextmanager
async def _lifespan(_app):
    _resume_queue()
    scheduler.start(lambda fn: _spawn(fn))  # PATCHPILOT_SCHEDULER=0 turns it off
    yield
    scheduler.stop()


app = FastAPI(title="PatchPilot", lifespan=_lifespan)
app.add_middleware(_GZipExceptSSE, minimum_size=1000)
RUNS = {}  # run_id -> {"events": [...], "done": bool}
MAX_RUNS = 50
MAX_ACTIVE_RUNS = 3
IDLE_TIMEOUT = 600.0  # seconds an SSE stream may go without new events before it is closed
ORG_TTL, ORG_MAX_OSV = 600.0, 300
RATE_LIMIT, RATE_WINDOW = 5, 60.0  # strict bucket: anonymous callers, sign-in attempts, LLM fix runs, org scans
USER_RATE_LIMIT = 60  # signed-in users and API keys: project and scan calls per minute
_hits = collections.defaultdict(collections.deque)
_lock = threading.Lock()
_runs_lock = threading.RLock()
_org_cache = {}  # owner.lower() -> (monotonic time, result)
RUN_ID = re.compile(r"[\w.-]+")
REPO = re.compile(r"https://github\.com/[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}?(?:\.git)?/?")
CASE = re.compile(r"case:[\w.-]{1,64}")
REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}")
MAX_UPLOAD = manifests.MAX_LOCK  # bytes of manifest text per uploaded project (lock files; others 1 MB)
MAX_BODY = MAX_UPLOAD + 1_000_000  # request bodies above this are refused with 413 before they are parsed
SUBDIR = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){0,4}")
CSP = ("default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
       "img-src 'self' data:; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
SECURITY_HEADERS = {"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                    "Referrer-Policy": "strict-origin-when-cross-origin"}
log = logging.getLogger(__name__)
config.RUNS_DIR.mkdir(parents=True, exist_ok=True)


class RunRequest(BaseModel):
    repo: str = ""
    project: int | None = Field(None, ge=1)

    @field_validator("repo")
    @classmethod
    def _repo(cls, v):
        v = v.strip()
        if v and (len(v) > 200 or not (REPO.fullmatch(v) or CASE.fullmatch(v))):
            raise ValueError("repo must be https://github.com/owner/repo or case:<sample>")
        return v


class ProjectRequest(BaseModel):
    """Exactly one source: a GitHub URL (+ optional ref), an uploaded manifest, or a local path."""
    name: str = Field("", max_length=100)
    git_url: str = ""
    ref: str = ""
    filename: str = ""
    content: str = Field("", max_length=MAX_UPLOAD)
    path: str = Field("", max_length=500)
    subdir: str = Field("", max_length=200)

    @field_validator("subdir")
    @classmethod
    def _subdir(cls, v):
        v = v.strip().strip("/")
        if v and (not SUBDIR.fullmatch(v) or ".." in v.split("/")):
            raise ValueError("subdir must be a relative folder such as backend or services/api")
        return v

    @field_validator("git_url")
    @classmethod
    def _git(cls, v):
        v = v.strip()
        if v and (len(v) > 200 or not REPO.fullmatch(v)):
            raise ValueError("git_url must be https://github.com/owner/repo")
        return v.rstrip("/").removesuffix(".git")

    @field_validator("ref")
    @classmethod
    def _ref(cls, v):
        v = v.strip()
        if v and (not REF.fullmatch(v) or ".." in v):
            raise ValueError("ref must be a branch, tag or commit name")
        return v

    @field_validator("filename")
    @classmethod
    def _filename(cls, v):
        v = v.strip().replace("\\", "/").rsplit("/", 1)[-1]
        if v and (len(v) > 100 or manifests.kind_of(v) is None):
            raise ValueError("filename must be requirements*.txt, pyproject.toml, poetry.lock, uv.lock or Pipfile.lock")
        return v


def _clean_msg(e):
    """One validation error as a short sentence: the field and pydantic's message, never the input value."""
    loc = ".".join(str(x) for x in e.get("loc", ()) if x not in ("body", "query", "path"))
    msg = re.sub(r"^(Value error|Assertion failed), ", "", str(e.get("msg", "invalid value")))
    return f"{loc}: {msg}" if loc and not msg.lower().startswith(loc.lower()) else msg


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    if any(e.get("type") == "string_too_long" and "content" in e.get("loc", ()) for e in errors):
        return JSONResponse({"detail": f"Manifest is larger than {MAX_UPLOAD // 1_000_000} MB"}, status_code=413)
    if any(e.get("type") == "json_invalid" for e in errors):
        return JSONResponse({"detail": "Request body is not valid JSON"}, status_code=422)
    return JSONResponse({"detail": "; ".join(dict.fromkeys(_clean_msg(e) for e in errors)) or "Invalid request"},
                        status_code=422)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    try:
        too_big = int(request.headers.get("content-length") or 0) > MAX_BODY
    except ValueError:
        too_big = False
    if too_big:
        resp = JSONResponse({"detail": f"Request body is larger than {MAX_BODY // 1_000_000} MB"}, status_code=413)
    else:
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


def _rate_ok(ip, now=None, limit=None):
    return _rate_wait(ip, now, limit) == 0


def _rate_wait(key, now=None, limit=None):
    """Record a hit for `key`; 0 if allowed, else the seconds until the next hit would be."""
    now = time.monotonic() if now is None else now
    limit = RATE_LIMIT if limit is None else limit
    with _lock:
        q = _hits[key]
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= limit:
            return max(1, int(RATE_WINDOW - (now - q[0])) + 1)
        q.append(now)
        return 0


def _limit(key, msg, limit=None):
    """429 with a Retry-After header when `key` is over its per-minute budget."""
    wait = _rate_wait(key, limit=limit)
    if wait:
        raise HTTPException(429, msg, headers={"Retry-After": str(wait)})


# ---------- authentication ----------
# Who is calling: a cookie session (browser), an API key (Authorization: Bearer pp_...), or the legacy
# PATCHPILOT_TOKEN bearer, which acts as an admin. Cookie-authenticated writes must carry the custom header
# X-Requested-With: patchpilot, which a cross-site form or image cannot send (CSRF).
CSRF_HEADER, CSRF_VALUE = "x-requested-with", "patchpilot"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def _public_demo():
    """PATCHPILOT_PUBLIC_DEMO=1: anonymous visitors may read sample projects and the shipped demo-run replays."""
    return os.getenv("PATCHPILOT_PUBLIC_DEMO", "") == "1"


def principal(request):
    """The authenticated caller as {id, email, name, role, via, label}, or None."""
    if hasattr(request.state, "pp_user"):
        return request.state.pp_user
    user = None
    authz = request.headers.get("authorization", "")
    if authz.startswith("Bearer "):
        tok = authz[7:].strip()
        legacy = os.getenv("PATCHPILOT_TOKEN", "")
        if legacy and secrets.compare_digest(tok.encode(), legacy.encode()):
            user = {"id": None, "email": None, "name": "PATCHPILOT_TOKEN", "role": "admin", "via": "token",
                    "label": "token"}
        else:
            hit = auth.key_user(tok)
            if hit:
                user, prefix = hit
                user.update(via="apikey", label=f"{user['email']} (key {prefix}…)")
    if user is None:
        user = auth.session_user(request.cookies.get(auth.SESSION_COOKIE))
        if user:
            user.update(via="session", label=user["email"])
    request.state.pp_user = user
    return user


def _need(request, role="member"):
    """Require a signed-in caller (and admin for role="admin"); enforce the CSRF header on cookie writes."""
    user = principal(request)
    if user is None:
        raise HTTPException(401, "Sign in required")
    if (user["via"] == "session" and request.method not in SAFE_METHODS
            and request.headers.get(CSRF_HEADER, "").lower() != CSRF_VALUE):
        raise HTTPException(403, "Missing X-Requested-With: patchpilot header")
    if role == "admin" and user["role"] != "admin":
        raise HTTPException(403, "Admins only")
    return user


def _reader(request):
    """Read access: a signed-in user, or None for an anonymous visitor of a public demo (callers then filter)."""
    user = principal(request)
    if user is None and not _public_demo():
        raise HTTPException(401, "Sign in required")
    return user


def _audit(request, action, detail=None):
    user = principal(request)
    db.audit(user["label"] if user else "anonymous", action, {**(detail or {}), "ip": _ip(request)})


def _ip(request):
    return request.client.host if request.client else "?"


def _run_path(run_id, demo_only=False):
    """Recorded run file for a validated id: live RUNS_DIR first, then the shipped demo folder."""
    if not RUN_ID.fullmatch(run_id):
        return None
    for d in (config.DEMO_RUNS_DIR,) if demo_only else (config.RUNS_DIR, config.DEMO_RUNS_DIR):
        p = d / f"{run_id}.jsonl"
        if p.is_file():
            return p
    return None


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
            try:
                db.finish_run(run_id, bool(ev.get("ok")), {"error": ev["error"]} if ev.get("error") else None)
            except Exception:
                log.warning("could not record end of run %s", run_id, exc_info=True)
            try:
                pid = db.runs_by_id().get(run_id)
                if pid:
                    notify.fix_completed(pid, run_id, bool(ev.get("ok")), ev.get("error"))
            except Exception:
                log.warning("fix_completed notification failed for run %s", run_id, exc_info=True)
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
    # model ids are the configured MODEL_* values (None = discovered from the provider catalog at run time)
    llm = bool(config.llm_api_key())
    return {"nebius": llm, "provider": config.provider_name() if llm else None, "tavily": bool(config.tavily_api_key()),
            "github": bool(config.github_token()), "remote_repos": config.allow_remote_repos(),
            "local_paths": config.ALLOW_LOCAL_PATHS, "fix_mode": bool(config.llm_api_key()), "scan_mode": True,
            "models": {t: (m or None) for t, m in config.model_overrides().items()},
            "guard_model": config.model_guard() or None, "public_demo": _public_demo(),
            "sandbox": _sandbox_state(), "remote_fix": config.remote_fix_allowed(),
            "scheduler": os.getenv("PATCHPILOT_SCHEDULER", "1") != "0", "public_url": bool(config.public_url())}


def _sandbox_state():
    """Where fix-run tests execute: mode, and for docker whether the daemon answers (so the UI can explain)."""
    mode = config.sandbox_mode()
    out = {"mode": mode, "image": config.sandbox_image() if mode == "docker" else None}
    out["docker"] = sandbox.docker_available() if mode == "docker" else None
    out["ready"] = mode == "local" or bool(out["docker"])
    return out


@app.get("/api/stats")
def stats(request: Request):
    user = _reader(request)
    if user is None:  # anonymous public demo: sample projects only
        d = db.dashboard(_sample_ids())
        return {"projects": d["projects"], "scans": None, "open_findings": d["open"]}
    return db.stats()


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
    for d in (config.RUNS_DIR, config.DEMO_RUNS_DIR):
        try:
            data = json.loads((d / "batch-summary.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, list) and data:
            return data
    return []


@app.get("/api/org/{owner}")
def org_scan(owner: str, request: Request):
    """Scan every public repo of a GitHub user/org: pinned requirements.txt -> OSV advisories."""
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", owner):
        raise HTTPException(400, "Invalid GitHub owner")
    _need(request)
    key = owner.lower()
    with _lock:
        hit = _org_cache.get(key)
    if hit and time.monotonic() - hit[0] < ORG_TTL:
        return hit[1]
    _limit("org:" + _ip(request), "Too many scans; try again in a minute")
    try:
        with httpx.Client(timeout=20, headers={"Accept": "application/vnd.github+json",
                          **({"Authorization": f"Bearer {config.github_token()}"} if config.github_token() else {})}) as gh:
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


def _fix_target(req):
    """(repo source for the agent, project id or None). Fix mode needs code to run, so uploads can't be fixed."""
    if req.project is None:
        if not req.repo:
            raise HTTPException(422, "Choose a project (or give a repo URL) to fix")
        return req.repo, None
    p = db.get_project(req.project)
    if p is None:
        raise HTTPException(404, "Unknown project")
    if p["source_type"] == "git":
        return p["source"], p["id"]
    if p["source_type"] == "sample":
        return f"case:{p['source']}", p["id"]
    if p["source_type"] == "upload":
        raise HTTPException(400, "Uploaded manifests can be scanned but not fixed: the agent needs the code and tests. "
                                 "Add the project as a GitHub repository to use fix mode")
    raise HTTPException(400, "Fix mode is not available for local path projects yet")


def _active_runs():
    with _runs_lock:
        return sum(1 for v in RUNS.values() if not v["done"])


def _launch(repo, project_id):
    """Start an agent fix run in a thread; the caller has checked keys, sandbox and the run budget."""
    run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
    with _runs_lock:
        RUNS[run_id] = {"events": [], "done": False}
    _evict()
    emit = _record(run_id)
    db.create_scan(project_id, "fix", "running", run_id)
    emit({"type": "start", "repo": repo, "project": project_id, "t": 0})
    threading.Thread(target=_run_agent, args=(run_id, repo, emit), daemon=True).start()
    return run_id


@app.post("/api/runs")
def start_run(req: RunRequest, request: Request):
    _need(request)
    if not config.llm_api_key():
        raise HTTPException(400, "No LLM API key is configured on the server (Settings or NEBIUS_API_KEY)")
    repo, project_id = _fix_target(req)
    try:
        sandbox.check_mode()
    except sandbox.SandboxUnavailable as e:
        raise HTTPException(503, str(e))
    if repo.startswith("https://") and not config.remote_fix_allowed():
        raise HTTPException(403, "Fix runs on remote repositories are disabled: use the Docker sandbox (SANDBOX=docker) "
                                 "or let an admin allow remote repos in Settings")
    if _active_runs() >= MAX_ACTIVE_RUNS:
        raise HTTPException(429, "Too many runs in progress; try again shortly", headers={"Retry-After": "30"})
    _limit(_ip(request), "Too many runs; try again in a minute")
    run_id = _launch(repo, project_id)
    _audit(request, "run.start", {"run_id": run_id, "project_id": project_id, "repo": repo})
    return {"id": run_id}


def autofix_after_scan(scan_id, project_id, ok):
    """Scanner hook: when a project's policy has auto_fix on and this scan found new fixable findings at or above
    its threshold, start an agent fix run (if fix mode can run here). Returns why it did or did not start."""
    if not ok:
        return "scan failed"
    pol = db.get_policy(project_id)
    if not pol["auto_fix"]:
        return "auto_fix off"
    project = db.get_project(project_id)
    if project is None or project["source_type"] not in ("git", "sample"):
        return "not a repository project"
    fixable = [f for f in db.new_findings(scan_id) if not f.get("suppressed") and f.get("fixed_in")]
    if not fixable:
        return "no new fixable findings"
    reason = None
    if not config.llm_api_key():
        reason = "no LLM API key"
    elif project["source_type"] == "git" and not config.remote_fix_allowed():
        reason = "remote fix runs not allowed (enable the Docker sandbox or allow remote repos)"
    else:
        try:
            sandbox.check_mode()
        except sandbox.SandboxUnavailable:
            reason = "Docker sandbox unavailable"
    if reason is None:
        with _runs_lock:
            if any(r["kind"] == "fix" and r["status"] == "running" for r in db.list_scans(project_id, 5)):
                reason = "a fix run is already in progress for this project"
            elif _active_runs() >= MAX_ACTIVE_RUNS:
                reason = f"{MAX_ACTIVE_RUNS} fix runs already in progress"
    if reason:
        db.audit("auto-fix", "autofix.skipped", {"project_id": project_id, "scan_id": scan_id, "reason": reason})
        return reason
    repo = project["source"] if project["source_type"] == "git" else f"case:{project['source']}"
    run_id = _launch(repo, project_id)
    db.audit("auto-fix", "autofix.start", {"project_id": project_id, "scan_id": scan_id, "run_id": run_id,
                                           "findings": len(fixable)})
    return "started"


if autofix_after_scan not in scanner.AFTER_SCAN:
    scanner.AFTER_SCAN.append(autofix_after_scan)


@app.api_route("/api/runs", methods=["GET", "HEAD"])
def list_runs(request: Request):
    out, seen = [], {}
    dirs = (config.RUNS_DIR, config.DEMO_RUNS_DIR) if _reader(request) else (config.DEMO_RUNS_DIR,)
    for d in dirs:  # live runs shadow demo runs with the same id
        for p in d.glob("*.jsonl"):
            if RUN_ID.fullmatch(p.stem):
                seen.setdefault(p.stem, p)
    try:
        projects = db.runs_by_id()
    except Exception:
        log.warning("could not read run/project links", exc_info=True)
        projects = {}
    for p in sorted(seen.values(), key=lambda p: p.stem, reverse=True):
        try:
            evs = _read_events(p)
        except OSError:
            continue
        if not evs:
            continue
        first, last = evs[0], evs[-1]
        done = last.get("type") == "done"
        row = {"id": p.stem, "repo": first.get("repo"), "ok": last.get("ok") if done else None}
        if p.parent == config.DEMO_RUNS_DIR:
            row["sample"] = True  # recorded run shipped with PatchPilot, not one of this server's own runs
        if projects.get(p.stem):
            row["project"] = projects[p.stem]
        if done and last.get("ok") is False:
            # failure reason: the done event's error, else the last error event's msg (older recordings),
            # else the final test summary (a run that simply ended with failing tests)
            err = (last.get("error")
                   or next((e.get("msg") for e in reversed(evs) if e.get("type") == "error" and e.get("msg")), None)
                   or next((f"Tests still failing: {e['summary']}" for e in reversed(evs)
                            if e.get("type") == "test" and e.get("summary")), None))
            row["error"] = str(err)[:300] if err else None
        out.append(row)
    return out[:30]


@app.get("/api/runs/{run_id}/events")
async def events(run_id: str, request: Request, replay: float = Query(0, ge=0, le=100, allow_inf_nan=False)):
    anonymous = _reader(request) is None
    run = None if anonymous else RUNS.get(run_id)
    if run is None:
        path = _run_path(run_id, demo_only=anonymous)
        if path is None:
            raise HTTPException(404)
        evs = _read_events(path)
        if anonymous:
            run = {"events": evs, "done": True}
        else:
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
def run_vex(run_id: str, request: Request):
    anonymous = _reader(request) is None
    evs = None if anonymous else RUNS.get(run_id, {}).get("events")
    if evs is None:
        path = _run_path(run_id, demo_only=anonymous)
        if path is None:
            raise HTTPException(404, "unknown run")
        evs = _read_events(path)
    doc = next((e["document"] for e in reversed(evs) if e.get("type") == "vex"), None)
    if doc is None:
        raise HTTPException(404, "no OpenVEX document for this run")
    return doc


# ---------- projects + scan-only mode ----------
def _mutate(request, bucket="api"):
    """Guard for mutating project endpoints: a signed-in member (or admin), then a per-caller rate limit
    (USER_RATE_LIMIT a minute per account or API key, keyed by IP for the account-less legacy token)."""
    user = _need(request)
    who = f"u{user['id']}" if user.get("id") is not None else _ip(request)
    _limit(f"{bucket}:{who}", "Too many requests; try again in a minute", USER_RATE_LIMIT)
    return user


def _sample_ids():
    return {p["id"] for p in db.list_projects() if p["source_type"] == "sample"}


def _visible(request, pid):
    """A project the caller may read (anonymous public-demo visitors: sample projects only), else 404."""
    user = _reader(request)
    p = db.get_project(pid)
    if p is None or (user is None and p["source_type"] != "sample"):
        raise HTTPException(404, "Unknown project")
    return p


def _spawn(fn, *args):
    """Background scan worker (tests replace this to run inline)."""
    threading.Thread(target=fn, args=args, daemon=True, name="pp-scan-worker").start()


def _resume_queue():
    """Scans that were queued or running when the server stopped are queued again and picked up now."""
    try:
        if db.requeue_interrupted() or db._q("SELECT 1 FROM scans WHERE kind = 'scan' AND status = 'queued' LIMIT 1"):
            for _ in range(scanner.MAX_ACTIVE_SCANS):
                scanner.kick(lambda fn: _spawn(fn))
    except Exception:
        log.warning("could not resume queued scans", exc_info=True)


def _project_or_404(pid):
    p = db.get_project(pid)
    if p is None:
        raise HTTPException(404, "Unknown project")
    return p


@app.post("/api/projects", status_code=201)
def create_project(req: ProjectRequest, request: Request):
    _need(request)
    given = [k for k, v in (("git", req.git_url), ("upload", req.filename or req.content), ("path", req.path)) if v]
    if len(given) != 1:
        raise HTTPException(422, "Give exactly one source: git_url, an uploaded manifest (filename + content), or path")
    kind = given[0]
    if req.subdir and kind == "upload":
        raise HTTPException(422, "subdir applies to repository and folder projects, not uploads")
    if kind == "upload":
        if not req.filename or not req.content.strip():
            raise HTTPException(422, "An uploaded manifest needs a filename and non-empty content")
        limit = manifests.size_limit(req.filename)
        if len(req.content.encode("utf-8")) > limit:
            raise HTTPException(413, f"{req.filename} is larger than {limit // 1_000_000} MB "
                                     f"(lock files may be up to {manifests.MAX_LOCK // 1_000_000} MB)")
        try:
            manifests.check_upload(req.filename, req.content)
            deps = manifests.parse(req.filename, req.content)
        except manifests.ManifestError as e:
            raise HTTPException(422, str(e))
        if not deps:
            raise HTTPException(422, f"No dependencies found in {req.filename}")
    if kind == "path":
        if not config.ALLOW_LOCAL_PATHS:
            raise HTTPException(403, "Local path projects are disabled on this server (ALLOW_LOCAL_PATHS=0)")
        if not os.path.isabs(req.path) or not os.path.isdir(req.path):
            raise HTTPException(422, "path must be an absolute path to an existing directory")
    _mutate(request)
    if kind == "git":  # fail now, with a clear reason, rather than on the first scan
        try:
            scanner.check_github(req.git_url, req.ref or None)
        except scanner.GitHubError as e:
            raise HTTPException(e.status, str(e))
        except scanner.ScanError as e:
            raise HTTPException(422, str(e))
    source = {"git": req.git_url, "upload": req.filename, "path": req.path}[kind]
    default = {"git": req.git_url.removeprefix("https://github.com/"), "upload": req.filename,
               "path": os.path.basename(req.path.rstrip("/\\")) or req.path}[kind]
    name = req.name.strip() or default
    pid = db.create_project(name, kind, source, ref=req.ref or None if kind == "git" else None,
                            manifest=req.content if kind == "upload" else None, subdir=req.subdir or None)
    _audit(request, "project.create", {"id": pid, "type": kind, "source": source})
    return db.get_project(pid)


@app.post("/api/projects/scan-all", status_code=202)
def scan_all(request: Request):
    """Admin: queue a scan for every project that has none queued or running."""
    _need(request, "admin")
    _limit("scanall:" + _ip(request), "Too many requests; try again in a minute")
    queued = []
    for p in db.list_projects():
        if not db.active_scan(p["id"]):
            queued.append(db.create_scan(p["id"], "scan", "queued"))
    _audit(request, "scan.all", {"scans": len(queued)})
    for _ in range(min(len(queued), scanner.MAX_ACTIVE_SCANS)):
        scanner.kick(lambda fn: _spawn(fn))
    return {"queued": len(queued), "scan_ids": queued}


@app.post("/api/projects/samples", status_code=201)
def create_samples(request: Request):
    """Add the bundled demo cases as sample projects (skipping any already added)."""
    _mutate(request)
    try:
        dirs = sorted(d for d in config.CASES_DIR.iterdir() if (d / "requirements.txt").is_file())
    except OSError:
        dirs = []
    created = []
    for d in dirs:
        if db.find_project("sample", d.name) is None:
            created.append(db.create_project(f"Sample: {d.name}", "sample", d.name))
    if created:
        _audit(request, "project.samples", {"ids": created})
    return {"created": created, "projects": db.list_projects()}


@app.get("/api/projects")
def list_projects(request: Request):
    user = _reader(request)
    return [p for p in db.list_projects() if user or p["source_type"] == "sample"]


@app.get("/api/projects/{pid}")
def get_project(pid: int, request: Request):
    return _visible(request, pid)


@app.delete("/api/projects/{pid}", status_code=204)
def delete_project(pid: int, request: Request):
    _mutate(request)
    _project_or_404(pid)
    db.delete_project(pid)
    _audit(request, "project.delete", {"id": pid})


@app.get("/api/projects/{pid}/scans")
def project_scans(pid: int, request: Request):
    _visible(request, pid)
    return db.list_scans(pid)


@app.post("/api/projects/{pid}/scan", status_code=202)
def start_scan(pid: int, request: Request):
    """Scan-only mode: manifests -> OSV/EPSS/KEV/PyPI. Needs no LLM key and never runs repository code,
    which is why it is allowed for remote repos even when ALLOW_REMOTE_REPOS=0."""
    _need(request)
    _project_or_404(pid)
    running = db.active_scan(pid)
    if running:
        return {"id": running, "status": db.get_scan(running)["status"]}
    _mutate(request, "scan")
    sid = db.create_scan(pid, "scan", "queued")
    _audit(request, "scan.start", {"project_id": pid, "scan_id": sid})
    # at most MAX_ACTIVE_SCANS run at once; the rest stay 'queued' and a worker picks them up in order
    scanner.kick(lambda fn: _spawn(fn))
    s = db.get_scan(sid)
    out = {"id": sid, "status": s["status"]}
    if s["status"] == "queued":
        out["position"] = db.queued_position(sid)
    return out


@app.get("/api/scans/{sid}")
def get_scan(sid: int, request: Request):
    s = db.get_scan(sid)
    if s is None or s["project_id"] is None:
        raise HTTPException(404, "Unknown scan")
    _visible(request, s["project_id"])
    return s


@app.get("/api/scans/{sid}/export")
def export_scan(sid: int, request: Request, format: str = Query("sarif", pattern="^(sarif|cyclonedx|json|csv)$")):
    """A finished scan as SARIF 2.1.0, CycloneDX 1.5 JSON, JSON or CSV (policy-suppressed findings are left out
    of SARIF and CycloneDX, and marked in JSON / CSV)."""
    s = db.get_scan(sid)
    if s is None or s["project_id"] is None or s["kind"] != "scan":
        raise HTTPException(404, "Unknown scan")
    p = _visible(request, s["project_id"])
    if s["status"] != "done":
        raise HTTPException(409, "The scan has not finished")
    summary = s["summary"] or {}
    report = {"name": p["name"], "findings": s["findings"], "deps": summary.get("deps") or [],
              "files": summary.get("files") or [], "commit": summary.get("commit"),
              "repository": p["source"] if p["source_type"] == "git" else None,
              "summary": {k: v for k, v in summary.items() if k != "deps"}}
    mime, ext = export.FORMATS[format]
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", p["name"]).strip("-")[:60] or "project"
    return Response(export.render(report, format), media_type=mime, headers={
        "Content-Disposition": f'attachment; filename="patchpilot-{slug}-scan{sid}.{ext}"'})


# ---------- per-project policy ----------
class PolicyRequest(BaseModel):
    severity_threshold: str = Field("low", pattern="^(low|moderate|high|critical)$")
    auto_fix: bool = False  # start a fix run when a scan finds new fixable findings (if fix mode can run)
    schedule: str | None = Field(None, pattern="^(off|daily|weekly)$")  # None keeps the stored schedule
    schedule_hour: int | None = Field(None, ge=0, le=23)  # UTC
    channels: list[int] | None = Field(None, max_length=100)  # None = every notification channel


class IgnoreRequest(BaseModel):
    vuln_id: str = Field(..., min_length=3, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    reason: str = Field(..., min_length=3, max_length=300)
    expires_at: float | None = Field(None, gt=0)


@app.get("/api/projects/{pid}/policy")
def get_policy(pid: int, request: Request):
    _visible(request, pid)
    return db.get_policy(pid)


@app.put("/api/projects/{pid}/policy")
def put_policy(pid: int, req: PolicyRequest, request: Request):
    user = _need(request)
    _project_or_404(pid)
    chans = req.channels if "channels" in req.model_fields_set else False
    if chans:
        known = {c["id"] for c in db.list_channels()}
        if any(c not in known for c in chans):
            raise HTTPException(422, "channels: unknown notification channel id")
    db.set_policy(pid, req.severity_threshold, req.auto_fix, user["label"], schedule=req.schedule,
                  schedule_hour=req.schedule_hour, channels=chans)
    pol = db.get_policy(pid)
    _audit(request, "policy.update", {"project_id": pid, "severity_threshold": req.severity_threshold,
                                      "auto_fix": req.auto_fix, "schedule": pol["schedule"],
                                      "schedule_hour": pol["schedule_hour"], "channels": pol["channels"]})
    return pol


@app.post("/api/projects/{pid}/ignores", status_code=201)
def add_ignore(pid: int, req: IgnoreRequest, request: Request):
    user = _need(request)
    _project_or_404(pid)
    if req.expires_at is not None and req.expires_at <= time.time():
        raise HTTPException(422, "expires_at must be in the future")
    iid = db.add_ignore(pid, req.vuln_id, req.reason.strip(), req.expires_at, user["label"])
    _audit(request, "finding.ignore", {"project_id": pid, "ignore_id": iid, "vuln_id": req.vuln_id,
                                       "reason": req.reason.strip(), "expires_at": req.expires_at})
    return db.get_policy(pid)


@app.delete("/api/projects/{pid}/ignores/{iid}")
def delete_ignore(pid: int, iid: int, request: Request):
    _need(request)
    if not db.delete_ignore(pid, iid):
        raise HTTPException(404, "Unknown ignore entry")
    _audit(request, "finding.unignore", {"project_id": pid, "ignore_id": iid})
    return db.get_policy(pid)


# ---------- dashboard ----------
@app.get("/api/dashboard")
def dashboard(request: Request):
    user = _reader(request)
    return db.dashboard(None if user else _sample_ids())


# ---------- accounts ----------
class SetupRequest(BaseModel):
    email: str = Field(..., max_length=200)
    name: str = Field("", max_length=100)
    password: str = Field(..., max_length=200)


class LoginRequest(BaseModel):
    email: str = Field(..., max_length=200)
    password: str = Field(..., max_length=200)


class UserRequest(SetupRequest):
    role: str = Field("member", pattern="^(admin|member)$")


class RoleRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|member)$")


class PasswordRequest(BaseModel):
    current_password: str = Field(..., max_length=200)
    new_password: str = Field(..., max_length=200)


class ResetRequest(BaseModel):
    password: str = Field(..., max_length=200)


class KeyRequest(BaseModel):
    name: str = Field(..., max_length=80)
    role: str = Field("member", pattern="^(admin|member)$")


def _csrf(request):
    """Login and setup set a cookie, so they need the same custom header as cookie writes (no login CSRF)."""
    if request.headers.get(CSRF_HEADER, "").lower() != CSRF_VALUE:
        raise HTTPException(403, "Missing X-Requested-With: patchpilot header")


def _signed_in(request, uid):
    token = auth.create_session(uid)
    resp = JSONResponse({"user": auth.get_user(uid)})
    https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "") == "https"
    resp.set_cookie(auth.SESSION_COOKIE, token, max_age=auth.SESSION_TTL, httponly=True, samesite="lax",
                    secure=https, path="/")
    return resp


@app.get("/api/auth/state")
def auth_state(request: Request):
    user = principal(request)
    return {"setup_needed": auth.user_count() == 0, "public_demo": _public_demo(),
            "user": {k: user[k] for k in ("id", "email", "name", "role", "via")} if user else None}


@app.post("/api/auth/setup")
def auth_setup(req: SetupRequest, request: Request):
    _csrf(request)
    try:
        uid = auth.setup_admin(req.email, req.name, req.password)
    except auth.AuthError as e:
        raise HTTPException(409 if "already" in str(e) else 422, str(e))
    db.audit(req.email.strip(), "auth.setup", {"user_id": uid, "ip": _ip(request)})
    return _signed_in(request, uid)


@app.post("/api/auth/login")
def auth_login(req: LoginRequest, request: Request):
    _csrf(request)
    _limit("login:" + _ip(request), "Too many sign-in attempts; try again in a minute")
    user = auth.authenticate(req.email, req.password)
    if user is None:
        db.audit(req.email.strip()[:200], "auth.login_failed", {"ip": _ip(request)})
        raise HTTPException(401, "Wrong email or password")
    db.audit(user["email"], "auth.login", {"ip": _ip(request)})
    return _signed_in(request, user["id"])


@app.post("/api/auth/logout", status_code=204)
def auth_logout(request: Request):
    _csrf(request)
    auth.end_session(request.cookies.get(auth.SESSION_COOKIE))
    resp = Response(status_code=204)
    resp.delete_cookie(auth.SESSION_COOKIE, path="/")
    return resp


@app.post("/api/auth/password")
def change_password(req: PasswordRequest, request: Request):
    """Change your own password (the current one is required); every other session of yours is signed out."""
    me = _need(request)
    if me["id"] is None:
        raise HTTPException(400, "The legacy token has no account password")
    _limit("login:" + _ip(request), "Too many attempts; try again in a minute")
    if auth.authenticate(me["email"], req.current_password) is None:
        raise HTTPException(403, "Current password is wrong")
    try:
        auth.set_password(me["id"], req.new_password)
    except auth.AuthError as e:
        raise HTTPException(422, str(e))
    ended = auth.end_user_sessions(me["id"], keep=request.cookies.get(auth.SESSION_COOKIE))
    _audit(request, "auth.password_change", {"user_id": me["id"], "other_sessions_ended": ended})
    return {"ok": True, "other_sessions_ended": ended}


@app.post("/api/auth/logout-all", status_code=204)
def logout_all(request: Request):
    """Sign out every session of the current user, this one included."""
    me = _need(request)
    if me["id"] is None:
        raise HTTPException(400, "The legacy token has no sessions")
    ended = auth.end_user_sessions(me["id"])
    _audit(request, "auth.logout_all", {"user_id": me["id"], "sessions_ended": ended})
    resp = Response(status_code=204)
    resp.delete_cookie(auth.SESSION_COOKIE, path="/")
    return resp


@app.get("/api/users")
def list_users(request: Request):
    _need(request, "admin")
    return auth.list_users()


@app.post("/api/users", status_code=201)
def create_user(req: UserRequest, request: Request):
    _need(request, "admin")
    try:
        uid = auth.create_user(req.email, req.name, req.password, req.role)
    except auth.AuthError as e:
        raise HTTPException(422, str(e))
    _audit(request, "user.create", {"user_id": uid, "email": req.email.strip(), "role": req.role})
    return auth.get_user(uid)


def _other_user(request, uid):
    me = _need(request, "admin")
    target = auth.get_user(uid)
    if target is None:
        raise HTTPException(404, "Unknown user")
    if me["id"] == uid:
        raise HTTPException(400, "You cannot change or delete your own account here")
    return target


@app.put("/api/users/{uid}/role")
def set_user_role(uid: int, req: RoleRequest, request: Request):
    target = _other_user(request, uid)
    if target["role"] == "admin" and req.role != "admin" and auth.admin_count() <= 1:
        raise HTTPException(400, "Keep at least one admin")
    auth.set_role(uid, req.role)
    _audit(request, "user.role", {"user_id": uid, "email": target["email"], "role": req.role})
    return auth.get_user(uid)


@app.post("/api/users/{uid}/password")
def reset_user_password(uid: int, req: ResetRequest, request: Request):
    """Admin: set a new password for another user and sign out all of their sessions."""
    target = _other_user(request, uid)
    try:
        auth.set_password(uid, req.password)
    except auth.AuthError as e:
        raise HTTPException(422, str(e))
    ended = auth.end_user_sessions(uid)
    _audit(request, "user.password_reset", {"user_id": uid, "email": target["email"], "sessions_ended": ended})
    return {"ok": True, "sessions_ended": ended}


@app.delete("/api/users/{uid}", status_code=204)
def delete_user(uid: int, request: Request):
    target = _other_user(request, uid)
    if target["role"] == "admin" and auth.admin_count() <= 1:
        raise HTTPException(400, "Keep at least one admin")
    auth.delete_user(uid)
    _audit(request, "user.delete", {"user_id": uid, "email": target["email"]})


@app.get("/api/keys")
def list_keys(request: Request):
    _need(request, "admin")
    return auth.list_keys()


@app.post("/api/keys", status_code=201)
def create_key(req: KeyRequest, request: Request):
    me = _need(request, "admin")
    if me["id"] is None:
        raise HTTPException(400, "Sign in as a user to create API keys (the legacy token has no account)")
    try:
        kid, key = auth.create_key(me["id"], req.name, req.role)
    except auth.AuthError as e:
        raise HTTPException(422, str(e))
    _audit(request, "apikey.create", {"key_id": kid, "name": req.name.strip(), "role": req.role, "prefix": key[:10]})
    return {"id": kid, "key": key, "prefix": key[:10], "name": req.name.strip(), "role": req.role}


@app.delete("/api/keys/{kid}", status_code=204)
def delete_key(kid: int, request: Request):
    _need(request, "admin")
    if not auth.delete_key(kid):
        raise HTTPException(404, "Unknown API key")
    _audit(request, "apikey.delete", {"key_id": kid})


@app.get("/api/audit")
def audit_log(request: Request, page: int = Query(1, ge=1, le=10_000), per_page: int = Query(50, ge=1, le=200)):
    _need(request, "admin")
    return db.audit_page(page, per_page)


# ---------- settings ----------
@app.get("/api/settings")
def get_settings(request: Request):
    _need(request, "admin")
    return settings.public()


@app.put("/api/settings")
async def put_settings(request: Request):
    me = _need(request, "admin")
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(422, "Body must be a JSON object")
    if not isinstance(body, dict):
        raise HTTPException(422, "Body must be a JSON object")
    try:
        changed = settings.update(body, me["label"])
    except settings.SettingsError as e:
        raise HTTPException(422, str(e))
    _audit(request, "settings.update", {"keys": changed})  # key names only, never values
    return settings.public()


def _probe(fn):
    """Run a connection test; report ok or a short error, never response bodies (they may echo secrets)."""
    try:
        r = fn()
    except httpx.HTTPError as e:
        return {"ok": False, "error": f"Could not connect ({type(e).__name__})"}
    if 200 <= r.status_code < 300:
        return {"ok": True, "error": None}
    return {"ok": False, "error": {401: "Rejected: invalid key (HTTP 401)", 403: "Forbidden (HTTP 403)"}.get(
        r.status_code, f"HTTP {r.status_code}")}


@app.post("/api/settings/test/{service}")
def test_connection(service: str, request: Request):
    _need(request, "admin")
    _limit("probe:" + _ip(request), "Too many tests; try again in a minute")
    with httpx.Client(timeout=15) as http:
        if service == "llm":
            if not config.llm_api_key():
                return {"ok": False, "error": "No LLM API key set"}
            result = _probe(lambda: http.get(config.llm_base_url() + "/models",
                                             headers={"Authorization": f"Bearer {config.llm_api_key()}"}))
        elif service == "tavily":
            if not config.tavily_api_key():
                return {"ok": False, "error": "No Tavily API key set"}
            result = _probe(lambda: http.post("https://api.tavily.com/search", json={
                "api_key": config.tavily_api_key(), "query": "OSV", "max_results": 1}))
        elif service == "github":
            if not config.github_token():
                return {"ok": False, "error": "No GitHub token set"}
            result = _probe(lambda: http.get("https://api.github.com/user", headers={
                "Authorization": f"Bearer {config.github_token()}", "Accept": "application/vnd.github+json"}))
        else:
            raise HTTPException(404, "Unknown service")
    _audit(request, "settings.test", {"service": service, "ok": result["ok"]})
    return result


# ---------- notification channels ----------
class ChannelRequest(BaseModel):
    type: str = Field(..., pattern="^(slack|webhook|email)$")
    name: str = Field(..., max_length=80)
    config: dict = Field(default_factory=dict)  # slack {url}; webhook {url, secret?}; email {to: [..] or "a, b"}
    events: list[str] = Field(..., max_length=len(notify.EVENTS))
    min_severity: str = Field("low", pattern="^(low|moderate|high|critical)$")
    enabled: bool = True


@app.get("/api/channels")
def list_channels(request: Request):
    """Admins see each channel's (masked) config; members only what they need to opt projects in or out."""
    user = _need(request)
    rows = db.list_channels()
    if user["role"] != "admin":
        return [{k: c[k] for k in ("id", "type", "name", "events", "enabled")} for c in rows]
    return [notify.public(c) for c in rows]


def _save_channel(request, cid, req):
    _need(request, "admin")
    try:
        cid = notify.save(cid, req.type, req.name, req.config, req.events, req.min_severity, req.enabled)
    except notify.ChannelError as e:
        raise HTTPException(422, str(e))
    except LookupError:
        raise HTTPException(404, "Unknown channel")
    return cid


@app.post("/api/channels", status_code=201)
def create_channel(req: ChannelRequest, request: Request):
    cid = _save_channel(request, None, req)
    _audit(request, "channel.create", {"channel_id": cid, "type": req.type, "name": req.name.strip(),
                                       "events": sorted(req.events)})
    row = notify.public(db.get_channel(cid))
    if req.type == "webhook":  # the signing secret is shown once, when it is set (generated if left blank)
        row["secret"] = notify.config_of(db.get_channel(cid)).get("secret")
    return row


@app.put("/api/channels/{cid}")
def update_channel(cid: int, req: ChannelRequest, request: Request):
    _save_channel(request, cid, req)
    _audit(request, "channel.update", {"channel_id": cid, "type": req.type, "name": req.name.strip(),
                                       "events": sorted(req.events), "enabled": req.enabled})
    return notify.public(db.get_channel(cid))


@app.delete("/api/channels/{cid}", status_code=204)
def delete_channel(cid: int, request: Request):
    _need(request, "admin")
    if not db.delete_channel(cid):
        raise HTTPException(404, "Unknown channel")
    _audit(request, "channel.delete", {"channel_id": cid})


@app.post("/api/channels/{cid}/test")
def test_channel(cid: int, request: Request):
    _need(request, "admin")
    _limit("probe:" + _ip(request), "Too many tests; try again in a minute")
    row = db.get_channel(cid)
    if row is None:
        raise HTTPException(404, "Unknown channel")
    status = notify.send_test(row)
    last = db.list_deliveries(cid, 1)
    _audit(request, "channel.test", {"channel_id": cid, "status": status})
    return {"ok": status == "ok", "status": status, "delivery": last[0] if last else None}


@app.get("/api/deliveries")
def list_deliveries(request: Request, channel: int | None = Query(None, ge=1),
                    limit: int = Query(50, ge=1, le=200)):
    _need(request, "admin")
    return db.list_deliveries(channel, limit)


@app.api_route("/robots.txt", methods=["GET", "HEAD"], include_in_schema=False)
def robots():
    return PlainTextResponse("User-agent: *\nAllow: /\n", headers={"Cache-Control": "public, max-age=86400"})


@app.api_route("/favicon.svg", methods=["GET", "HEAD"], include_in_schema=False)
def favicon():
    return FileResponse(config.ROOT / "web" / "favicon.svg", media_type="image/svg+xml",
                        headers={"Cache-Control": "public, max-age=86400"})


app.mount("/static", CachedStatic(directory=config.ROOT / "web"), name="static")

PAGES = {"": "landing", "projects": "projects", "console": "console", "app": "console", "runs": "runs", "how": "how",
         "org": "org", "dashboard": "dashboard", "settings": "settings", "login": "login", "setup": "setup"}


# Pages that need a signed-in user; with PATCHPILOT_PUBLIC_DEMO=1 anonymous visitors may still read these
PROTECTED = {"dashboard", "projects", "console", "app", "runs", "org", "settings"}
PUBLIC_DEMO_PAGES = {"dashboard", "projects", "console", "app", "runs"}


@app.api_route("/{page}", methods=["GET", "HEAD"])
@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
def page(request: Request, page: str = ""):
    if page not in PAGES:
        raise HTTPException(404)
    if page in PROTECTED and principal(request) is None:
        if auth.user_count() == 0:
            return RedirectResponse("/setup", 302)
        if not (_public_demo() and page in PUBLIC_DEMO_PAGES):
            here = request.url.path + (f"?{request.url.query}" if request.url.query else "")
            return RedirectResponse(f"/login?next={quote(here, safe='')}", 302)
    return FileResponse(config.ROOT / "web" / f"{PAGES[page]}.html")
