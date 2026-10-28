"""FastAPI server: start runs, stream events over SSE, replay recorded runs."""
import asyncio
import json
import threading
import time
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import config
from .agent import Agent

app = FastAPI(title="PatchPilot")
RUNS = {}  # run_id -> {"events": [...], "done": bool}
config.RUNS_DIR.mkdir(exist_ok=True)


class RunRequest(BaseModel):
    repo: str = ""


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
    return {"nebius": bool(config.NEBIUS_API_KEY), "tavily": bool(config.TAVILY_API_KEY),
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


@app.post("/api/runs")
def start_run(req: RunRequest):
    if not config.NEBIUS_API_KEY:
        raise HTTPException(400, "NEBIUS_API_KEY is not configured on the server")
    run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
    RUNS[run_id] = {"events": [], "done": False}
    emit = _record(run_id)
    emit({"type": "start", "repo": req.repo or f"case:{config.DEFAULT_CASE}", "t": 0})
    threading.Thread(target=Agent(run_id, req.repo, emit).run, daemon=True).start()
    return {"id": run_id}


@app.get("/api/runs")
def list_runs():
    out = []
    for p in sorted(config.RUNS_DIR.glob("*.jsonl"), reverse=True):
        lines = p.read_text(encoding="utf-8").splitlines()
        if not lines:
            continue
        first, last = json.loads(lines[0]), json.loads(lines[-1])
        out.append({"id": p.stem, "repo": first.get("repo"), "ok": last.get("ok") if last["type"] == "done" else None})
    return out[:30]


@app.get("/api/runs/{run_id}/events")
async def events(run_id: str, replay: float = 0):
    if run_id not in RUNS:
        path = config.RUNS_DIR / f"{run_id}.jsonl"
        if not path.exists():
            raise HTTPException(404)
        RUNS[run_id] = {"events": [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()],
                        "done": True}

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


@app.get("/")
def index():
    return FileResponse(config.ROOT / "web" / "index.html")
