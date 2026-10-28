"""Headless entrypoint, used locally and as a Nebius Serverless Job.

  python -m patchpilot.cli case:authsvc case:webhooks https://github.com/org/repo ...

Runs the agent on each repo, records events to runs/<id>.jsonl, and writes runs/batch-summary.json.
"""
import json
import sys
import time

from . import config
from .agent import Agent


def run_one(repo):
    run_id = time.strftime("%Y%m%d-%H%M%S-") + "job"
    path = config.RUNS_DIR / f"{run_id}.jsonl"
    result = {}

    def emit(ev):
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
        if ev["type"] in ("step", "test", "error"):
            print(f"[{repo}] {ev['type']}: {ev.get('key') or ev.get('label') or ''} {ev.get('status') or ev.get('summary') or ev.get('msg') or ''}",
                  flush=True)
        if ev["type"] == "done":
            result.update(ev)

    emit({"type": "start", "repo": repo or f"case:{config.DEFAULT_CASE}", "t": 0})
    Agent(run_id, repo, emit).run()
    return {"repo": repo, "run": run_id, "ok": result.get("ok"), "attempts": result.get("attempts"),
            "seconds": result.get("seconds"), "usage": result.get("usage")}


def main(argv):
    config.RUNS_DIR.mkdir(exist_ok=True)
    repos = argv or [f"case:{p.name}" for p in sorted(config.CASES_DIR.iterdir()) if (p / "requirements.txt").exists()]
    results = [run_one(r) for r in repos]
    (config.RUNS_DIR / "batch-summary.json").write_text(json.dumps(results, indent=2))
    print(json.dumps([{k: r[k] for k in ("repo", "ok", "attempts", "seconds")} for r in results], indent=2))
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
