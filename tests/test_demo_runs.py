import json

import pytest
from fastapi.testclient import TestClient

from conftest import AUTH

from patchpilot.core import config
from patchpilot.app import server


@pytest.fixture
def dirs(monkeypatch, tmp_path):
    live, demo = tmp_path / "runs", tmp_path / "demo"
    live.mkdir(); demo.mkdir()
    monkeypatch.setattr(config, "RUNS_DIR", live)
    monkeypatch.setattr(config, "DEMO_RUNS_DIR", demo)
    return live, demo


def _write(d, rid, ok=True, repo="case:x"):
    evs = [{"type": "start", "repo": repo, "t": 0},
           {"type": "vex", "document": {"id": rid}},
           {"type": "done", "ok": ok}]
    (d / f"{rid}.jsonl").write_text("\n".join(json.dumps(e) for e in evs) + "\n", encoding="utf-8")


def test_lists_and_replays_demo_runs(dirs):
    live, demo = dirs
    _write(demo, "20260101-000000-demo")
    _write(live, "20260202-000000-live")
    c = TestClient(server.app, headers=AUTH)
    ids = [r["id"] for r in c.get("/api/runs").json()]
    assert ids == ["20260202-000000-live", "20260101-000000-demo"]
    r = c.get("/api/runs/20260101-000000-demo/events")
    assert r.status_code == 200 and '"done"' in r.text
    assert c.get("/api/runs/20260101-000000-demo/vex").json() == {"id": "20260101-000000-demo"}
    server.RUNS.pop("20260101-000000-demo", None)


def test_live_run_shadows_demo_with_same_id(dirs):
    live, demo = dirs
    _write(demo, "same", repo="case:demo")
    _write(live, "same", repo="case:live")
    rows = TestClient(server.app, headers=AUTH).get("/api/runs").json()
    assert [(r["id"], r["repo"]) for r in rows] == [("same", "case:live")]


def test_demo_lookup_rejects_bad_ids(dirs):
    _, demo = dirs
    _write(demo, "ok-id")
    assert server._run_path("../ok-id") is None
    assert server._run_path("ok id") is None
    assert server._run_path("missing") is None
    assert server._run_path("ok-id") == demo / "ok-id.jsonl"
    c = TestClient(server.app, headers=AUTH)
    assert c.get("/api/runs/..%2Fok-id/vex").status_code == 404


def test_bench_falls_back_to_demo_summary(dirs):
    live, demo = dirs
    c = TestClient(server.app, headers=AUTH)
    assert c.get("/api/bench").json() == []
    (demo / "batch-summary.json").write_text(json.dumps([{"repo": "case:a", "ok": True}]))
    assert c.get("/api/bench").json() == [{"repo": "case:a", "ok": True}]
    (live / "batch-summary.json").write_text(json.dumps([{"repo": "case:b", "ok": False}]))
    assert c.get("/api/bench").json() == [{"repo": "case:b", "ok": False}]
    (live / "batch-summary.json").write_text("not json")
    assert c.get("/api/bench").json()[0]["repo"] == "case:a"
