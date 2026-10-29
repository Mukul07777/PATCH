import importlib
import json

import pytest
from fastapi.testclient import TestClient

from conftest import AUTH

from patchpilot import config, github_pr, server


def test_config_bad_numbers_fall_back(monkeypatch):
    for k, v in {"MAX_FIX_ATTEMPTS": "x", "FIX_TIMEOUT": "", "GUARD_TIMEOUT": "abc", "PRICE_NANO": "a/b",
                 "ALLOW_REMOTE_REPOS": ""}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("PATCHPILOT_DEMO", raising=False)
    try:
        c = importlib.reload(config)
        assert (c.MAX_FIX_ATTEMPTS, c.FIX_TIMEOUT, c.GUARD_TIMEOUT) == (4, 90.0, 30.0)
        assert c.PRICES["nano"] is None and c.ALLOW_REMOTE_REPOS is False
    finally:
        monkeypatch.undo()
        importlib.reload(config)


@pytest.mark.parametrize("url,want", [
    ("https://github.com/psf/requests", ("psf", "requests")),
    ("https://github.com/a-b/socket.io.git", ("a-b", "socket.io")),
    ("https://github.com/o/r/", ("o", "r")),
])
def test_parse_repo(url, want):
    assert github_pr.parse_repo(url) == want


@pytest.mark.parametrize("url", ["https://gitlab.com/o/r", "github.com/o/r", "", "https://github.com/o"])
def test_parse_repo_rejects(url):
    with pytest.raises(ValueError):
        github_pr.parse_repo(url)


def test_push_scrubs_token(monkeypatch, tmp_path):
    import subprocess
    calls = []

    def fake_run(args, **kw):
        calls.append(args)
        if "push" in args:
            raise subprocess.CalledProcessError(1, args, stderr="fatal: bad creds for SECRETTOKEN")
    monkeypatch.setattr(config, "GITHUB_TOKEN", "SECRETTOKEN")
    monkeypatch.setattr(github_pr.subprocess, "run", fake_run)

    class FakeClient:
        def __init__(self, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url):
            class R:
                def json(self): return {"default_branch": "main"}
            return R()
    monkeypatch.setattr(github_pr.httpx, "Client", FakeClient)
    with pytest.raises(RuntimeError) as e:
        github_pr.open_pull_request(tmp_path, "https://github.com/o/r", "x", {"upgrades": []}, "")
    assert "SECRETTOKEN" not in str(e.value)
    push = next(a for a in calls if "push" in a)
    assert not any("SECRETTOKEN" in a for a in push)


def test_list_runs_skips_malformed(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path)
    (tmp_path / "good.jsonl").write_text(json.dumps({"type": "start", "repo": "x"}) + "\n"
                                         + json.dumps({"type": "done", "ok": True}) + "\n", encoding="utf-8")
    (tmp_path / "partial.jsonl").write_text(json.dumps({"type": "start", "repo": "y"}) + "\n{\"type\": \"lo",
                                            encoding="utf-8")
    (tmp_path / "junk.jsonl").write_text("not json\n[1]\n", encoding="utf-8")
    (tmp_path / "empty.jsonl").write_text("", encoding="utf-8")
    r = TestClient(server.app, headers=AUTH).get("/api/runs")
    assert r.status_code == 200
    got = {x["id"]: x["ok"] for x in r.json()}
    assert got == {"good": True, "partial": None}


def test_events_rejects_bad_run_id():
    assert TestClient(server.app, headers=AUTH).get("/api/runs/a%20b/events").status_code == 404


def test_run_request_validation():
    server.RunRequest(repo="")
    server.RunRequest(repo="https://github.com/o/r.js")
    for bad in ["https://evil.com/o/r", "file:///etc", "https://github.com/" + "a" * 300]:
        with pytest.raises(ValueError):
            server.RunRequest(repo=bad)


@pytest.fixture
def no_agent(monkeypatch):
    monkeypatch.setattr(config, "NEBIUS_API_KEY", "k")
    monkeypatch.setattr(server, "_record", lambda rid: lambda ev: None)

    class A:
        def __init__(self, *a): pass
        def run(self): pass
    monkeypatch.setattr(server, "Agent", A)
    monkeypatch.setattr(server, "_hits", server.collections.defaultdict(server.collections.deque))
    monkeypatch.setattr(server, "MAX_ACTIVE_RUNS", 1000)
    yield
    for k in [k for k, v in server.RUNS.items() if not v["events"]]:
        server.RUNS.pop(k, None)


def test_token_auth(no_agent, monkeypatch):
    monkeypatch.setenv("PATCHPILOT_TOKEN", "t0k")
    c = TestClient(server.app, headers=AUTH)
    assert c.post("/api/runs", json={"repo": "case:x"}).status_code == 401
    assert c.post("/api/runs", json={"repo": "case:x"}, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.post("/api/runs", json={"repo": "case:x"}, headers={"Authorization": "Bearer t0k"}).status_code == 200


def test_rate_limit(no_agent, monkeypatch):
    c = TestClient(server.app, headers=AUTH)
    codes = [c.post("/api/runs", json={"repo": "case:x"}).status_code for _ in range(server.RATE_LIMIT + 1)]
    assert codes[:-1] == [200] * server.RATE_LIMIT and codes[-1] == 429


def test_rate_window_expires():
    server._hits.pop("t", None)
    assert all(server._rate_ok("t", now=i) for i in range(server.RATE_LIMIT))
    assert not server._rate_ok("t", now=10)
    assert server._rate_ok("t", now=10 + server.RATE_WINDOW)


def test_runs_cap(monkeypatch):
    runs = {f"r{i}": {"events": [], "done": i != 0} for i in range(server.MAX_RUNS + 10)}
    monkeypatch.setattr(server, "RUNS", runs)
    server._evict()
    assert len(runs) == server.MAX_RUNS and "r0" in runs


def _jsonl(*evs):
    return "".join(json.dumps(e) + "\n" for e in evs)


def test_list_runs_includes_failure_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path)
    (tmp_path / "a.jsonl").write_text(_jsonl({"type": "start", "repo": "x"}, {"type": "done", "ok": False, "error": "boom"}), encoding="utf-8")
    (tmp_path / "b.jsonl").write_text(_jsonl({"type": "start", "repo": "y"}, {"type": "error", "msg": "RateLimit: 429"},
                                         {"type": "done", "ok": False}), encoding="utf-8")
    (tmp_path / "c.jsonl").write_text(_jsonl({"type": "start", "repo": "z"}, {"type": "done", "ok": True}), encoding="utf-8")
    got = {x["id"]: x for x in TestClient(server.app, headers=AUTH).get("/api/runs").json()}
    assert got["a"]["error"] == "boom"
    assert got["b"]["error"] == "RateLimit: 429"
    assert "error" not in got["c"]


def test_list_runs_reason_falls_back_to_last_test_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path)
    (tmp_path / "d.jsonl").write_text(_jsonl({"type": "start", "repo": "w"},
                                         {"type": "test", "ok": False, "summary": "3 failed, 2 passed"},
                                         {"type": "test", "ok": False, "summary": "1 failed, 4 passed"},
                                         {"type": "done", "ok": False}), encoding="utf-8")
    (tmp_path / "e.jsonl").write_text(_jsonl({"type": "start", "repo": "v"}, {"type": "done", "ok": False}), encoding="utf-8")
    got = {x["id"]: x for x in TestClient(server.app, headers=AUTH).get("/api/runs").json()}
    assert got["d"]["error"] == "Tests still failing: 1 failed, 4 passed"
    assert got["e"]["error"] is None


def test_event_stream_is_not_gzipped():
    with TestClient(server.app, headers=AUTH) as c:
        r = c.get("/api/runs/20261029-153214-job/events?replay=0", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200 and "gzip" not in r.headers.get("content-encoding", "")
