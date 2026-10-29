"""Round-2 hardening: headers, org scan robustness, run start ordering, SSE, page routing."""
import json
import shutil
import subprocess
import threading
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from patchpilot import config, server

WEB = Path(server.config.ROOT) / "web"
GH = "https://api.github.com/users/acme/repos"
RAW = "https://raw.githubusercontent.com/acme/{}/main/requirements.txt"


def _repo(name):
    return {"name": name, "full_name": f"acme/{name}", "default_branch": "main", "html_url": f"https://github.com/acme/{name}",
            "language": "Python", "stargazers_count": 1}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("PATCHPILOT_TOKEN", raising=False)
    monkeypatch.setattr(server, "_hits", server.collections.defaultdict(server.collections.deque))
    monkeypatch.setattr(server, "_org_cache", {})
    return TestClient(server.app)


# ---------- 3 / 5: headers + health ----------
def test_security_headers_everywhere(client):
    for url in ["/", "/console", "/api/health", "/static/app.js"]:
        h = client.get(url).headers
        assert h["content-security-policy"] == server.CSP
        assert "script-src 'self'" in h["content-security-policy"] and "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "strict-origin-when-cross-origin"


def test_health_hides_base_url(client):
    body = client.get("/api/health").json()
    assert "base_url" not in body and "nebius" in body


# ---------- 2 / 6 / 7: org scan ----------
@respx.mock
def test_org_scan_happy_path_and_cache(client, monkeypatch):
    calls = []
    monkeypatch.setattr(server.sources, "osv_vulns", lambda p, v: calls.append(p) or [{"severity": "HIGH"}])
    gh = respx.get(GH).mock(return_value=httpx.Response(200, json=[_repo("a"), _repo("b")]))
    respx.get(RAW.format("a")).mock(return_value=httpx.Response(200, text="flask==1.0\nrequests==2.0\n"))
    respx.get(RAW.format("b")).mock(side_effect=httpx.ConnectError("boom"))
    r = client.get("/api/org/acme")
    assert r.status_code == 200
    rows = {x["name"]: x for x in r.json()["repos"]}
    assert rows["a"]["high"] == 2 and rows["a"]["has_reqs"]
    assert rows["b"]["has_reqs"] is False and "error" in rows["b"]
    assert client.get("/api/org/ACME").status_code == 200  # cached, case-insensitive
    assert gh.call_count == 1 and len(calls) == 2


@respx.mock
def test_org_scan_caps_osv_calls(client, monkeypatch):
    monkeypatch.setattr(server, "ORG_MAX_OSV", 3)
    calls = []
    monkeypatch.setattr(server.sources, "osv_vulns", lambda p, v: calls.append(p) or [])
    respx.get(GH).mock(return_value=httpx.Response(200, json=[_repo("a")]))
    respx.get(RAW.format("a")).mock(return_value=httpx.Response(200, text="".join(f"p{i}==1.0\n" for i in range(10))))
    body = client.get("/api/org/acme").json()
    assert len(calls) == 3 and body["osv_capped"] and body["repos"][0]["pins"] == 10


@respx.mock
@pytest.mark.parametrize("resp,code", [
    (httpx.Response(403, headers={"X-RateLimit-Remaining": "0"}), 429),
    (httpx.Response(403, headers={"X-RateLimit-Remaining": "12"}), 502),
    (httpx.Response(500), 502),
    (httpx.Response(404), 404),
])
def test_org_scan_github_errors(client, resp, code):
    respx.get(GH).mock(return_value=resp)
    assert client.get("/api/org/acme").status_code == code


@respx.mock
def test_org_scan_github_unreachable(client):
    respx.get(GH).mock(side_effect=httpx.ConnectTimeout("slow"))
    r = client.get("/api/org/acme")
    assert r.status_code == 502 and r.json()["detail"] == "GitHub unreachable"


@respx.mock
def test_org_scan_auth_and_rate_limit(client, monkeypatch):
    respx.get(url__regex=r"https://api\.github\.com/users/.*").mock(return_value=httpx.Response(200, json=[]))
    monkeypatch.setenv("PATCHPILOT_TOKEN", "t0k")
    assert client.get("/api/org/acme").status_code == 401
    ok = {"Authorization": "Bearer t0k"}
    codes = [client.get(f"/api/org/u{i}", headers=ok).status_code for i in range(server.RATE_LIMIT + 1)]
    assert codes[:-1] == [200] * server.RATE_LIMIT and codes[-1] == 429


# ---------- 8 / 12: start ordering + active cap ----------
@pytest.fixture
def fake_agent(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path)
    monkeypatch.setattr(server, "_hits", server.collections.defaultdict(server.collections.deque))
    monkeypatch.delenv("PATCHPILOT_TOKEN", raising=False)
    gate = threading.Event()

    class A:
        def __init__(self, *a): pass
        def run(self): gate.wait(5)
    monkeypatch.setattr(server, "Agent", A)
    before = set(server.RUNS)
    yield gate
    gate.set()
    for k in set(server.RUNS) - before:
        server.RUNS.pop(k, None)


def test_missing_key_or_auth_does_not_consume_rate_limit(fake_agent, monkeypatch, client):
    monkeypatch.setattr(config, "NEBIUS_API_KEY", "")
    for _ in range(server.RATE_LIMIT + 2):
        assert client.post("/api/runs", json={}).status_code == 400
    monkeypatch.setenv("PATCHPILOT_TOKEN", "t")
    for _ in range(server.RATE_LIMIT + 2):
        assert client.post("/api/runs", json={}).status_code == 401
    assert not server._hits.get("testclient")


def test_active_run_cap(fake_agent, monkeypatch, client):
    monkeypatch.setattr(config, "NEBIUS_API_KEY", "k")
    monkeypatch.setattr(server, "MAX_ACTIVE_RUNS", 2)
    codes = [client.post("/api/runs", json={}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


# ---------- 9: agent crash still ends the stream ----------
def test_agent_crash_emits_done(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path)

    class Boom:
        def __init__(self, *a): pass
        def run(self): raise RuntimeError("kaput")
    monkeypatch.setattr(server, "Agent", Boom)
    server.RUNS["crash-1"] = {"events": [], "done": False}
    try:
        server._run_agent("crash-1", "", server._record("crash-1"))
        run = server.RUNS["crash-1"]
        assert run["done"] and run["events"][-1]["ok"] is False and "kaput" in run["events"][-1]["error"]
    finally:
        server.RUNS.pop("crash-1", None)


def test_agent_silent_exit_emits_done(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path)

    class Quiet:
        def __init__(self, *a): pass
        def run(self): pass
    monkeypatch.setattr(server, "Agent", Quiet)
    server.RUNS["quiet-1"] = {"events": [], "done": False}
    try:
        server._run_agent("quiet-1", "", server._record("quiet-1"))
        assert server.RUNS["quiet-1"]["done"]
    finally:
        server.RUNS.pop("quiet-1", None)


def test_sse_idle_timeout(monkeypatch, client):
    monkeypatch.setattr(server, "IDLE_TIMEOUT", 0.3)
    server.RUNS["idle-1"] = {"events": [{"type": "start"}], "done": False}
    try:
        body = client.get("/api/runs/idle-1/events").text
        assert '"type": "start"' in body and "idle" in body
    finally:
        server.RUNS.pop("idle-1", None)


# ---------- 10: replay validation ----------
@pytest.mark.parametrize("val", ["nan", "inf", "-1", "101", "abc"])
def test_replay_rejects_bad_values(client, val):
    server.RUNS["r-ok"] = {"events": [], "done": True}
    try:
        assert client.get(f"/api/runs/r-ok/events?replay={val}").status_code == 422
    finally:
        server.RUNS.pop("r-ok", None)


def test_replay_accepts_valid(client):
    server.RUNS["r-ok2"] = {"events": [{"type": "done", "t": 0}], "done": True}
    try:
        assert client.get("/api/runs/r-ok2/events?replay=50").status_code == 200
    finally:
        server.RUNS.pop("r-ok2", None)


# ---------- 11: bench / cases ----------
def test_bench_malformed(client, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path)
    assert client.get("/api/bench").json() == []
    (tmp_path / "batch-summary.json").write_text("{not json", encoding="utf-8")
    assert client.get("/api/bench").json() == []
    (tmp_path / "batch-summary.json").write_text('{"a": 1}', encoding="utf-8")
    assert client.get("/api/bench").json() == []
    (tmp_path / "batch-summary.json").write_text(json.dumps([{"repo": "café"}]), encoding="utf-8")
    assert client.get("/api/bench").json() == [{"repo": "café"}]


def test_cases_utf8_and_missing_dir(client, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CASES_DIR", tmp_path / "nope")
    assert client.get("/api/cases").json() == []
    (tmp_path / "c1").mkdir()
    (tmp_path / "c1" / "requirements.txt").write_text("# naïve\nflask==1.0\npytest==8\n", encoding="utf-8")
    (tmp_path / "c2").mkdir()
    (tmp_path / "c2" / "requirements.txt").write_bytes(b"\xff\xfe==bad")
    monkeypatch.setattr(config, "CASES_DIR", tmp_path)
    assert client.get("/api/cases").json() == [{"id": "c1", "pins": ["flask==1.0"]}]


# ---------- 13 / 20 / 35: pages, HEAD, gzip, static caching ----------
@pytest.mark.parametrize("url", ["/", "/console", "/app", "/runs", "/how", "/org"])
def test_pages_get_and_head(client, url):
    assert client.get(url).status_code == 200
    assert client.head(url).status_code == 200


def test_unknown_page_404(client):
    assert client.get("/nope").status_code == 404


def test_static_cache_and_gzip(client):
    r = client.get("/static/app.js", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200 and r.headers["cache-control"] == "public, max-age=3600"
    assert r.headers.get("content-encoding") == "gzip"
    assert client.get("/favicon.svg").headers["content-type"].startswith("image/svg")


def test_static_mounted_before_catch_all():
    paths = [getattr(r, "path", "") for r in server.app.routes]
    assert paths.index("/static") < paths.index("/{page}")
    assert all(paths.index(p) < paths.index("/static") for p in paths if p.startswith("/api/"))


# ---------- 1 / 4: front-end hygiene ----------
def test_no_inline_scripts_or_handlers():
    import re
    for f in WEB.glob("*.html"):
        s = f.read_text(encoding="utf-8")
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", s), f.name
        assert not re.search(r"\son[a-z]+\s*=", s, re.I), f.name
        assert '<main id="main"' in s, f.name


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_markdown_link_sanitizer():
    js = r"""
    global.window={};global.location={pathname:"/"};
    global.document={getElementById:()=>null,querySelector:()=>null,querySelectorAll:()=>[],addEventListener(){},
      documentElement:{nodeType:1,hasAttribute:()=>false,querySelectorAll:()=>[],dataset:{}}};
    global.fetch=()=>Promise.reject(new Error("x"));global.IntersectionObserver=class{observe(){}};
    global.MutationObserver=class{observe(){}};
    require(process.argv[1]);
    const e=window.ppEsc,l=(a,b)=>window.ppMdLink(e(a),e(b));
    console.log(JSON.stringify([l("x","javascript:alert(1)"),l("y","https://ok.dev/a"),e(`<'">&`)]));
    """
    out = subprocess.run(["node", "-e", js, str(WEB / "site.js")], capture_output=True, text=True, timeout=30)
    bad, good, escaped = json.loads(out.stdout.strip().splitlines()[-1])
    assert "<a" not in bad
    assert good == '<a href="https://ok.dev/a" target="_blank" rel="noopener">y</a>'
    assert escaped == "&lt;&#39;&quot;&gt;&amp;"


# ---------- round 3: HEAD, robots.txt, org reason, inline-style-free CSP ----------
@pytest.mark.parametrize("url", ["/api/health", "/api/runs"])
def test_head_supported(client, url):
    r = client.head(url)
    assert r.status_code == 200 and r.content == b""
    assert client.get(url).status_code == 200


def test_robots_txt(client):
    r = client.get("/robots.txt")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert r.text == "User-agent: *\nAllow: /\n"
    assert client.head("/robots.txt").status_code == 200


@respx.mock
def test_org_reason_no_python_repos(client):
    respx.get(GH).mock(return_value=httpx.Response(200, json=[]))
    body = client.get("/api/org/acme").json()
    assert body["scanned"] == 0 and body["reason"] == "no public python repos"


@respx.mock
def test_org_reason_no_requirements_and_clean(client, monkeypatch):
    monkeypatch.setattr(server.sources, "osv_vulns", lambda p, v: [])
    respx.get(GH).mock(return_value=httpx.Response(200, json=[_repo("a")]))
    respx.get(RAW.format("a")).mock(return_value=httpx.Response(404))
    assert client.get("/api/org/acme").json()["reason"] == "no requirements.txt found"
    server._org_cache.clear()
    respx.get(RAW.format("a")).mock(return_value=httpx.Response(200, text="flask==1.0\n"))
    assert client.get("/api/org/acme").json()["reason"] is None


@respx.mock
def test_org_reason_rate_limited(client):
    respx.get(GH).mock(return_value=httpx.Response(403, headers={"X-RateLimit-Remaining": "0"}))
    r = client.get("/api/org/acme")
    assert r.status_code == 429 and "rate limit" in r.json()["detail"].lower()


def test_csp_and_markup_have_no_inline_styles():
    assert "unsafe-inline" not in server.CSP
    for f in WEB.iterdir():
        if f.suffix in (".html", ".js"):
            text = f.read_text(encoding="utf-8")
            assert " style=\"" not in text and "<style" not in text, f.name
            if f.suffix == ".html":
                assert 'href="data:image' not in text, f.name


def test_debate_tier_is_allow_listed():
    js = (WEB / "app.js").read_text(encoding="utf-8")
    i = js.index("function renderDebate")
    body = js[i:js.index("\n}\n", i)]
    assert "TIERS.includes(p.tier)" in body and "${p.tier}" not in body
    assert "(p.files || [])" in body and "esc(String(p.attempt))" in body
