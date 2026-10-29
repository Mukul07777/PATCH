"""Real-world practicality: honest coverage, monorepos, size limits, OSV batching, CVSS severity, EPSS batching,
GitHub repo/ref validation, garbage uploads, rate limits + queue, page protection and account management."""
import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from conftest import AUTH, osv_from
from patchpilot.app import auth, db, server
from patchpilot.core import config
from patchpilot.intel import manifests, scanner, sources

CSRF = {"X-Requested-With": "patchpilot"}
PW = "correct horse battery"
API = "https://api.github.com/repos/acme/mono"
REAL_PYPI_MISSING = sources.pypi_missing  # captured at import, before the autouse offline stub


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(server, "_hits", server.collections.defaultdict(server.collections.deque))
    monkeypatch.setattr(server, "_spawn", lambda fn, *a: fn(*a))
    monkeypatch.setattr(sources, "osv_batch", osv_from(lambda p, v: []))
    monkeypatch.setattr(sources, "kev", lambda: {})
    monkeypatch.setattr(sources, "epss", lambda cves: {})
    return TestClient(server.app, headers=AUTH)


def _scan(c, pid):
    return c.get(f"/api/scans/{c.post(f'/api/projects/{pid}/scan').json()['id']}").json()


def _upload(c, content, filename="requirements.txt"):
    r = c.post("/api/projects", json={"filename": filename, "content": content})
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ---------- 1. coverage ----------
@pytest.mark.parametrize("content,state,checked,total", [
    ("flask>=2\nrequests\n", "unverified", 0, 2),
    ("flask==2.0.0\nrequests\n", "partial", 1, 2),
    ("flask==2.0.0\nrequests==2.31.0\n", "verified", 2, 2),
])
def test_coverage_states(client, content, state, checked, total):
    s = _scan(client, _upload(client, content))
    assert s["summary"]["coverage"]["state"] == state
    assert (s["summary"]["coverage"]["checked"], s["summary"]["coverage"]["total"]) == (checked, total)


def test_dashboard_does_not_count_unverified_projects_as_clean(client):
    _scan(client, _upload(client, "flask>=2\n"))
    _scan(client, _upload(client, "flask==2.0.0\n"))
    d = client.get("/api/dashboard").json()
    assert d["clean"] == 1 and [u["state"] for u in d["unverified"]] == ["unverified"]


# ---------- 2. size limits ----------
def test_read_dir_size_limits(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("six==1.16.0\n" + "#" * manifests.MAX_MANIFEST)
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "six"\nversion = "1.16.0"\n' + "#" * 2_000_000)
    files, notes, skipped = scanner._read_dir(tmp_path)
    assert [f for f, _ in files] == ["poetry.lock"]  # 2 MB lock file is fine, 1 MB+ requirements is not
    assert skipped == [{"path": "requirements.txt", "reason": "larger than 1 MB"}]


def test_lock_upload_up_to_5mb_accepted(client):
    big = "".join(f'[[package]]\nname = "pkg{i}"\nversion = "1.0.{i}"\n\n' for i in range(30_000))
    assert 1_000_000 < len(big) < 5_000_000
    pid = _upload(client, big, "poetry.lock")
    s = _scan(client, pid)
    assert s["summary"]["pinned"] == 30_000 and s["summary"]["coverage"]["state"] == "verified"


def test_dependency_cap_is_reported_not_silent(client, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_DEPS", 2)
    s = _scan(client, _upload(client, "a==1\nb==1\nc==1\n"))
    assert s["summary"]["coverage"]["state"] == "partial" and s["summary"]["coverage"]["checked"] == 2
    assert any("only the first 2 were checked" in w for w in s["summary"]["warnings"])


def test_oversize_body_is_413_and_validation_never_echoes(client):
    r = client.post("/api/projects", content=b"{" + b" " * (server.MAX_BODY + 10) + b"}",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    secret = "https://evil.example/" + "x" * 20
    r = client.post("/api/projects", json={"git_url": secret})
    assert r.status_code == 422 and secret not in r.text and "Value error" not in r.text
    assert r.json()["detail"].startswith("git_url must be")


# ---------- 3. EPSS ----------
@respx.mock
def test_epss_batches_of_100():
    calls = []

    def epss(request):
        cves = request.url.params["cve"].split(",")
        calls.append((len(cves), request.url.params["limit"]))
        return httpx.Response(200, json={"data": [{"cve": c, "epss": "0.1", "percentile": "0.5"} for c in cves]})
    respx.get("https://api.first.org/data/v1/epss").mock(side_effect=epss)
    out = sources.epss([f"CVE-2024-{i:05d}" for i in range(250)])
    assert len(out) == 250 and calls == [(100, "100"), (100, "100"), (50, "100")]


def test_epss_failure_is_a_warning(client, monkeypatch):
    monkeypatch.setattr(sources, "osv_batch", osv_from(lambda p, v: [
        {"id": "GHSA-1", "cve": "CVE-2024-1", "summary": "x", "severity": "HIGH", "fixed": [], "aliases": ["CVE-2024-1"]}]))
    monkeypatch.setattr(sources, "pypi_latest", lambda p: "9")

    def boom(cves):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(sources, "epss", boom)
    s = _scan(client, _upload(client, "six==1.0\n"))
    assert s["status"] == "done" and s["summary"]["epss"] == "unavailable"
    assert any("EPSS unavailable" in w for w in s["summary"]["warnings"])


# ---------- 4 + 5. GitHub validation, monorepos ----------
@respx.mock
@pytest.mark.parametrize("repo,commit,code,msg", [
    (404, 200, 422, "Repository not found or private"),
    (200, 404, 422, "Branch or tag 'nope' not found"),
    (200, 422, 422, "Branch or tag 'nope' not found"),
])
def test_repo_and_ref_validated_at_create(client, repo, commit, code, msg):
    respx.get(API).mock(return_value=httpx.Response(repo, json={"default_branch": "main"}))
    respx.get(f"{API}/commits/nope").mock(return_value=httpx.Response(commit, json={"sha": "s"}))
    r = client.post("/api/projects", json={"git_url": "https://github.com/acme/mono", "ref": "nope"})
    assert r.status_code == code and msg in r.json()["detail"]
    assert client.get("/api/projects").json() == []


@respx.mock
def test_github_rate_limit_message(client):
    respx.get(API).mock(return_value=httpx.Response(403, headers={"x-ratelimit-remaining": "0"}, text="API rate limit"))
    r = client.post("/api/projects", json={"git_url": "https://github.com/acme/mono"})
    assert r.status_code == 429 and "rate limit" in r.json()["detail"] and "GitHub token" in r.json()["detail"]


def _mono(tree):
    respx.get(API).mock(return_value=httpx.Response(200, json={"default_branch": "main"}))
    respx.get(f"{API}/commits/main").mock(return_value=httpx.Response(200, json={"sha": "c0ffee"}))
    respx.get(f"{API}/git/trees/c0ffee").mock(return_value=httpx.Response(200, json={
        "tree": [{"path": p, "type": "blob", "size": len(t)} for p, t in tree.items()]}))
    for p, t in tree.items():
        respx.get(f"https://raw.githubusercontent.com/acme/mono/c0ffee/{p}").mock(return_value=httpx.Response(200, text=t))


@respx.mock
def test_monorepo_finds_nested_manifests_and_prefers_locks(client, monkeypatch):
    monkeypatch.setattr(sources, "osv_batch", osv_from(lambda p, v: [
        {"id": "GHSA-x", "cve": None, "summary": "bad", "severity": "HIGH", "fixed": ["9"], "aliases": []}] if p == "fastapi" else []))
    monkeypatch.setattr(sources, "pypi_latest", lambda p: "9")
    _mono({
        "README.md": "x",
        "backend/pyproject.toml": '[project]\nname="b"\ndependencies=["fastapi>=0.1"]\n',
        "backend/uv.lock": '[[package]]\nname = "fastapi"\nversion = "0.100.0"\n',
        "services/api/requirements-dev.txt": "pytest==8.0.0\n",
        "frontend/node_modules/x/requirements.txt": "evil==1\n",
        "tests/fixtures/requirements.txt": "old==0.1\n",
        "a/b/c/d/requirements.txt": "deep==1\n",
    })
    pid = client.post("/api/projects", json={"git_url": "https://github.com/acme/mono"}).json()["id"]
    s = _scan(client, pid)
    assert s["summary"]["files"] == ["backend/uv.lock", "services/api/requirements-dev.txt"]
    assert s["summary"]["coverage"]["state"] == "verified"
    [f] = s["findings"]
    assert f["source_file"] == "backend/uv.lock" and f["package"] == "fastapi"


@respx.mock
def test_subdir_restricts_scan(client):
    _mono({"backend/requirements.txt": "six==1.16.0\n", "other/requirements.txt": "flask==2.0.0\n"})
    pid = client.post("/api/projects", json={"git_url": "https://github.com/acme/mono", "subdir": "backend/"}).json()["id"]
    assert db.get_project(pid)["subdir"] == "backend"
    assert _scan(client, pid)["summary"]["files"] == ["backend/requirements.txt"]


# ---------- 6 + 12. uploads ----------
@pytest.mark.parametrize("content", ["\x00\x00PK\x03\x04", "".join(chr(i) for i in range(1, 32)) * 20,
                                     "Lorem ipsum dolor sit amet\nconsectetur adipiscing elit\nsed do\n"])
def test_garbage_uploads_rejected(client, content):
    r = client.post("/api/projects", json={"filename": "requirements.txt", "content": content})
    assert r.status_code == 422


def test_skipped_lines_are_warnings(client):
    s = _scan(client, _upload(client, "-r base.txt\n-c constraints.txt\n-e .\ngit+https://github.com/a/b\nsix==1.16.0\n"))
    w = " | ".join(s["summary"]["warnings"])
    assert "'-r base.txt' not followed; upload that file too" in w and "constraints file" in w
    assert "editable" in w and "URL / VCS" in w


# ---------- 7. rate limits + queue ----------
def test_rate_limit_sends_retry_after(client, monkeypatch):
    monkeypatch.setattr(server, "USER_RATE_LIMIT", 2)
    codes = [client.post("/api/projects", json={"filename": "requirements.txt", "content": "six==1\n"}) for _ in range(3)]
    assert [r.status_code for r in codes] == [201, 201, 429] and int(codes[-1].headers["Retry-After"]) >= 1


def test_scans_queue_beyond_capacity(client, monkeypatch):
    started = []
    monkeypatch.setattr(server, "_spawn", lambda fn, *a: started.append(fn))  # workers never run
    monkeypatch.setattr(scanner, "_active", 0)
    pids = [_upload(client, f"six==1.{i}\n") for i in range(scanner.MAX_ACTIVE_SCANS + 2)]
    out = [client.post(f"/api/projects/{p}/scan").json() for p in pids]
    assert all(o["status"] == "queued" for o in out) and out[-1]["position"] == len(pids) - 1
    assert len(started) == scanner.MAX_ACTIVE_SCANS  # the rest wait for a free worker
    # a restart re-queues what was running; a worker then drains the whole queue
    db.claim_queued_scan()
    assert db.requeue_interrupted() == 1
    monkeypatch.setattr(scanner, "_active", 0)
    scanner.kick(lambda fn: fn())
    assert {db.get_scan(o["id"])["status"] for o in out} == {"done"}


# ---------- 8. OSV batch ----------
@respx.mock
def test_osv_batch_chunks_and_caches_details(monkeypatch):
    monkeypatch.setattr(sources, "OSV_BATCH", 2)
    monkeypatch.setattr(sources, "_vuln_cache", {})
    sizes = []

    def batch(request):
        qs = json.loads(request.content)["queries"]
        sizes.append(len(qs))
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "PYSEC-1"}]} if q["package"]["name"] == "a" else {}
                                                     for q in qs]})
    respx.post("https://api.osv.dev/v1/querybatch").mock(side_effect=batch)
    detail = respx.get("https://api.osv.dev/v1/vulns/PYSEC-1").mock(return_value=httpx.Response(200, json={
        "id": "PYSEC-1", "aliases": ["CVE-2024-9"], "summary": "s",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"package": {"name": "a"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0rc1"}]}]}]}))
    out = sources.osv_batch([("a", "1.0"), ("b", "1.0"), ("c", "1.0"), ("a", "1.1")])
    assert sizes == [2, 2] and detail.call_count == 1
    v = out[("a", "1.0")][0]
    assert v["severity"] == "CRITICAL" and v["cvss_score"] == 9.8 and v["fixed"] == ["2.0rc1"]
    assert out[("b", "1.0")] == []


# ---------- 9. severity from CVSS / GHSA alias ----------
def test_pysec_severity_from_vector_and_ghsa_alias():
    v4 = {"id": "PYSEC-2", "affected": [], "severity": [
        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}]}
    [a] = sources.normalize("x", [v4])
    assert a["severity"] in ("MODERATE", "LOW") and a["cvss_score"] is not None
    ghsa = {"id": "GHSA-abcd", "database_specific": {"severity": "HIGH"}}
    [b] = sources.normalize("x", [{"id": "PYSEC-3", "aliases": ["GHSA-abcd"], "affected": []}], lambda i: ghsa)
    assert b["severity"] == "HIGH"
    assert sources.band(9.0) == "CRITICAL" and sources.band(6.9) == "MODERATE" and sources.band(None) is None


# ---------- 10. versions ----------
def test_pep440_versions():
    assert sources.version_gte("1.0", "1.0rc1") and not sources.version_gte("1.0rc1", "1.0")
    assert sources.version_gte("1.0.post1", "1.0") and not sources.version_gte("1.0.dev1", "1.0a1")
    assert sources.min_safe_version("1.0rc1", [{"fixed": ["1.0rc2", "1.0"]}]) == "1.0rc2"
    assert scanner._lowest_fix_above("2.0.0", ["2.0.0.post1", "2.1"]) == "2.0.0.post1"


# ---------- 13. not on PyPI ----------
@respx.mock
def test_pypi_missing_flagged(client, monkeypatch):
    monkeypatch.setattr(sources, "pypi_missing", REAL_PYPI_MISSING)
    respx.head("https://pypi.org/pypi/acme-internal-lib/json").mock(return_value=httpx.Response(404))
    respx.head("https://pypi.org/pypi/six/json").mock(return_value=httpx.Response(200))
    s = _scan(client, _upload(client, "six==1.16.0\nacme-internal-lib==0.3\n"))
    assert s["summary"]["not_on_pypi"] == ["acme-internal-lib"]
    assert any("not on PyPI — private package or typo (possible dependency confusion)" in w for w in s["summary"]["warnings"])


# ---------- 15. health ----------
def test_health_provider_null_without_key(client, monkeypatch):
    monkeypatch.setattr(config, "llm_api_key", lambda: "")
    h = client.get("/api/health").json()
    assert h["provider"] is None and h["fix_mode"] is False and h["scan_mode"] is True


# ---------- 17. page protection ----------
@pytest.fixture
def anon(monkeypatch):
    monkeypatch.delenv("PATCHPILOT_TOKEN", raising=False)
    monkeypatch.setattr(server, "_hits", server.collections.defaultdict(server.collections.deque))
    return TestClient(server.app, follow_redirects=False)


def test_protected_pages_redirect(anon, monkeypatch):
    assert anon.get("/projects").headers["location"] == "/setup"
    auth.create_user("a@example.com", "", PW, "admin")
    for page in ("dashboard", "projects", "console", "runs", "org", "settings"):
        r = anon.get(f"/{page}?id=3")
        assert r.status_code == 302 and r.headers["location"] == f"/login?next=%2F{page}%3Fid%3D3"
    for page in ("", "how", "login", "setup"):
        assert anon.get(f"/{page}").status_code == 200
    monkeypatch.setenv("PATCHPILOT_PUBLIC_DEMO", "1")
    assert anon.get("/projects").status_code == 200 and anon.get("/settings").status_code == 302
    anon.post("/api/auth/login", json={"email": "a@example.com", "password": PW}, headers=CSRF)
    assert anon.get("/settings").status_code == 200


# ---------- 18. account ----------
def test_change_password_reset_and_sign_out_everywhere(anon):
    r = anon.post("/api/auth/setup", json={"email": "a@example.com", "password": PW}, headers=CSRF)
    assert r.status_code == 200
    other = TestClient(server.app)
    other.post("/api/auth/login", json={"email": "a@example.com", "password": PW}, headers=CSRF)
    assert other.get("/api/auth/state").json()["user"]
    bad = anon.post("/api/auth/password", json={"current_password": "wrong-password", "new_password": "x" * 12}, headers=CSRF)
    assert bad.status_code == 403
    ok = anon.post("/api/auth/password", json={"current_password": PW, "new_password": "brand new secret"}, headers=CSRF)
    assert ok.status_code == 200 and ok.json()["other_sessions_ended"] == 1
    assert other.get("/api/auth/state").json()["user"] is None  # the other session was signed out
    assert anon.get("/api/auth/state").json()["user"]  # this one stays
    assert auth.authenticate("a@example.com", "brand new secret")

    uid = auth.create_user("m@example.com", "", PW)
    member = TestClient(server.app)
    member.post("/api/auth/login", json={"email": "m@example.com", "password": PW}, headers=CSRF)
    assert member.post(f"/api/users/{uid}/password", json={"password": "y" * 12}, headers=CSRF).status_code == 403
    r = anon.post(f"/api/users/{uid}/password", json={"password": "reset by admin"}, headers=CSRF)
    assert r.status_code == 200 and r.json()["sessions_ended"] == 1
    assert member.get("/api/auth/state").json()["user"] is None
    assert auth.authenticate("m@example.com", "reset by admin")
    assert anon.post(f"/api/users/{uid}/password", json={"password": "short"}, headers=CSRF).status_code == 422

    assert anon.post("/api/auth/logout-all", headers=CSRF).status_code == 204
    assert anon.get("/api/auth/state").json()["user"] is None
    actions = [e["action"] for e in db.audit_entries()]
    assert {"auth.password_change", "user.password_reset", "auth.logout_all"} <= set(actions)
