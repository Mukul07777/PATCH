"""Product round 2: accounts + sessions + API keys, CSRF, encrypted settings, getters, policy, dashboard."""
import sqlite3
import time

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from conftest import AUTH, osv_from
from patchpilot.app import auth, db, server, settings
from patchpilot.core import config
from patchpilot.intel import scanner, sources

CSRF = {"X-Requested-With": "patchpilot"}
PW = "correct horse battery"


@pytest.fixture
def anon(monkeypatch):
    """A browser-like client: no bearer token, cookie sessions only."""
    monkeypatch.delenv("PATCHPILOT_TOKEN", raising=False)
    monkeypatch.setattr(server, "_hits", server.collections.defaultdict(server.collections.deque))
    monkeypatch.setattr(server, "_spawn", lambda fn, *a: fn(*a))
    return TestClient(server.app)


def _setup(c, email="admin@example.com"):
    r = c.post("/api/auth/setup", json={"email": email, "name": "Ada", "password": PW}, headers=CSRF)
    assert r.status_code == 200, r.text
    return r


def _login(c, email, pw=PW):
    return c.post("/api/auth/login", json={"email": email, "password": pw}, headers=CSRF)


# ---------- auth ----------
def test_password_hash_roundtrip():
    h = auth.hash_password(PW)
    assert h.startswith("scrypt$") and PW not in h
    assert auth.verify_password(PW, h) and not auth.verify_password("nope", h)
    assert h != auth.hash_password(PW)  # salted
    assert not auth.verify_password(PW, "garbage")


def test_setup_only_once_and_needs_csrf(anon):
    assert anon.get("/api/auth/state").json()["setup_needed"] is True
    assert anon.post("/api/auth/setup", json={"email": "a@b.co", "password": PW}).status_code == 403
    assert anon.post("/api/auth/setup", json={"email": "a@b.co", "password": "short"}, headers=CSRF).status_code == 422
    _setup(anon)
    st = anon.get("/api/auth/state").json()
    assert st["setup_needed"] is False and st["user"]["role"] == "admin" and st["user"]["via"] == "session"
    other = TestClient(server.app)
    r = other.post("/api/auth/setup", json={"email": "evil@x.co", "password": PW}, headers=CSRF)
    assert r.status_code == 409 and auth.user_count() == 1


def test_login_wrong_password_logout_and_cookie_flags(anon):
    _setup(anon)
    anon.cookies.clear()
    assert anon.get("/api/projects").status_code == 401
    assert _login(anon, "admin@example.com", "wrong password!").status_code == 401
    assert _login(anon, "nobody@example.com").status_code == 401
    r = _login(anon, "ADMIN@example.com")  # emails are case-insensitive
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert anon.get("/api/projects").status_code == 200
    assert anon.post("/api/auth/logout", headers=CSRF).status_code == 204
    assert anon.get("/api/projects").status_code == 401
    actions = [e["action"] for e in db.audit_entries()]
    assert actions.count("auth.login_failed") == 2 and "auth.login" in actions


def test_session_expiry(anon, monkeypatch):
    _setup(anon)
    uid = auth.list_users()[0]["id"]
    token = auth.create_session(uid, now=time.time() - auth.SESSION_TTL - 5)
    assert auth.session_user(token) is None
    fresh = auth.create_session(uid)
    assert auth.session_user(fresh)["id"] == uid
    assert auth.session_user(fresh, now=time.time() + auth.SESSION_TTL + 5) is None


def test_session_token_not_stored_in_plaintext(anon, tmp_path):
    r = _setup(anon)
    token = r.cookies.get(auth.SESSION_COOKIE) or anon.cookies.get(auth.SESSION_COOKIE)
    assert token
    raw = (tmp_path / "pp.db").read_bytes() + (tmp_path / "pp.db-wal").read_bytes()
    assert token.encode() not in raw


def test_csrf_header_required_for_cookie_writes(anon):
    _setup(anon)
    body = {"filename": "requirements.txt", "content": "six==1.16.0\n"}
    assert anon.post("/api/projects", json=body).status_code == 403
    assert anon.post("/api/projects", json=body, headers=CSRF).status_code == 201


def test_api_key_auth_member_vs_admin(anon):
    _setup(anon)
    r = anon.post("/api/keys", json={"name": "ci", "role": "member"}, headers=CSRF)
    assert r.status_code == 201
    key = r.json()["key"]
    assert key.startswith("pp_") and r.json()["prefix"] == key[:10]
    listed = anon.get("/api/keys").json()
    assert listed[0]["prefix"] == key[:10] and "key" not in listed[0] and "key_hash" not in listed[0]
    bot = TestClient(server.app, headers={"Authorization": f"Bearer {key}"})
    # API keys need no CSRF header (not cookie-authenticated); member may create projects ...
    assert bot.post("/api/projects", json={"filename": "requirements.txt", "content": "six==1.16.0\n"}).status_code == 201
    # ... but not touch admin endpoints
    assert bot.get("/api/settings").status_code == 403
    assert bot.get("/api/users").status_code == 403
    assert TestClient(server.app, headers={"Authorization": "Bearer pp_wrong"}).get("/api/projects").status_code == 401
    assert auth.list_keys()[0]["last_used"] is not None
    assert any(e["actor"].startswith("admin@example.com (key pp_") for e in db.audit_entries()
               if e["action"] == "project.create")


def test_member_cannot_admin(anon):
    _setup(anon)
    assert anon.post("/api/users", json={"email": "m@example.com", "password": PW, "role": "member"},
                     headers=CSRF).status_code == 201
    m = TestClient(server.app)
    assert _login(m, "m@example.com").status_code == 200
    assert m.get("/api/settings").status_code == 403
    assert m.put("/api/settings", json={"tavily_api_key": "x" * 20}, headers=CSRF).status_code == 403
    assert m.post("/api/keys", json={"name": "k"}, headers=CSRF).status_code == 403
    assert m.get("/api/audit").status_code == 403
    assert m.post("/api/projects/samples", headers=CSRF).status_code == 201  # members can manage projects


def test_last_admin_and_self_protection(anon):
    _setup(anon)
    me = auth.list_users()[0]["id"]
    assert anon.delete(f"/api/users/{me}", headers=CSRF).status_code == 400
    uid = anon.post("/api/users", json={"email": "m@example.com", "password": PW}, headers=CSRF).json()["id"]
    assert anon.put(f"/api/users/{uid}/role", json={"role": "admin"}, headers=CSRF).json()["role"] == "admin"
    assert anon.delete(f"/api/users/{uid}", headers=CSRF).status_code == 204


def test_legacy_token_is_admin():
    c = TestClient(server.app, headers=AUTH)
    assert c.get("/api/settings").status_code == 200
    c.post("/api/projects", json={"filename": "requirements.txt", "content": "six==1.16.0\n"})
    assert db.audit_entries()[0]["actor"] == "token"


def test_public_demo_is_read_only_and_samples_only(anon, monkeypatch, tmp_path):
    (tmp_path / "cases" / "demo").mkdir(parents=True)
    (tmp_path / "cases" / "demo" / "requirements.txt").write_text("six==1.16.0\n")
    monkeypatch.setattr(config, "CASES_DIR", tmp_path / "cases")
    _setup(anon)
    anon.post("/api/projects/samples", headers=CSRF)
    private = anon.post("/api/projects", json={"filename": "requirements.txt", "content": "six==1.16.0\n"},
                        headers=CSRF).json()["id"]
    visitor = TestClient(server.app)
    assert visitor.get("/api/projects").status_code == 401
    monkeypatch.setenv("PATCHPILOT_PUBLIC_DEMO", "1")
    names = [p["source_type"] for p in visitor.get("/api/projects").json()]
    assert names == ["sample"]
    assert visitor.get(f"/api/projects/{private}").status_code == 404
    assert visitor.get("/api/dashboard").status_code == 200
    assert visitor.post("/api/projects/samples", headers=CSRF).status_code == 401
    assert visitor.get("/api/settings").status_code == 401


# ---------- settings ----------
def test_settings_encrypted_at_rest_and_never_returned(tmp_path):
    c = TestClient(server.app, headers=AUTH)
    secret = "tvly-SUPERSECRET-1234"
    r = c.put("/api/settings", json={"tavily_api_key": secret, "model_nano": "nvidia/nano-x", "max_fix_attempts": 3})
    assert r.status_code == 200
    body = r.json()
    assert body["tavily_api_key"] == {"set": True, "last4": "1234", "source": "settings"}
    assert body["model_nano"]["value"] == "nvidia/nano-x" and body["max_fix_attempts"]["value"] == 3
    assert secret not in r.text and secret not in c.get("/api/settings").text
    db.close()
    raw = b"".join(p.read_bytes() for p in tmp_path.glob("pp.db*"))
    assert secret.encode() not in raw
    row = sqlite3.connect(tmp_path / "pp.db").execute("SELECT value, secret FROM settings WHERE key = 'tavily_api_key'").fetchone()
    assert row[1] == 1 and secret not in row[0]
    assert settings.get("tavily_api_key") == secret
    assert (tmp_path / "secret.key").is_file()
    audit = [e for e in db.audit_entries() if e["action"] == "settings.update"][0]
    assert secret not in audit["detail"] and "tavily_api_key" in audit["detail"]


def test_settings_validation_and_clearing(monkeypatch):
    c = TestClient(server.app, headers=AUTH)
    assert c.put("/api/settings", json={"bogus": 1}).status_code == 422
    assert c.put("/api/settings", json={"llm_base_url": "ftp://x"}).status_code == 422
    assert c.put("/api/settings", json={"max_fix_attempts": 99}).status_code == 422
    assert c.put("/api/settings", json={"model_nano": "has space"}).status_code == 422
    monkeypatch.setattr(config, "TAVILY_API_KEY", "env-key-abcd")
    c.put("/api/settings", json={"tavily_api_key": "db-key-wxyz"})
    assert config.tavily_api_key() == "db-key-wxyz"
    c.put("/api/settings", json={"tavily_api_key": ""})
    assert config.tavily_api_key() == "env-key-abcd"
    assert c.get("/api/settings").json()["tavily_api_key"]["source"] == "env"


def test_secret_key_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("PATCHPILOT_SECRET_KEY", "any passphrase works")
    settings.update({"github_token": "ghp_" + "a" * 36}, "t")
    assert settings.get("github_token") == "ghp_" + "a" * 36
    assert not (tmp_path / "secret.key").exists()
    monkeypatch.setenv("PATCHPILOT_SECRET_KEY", "a different passphrase")
    assert settings.get("github_token") is None  # undecryptable -> treated as unset, not a crash


def test_getters_prefer_settings_then_env(monkeypatch):
    monkeypatch.setattr(config, "NEBIUS_API_KEY", "env-llm")
    monkeypatch.setattr(config, "NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1")
    monkeypatch.setattr(config, "MODEL_OVERRIDES", {"nano": "env-nano", "super": "", "ultra": ""})
    monkeypatch.setattr(config, "MODEL_GUARD", "")
    monkeypatch.setattr(config, "ALLOW_REMOTE_REPOS", False)
    assert config.llm_api_key() == "env-llm" and config.model("nano") == "env-nano" and config.model_guard() == ""
    settings.update({"llm_api_key": "db-llm-key", "model_nano": "db-nano", "llm_base_url": "https://openrouter.ai/api/v1/",
                     "allow_remote_repos": True, "max_fix_attempts": "7"}, "t")
    assert config.llm_api_key() == "db-llm-key" and config.model_overrides()["nano"] == "db-nano"
    assert config.llm_base_url() == "https://openrouter.ai/api/v1" and config.provider_name() == "OpenRouter"
    assert config.model_guard().startswith("nvidia/") and config.allow_remote_repos() is True
    monkeypatch.setattr(config, "DEMO", False)
    assert config.max_fix_attempts() == 7
    h = TestClient(server.app).get("/api/health").json()  # health is public and reads the getters
    assert h["models"]["nano"] == "db-nano" and h["provider"] == "OpenRouter" and "db-llm-key" not in str(h)


@respx.mock
def test_connection_tests_report_ok_or_error_only(monkeypatch):
    monkeypatch.setattr(config, "TAVILY_API_KEY", "")
    c = TestClient(server.app, headers=AUTH)
    assert c.post("/api/settings/test/tavily").json() == {"ok": False, "error": "No Tavily API key set"}
    settings.update({"github_token": "ghp_" + "b" * 36, "llm_api_key": "sk-test-0000"}, "t")
    respx.get("https://api.github.com/user").mock(return_value=httpx.Response(401, json={"message": "Bad credentials ghp_"}))
    respx.get(url__regex=r".*/models$").mock(return_value=httpx.Response(200, json={"data": []}))
    assert c.post("/api/settings/test/github").json() == {"ok": False, "error": "Rejected: invalid key (HTTP 401)"}
    assert c.post("/api/settings/test/llm").json() == {"ok": True, "error": None}
    assert c.post("/api/settings/test/nope").status_code == 404


# ---------- findings lifecycle, policy, dashboard ----------
def _vuln(vid, sev, cve=None):
    return {"id": vid, "cve": cve, "summary": vid, "severity": sev, "fixed": ["99"], "aliases": [cve] if cve else []}


@pytest.fixture
def feeds(monkeypatch):
    table = {}
    monkeypatch.setattr(sources, "osv_batch", osv_from(lambda p, v: table.get((p, v), [])))
    monkeypatch.setattr(sources, "pypi_latest", lambda p: "99")
    monkeypatch.setattr(sources, "epss", lambda cves: {})
    monkeypatch.setattr(sources, "kev", lambda: {"CVE-2024-0001": {}})
    monkeypatch.setattr(server, "_hits", server.collections.defaultdict(server.collections.deque))
    monkeypatch.setattr(server, "_spawn", lambda fn, *a: fn(*a))
    return table


def _scan(c, pid):
    return c.get(f"/api/scans/{c.post(f'/api/projects/{pid}/scan').json()['id']}").json()


def test_new_and_fixed_tracking_and_mttr(feeds):
    c = TestClient(server.app, headers=AUTH)
    feeds[("jinja2", "2.10")] = [_vuln("GHSA-a", "HIGH"), _vuln("GHSA-b", "LOW")]
    pid = c.post("/api/projects", json={"filename": "requirements.txt", "content": "jinja2==2.10\n"}).json()["id"]
    s1 = _scan(c, pid)
    assert s1["summary"]["diff"] == {"new": 2, "fixed": 0} and all(f["new"] for f in s1["findings"])
    feeds[("jinja2", "2.10")] = [_vuln("GHSA-a", "HIGH")]  # GHSA-b fixed upstream / upgraded away
    s2 = _scan(c, pid)
    assert s2["summary"]["diff"] == {"new": 0, "fixed": 1} and not s2["findings"][0]["new"]
    d = c.get("/api/dashboard").json()
    assert d["fixed_total"] == 1 and d["mttr_seconds"] is not None and d["mttr_seconds"] >= 0
    feeds[("jinja2", "2.10")] = [_vuln("GHSA-a", "HIGH"), _vuln("GHSA-b", "LOW")]  # regression reopens it
    assert _scan(c, pid)["summary"]["diff"] == {"new": 1, "fixed": 0}
    assert c.get("/api/dashboard").json()["fixed_total"] == 0


def test_track_findings_unit():
    pid = db.create_project("p", "upload", "requirements.txt", manifest="x==1\n")
    s1, s2 = db.create_scan(pid), db.create_scan(pid)
    assert db.track_findings(s1, pid, [{"package": "X", "vuln_id": "V1"}], now=100) == {"new": 1, "fixed": 0}
    assert db.track_findings(s2, pid, [{"package": "x", "vuln_id": "V1"}], now=200) == {"new": 0, "fixed": 0}
    assert db.track_findings(s2, pid, [], now=400) == {"new": 0, "fixed": 1}
    row = db._q("SELECT * FROM finding_status")[0]
    assert row["status"] == "fixed" and row["resolved_at"] - row["first_seen_at"] == 300


def test_dashboard_aggregation(feeds):
    c = TestClient(server.app, headers=AUTH)
    empty = c.get("/api/dashboard").json()
    assert empty["projects"] == 0 and empty["open"] == 0 and empty["trend"] == [] and empty["mttr_seconds"] is None
    feeds[("jinja2", "2.10")] = [_vuln("GHSA-a", "CRITICAL", "CVE-2024-0001"), _vuln("GHSA-b", "MODERATE")]
    feeds[("six", "1.0")] = [_vuln("GHSA-c", "HIGH")]
    a = c.post("/api/projects", json={"filename": "requirements.txt", "content": "jinja2==2.10\nsix==1.0\n", "name": "a"}).json()["id"]
    b = c.post("/api/projects", json={"filename": "requirements.txt", "content": "six==1.0\n", "name": "b"}).json()["id"]
    c.post("/api/projects", json={"filename": "requirements.txt", "content": "six==1.0\n", "name": "never-scanned"})
    _scan(c, a), _scan(c, b), _scan(c, b)  # only b's latest scan counts
    d = c.get("/api/dashboard").json()
    assert d["projects"] == 3 and d["scanned"] == 2 and d["open"] == 4
    assert d["by_severity"] == {"CRITICAL": 1, "HIGH": 2, "MODERATE": 1, "LOW": 0, "UNKNOWN": 0}
    assert d["kev"] == 1
    assert [p["name"] for p in d["at_risk"]] == ["a", "b"] and d["at_risk"][0]["kev"] == 1
    top = {p["package"]: p for p in d["top_packages"]}
    assert top["six"] == {"package": "six", "findings": 2, "projects": 2, "kev": 0, "worst": "HIGH"}
    assert d["top_packages"][0]["package"] == "jinja2" and top["jinja2"]["worst"] == "CRITICAL"  # tie broken by KEV
    assert d["trend"][-1]["open"] == 4 and d["new_7d"] == 4
    assert c.get("/api/stats").json()["open_findings"] == 4


def test_policy_threshold_and_ignore_suppress(feeds):
    c = TestClient(server.app, headers=AUTH)
    feeds[("jinja2", "2.10")] = [_vuln("GHSA-a", "HIGH", "CVE-2024-0001"), _vuln("GHSA-b", "LOW"), _vuln("GHSA-u", None)]
    pid = c.post("/api/projects", json={"filename": "requirements.txt", "content": "jinja2==2.10\n"}).json()["id"]
    sid = _scan(c, pid)["id"]
    assert c.get("/api/dashboard").json()["open"] == 3
    assert c.put(f"/api/projects/{pid}/policy", json={"severity_threshold": "bogus"}).status_code == 422
    pol = c.put(f"/api/projects/{pid}/policy", json={"severity_threshold": "moderate", "auto_fix": True}).json()
    assert pol["severity_threshold"] == "moderate" and pol["auto_fix"] is True
    s = c.get(f"/api/scans/{sid}").json()
    sup = {f["vuln_id"]: f["suppressed"] for f in s["findings"]}
    assert sup == {"GHSA-a": None, "GHSA-b": "below moderate threshold", "GHSA-u": None}  # unrated never hidden
    assert s["suppressed"] == 1 and s["counts"]["LOW"] == 0
    # ignore by alias (CVE) with a reason
    assert c.post(f"/api/projects/{pid}/ignores", json={"vuln_id": "CVE-2024-0001", "reason": "x"}).status_code == 422
    assert c.post(f"/api/projects/{pid}/ignores", json={"vuln_id": "CVE-2024-0001", "reason": "not reachable",
                                                         "expires_at": time.time() - 10}).status_code == 422
    ign = c.post(f"/api/projects/{pid}/ignores", json={"vuln_id": "CVE-2024-0001", "reason": "not reachable"}).json()
    d = c.get("/api/dashboard").json()
    assert d["open"] == 1 and d["suppressed"] == 2 and d["kev"] == 0
    assert c.get(f"/api/projects/{pid}").json()["last_scan"]["counts"]["HIGH"] == 0
    # expired ignores stop suppressing
    db._x("UPDATE ignores SET expires_at = ?", (time.time() - 1,))
    assert c.get("/api/dashboard").json()["open"] == 2
    iid = ign["ignores"][0]["id"]
    assert c.delete(f"/api/projects/{pid}/ignores/{iid}").status_code == 200
    assert c.delete(f"/api/projects/{pid}/ignores/{iid}").status_code == 404
    actions = [e["action"] for e in db.audit_entries()]
    assert {"policy.update", "finding.ignore", "finding.unignore"} <= set(actions)


def test_audit_pagination_records_actor(anon):
    _setup(anon)
    for i in range(3):
        anon.post("/api/projects", json={"filename": "requirements.txt", "content": f"six==1.{i}\n"}, headers=CSRF)
    r = anon.get("/api/audit?page=1&per_page=2").json()
    assert r["total"] == 4 and len(r["entries"]) == 2 and r["entries"][0]["actor"] == "admin@example.com"
    assert r["entries"][0]["detail"]["ip"]
    assert len(anon.get("/api/audit?page=2&per_page=2").json()["entries"]) == 2


def test_new_pages_served(anon):
    _setup(anon)
    for page in ("dashboard", "settings", "login", "setup"):
        r = anon.get(f"/{page}")
        assert r.status_code == 200 and f"{'auth' if page in ('login', 'setup') else page}.js" in r.text


def test_scanner_records_diff_in_summary(feeds):
    pid = db.create_project("p", "upload", "requirements.txt", manifest="six==1.0\n")
    sid = db.create_scan(pid)
    scanner.run_scan(sid, pid)
    assert db.get_scan(sid)["summary"]["diff"] == {"new": 0, "fixed": 0}
