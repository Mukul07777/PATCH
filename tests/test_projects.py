"""Projects API, scan-only mode (OSV mocked with respx), SQLite persistence and fix-run linking."""
import json
import time

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from patchpilot import config, db, scanner, server, sources

OSV = "https://api.osv.dev/v1/query"
VULN = {"id": "GHSA-462w-v97r-4m45", "aliases": ["CVE-2019-10906"], "summary": "Jinja2 sandbox escape",
        "database_specific": {"severity": "HIGH"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"}],
        "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}]}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("PATCHPILOT_TOKEN", raising=False)
    monkeypatch.setattr(server, "_hits", server.collections.defaultdict(server.collections.deque))
    monkeypatch.setattr(server, "_spawn", lambda fn, *a: fn(*a))  # run scans inline
    monkeypatch.setattr(sources, "_kev", None)
    return TestClient(server.app)


def _mock_feeds():
    def osv(request):
        body = json.loads(request.content)
        return httpx.Response(200, json={"vulns": [VULN]} if body["package"]["name"].lower() == "jinja2" else {})
    respx.post(OSV).mock(side_effect=osv)
    respx.get("https://api.first.org/data/v1/epss").mock(return_value=httpx.Response(
        200, json={"data": [{"cve": "CVE-2019-10906", "epss": "0.42", "percentile": "0.9"}]}))
    respx.get(url__startswith="https://www.cisa.gov/").mock(return_value=httpx.Response(
        200, json={"vulnerabilities": [{"cveID": "CVE-2019-10906", "dateAdded": "2024-01-01"}]}))
    respx.get("https://pypi.org/pypi/jinja2/json").mock(return_value=httpx.Response(200, json={"info": {"version": "3.1.4"}}))


def _upload(client, content="jinja2==2.10\nrequests>=2\nsix==1.16.0\n", filename="requirements.txt", **kw):
    return client.post("/api/projects", json={"filename": filename, "content": content, **kw})


@respx.mock
def test_upload_scan_and_findings(client):
    _mock_feeds()
    r = _upload(client, name="shop")
    assert r.status_code == 201
    p = r.json()
    assert p["name"] == "shop" and p["source_type"] == "upload" and p["last_scan"] is None and "manifest" not in p
    s = client.post(f"/api/projects/{p['id']}/scan")
    assert s.status_code == 202
    scan = client.get(f"/api/scans/{s.json()['id']}").json()
    assert scan["status"] == "done" and scan["kind"] == "scan"
    assert scan["summary"]["unpinned"] == ["requests"] and scan["summary"]["pinned"] == 2
    assert scan["summary"]["vulnerable_packages"][0]["latest"] == "3.1.4"
    [f] = scan["findings"]
    assert f["package"] == "jinja2" and f["version"] == "2.10" and f["vuln_id"] == "GHSA-462w-v97r-4m45"
    assert "CVE-2019-10906" in f["aliases"] and f["severity"] == "HIGH" and f["cvss"].startswith("CVSS:3.1")
    assert f["epss"] == 0.42 and f["kev"] is True and f["fixed_in"] == "2.10.1"
    assert scan["counts"]["HIGH"] == 1
    listed = client.get("/api/projects").json()
    assert listed[0]["last_scan"]["counts"]["HIGH"] == 1 and listed[0]["last_scan_at"]
    assert [x["id"] for x in client.get(f"/api/projects/{p['id']}/scans").json()] == [scan["id"]]
    assert client.get("/api/stats").json() == {"projects": 1, "scans": 1, "open_findings": 1}


@respx.mock
def test_scan_osv_outage_reports_error_not_crash(client):
    respx.post(OSV).mock(return_value=httpx.Response(503))
    pid = _upload(client).json()["id"]
    scan = client.get(f"/api/scans/{client.post(f'/api/projects/{pid}/scan').json()['id']}").json()
    assert scan["status"] == "done" and scan["findings"] == []
    assert any("OSV lookup failed" in e for e in scan["summary"]["errors"])


@respx.mock
def test_git_project_scans_raw_manifests_even_with_remote_repos_off(client, monkeypatch):
    monkeypatch.setattr(config, "ALLOW_REMOTE_REPOS", False)
    _mock_feeds()
    raw = "https://raw.githubusercontent.com/acme/app/v1.2/"
    respx.get(raw + "requirements.txt").mock(return_value=httpx.Response(200, text="Jinja2==2.10\n"))
    respx.get(url__startswith=raw).mock(return_value=httpx.Response(404))
    p = client.post("/api/projects", json={"git_url": "https://github.com/acme/app.git", "ref": "v1.2"}).json()
    assert p["source"] == "https://github.com/acme/app" and p["ref"] == "v1.2" and p["name"] == "acme/app"
    scan = client.get(f"/api/scans/{client.post(f'/api/projects/{p['id']}/scan').json()['id']}").json()
    assert scan["status"] == "done" and scan["summary"]["files"] == ["requirements.txt"]
    assert len(scan["findings"]) == 1


@respx.mock
def test_git_project_without_manifest_errors(client):
    respx.get(url__startswith="https://raw.githubusercontent.com/").mock(return_value=httpx.Response(404))
    pid = client.post("/api/projects", json={"git_url": "https://github.com/acme/empty"}).json()["id"]
    scan = client.get(f"/api/scans/{client.post(f'/api/projects/{pid}/scan').json()['id']}").json()
    assert scan["status"] == "error" and "No supported manifest" in scan["summary"]["error"]


@pytest.mark.parametrize("body,code", [
    ({}, 422),
    ({"git_url": "https://evil.com/a/b"}, 422),
    ({"git_url": "https://github.com/a/b", "ref": "../x"}, 422),
    ({"git_url": "https://github.com/a/b", "filename": "requirements.txt", "content": "x==1"}, 422),
    ({"filename": "setup.py", "content": "x"}, 422),
    ({"filename": "requirements.txt", "content": "   "}, 422),
    ({"filename": "requirements.txt", "content": "# only comments\n"}, 422),
    ({"filename": "pyproject.toml", "content": "[broken"}, 422),
    ({"filename": "requirements.txt", "content": "a==1\n" * 50_001}, 422),
    ({"path": "/tmp"}, 403),
])
def test_create_project_validation(client, body, code):
    assert client.post("/api/projects", json=body).status_code == code
    assert client.get("/api/projects").json() == []


def test_local_path_projects_need_flag(client, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "ALLOW_LOCAL_PATHS", True)
    (tmp_path / "requirements.txt").write_text("six==1.16.0\n")
    monkeypatch.setattr(sources, "osv_vulns", lambda p, v: [])
    p = client.post("/api/projects", json={"path": str(tmp_path)}).json()
    assert p["source_type"] == "path"
    scan = client.get(f"/api/scans/{client.post(f'/api/projects/{p['id']}/scan').json()['id']}").json()
    assert scan["status"] == "done" and scan["summary"]["pinned"] == 1
    assert client.post("/api/projects", json={"path": "relative/dir"}).status_code == 422


def test_mutations_need_token_and_are_audited(client, monkeypatch):
    monkeypatch.setenv("PATCHPILOT_TOKEN", "t0k")
    assert _upload(client).status_code == 401
    auth = {"Authorization": "Bearer t0k"}
    pid = client.post("/api/projects", json={"filename": "requirements.txt", "content": "six==1\n"}, headers=auth).json()["id"]
    assert client.delete(f"/api/projects/{pid}").status_code == 401
    assert client.post(f"/api/projects/{pid}/scan").status_code == 401
    assert client.delete(f"/api/projects/{pid}", headers=auth).status_code == 204
    assert client.get(f"/api/projects/{pid}").status_code == 404
    assert [e["action"] for e in db.audit_entries()] == ["project.delete", "project.create"]


def test_project_rate_limit(client):
    codes = [_upload(client).status_code for _ in range(server.RATE_LIMIT + 1)]
    assert codes[:-1] == [201] * server.RATE_LIMIT and codes[-1] == 429


def test_delete_cascades_scans_and_findings(client, monkeypatch):
    monkeypatch.setattr(sources, "osv_vulns", lambda p, v: [{"id": "PYSEC-1", "cve": None, "summary": "x", "severity": "LOW",
                                                            "fixed": ["2.0"], "aliases": []}])
    monkeypatch.setattr(sources, "pypi_latest", lambda p: "9.9")
    pid = _upload(client, content="six==1.0\n").json()["id"]
    sid = client.post(f"/api/projects/{pid}/scan").json()["id"]
    assert client.get(f"/api/scans/{sid}").json()["counts"]["LOW"] == 1
    client.delete(f"/api/projects/{pid}")
    assert client.get(f"/api/scans/{sid}").status_code == 404
    assert client.get(f"/api/projects/{pid}/scans").status_code == 404


def test_samples_created_once_from_cases(client, monkeypatch, tmp_path):
    for name in ("alpha", "beta"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "requirements.txt").write_text("six==1.0\n")
    (tmp_path / "notacase").mkdir()
    monkeypatch.setattr(config, "CASES_DIR", tmp_path)
    assert client.get("/api/projects").json() == []  # nothing is seeded automatically
    first = client.post("/api/projects/samples").json()
    assert len(first["created"]) == 2
    assert {p["source"] for p in first["projects"]} == {"alpha", "beta"}
    assert all(p["source_type"] == "sample" for p in first["projects"])
    assert client.post("/api/projects/samples").json()["created"] == []


def test_db_persists_across_reopen(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "persist.db")
    pid = db.create_project("p", "upload", "requirements.txt", manifest="six==1\n")
    sid = db.create_scan(pid)
    db.add_findings(sid, pid, [{"package": "six", "version": "1", "vuln_id": "X-1", "severity": "HIGH", "kev": True}])
    db.update_scan(sid, "done", {"pinned": 1})
    db.audit("me", "test", {"a": 1})
    db.close()
    assert db.schema_version() == len(db.MIGRATIONS)
    assert db.get_project(pid, with_manifest=True)["manifest"] == "six==1\n"
    s = db.get_scan(sid)
    assert s["summary"] == {"pinned": 1} and s["findings"][0]["kev"] is True and s["counts"]["HIGH"] == 1
    assert db.audit_entries()[0]["action"] == "test"


def test_migrations_are_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "m.db")
    db.schema_version()
    db.close()
    db.schema_version()
    assert db._q("SELECT COUNT(*) AS n FROM schema_version")[0]["n"] == len(db.MIGRATIONS)


# ---------- fix runs ----------
@pytest.fixture
def fake_agent(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "NEBIUS_API_KEY", "k")
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path)
    started = []

    class A:
        def __init__(self, run_id, repo, emit):
            started.append(repo)
            self.emit = emit

        def run(self):
            self.emit({"type": "done", "ok": True})
    monkeypatch.setattr(server, "Agent", A)
    before = set(server.RUNS)
    yield started
    for k in set(server.RUNS) - before:
        server.RUNS.pop(k, None)


def test_fix_run_for_project_records_scan_row(client, fake_agent):
    pid = db.create_project("Sample: authsvc", "sample", "authsvc")
    r = client.post("/api/runs", json={"project": pid})
    assert r.status_code == 200
    run_id = r.json()["id"]
    for _ in range(100):
        if server.RUNS[run_id]["done"]:
            break
        time.sleep(0.02)
    assert fake_agent == ["case:authsvc"]
    [row] = client.get(f"/api/projects/{pid}/scans").json()
    assert row["kind"] == "fix" and row["run_id"] == run_id and row["status"] == "done"
    listed = {x["id"]: x for x in client.get("/api/runs").json()}
    assert listed[run_id]["project"] == pid and "sample" not in listed[run_id]


def test_fix_run_rejects_upload_projects_and_empty_target(client, fake_agent):
    pid = _upload(client).json()["id"]
    r = client.post("/api/runs", json={"project": pid})
    assert r.status_code == 400 and "scanned but not fixed" in r.json()["detail"]
    assert client.post("/api/runs", json={}).status_code == 422
    assert client.post("/api/runs", json={"project": 999}).status_code == 404
    assert fake_agent == []


def test_demo_runs_are_flagged_sample(client, monkeypatch, tmp_path):
    demo = tmp_path / "demo"
    demo.mkdir()
    (demo / "r1.jsonl").write_text('{"type": "start", "repo": "case:x"}\n{"type": "done", "ok": true}\n')
    monkeypatch.setattr(config, "DEMO_RUNS_DIR", demo)
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path / "live")
    (tmp_path / "live").mkdir()
    assert client.get("/api/runs").json()[0]["sample"] is True


def test_health_exposes_models_without_secrets(client, monkeypatch):
    monkeypatch.setattr(config, "MODEL_OVERRIDES", {"nano": "nvidia/nano-x", "super": "", "ultra": ""})
    monkeypatch.setattr(config, "NEBIUS_API_KEY", "sk-secret")
    body = client.get("/api/health").json()
    assert body["models"] == {"nano": "nvidia/nano-x", "super": None, "ultra": None}
    assert body["fix_mode"] is True and body["scan_mode"] is True
    assert "sk-secret" not in str(body)


def test_projects_page_served(client):
    r = client.get("/projects")
    assert r.status_code == 200 and "projects.js" in r.text


def test_scanner_lowest_fix():
    assert scanner._lowest_fix_above("2.10", ["2.10.1", "3.0", "2.9"]) == "2.10.1"
    assert scanner._lowest_fix_above("5.0", ["2.0"]) is None
