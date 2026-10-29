"""Round 4: scheduled scans + lease, notifications (diff, dedupe, HMAC, retries, SMTP), exports (SARIF,
CycloneDX, CSV), the scan CLI's exit codes, auto-fix conditions, the Docker sandbox argv and the GitHub cache."""
import calendar
import hashlib
import hmac
import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from conftest import AUTH

from patchpilot import cli, config, db, export, notify, sandbox, scanner, scheduler, server, settings, sources

OSV = "https://api.osv.dev/v1/querybatch"
HOOK = "https://hooks.example.com/pp"
VULNS = {
    "jinja2": {"id": "GHSA-462w-v97r-4m45", "aliases": ["CVE-2019-10906"], "summary": "Jinja2 sandbox escape",
               "database_specific": {"severity": "HIGH"},
               "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}]},
    "urllib3": {"id": "GHSA-crit-0000-0000", "aliases": ["CVE-2099-0001"], "summary": "urllib3 critical bug",
                "database_specific": {"severity": "CRITICAL"},
                "affected": [{"package": {"name": "urllib3", "ecosystem": "PyPI"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.5"}]}]}]},
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(server, "_hits", server.collections.defaultdict(server.collections.deque))
    monkeypatch.setattr(server, "_spawn", lambda fn, *a: fn(*a))
    monkeypatch.setattr(sources, "_kev", None)
    monkeypatch.setattr(notify, "_sleep", lambda s: None)
    monkeypatch.setattr(config, "NEBIUS_API_KEY", "")
    return TestClient(server.app, headers=AUTH)


def feeds(vulnerable=("jinja2",), kev=()):
    def osv(request):
        qs = json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [
            {"vulns": [{"id": VULNS[q["package"]["name"].lower()]["id"], "modified": "2024-01-01T00:00:00Z"}]}
            if q["package"]["name"].lower() in vulnerable else {} for q in qs]})
    respx.post(OSV).mock(side_effect=osv)
    for v in VULNS.values():
        respx.get(f"https://api.osv.dev/v1/vulns/{v['id']}").mock(return_value=httpx.Response(200, json=v))
    respx.get("https://api.first.org/data/v1/epss").mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(url__startswith="https://www.cisa.gov/").mock(return_value=httpx.Response(
        200, json={"vulnerabilities": [{"cveID": c, "dateAdded": "2024-01-01"} for c in kev]}))
    respx.get(url__startswith="https://pypi.org/pypi/").mock(return_value=httpx.Response(200, json={"info": {"version": "9.9"}}))


def upload(client, content="jinja2==2.10\nsix==1.16.0\n"):
    r = client.post("/api/projects", json={"filename": "requirements.txt", "content": content, "name": "shop"})
    assert r.status_code == 201
    return r.json()["id"]


def scan(client, pid):
    return client.get(f"/api/scans/{client.post(f'/api/projects/{pid}/scan').json()['id']}").json()


def webhook(client, **kw):
    body = {"type": "webhook", "name": "hook", "config": {"url": HOOK, "secret": "s" * 32},
            "events": ["new_findings", "scan_failed"], **kw}
    r = client.post("/api/channels", json=body)
    assert r.status_code == 201, r.text
    return r.json()


# ---------- scheduler ----------
def test_next_run_daily_and_weekly():
    now = calendar.timegm((2026, 10, 29, 10, 0, 0))  # a Thursday, 10:00 UTC
    assert db.next_run("daily", 3, now) == calendar.timegm((2026, 10, 30, 3, 0, 0))
    assert db.next_run("daily", 11, now) == calendar.timegm((2026, 10, 29, 11, 0, 0))
    assert db.next_run("weekly", 3, now) == calendar.timegm((2026, 11, 2, 3, 0, 0))  # next Monday
    assert db.next_run("off", 3, now) is None


@respx.mock
def test_scheduler_tick_queues_due_projects_with_fake_clock(client):
    feeds()
    pid = upload(client)
    t0 = calendar.timegm((2026, 10, 29, 10, 0, 0))
    db.set_policy(pid, "low", False, "t", schedule="daily", schedule_hour=3, now=t0)
    pol = client.get(f"/api/projects/{pid}/policy").json()
    assert pol["schedule"] == "daily" and pol["next_run_at"] == calendar.timegm((2026, 10, 30, 3, 0, 0))
    assert scheduler.tick(now=t0) == []  # not due yet
    due = pol["next_run_at"] + 5
    created = scheduler.tick(spawn=lambda fn: fn(), now=due)
    assert len(created) == 1
    s = db.get_scan(created[0])
    assert s["status"] == "done" and s["findings"][0]["package"] == "jinja2"
    assert db.get_policy(pid)["next_run_at"] == calendar.timegm((2026, 10, 31, 3, 0, 0))
    assert scheduler.tick(now=due + 60) == []  # already advanced: no double run
    assert any(e["action"] == "scan.scheduled" for e in db.audit_entries())


def test_lease_blocks_second_process():
    now = 1000.0
    assert db.acquire_lease("scheduler", "a", 120, now)
    assert not db.acquire_lease("scheduler", "b", 120, now + 10)
    assert db.acquire_lease("scheduler", "a", 120, now + 10)  # renew
    assert db.acquire_lease("scheduler", "b", 120, now + 200)  # a's lease expired
    assert scheduler.tick(now=now + 210, holder="a") == []  # b holds it now


def test_policy_put_keeps_schedule_and_validates_channels(client):
    pid = upload(client)
    r = client.put(f"/api/projects/{pid}/policy", json={"severity_threshold": "low", "schedule": "weekly", "schedule_hour": 7})
    assert r.status_code == 200 and r.json()["schedule"] == "weekly" and r.json()["next_run_at"]
    r = client.put(f"/api/projects/{pid}/policy", json={"severity_threshold": "high"})
    assert r.json()["schedule"] == "weekly" and r.json()["schedule_hour"] == 7 and r.json()["channels"] is None
    assert client.put(f"/api/projects/{pid}/policy", json={"channels": [999]}).status_code == 422
    assert client.put(f"/api/projects/{pid}/policy", json={"schedule": "hourly"}).status_code == 422


@respx.mock
def test_scan_all_queues_every_project(client):
    feeds()
    a, b = upload(client), upload(client, "six==1.16.0\n")
    r = client.post("/api/projects/scan-all")
    assert r.status_code == 202 and r.json()["queued"] == 2
    assert all(db.list_scans(p)[0]["status"] == "done" for p in (a, b))


# ---------- notifications ----------
@respx.mock
def test_webhook_gets_only_new_findings_signed_and_deduped(client, monkeypatch):
    feeds()
    monkeypatch.setenv("PATCHPILOT_PUBLIC_URL", "https://pp.example.com")
    got = []
    respx.post(HOOK).mock(side_effect=lambda req: got.append(req) or httpx.Response(200))
    ch = webhook(client)
    assert ch["config"]["secret_last4"] == "ssss" and ch["secret"] == "s" * 32
    pid = upload(client)
    s1 = scan(client, pid)
    assert len(got) == 1
    req = got[0]
    body = json.loads(req.content)
    assert body["event"] == "new_findings" and body["counts"]["HIGH"] == 1
    assert body["new_findings"][0]["vuln_id"] == "GHSA-462w-v97r-4m45"
    assert body["project"]["url"] == f"https://pp.example.com/projects?id={pid}"
    ts = req.headers["X-PatchPilot-Timestamp"]
    want = "sha256=" + hmac.new(b"s" * 32, ts.encode() + b"." + req.content, hashlib.sha256).hexdigest()
    assert req.headers["X-PatchPilot-Signature"] == want and req.headers["X-PatchPilot-Event"] == "new_findings"
    scan(client, pid)  # same findings again: nothing new, nothing sent
    assert len(got) == 1
    assert notify.after_scan(s1["id"], pid, True) == [(ch["id"], "duplicate")]  # replayed scan: deduped
    log = client.get("/api/deliveries").json()
    assert log[0]["status"] == "ok" and log[0]["response_code"] == 200 and log[0]["attempts"] == 1
    assert any(e["action"] == "channel.create" for e in db.audit_entries())


@respx.mock
def test_retry_with_backoff_then_give_up(client, monkeypatch):
    feeds()
    slept = []
    monkeypatch.setattr(notify, "_sleep", slept.append)
    route = respx.post(HOOK).mock(return_value=httpx.Response(503))
    webhook(client)
    scan(client, upload(client))
    assert route.call_count == 3 and slept == [1.0, 4.0]
    d = client.get("/api/deliveries").json()[0]
    assert d["status"] == "failed" and d["response_code"] == 503 and d["attempts"] == 3


@respx.mock
def test_retry_succeeds_and_4xx_is_not_retried(client):
    feeds()
    route = respx.post(HOOK).mock(side_effect=[httpx.ConnectError("x"), httpx.Response(204)])
    webhook(client)
    scan(client, upload(client))
    assert route.call_count == 2 and client.get("/api/deliveries").json()[0]["status"] == "ok"
    route.side_effect = None
    route.return_value = httpx.Response(410)
    ch = db.list_channels()[0]
    assert notify.deliver(ch, "test", {"event": "test"}, "k1") == "failed" and route.call_count == 3


@respx.mock
def test_min_severity_specific_events_and_project_opt_out(client):
    feeds(vulnerable=("jinja2", "urllib3"), kev=("CVE-2099-0001",))
    hook2 = "https://hooks.example.com/crit"
    a, b = [], []
    respx.post(HOOK).mock(side_effect=lambda r: a.append(json.loads(r.content)) or httpx.Response(200))
    respx.post(hook2).mock(side_effect=lambda r: b.append(json.loads(r.content)) or httpx.Response(200))
    webhook(client, min_severity="high")
    c2 = webhook(client, config={"url": hook2}, events=["kev", "new_critical"], min_severity="critical")
    pid = upload(client, "jinja2==2.10\nurllib3==1.26.0\n")
    scan(client, pid)
    assert a[0]["event"] == "new_findings" and len(a[0]["new_findings"]) == 2
    assert b[0]["event"] == "kev" and b[0]["events"] == ["kev", "new_critical"]
    assert [f["package"] for f in b[0]["new_findings"]] == ["urllib3"]
    # opt the project out of the first channel
    pid2 = upload(client, "jinja2==2.10\n")
    client.put(f"/api/projects/{pid2}/policy", json={"severity_threshold": "low", "channels": [c2["id"]]})
    scan(client, pid2)
    assert len(a) == 1 and len(b) == 1  # c2 got nothing: jinja2 is high, not critical / KEV


@respx.mock
def test_scan_failed_notification(client):
    respx.post(HOOK).mock(return_value=httpx.Response(200))
    webhook(client)
    pid = db.create_project("gone", "sample", "no-such-case")
    sid = db.create_scan(pid, "scan", "queued")
    scanner.run_scan(sid, pid)
    d = client.get("/api/deliveries").json()[0]
    assert d["event"] == "scan_failed" and d["status"] == "ok"


@respx.mock
def test_slack_blocks_and_masked_config(client):
    feeds()
    url = "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX"
    sent = []
    respx.post(url).mock(side_effect=lambda r: sent.append(json.loads(r.content)) or httpx.Response(200))
    r = client.post("/api/channels", json={"type": "slack", "name": "sec", "config": {"url": url}, "events": ["new_findings"]})
    assert r.status_code == 201 and "XXXXXXXXXXXXXXXX" not in r.json()["config"]["url"]
    assert client.post("/api/channels", json={"type": "slack", "name": "x", "config": {"url": "https://evil.example/x"},
                                              "events": ["new_findings"]}).status_code == 422
    scan(client, upload(client))
    blocks = sent[0]["blocks"]
    assert blocks[0]["type"] == "header" and "1 new finding in shop" in sent[0]["text"]
    assert "GHSA-462w-v97r-4m45" in json.dumps(blocks)
    # stored encrypted
    raw = db._q("SELECT config FROM channels")[0]["config"]
    assert "hooks.slack.com" not in raw and json.loads(settings.decrypt(raw))["url"] == url


def test_send_test_email_via_mocked_smtp(client, monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent["addr"] = (host, port)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context):
            sent["tls"] = True

        def login(self, u, p):
            sent["login"] = (u, p)

        def send_message(self, msg):
            sent["msg"] = msg

    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    assert client.put("/api/settings", json={"smtp_host": "mail.example.com", "smtp_port": "587", "smtp_user": "pp",
                                             "smtp_password": "hunter2hunter2", "smtp_from": "pp@example.com"}).status_code == 200
    assert client.get("/api/settings").json()["smtp_password"]["set"] is True
    ch = client.post("/api/channels", json={"type": "email", "name": "mail", "config": {"to": "a@example.com, b@example.com"},
                                            "events": ["new_findings"]}).json()
    r = client.post(f"/api/channels/{ch['id']}/test").json()
    assert r["ok"] and sent["addr"] == ("mail.example.com", 587) and sent["tls"] and sent["login"] == ("pp", "hunter2hunter2")
    assert sent["msg"]["To"] == "a@example.com, b@example.com" and "[PatchPilot test]" in sent["msg"]["Subject"]


def test_channels_admin_only_and_member_view(client, monkeypatch):
    from patchpilot import auth
    webhook(client)
    uid = auth.create_user("m@example.com", "M", "longpassword1", "member")
    _, key = auth.create_key(uid, "k", "member")
    m = TestClient(server.app, headers={"Authorization": f"Bearer {key}"})
    rows = m.get("/api/channels").json()
    assert rows == [{"id": rows[0]["id"], "type": "webhook", "name": "hook", "events": ["new_findings", "scan_failed"], "enabled": True}]
    assert m.post("/api/channels", json={"type": "webhook", "name": "x", "config": {"url": HOOK}, "events": ["kev"]}).status_code == 403
    assert m.get("/api/deliveries").status_code == 403


# ---------- exports ----------
SARIF_REQUIRED = {"$schema", "version", "runs"}


def _check_sarif(doc):
    """A minimal subset of the SARIF 2.1.0 schema that GitHub code scanning relies on."""
    assert SARIF_REQUIRED <= set(doc) and doc["version"] == "2.1.0"
    for run in doc["runs"]:
        drv = run["tool"]["driver"]
        assert isinstance(drv["name"], str)
        ids = [r["id"] for r in drv["rules"]]
        assert len(ids) == len(set(ids))
        for r in drv["rules"]:
            assert r["shortDescription"]["text"] and float(r["properties"]["security-severity"]) >= 0
        for res in run["results"]:
            assert res["ruleId"] in ids and drv["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
            assert res["level"] in ("none", "note", "warning", "error") and res["message"]["text"]
            loc = res["locations"][0]["physicalLocation"]
            assert loc["artifactLocation"]["uri"] and loc["region"]["startLine"] >= 1


@respx.mock
def test_export_endpoints(client):
    feeds()
    pid = upload(client, "# deps\nsix==1.16.0\njinja2==2.10\n")
    sid = client.post(f"/api/projects/{pid}/scan").json()["id"]
    r = client.get(f"/api/scans/{sid}/export?format=sarif")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    doc = r.json()
    _check_sarif(doc)
    res = doc["runs"][0]["results"][0]
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "requirements.txt"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
    cdx = client.get(f"/api/scans/{sid}/export?format=cyclonedx").json()
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.5" and cdx["serialNumber"].startswith("urn:uuid:")
    assert {c["purl"] for c in cdx["components"]} == {"pkg:pypi/six@1.16.0", "pkg:pypi/jinja2@2.10"}
    [v] = cdx["vulnerabilities"]
    assert v["id"] == "GHSA-462w-v97r-4m45" and v["affects"] == [{"ref": "pkg:pypi/jinja2@2.10"}]
    assert v["ratings"][0]["severity"] == "high" and v["recommendation"].endswith("2.10.1 or later")
    csv_text = client.get(f"/api/scans/{sid}/export?format=csv").text
    assert csv_text.splitlines()[0].startswith("package,version,vuln_id") and "jinja2,2.10,GHSA-462w" in csv_text
    assert client.get(f"/api/scans/{sid}/export?format=json").json()["findings"][0]["source_line"] == 3
    assert client.get(f"/api/scans/{sid}/export?format=pdf").status_code == 422
    assert client.get("/api/scans/999/export").status_code == 404


def test_csv_neutralises_formulas():
    text = export.to_csv({"findings": [{"package": "=cmd()", "vuln_id": "X", "aliases": []}]})
    assert "'=cmd()" in text


# ---------- CLI ----------
@pytest.fixture
def req_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sources, "_kev", None)
    monkeypatch.setattr(config, "NO_DB", False)  # scan_main switches it on; restored after the test
    (tmp_path / "requirements.txt").write_text("six==1.16.0\njinja2==2.10\n", encoding="utf-8")
    return tmp_path / "requirements.txt"


@respx.mock
def test_cli_exit_codes_and_formats(req_file, capsys, monkeypatch):
    feeds()
    assert cli.scan_main([str(req_file), "--fail-on", "high"]) == 1
    out = capsys.readouterr().out
    assert "GHSA-462w-v97r-4m45" in out and "requirements.txt:2" in out
    assert cli.scan_main([str(req_file), "--fail-on", "critical"]) == 0
    assert cli.scan_main([str(req_file), "--ignore", "CVE-2019-10906"]) == 0
    assert cli.scan_main(["."]) == 1
    assert cli.scan_main([".", "--format", "sarif", "--fail-on", "none", "--output", "out.sarif"]) == 0
    _check_sarif(json.loads((req_file.parent / "out.sarif").read_text()))
    capsys.readouterr()
    assert cli.scan_main([".", "--format", "cyclonedx", "--fail-on", "none"]) == 0
    assert json.loads(capsys.readouterr().out)["specVersion"] == "1.5"
    assert not (req_file.parent / "runs").exists()  # no database was created


@respx.mock
def test_cli_errors_exit_2(req_file, capsys):
    respx.post(OSV).mock(return_value=httpx.Response(503))
    assert cli.scan_main([str(req_file)]) == 2
    assert cli.scan_main(["missing.txt"]) == 2
    (req_file.parent / "notes.md").write_text("x")
    assert cli.scan_main(["notes.md"]) == 2


def test_main_dispatch(capsys):
    from patchpilot.__main__ import main
    assert main(["--help"]) == 0 and "scan" in capsys.readouterr().out
    assert main(["bogus"]) == 2


# ---------- auto-fix ----------
def _scan_with_new(pid, fixed_in="2.10.1"):
    sid = db.create_scan(pid, "scan", "done")
    rows = [{"package": "jinja2", "version": "2.10", "vuln_id": "GHSA-x", "severity": "HIGH", "fixed_in": fixed_in}]
    db.add_findings(sid, pid, rows)
    db.track_findings(sid, pid, rows)
    return sid


def test_autofix_conditions(client, monkeypatch):
    launched = []
    monkeypatch.setattr(server, "_launch", lambda repo, pid: launched.append((repo, pid)) or "run-1")
    monkeypatch.setattr(config, "ALLOW_REMOTE_REPOS", False)
    monkeypatch.delenv("SANDBOX", raising=False)
    upid = upload(client)
    sid = _scan_with_new(upid)
    assert server.autofix_after_scan(sid, upid, True) == "auto_fix off"
    db.set_policy(upid, "low", True, "t")
    assert server.autofix_after_scan(sid, upid, True) == "not a repository project"
    pid = db.create_project("demo", "sample", "authsvc")
    db.set_policy(pid, "low", True, "t")
    sid = _scan_with_new(pid)
    assert server.autofix_after_scan(sid, pid, False) == "scan failed"
    assert server.autofix_after_scan(sid, pid, True) == "no LLM API key" and launched == []
    assert any(e["action"] == "autofix.skipped" for e in db.audit_entries())
    monkeypatch.setattr(config, "NEBIUS_API_KEY", "k")
    assert server.autofix_after_scan(sid, pid, True) == "started" and launched == [("case:authsvc", pid)]
    assert any(e["action"] == "autofix.start" for e in db.audit_entries())
    monkeypatch.setattr(server, "_active_runs", lambda: server.MAX_ACTIVE_RUNS)
    assert "fix runs already in progress" in server.autofix_after_scan(sid, pid, True)
    nofix = db.create_project("nofix", "sample", "authsvc")
    db.set_policy(nofix, "low", True, "t")
    assert server.autofix_after_scan(_scan_with_new(nofix, None), nofix, True) == "no new fixable findings"
    crit = db.create_project("crit", "sample", "authsvc")
    db.set_policy(crit, "critical", True, "t")  # HIGH finding is below the threshold: suppressed, not fixed
    assert server.autofix_after_scan(_scan_with_new(crit), crit, True) == "no new fixable findings"
    gid = db.create_project("r", "git", "https://github.com/o/r")
    db.set_policy(gid, "low", True, "t")
    gsid = _scan_with_new(gid)
    assert server.autofix_after_scan(gsid, gid, True).startswith("remote fix runs not allowed")
    monkeypatch.setenv("SANDBOX", "docker")
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    assert server.autofix_after_scan(gsid, gid, True) == "Docker sandbox unavailable"


# ---------- docker sandbox ----------
def test_docker_argv_is_locked_down(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX", "docker")
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    calls = []
    monkeypatch.setattr(sandbox.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or
                        type("P", (), {"returncode": 0, "stdout": "1 passed", "stderr": ""})())
    box = sandbox.Sandbox(tmp_path, lambda m: None)
    assert box.install()[0]
    ok, summary, _ = box.test()
    assert ok and summary == "1 passed"
    install, test = calls
    for argv in (install, test):
        assert argv[:3] == ["docker", "run", "--rm"]
        for flag, val in (("--memory", "2g"), ("--cpus", "2"), ("--pids-limit", "512"), ("--tmpfs", "/tmp:rw,exec,size=512m")):
            assert argv[argv.index(flag) + 1] == val
        assert "--read-only" in argv and argv[argv.index("--user") + 1] != "0:0"
        mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
        assert mounts == [f"{tmp_path.resolve()}:/work:rw"]
        assert "python:3.12-slim" in argv
    assert install[install.index("--network") + 1] == "bridge"
    assert test[test.index("--network") + 1] == "none"
    i = test.index("python:3.12-slim")
    assert test[i + 1:i + 4] == ["/work/.patchpilot/venv/bin/python", "-m", "pytest"]


def test_docker_mode_without_docker_refuses_runs(client, monkeypatch):
    monkeypatch.setenv("SANDBOX", "docker")
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    monkeypatch.setattr(config, "NEBIUS_API_KEY", "k")
    with pytest.raises(sandbox.SandboxUnavailable):
        sandbox.Sandbox(".", lambda m: None)
    r = client.post("/api/runs", json={"repo": "case:authsvc"})
    assert r.status_code == 503 and "Docker" in r.json()["detail"]
    h = client.get("/api/health").json()
    assert h["sandbox"] == {"mode": "docker", "image": "python:3.12-slim", "docker": False, "ready": False}
    assert h["remote_fix"] is True  # docker mode is what allows remote repos (once docker is up)


def test_remote_fix_needs_docker_or_admin_switch(client, monkeypatch):
    monkeypatch.setattr(config, "NEBIUS_API_KEY", "k")
    monkeypatch.setattr(config, "ALLOW_REMOTE_REPOS", False)
    monkeypatch.delenv("SANDBOX", raising=False)
    r = client.post("/api/runs", json={"repo": "https://github.com/o/r"})
    assert r.status_code == 403 and "Docker sandbox" in r.json()["detail"]
    assert client.get("/api/health").json()["sandbox"]["mode"] == "local"


def test_settings_validation(client):
    assert client.put("/api/settings", json={"public_url": "ftp://x"}).status_code == 422
    assert client.put("/api/settings", json={"sandbox": "vm"}).status_code == 422
    r = client.put("/api/settings", json={"public_url": "https://pp.example.com/", "sandbox": "docker",
                                          "sandbox_image": "python:3.12-slim"})
    assert r.status_code == 200 and r.json()["public_url"]["value"] == "https://pp.example.com"
    assert config.public_url() == "https://pp.example.com" and config.sandbox_mode() == "docker"


# ---------- GitHub cache ----------
@respx.mock
def test_github_tree_cached_by_sha_and_etag_reused():
    sha = "a" * 40
    repo = respx.get("https://api.github.com/repos/o/r").mock(
        side_effect=[httpx.Response(200, json={"default_branch": "main"}, headers={"etag": '"e1"'}),
                     httpx.Response(304)])
    respx.get("https://api.github.com/repos/o/r/commits/main").mock(
        return_value=httpx.Response(200, json={"sha": sha}, headers={"etag": '"c1"'}))
    tree = respx.get(f"https://api.github.com/repos/o/r/git/trees/{sha}").mock(return_value=httpx.Response(
        200, json={"tree": [{"path": "requirements.txt", "type": "blob", "size": 10}]}))
    respx.get(f"https://raw.githubusercontent.com/o/r/{sha}/requirements.txt").mock(return_value=httpx.Response(200, text="six==1.16.0\n"))
    for _ in range(2):
        files, *_ = scanner._fetch_github("https://github.com/o/r", None)
        assert files == [("requirements.txt", "six==1.16.0\n")]
    assert tree.call_count == 1  # immutable: second scan served from the cache
    assert repo.calls[1].request.headers["If-None-Match"] == '"e1"'
