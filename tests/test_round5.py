"""Round 5 (practicality fixes): asynchronous notification delivery + circuit breaker + restart resume, SSRF guard
for webhook / Slack / SMTP destinations, CLI false-pass exit codes, single-file manifest names, unparsable
requirement lines in coverage, failed-only sign-in rate limits, self-hosted fonts + 'self'-only CSP, an end-to-end
email delivery through a local SMTP server, the auto-fix enqueue path with a mocked agent, and CycloneDX shape."""
import json
import re
import socketserver
import threading
import time
import uuid

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from conftest import AUTH, osv_from
from patchpilot import cli
from patchpilot.core import config, netguard
from patchpilot.app import db, notify, server
from patchpilot.intel import manifests, scanner, sources

HOOK = "https://hooks.example.com/pp"
CSRF = {"X-Requested-With": "patchpilot"}
PW = "correct horse battery"
JINJA = {"id": "GHSA-462w-v97r-4m45", "aliases": ["CVE-2019-10906"], "summary": "Jinja2 sandbox escape",
         "severity": "HIGH", "fixed": ["2.10.1"], "cve": "CVE-2019-10906"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(server, "_hits", server.collections.defaultdict(server.collections.deque))
    monkeypatch.setattr(server, "_spawn", lambda fn, *a: fn(*a))
    monkeypatch.setattr(notify, "_sleep", lambda s: None)
    monkeypatch.setattr(config, "NEBIUS_API_KEY", "")
    monkeypatch.setattr(sources, "osv_batch", osv_from(lambda n, v: [JINJA] if n.lower() == "jinja2" else []))
    monkeypatch.setattr(sources, "epss", lambda cves: {})
    monkeypatch.setattr(sources, "kev", lambda: {})
    monkeypatch.setattr(sources, "pypi_latest", lambda n: "9.9")
    return TestClient(server.app, headers=AUTH)


def webhook(client, url=HOOK, **kw):
    body = {"type": "webhook", "name": "hook", "config": {"url": url}, "events": ["new_findings", "scan_failed"]} | kw
    return client.post("/api/channels", json=body)


def upload(client, content="jinja2==2.10\nsix==1.16.0\n", name="shop"):
    r = client.post("/api/projects", json={"filename": "requirements.txt", "content": content, "name": name})
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ---------- 1. notifications never stall the scan queue ----------
def test_dead_channel_does_not_slow_scans_and_breaker_opens(client, monkeypatch):
    monkeypatch.setattr(notify, "_submit", notify._pool_submit)  # the real background pool
    calls = []

    def dead(row, payload, did):  # an endpoint that hangs, then times out
        calls.append(did)
        time.sleep(0.5)
        return False, None, notify.UNREACHABLE, True
    monkeypatch.setattr(notify, "_send", dead)
    assert webhook(client).status_code == 201
    pids = [upload(client, name=f"p{i}") for i in range(10)]
    t0 = time.monotonic()
    for pid in pids:
        sid = db.create_scan(pid, "scan", "queued")
        scanner.run_scan(sid, pid)
    elapsed = time.monotonic() - t0
    # 10 scans x 3 attempts x 0.5 s would be 15 s inline; the scan workers never wait for delivery
    assert elapsed < 3, elapsed
    assert all(db.get_scan(s["id"])["status"] == "done" for p in pids for s in db.list_scans(p, 1))
    deadline = time.time() + 20
    while time.time() < deadline and db.get_channel(1)["failures"] < notify.BREAKER_THRESHOLD:
        notify.sweep()  # what the sweeper thread does every few seconds
        time.sleep(0.1)
    ch = db.get_channel(1)
    assert ch["failures"] >= notify.BREAKER_THRESHOLD and ch["open_until"] > time.time()
    assert client.get("/api/channels").json()[0]["health"]["state"] == "failing"
    for _ in range(5):
        notify.sweep()
        time.sleep(0.1)
    n = len(calls)
    # with the breaker open the remaining deliveries wait instead of being attempted
    assert n <= (notify.BREAKER_THRESHOLD + 1) * notify.ATTEMPTS
    pending = [d for d in client.get("/api/deliveries").json() if d["status"] == "pending"]
    assert pending and all(d["next_at"] for d in pending)
    deadline = time.time() + 10  # let in-flight sends finish before this test's database goes away
    while time.time() < deadline and (notify._queued or db._q("SELECT 1 FROM deliveries WHERE status = 'sending'")):
        time.sleep(0.05)


def test_breaker_inline_defers_and_test_send_closes_it(client, monkeypatch):
    route_calls = []
    monkeypatch.setattr(notify, "_send", lambda row, p, did: route_calls.append(did) or (False, 503, "HTTP 503", True))
    cid = webhook(client).json()["id"]
    row = db.get_channel(cid)
    for i in range(notify.BREAKER_THRESHOLD):
        assert notify.deliver(row, "new_findings", {"event": "new_findings"}, f"k{i}") == "failed"
    assert db.get_channel(cid)["open_until"] > time.time()
    before = len(route_calls)
    assert notify.deliver(row, "new_findings", {"event": "new_findings"}, "later") == "pending"
    assert len(route_calls) == before  # not attempted while failing
    monkeypatch.setattr(notify, "_send", lambda row, p, did: (True, 200, None, False))
    assert client.post(f"/api/channels/{cid}/test").json()["ok"] is True
    assert client.get("/api/channels").json()[0]["health"] == {"state": "ok", "failures": 0, "retry_at": None}
    assert notify.sweep() == 1  # the waiting delivery goes out now
    assert db._q("SELECT status FROM deliveries WHERE dedupe_key = 'later'")[0]["status"] == "ok"


def test_pending_deliveries_survive_restart(client, monkeypatch):
    cid = webhook(client).json()["id"]
    did = db.start_delivery(cid, "new_findings", "scan:1", None, json.dumps({"event": "new_findings"}), 3)
    db.claim_delivery(did)  # the process died mid-send
    sent = []
    monkeypatch.setattr(notify, "_send", lambda row, p, d: sent.append((d, p)) or (True, 200, None, False))
    monkeypatch.setattr(notify, "SWEEP_INTERVAL", 3600)
    notify.start(interval=3600)
    try:
        assert sent == [(did, {"event": "new_findings"})]
        assert db.get_delivery(did)["status"] == "ok"
    finally:
        notify.stop()


# ---------- 3. SSRF ----------
@pytest.mark.parametrize("ip,ok", [
    ("8.8.8.8", True), ("2606:4700:4700::1111", True), ("127.0.0.1", False), ("10.1.2.3", False),
    ("172.16.0.1", False), ("192.168.1.1", False), ("169.254.169.254", False), ("100.64.0.1", False),
    ("0.0.0.0", False), ("224.0.0.1", False), ("240.0.0.1", False), ("::1", False), ("::", False),
    ("fc00::1", False), ("fe80::1", False), ("ff02::1", False), ("::ffff:127.0.0.1", False),
    ("::ffff:10.0.0.1", False), ("2002:7f00:0001::1", False), ("not-an-ip", False)])
def test_is_public(ip, ok):
    assert netguard.is_public(ip) is ok


@pytest.mark.parametrize("url", ["http://127.0.0.1/x", "http://[::1]:8080/x", "http://[::ffff:127.0.0.1]/x",
                                 "http://169.254.169.254/latest/meta-data", "http://localhost/x",
                                 "http://0.0.0.0/x", "http://10.0.0.5/hook"])
def test_private_webhook_rejected_at_save(client, url):
    r = webhook(client, url)
    assert r.status_code == 422 and "not allowed" in r.json()["detail"]


def test_hostname_resolving_private_rejected_and_opt_in(client, monkeypatch):
    monkeypatch.setattr(netguard, "_resolve", lambda h, p: ["93.184.216.34", "10.0.0.7"])  # any private answer
    assert webhook(client, "https://internal.example.com/x").status_code == 422
    monkeypatch.setenv("PATCHPILOT_ALLOW_PRIVATE_WEBHOOKS", "1")
    assert webhook(client, "https://internal.example.com/x").status_code == 201


def test_smtp_host_guarded(client, monkeypatch):
    r = client.put("/api/settings", json={"smtp_host": "127.0.0.1"})
    assert r.status_code in (400, 422) and "not allowed" in r.text
    assert client.put("/api/settings", json={"smtp_host": "mail.example.com"}).status_code == 200


def test_dns_rebinding_blocked_at_connect_with_generic_error(client, monkeypatch):
    cid = webhook(client).json()["id"]  # resolved public when saved
    monkeypatch.setattr(netguard, "_resolve", lambda h, p: ["127.0.0.1"])  # ...then rebinds to loopback
    connected = []
    monkeypatch.setattr(netguard.httpcore.SyncBackend, "connect_tcp",
                        lambda self, *a, **k: connected.append(a) or (_ for _ in ()).throw(OSError("x")))
    assert notify.deliver(db.get_channel(cid), "new_findings", {"event": "new_findings"}, "rb") == "failed"
    assert connected == []  # the socket was never opened
    d = client.get("/api/deliveries").json()[0]
    assert d["error"] == notify.UNREACHABLE and d["attempts"] == 1  # blocked: not retried, no error class leaked
    t = client.post(f"/api/channels/{cid}/test").json()
    assert t["ok"] is False and t["delivery"]["error"] == notify.UNREACHABLE


def test_pinned_backend_connects_to_checked_ip(monkeypatch):
    seen = []
    monkeypatch.setattr(netguard, "_resolve", lambda h, p: ["93.184.216.34"])
    monkeypatch.setattr(netguard.httpcore.SyncBackend, "connect_tcp", lambda self, host, port, **k: seen.append((host, port)))
    netguard._PinnedBackend().connect_tcp("hooks.example.com", 443)
    assert seen == [("93.184.216.34", 443)]


@respx.mock
def test_redirects_not_followed(client):
    respx.post(HOOK).mock(return_value=httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"}))
    inner = respx.post("http://127.0.0.1/admin").mock(return_value=httpx.Response(200))
    cid = webhook(client).json()["id"]
    assert notify.deliver(db.get_channel(cid), "new_findings", {"event": "new_findings"}, "r") == "failed"
    assert inner.call_count == 0 and client.get("/api/deliveries").json()[0]["error"] == "HTTP 302"


# ---------- email end to end through a local SMTP server ----------
class _SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        w = lambda s: self.wfile.write(s.encode() + b"\r\n")  # noqa: E731
        w("220 localhost test SMTP")
        mail = {"rcpt": []}
        while True:
            line = self.rfile.readline().decode(errors="replace").rstrip("\r\n")
            if not line:
                return
            cmd = line.split(" ", 1)[0].upper()
            if cmd in ("EHLO", "HELO"):
                w("250 localhost")
            elif cmd == "MAIL":
                mail["from"] = line
                w("250 OK")
            elif cmd == "RCPT":
                mail["rcpt"].append(line)
                w("250 OK")
            elif cmd == "DATA":
                w("354 go ahead")
                data = []
                while (l := self.rfile.readline()) not in (b".\r\n", b".\n", b""):
                    data.append(l)
                mail["data"] = b"".join(data).decode(errors="replace")
                self.server.inbox.append(mail)
                w("250 queued")
            elif cmd == "QUIT":
                w("221 bye")
                return
            else:
                w("250 OK")


def test_email_channel_end_to_end_with_local_smtp(client, monkeypatch):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _SMTPHandler)
    srv.inbox = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        assert client.put("/api/settings", json={"smtp_host": "127.0.0.1"}).status_code in (400, 422)  # guarded
        monkeypatch.setenv("PATCHPILOT_ALLOW_PRIVATE_WEBHOOKS", "1")  # on-prem relay
        assert client.put("/api/settings", json={"smtp_host": "127.0.0.1", "smtp_port": str(port), "smtp_starttls": False,
                                                 "smtp_from": "pp@example.com"}).status_code == 200
        cid = client.post("/api/channels", json={"type": "email", "name": "sec", "config": {"to": "sec@example.com, b@example.com"},
                                                 "events": ["new_findings"]}).json()["id"]
        assert client.post(f"/api/channels/{cid}/test").json()["ok"] is True
        pid = upload(client)
        client.post(f"/api/projects/{pid}/scan")
        assert len(srv.inbox) == 2
        m = srv.inbox[1]
        assert "pp@example.com" in m["from"] and len(m["rcpt"]) == 2
        assert "Subject: [PatchPilot] 1 new finding in shop" in m["data"] and "GHSA-462w-v97r-4m45" in m["data"]
        assert client.get("/api/deliveries").json()[0]["status"] == "ok"
    finally:
        srv.shutdown()
        srv.server_close()


# ---------- 4. sign-in rate limit ----------
@pytest.fixture
def anon(monkeypatch):
    monkeypatch.delenv("PATCHPILOT_TOKEN", raising=False)
    monkeypatch.setattr(server, "_hits", server.collections.defaultdict(server.collections.deque))
    c = TestClient(server.app)
    assert c.post("/api/auth/setup", json={"email": "a@example.com", "name": "A", "password": PW}, headers=CSRF).status_code == 200
    return c


def _login(c, email, pw):
    return c.post("/api/auth/login", json={"email": email, "password": pw}, headers=CSRF).status_code


def test_login_counts_failures_only_and_success_resets(anon):
    for _ in range(12):  # successful sign-ins are never limited
        assert _login(anon, "a@example.com", PW) == 200
    for _ in range(4):
        assert _login(anon, "a@example.com", "wrong-password") == 401
    assert _login(anon, "a@example.com", PW) == 200  # resets this (IP, email) counter
    for _ in range(5):
        assert _login(anon, "a@example.com", "wrong-password") == 401
    assert _login(anon, "a@example.com", "wrong-password") == 429
    assert _login(anon, "a@example.com", PW) == 429  # locked for this email from this IP for the window


def test_login_per_ip_cap_is_looser(anon):
    codes = [_login(anon, f"u{i}@example.com", "wrong-password") for i in range(server.LOGIN_FAILS_PER_IP + 1)]
    assert codes[:server.LOGIN_FAILS_PER_IP] == [401] * server.LOGIN_FAILS_PER_IP and codes[-1] == 429


# ---------- 2 + 5. CLI exit codes, manifest names, unparsable lines ----------
def test_kind_of_requires_requirements_like_names():
    for ok in ("requirements.txt", "requirements-dev.txt", "constraints.txt", "requirements.in", "dev.in",
               "requirements/base.txt", "a/b/Requirements_test.TXT"):
        assert manifests.kind_of(ok) == "requirements", ok
    for bad in ("notes.txt", "LICENSE.txt", "deps.txt", "setup.py", "readme.md"):
        assert manifests.kind_of(bad) is None, bad


def test_unparsable_lines_are_warnings_and_partial_coverage():
    deps, warns = manifests.parse_ex("requirements.txt", "six==1.16.0\nthis is not a requirement\n-r other.txt\njinja2==2.10\n")
    assert [d.name for d in deps] == ["six", "jinja2"]
    assert any("line 2: not a valid requirement" in w for w in warns)
    import patchpilot.intel.sources as s
    orig = s.osv_batch
    try:
        s.osv_batch = lambda pairs: {}
        _, summary = scanner.scan_files([("requirements.txt", "six==1.16.0\n!!! junk\n")])
    finally:
        s.osv_batch = orig
    assert summary["coverage"] == {"state": "partial", "total": 2, "pinned": 1, "checked": 1, "unpinned": 0, "invalid": 1}


@pytest.fixture
def cli_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(config, "NO_DB", False)
    monkeypatch.setattr(sources, "osv_batch", osv_from(lambda n, v: []))
    monkeypatch.setattr(sources, "pypi_missing", lambda names: set())
    return tmp_path


def test_cli_manifest_error_exits_2_unless_allowed(cli_dir, capsys):
    (cli_dir / "requirements.txt").write_text("six==1.16.0\n")
    (cli_dir / "pyproject.toml").write_text("[project\nbroken")
    assert cli.scan_main(["."]) == 2
    assert "scan incomplete" in capsys.readouterr().err
    assert cli.scan_main([".", "--allow-unverified"]) == 0


def test_cli_unverified_exits_2(cli_dir, capsys):
    (cli_dir / "requirements.txt").write_text("six>=1.0\n")  # nothing pinned: nothing checked
    assert cli.scan_main(["requirements.txt"]) == 2
    assert cli.scan_main(["requirements.txt", "--allow-unverified"]) == 0


def test_cli_partial_warns_or_fails(cli_dir, capsys):
    (cli_dir / "requirements.txt").write_text("six==1.16.0\nrequests>=2\n")
    assert cli.scan_main(["requirements.txt"]) == 0
    assert "warning: only 1 of 2 dependencies were checked" in capsys.readouterr().err
    assert cli.scan_main(["requirements.txt", "--fail-on-partial"]) == 2


def test_cli_single_file_name_check(cli_dir, capsys):
    (cli_dir / "notes.txt").write_text("six==1.16.0\n")
    assert cli.scan_main(["notes.txt"]) == 2
    assert "not a recognised manifest name" in capsys.readouterr().err
    (cli_dir / "constraints.txt").write_text("six==1.16.0\n")
    assert cli.scan_main(["constraints.txt"]) == 0


# ---------- 6. fonts + CSP ----------
def test_csp_is_self_only_and_fonts_are_local(client):
    r = client.get("/login")
    csp = r.headers["content-security-policy"]
    assert "googleapis" not in csp and "gstatic" not in csp and "https:" not in csp
    assert "font-src 'self'" in csp and "style-src 'self'" in csp
    for page in ("landing", "login", "projects", "settings", "dashboard", "console", "runs", "org", "how", "setup"):
        html = (config.ROOT / "web" / f"{page}.html").read_text(encoding="utf-8")
        assert "fonts.g" not in html, page
    css = client.get("/static/style.css").text
    for f in re.findall(r'url\("(/static/fonts/[^"]+)"\)', css):
        fr = client.get(f)
        assert fr.status_code == 200 and fr.content[:4] == b"wOF2" and fr.headers["content-type"] == "font/woff2"
    assert len(re.findall(r"@font-face", css)) == 3
    for lic in ("inter", "jetbrains-mono", "archivo"):
        assert "SIL Open Font License" in (config.ROOT / "web" / "fonts" / f"{lic}-OFL.txt").read_text(encoding="utf-8")


# ---------- 7. auto-fix enqueue path with a mocked agent ----------
def test_autofix_enqueues_run_and_notifies_on_completion(client, monkeypatch):
    class FakeAgent:
        def __init__(self, run_id, repo, emit):
            self.run_id, self.repo, self.emit = run_id, repo, emit

        def run(self):
            self.emit({"type": "step", "key": "fix", "status": "ok"})
            self.emit({"type": "done", "ok": True, "attempts": 1})

    monkeypatch.setattr(server, "Agent", FakeAgent)
    monkeypatch.setattr(config, "NEBIUS_API_KEY", "k")
    monkeypatch.delenv("SANDBOX", raising=False)
    got = []
    monkeypatch.setattr(notify, "_send", lambda row, p, did: got.append(p) or (True, 200, None, False))
    webhook(client, events=["fix_completed"])
    pid = db.create_project("demo", "sample", "mailer")
    db.set_policy(pid, "low", True, "t")
    monkeypatch.setattr(sources, "osv_batch", osv_from(lambda n, v: [JINJA | {"fixed": ["99"]}] if n.lower() == "jinja2" else []))
    sid = client.post(f"/api/projects/{pid}/scan").json()["id"]
    assert client.get(f"/api/scans/{sid}").json()["status"] == "done"
    start = [e for e in db.audit_entries() if e["action"] == "autofix.start"]
    assert start, [e for e in db.audit_entries() if e["action"].startswith("autofix")]
    run_id = start[0]["detail"]["run_id"] if isinstance(start[0].get("detail"), dict) else json.loads(start[0]["detail"])["run_id"]
    deadline = time.time() + 10
    while time.time() < deadline and not server.RUNS.get(run_id, {}).get("done"):
        time.sleep(0.05)
    assert server.RUNS[run_id]["done"]
    fix = [s for s in db.list_scans(pid, 5) if s["kind"] == "fix"]
    assert fix and fix[0]["status"] == "done"
    deadline = time.time() + 5
    while time.time() < deadline and not got:
        time.sleep(0.05)
    assert got and got[0]["event"] == "fix_completed" and got[0]["run"]["id"] == run_id and got[0]["run"]["ok"] is True


# ---------- 7. CycloneDX against the key schema requirements ----------
def _check_cyclonedx(doc):
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] in ("1.4", "1.5", "1.6")
    assert re.fullmatch(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", doc["serialNumber"])
    uuid.UUID(doc["serialNumber"][9:])
    assert isinstance(doc.get("version", 1), int) and doc.get("version", 1) >= 1
    refs = set()
    for c in doc["components"]:
        assert c["type"] == "library" and isinstance(c["name"], str) and c["name"]
        assert re.fullmatch(r"pkg:pypi/[a-z0-9._-]+(@[^@\s]+)?", c["purl"]), c["purl"]
        if "version" in c:
            assert isinstance(c["version"], str) and c["purl"].endswith("@" + c["version"])
        assert c["bom-ref"] not in refs
        refs.add(c["bom-ref"])
    vids = set()
    for v in doc.get("vulnerabilities", []):
        assert v["id"] and v["id"] not in vids
        vids.add(v["id"])
        assert v["affects"] and all(a["ref"] in refs for a in v["affects"])
        for r in v.get("ratings", []):
            assert r["severity"] in ("critical", "high", "medium", "low", "info", "none", "unknown")
    return refs


def test_cyclonedx_schema_requirements(client):
    pid = upload(client, "jinja2==2.10\nsix==1.16.0\nrequests>=2\n")
    sid = client.post(f"/api/projects/{pid}/scan").json()["id"]
    doc = client.get(f"/api/scans/{sid}/export?format=cyclonedx").json()
    refs = _check_cyclonedx(doc)
    assert {"pkg:pypi/jinja2@2.10", "pkg:pypi/six@1.16.0", "pkg:pypi/requests"} <= refs
    [v] = doc["vulnerabilities"]
    assert v["affects"] == [{"ref": "pkg:pypi/jinja2@2.10"}] and v["ratings"][0]["severity"] == "high"
