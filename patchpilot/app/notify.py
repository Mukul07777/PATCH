"""Notification channels: Slack incoming webhooks, signed generic webhooks and SMTP email.

Only findings a scan saw for the first time (finding_status first_seen_scan == that scan) trigger a message, and
each (channel, scan) or (channel, fix run) is delivered at most once: the deliveries table has a unique
(channel_id, dedupe_key) row that is claimed before anything is sent. Failed sends are retried with backoff
(3 attempts) on a background worker pool, never on the scan worker, and every outcome is kept in the delivery
log; pending deliveries survive restarts and a per-channel circuit breaker pauses a failing endpoint.
Destinations are SSRF-checked (netguard). Channel configs (webhook URLs, signing
secrets) are encrypted at rest with the settings key. Payload schema: docs/notifications.md.
"""
import concurrent.futures
import hashlib
import hmac
import json
import logging
import re
import secrets
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage

import httpx

from patchpilot import __version__
from patchpilot.core import config, netguard
from patchpilot.app import db, settings
from patchpilot.intel import scanner

log = logging.getLogger(__name__)

TYPES = ("slack", "webhook", "email")
EVENTS = ("new_findings", "new_critical", "kev", "scan_failed", "fix_completed")
SEVERITIES = ("low", "moderate", "high", "critical")
ATTEMPTS = 3
BACKOFF = (1.0, 4.0)  # seconds slept before the 2nd and 3rd attempt
MAX_LISTED = 50  # findings included in a webhook payload (the rest are counted)
SLACK = re.compile(r"https://hooks\.slack(?:-gov)?\.com/[\w/+-]{10,300}")
URL = re.compile(r"https?://[^\s]{3,500}")
EMAIL = re.compile(r"[^@\s,;]{1,64}@[^@\s,;]{1,190}")
_sleep = time.sleep  # tests replace this


class ChannelError(ValueError):
    pass


# ---------- channel CRUD (validation + encryption) ----------
def _clean_config(type_, cfg, old=None):
    old = old or {}
    cfg = dict(cfg or {})
    if type_ == "slack":
        url = (cfg.get("url") or "").strip() or old.get("url", "")
        if not SLACK.fullmatch(url):
            raise ChannelError("Slack channels need an incoming webhook URL (https://hooks.slack.com/services/...)")
        return {"url": url}
    if type_ == "webhook":
        url = (cfg.get("url") or "").strip() or old.get("url", "")
        if not URL.fullmatch(url):
            raise ChannelError("Webhook channels need an http(s) URL")
        secret = (cfg.get("secret") or "").strip() or old.get("secret") or secrets.token_hex(32)
        if len(secret) < 16 or len(secret) > 200:
            raise ChannelError("The signing secret must be 16 to 200 characters")
        return {"url": url, "secret": secret}
    if type_ == "email":
        to = cfg.get("to") or old.get("to") or []
        if isinstance(to, str):
            to = [t for t in re.split(r"[\s,;]+", to) if t]
        if not to or len(to) > 20 or not all(isinstance(t, str) and EMAIL.fullmatch(t) for t in to):
            raise ChannelError("Email channels need 1 to 20 recipient addresses")
        return {"to": to}
    raise ChannelError("type must be slack, webhook or email")


def save(cid, type_, name, cfg, events, min_severity="low", enabled=True):
    """Create (cid None) or update a channel; blank secret fields keep the stored ones. Returns the id."""
    name = (name or "").strip()
    if not 1 <= len(name) <= 80:
        raise ChannelError("Give the channel a name (up to 80 characters)")
    if type_ not in TYPES:
        raise ChannelError("type must be slack, webhook or email")
    events = sorted(set(events or []))
    if not events or any(e not in EVENTS for e in events):
        raise ChannelError(f"events must be a non-empty subset of {', '.join(EVENTS)}")
    if min_severity not in SEVERITIES:
        raise ChannelError("min_severity must be low, moderate, high or critical")
    old = None
    if cid is not None:
        row = db.get_channel(cid)
        if row is None:
            raise LookupError("Unknown channel")
        old = config_of(row) if row["type"] == type_ else None
    clean = _clean_config(type_, cfg, old)
    _check_destination(type_, clean)
    return db.save_channel(cid, type_, name, settings.encrypt(json.dumps(clean)), events, min_severity, enabled)


def config_of(row):
    raw = settings.decrypt(row["config"])
    return json.loads(raw) if raw else {}


def _mask(url):
    m = re.match(r"(https?://[^/]+)(/.*)?", url or "")
    if not m:
        return None
    path = m.group(2) or ""
    return m.group(1) + (path[:12] + "…" + path[-4:] if len(path) > 20 else path)


def public(row):
    """What the API returns for a channel: never a Slack URL in full nor a signing secret."""
    cfg = config_of(row)
    out = {k: row[k] for k in ("id", "type", "name", "events", "min_severity", "enabled", "created_at", "updated_at")}
    if row["type"] == "slack":
        out["config"] = {"url": _mask(cfg.get("url"))}
    elif row["type"] == "webhook":
        out["config"] = {"url": cfg.get("url"), "secret_set": bool(cfg.get("secret")),
                         "secret_last4": (cfg.get("secret") or "")[-4:] or None}
    else:
        out["config"] = {"to": cfg.get("to") or []}
    out["readable"] = bool(cfg)
    out["health"] = health(row)
    return out


# ---------- payloads ----------
_RANK = {"LOW": 0, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}


def _rank(f):
    s = db.sev_key(f.get("severity"))
    return _RANK.get(s, 0)  # unrated advisories count as low: they still reach channels set to "low"


def _link(path):
    base = config.public_url()
    return base + path if base else None


def _finding(f):
    return {k: f.get(k) for k in ("package", "version", "vuln_id", "aliases", "severity", "cvss_score", "epss", "kev",
                                  "fixed_in", "summary", "source_file")} | {"url": f"https://osv.dev/vulnerability/{f['vuln_id']}"}


def _counts(findings):
    out = {k: 0 for k in db.SEVERITIES}
    for f in findings:
        out[db.sev_key(f.get("severity"))] += 1
    return out


def build_payload(event, project, *, scan=None, findings=(), events=None, error=None, run=None, test=False):
    findings = sorted(findings, key=lambda f: (-_rank(f), -(1 if f.get("kev") else 0), f["package"].lower()))
    p = {"event": event, "events": events or [event], "test": test,
         "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "patchpilot_version": __version__,
         "project": {"id": project["id"], "name": project["name"], "source_type": project["source_type"],
                     "url": _link(f"/projects?id={project['id']}")}}
    if scan is not None:
        p["scan"] = {"id": scan["id"], "status": scan["status"], "url": _link(f"/projects?id={project['id']}&scan={scan['id']}")}
    if event in ("new_findings", "new_critical", "kev"):
        p["counts"] = _counts(findings)
        p["new_findings"] = [_finding(f) for f in findings[:MAX_LISTED]]
        p["truncated"] = len(findings) > MAX_LISTED
    if error:
        p["error"] = error
    if run is not None:
        p["run"] = run
    return p


def _title(p):
    name = p["project"]["name"]
    if p["event"] == "scan_failed":
        return f"Scan failed for {name}"
    if p["event"] == "fix_completed":
        return f"Fix run {'succeeded' if p['run'].get('ok') else 'failed'} for {name}"
    n = sum(p["counts"].values())
    what = {"kev": "known-exploited", "new_critical": "critical"}.get(p["event"], "")
    return f"{n} new {what + ' ' if what else ''}finding{'' if n == 1 else 's'} in {name}".replace("  ", " ")


def _lines(p, limit=5):
    out = []
    for f in p.get("new_findings", [])[:limit]:
        out.append(f"{f['package']} {f.get('version') or ''} - {f['vuln_id']} ({(f.get('severity') or 'unrated').lower()})"
                   + (f", fixed in {f['fixed_in']}" if f.get("fixed_in") else "") + (" [KEV]" if f.get("kev") else ""))
    return out


def slack_body(p):
    title = ("[test] " if p["test"] else "") + _title(p)
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": title[:150]}}]
    if "counts" in p:
        c = p["counts"]
        blocks.append({"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Project*\n{p['project']['name']}"},
            {"type": "mrkdwn", "text": "*New findings*\n" + ", ".join(f"{n} {k.lower()}" for k, n in c.items() if n) or "none"}]})
        top = _lines(p)
        if top:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(f"• `{l}`" for l in top)}})
    if p.get("error"):
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Error*: {p['error'][:500]}"}})
    if p.get("run"):
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
                                                    "text": f"Run `{p['run']['id']}`: {'tests pass' if p['run'].get('ok') else 'not fixed'}"}})
    link = (p.get("run") or {}).get("url") or (p.get("scan") or {}).get("url") or p["project"]["url"]
    if link:
        blocks.append({"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": "Open in PatchPilot"}, "url": link}]})
    return {"text": title, "blocks": blocks}


def sign(secret, timestamp, body):
    """X-PatchPilot-Signature: sha256=HMAC_SHA256(secret, "<timestamp>.<raw body>") as hex."""
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return "sha256=" + mac


def email_message(p, to):
    msg = EmailMessage()
    msg["Subject"] = ("[PatchPilot test] " if p["test"] else "[PatchPilot] ") + _title(p)
    msg["From"] = config.smtp()["from"]
    msg["To"] = ", ".join(to)
    body = [_title(p), ""]
    body += _lines(p, 20)
    if p.get("error"):
        body.append(f"Error: {p['error']}")
    link = (p.get("run") or {}).get("url") or (p.get("scan") or {}).get("url") or p["project"]["url"]
    if link:
        body += ["", link]
    msg.set_content("\n".join(body) + "\n")
    return msg


# ---------- sending ----------
# Delivery is asynchronous: deliver() stores the payload in the deliveries row (status 'pending') and hands the
# id to a small bounded worker pool, so a slow or dead endpoint never holds up a scan worker. Pending rows
# survive a restart (start() requeues and resumes them). Each channel has a circuit breaker: after
# BREAKER_THRESHOLD deliveries in a row fail, the channel is "failing" and its deliveries wait (exponential
# backoff, BREAKER_BASE doubling up to BREAKER_CAP seconds) instead of hammering the endpoint; one success closes it.
WORKERS = 4
MAX_QUEUED = 500  # ids handed to the pool at once; the rest stay pending in SQLite and the sweeper picks them up
SWEEP_INTERVAL = 5.0
BREAKER_THRESHOLD = 3
BREAKER_BASE, BREAKER_CAP = 60.0, 3600.0
UNREACHABLE = "Could not connect (endpoint unreachable)"  # deliberately generic: no error class / blocked reason
_pool = None
_pool_lock = threading.Lock()
_queued = set()
_busy_channels = set()
_stop = threading.Event()
_sweeper = None


def _check_destination(type_, cfg):
    """SSRF guard at save time (and again at connect time, see netguard)."""
    if type_ in ("slack", "webhook"):
        try:
            netguard.check_url(cfg["url"])
        except netguard.Blocked as e:
            raise ChannelError(f"Destination not allowed: {e}") from None


def _send(row, payload, delivery_id):
    """One attempt: (ok, status code or None, error or None, retryable)."""
    cfg = config_of(row)
    if not cfg:
        return False, None, "channel config cannot be decrypted with the current PATCHPILOT_SECRET_KEY", False
    if row["type"] == "email":
        s = config.smtp()
        if not s["host"] or not s["from"]:
            return False, None, "SMTP is not configured (Settings: SMTP host and from address)", False
        try:
            cls = netguard.smtp_class(smtplib.SMTP_SSL if s["port"] == 465 else smtplib.SMTP)
            with cls(s["host"], s["port"], timeout=20) as smtp:
                if s["port"] != 465 and s["starttls"]:
                    smtp.starttls(context=ssl.create_default_context())
                if s["user"]:
                    smtp.login(s["user"], s["password"])
                smtp.send_message(email_message(payload, cfg["to"]))
            return True, 250, None, False
        except netguard.Blocked:
            return False, None, UNREACHABLE, False
        except smtplib.SMTPResponseException as e:
            return False, e.smtp_code, f"SMTP {e.smtp_code}", 400 <= e.smtp_code < 500
        except (smtplib.SMTPException, OSError):
            return False, None, "SMTP server unreachable", True
    if row["type"] == "slack":
        body, headers = json.dumps(slack_body(payload)).encode(), {}
    else:
        body = json.dumps(payload).encode()
        ts = str(int(time.time()))
        headers = {"X-PatchPilot-Event": payload["event"], "X-PatchPilot-Delivery": str(delivery_id),
                   "X-PatchPilot-Timestamp": ts, "X-PatchPilot-Signature": sign(cfg["secret"], ts, body)}
    try:
        with netguard.client(15) as http:
            r = http.post(cfg["url"], content=body, headers={"Content-Type": "application/json",
                                                             "User-Agent": f"PatchPilot/{__version__}", **headers})
    except netguard.Blocked:
        return False, None, UNREACHABLE, False
    except httpx.HTTPError:
        return False, None, UNREACHABLE, True
    if 200 <= r.status_code < 300:
        return True, r.status_code, None, False
    return False, r.status_code, f"HTTP {r.status_code}", r.status_code >= 500 or r.status_code == 429


def _attempts(row, payload, did, attempts):
    ok, code, err, tries = False, None, None, 0
    for i in range(attempts):
        if i:
            _sleep(BACKOFF[min(i - 1, len(BACKOFF) - 1)])
        tries = i + 1
        try:
            ok, code, err, retry = _send(row, payload, did)
        except Exception as e:  # a bug in a sender must not lose the log row
            log.exception("notification send crashed")
            ok, code, err, retry = False, None, f"{type(e).__name__}", False
        if ok or not retry:
            break
    return ok, code, err, tries


def process(did):
    """Send one pending delivery (worker body); returns its status afterwards."""
    try:
        d = db.get_delivery(did)
        if d is None or d["status"] != "pending" or not db.claim_delivery(did):
            return d["status"] if d else "gone"
        row = db.get_channel(d["channel_id"])
        if row is None:
            db.finish_delivery(did, "failed", None, 0, "channel deleted")
            return "failed"
        now = time.time()
        if row.get("open_until") and row["open_until"] > now:  # breaker open: wait instead of sending
            db.defer_delivery(did, row["open_until"])
            return "pending"
        with _pool_lock:
            busy = row["id"] in _busy_channels  # one send per channel at a time: a dead endpoint ties up one worker
            if not busy:
                _busy_channels.add(row["id"])
        if busy:
            db.defer_delivery(did, now + 1.0)
            return "pending"
        try:
            ok, code, err, tries = _attempts(row, json.loads(d["payload"]), did, d["max_attempts"] or ATTEMPTS)
        finally:
            with _pool_lock:
                _busy_channels.discard(row["id"])
        status = "ok" if ok else "failed"
        db.finish_delivery(did, status, code, tries, err)
        if ok:
            db.channel_ok(row["id"])
        else:
            until = db.channel_failed(row["id"], BREAKER_THRESHOLD, time.time(), BREAKER_BASE, BREAKER_CAP)
            if until:
                log.warning("notification channel %s is failing; deliveries paused until %s", row["id"], until)
        return status
    finally:
        with _pool_lock:
            _queued.discard(did)


def _executor():
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = concurrent.futures.ThreadPoolExecutor(WORKERS, thread_name_prefix="pp-notify")
        return _pool


def _pool_submit(did):
    """Hand a delivery id to the worker pool (tests replace _submit with process to run inline); None when the
    id is already queued or the pool is full (the row stays pending and the sweeper submits it later)."""
    with _pool_lock:
        if did in _queued or len(_queued) >= MAX_QUEUED:
            return None
        _queued.add(did)
    try:
        return _executor().submit(process, did)
    except RuntimeError:  # pool shut down
        with _pool_lock:
            _queued.discard(did)
        return None


_submit = _pool_submit


def deliver(row, event, payload, dedupe_key, project_id=None, attempts=ATTEMPTS):
    """Queue a message once per (channel, dedupe_key). Returns 'duplicate', 'queued', or (when _submit runs
    inline, as in tests) the final status."""
    did = db.start_delivery(row["id"], event, dedupe_key, project_id, json.dumps(payload), attempts)
    if did is None:
        return "duplicate"
    res = _submit(did)
    return res if isinstance(res, str) else "queued"


def sweep(now=None):
    """Submit every pending delivery that is due (after a restart, a full pool, or an open breaker)."""
    n = 0
    for did in db.due_deliveries(time.time() if now is None else now):
        if _submit(did) is not None:
            n += 1
    return n


def _loop(interval):
    while not _stop.wait(interval):
        try:
            sweep()
        except Exception:
            log.exception("notification sweep failed")


def start(interval=SWEEP_INTERVAL):
    """Resume deliveries left pending by the last process and keep sweeping (server lifespan)."""
    global _sweeper
    if _sweeper and _sweeper.is_alive():
        return
    _stop.clear()
    try:
        db.requeue_deliveries()
        sweep()
    except Exception:
        log.exception("could not resume pending notifications")
    _sweeper = threading.Thread(target=_loop, args=(interval,), daemon=True, name="pp-notify-sweeper")
    _sweeper.start()


def stop():
    _stop.set()


def health(row):
    """Circuit-breaker state for the UI: ok, or failing (with when deliveries resume)."""
    failures = row.get("failures") or 0
    if failures >= BREAKER_THRESHOLD:
        return {"state": "failing", "failures": failures, "retry_at": row.get("open_until")}
    return {"state": "ok", "failures": failures, "retry_at": None}


def _channels_for(project_id, event):
    pol = db.get_policy(project_id)
    allowed = pol["channels"]  # None = every channel
    return [c for c in db.list_channels() if c["enabled"] and event in c["events"]
            and (allowed is None or c["id"] in allowed)]


def after_scan(scan_id, project_id, ok):
    """Scanner hook: tell each opted-in channel about this scan's new findings, or that it failed."""
    project = db.get_project(project_id)
    if project is None:
        return []
    scan = db.get_scan(scan_id)
    sent = []
    if not ok:
        for c in _channels_for(project_id, "scan_failed"):
            p = build_payload("scan_failed", project, scan=scan, error=(scan.get("summary") or {}).get("error"))
            sent.append((c["id"], deliver(c, "scan_failed", p, f"scan:{scan_id}", project_id)))
        return sent
    new = [f for f in scan["findings"] if f.get("new") and not f.get("suppressed")]
    if not new:
        return sent
    pol = db.get_policy(project_id)
    for c in db.list_channels():
        if not c["enabled"] or (pol["channels"] is not None and c["id"] not in pol["channels"]):
            continue
        floor = SEVERITIES.index(c["min_severity"])
        sel = [f for f in new if _rank(f) >= floor]
        matched = [e for e, hit in (("kev", any(f.get("kev") for f in sel)),
                                    ("new_critical", any(db.sev_key(f.get("severity")) == "CRITICAL" for f in sel)),
                                    ("new_findings", bool(sel))) if hit and e in c["events"]]
        if not matched:
            continue
        event = matched[0]  # the most specific event this channel asked for; one message per scan
        if event == "kev":
            sel_ = [f for f in sel if f.get("kev")]
        elif event == "new_critical":
            sel_ = [f for f in sel if db.sev_key(f.get("severity")) == "CRITICAL"]
        else:
            sel_ = sel
        p = build_payload(event, project, scan=scan, findings=sel_, events=matched)
        sent.append((c["id"], deliver(c, event, p, f"scan:{scan_id}", project_id)))
    return sent


def fix_completed(project_id, run_id, ok, error=None):
    project = db.get_project(project_id) if project_id else None
    if project is None:
        return []
    run = {"id": run_id, "ok": bool(ok), "error": error, "url": _link(f"/console?replay={run_id}")}
    return [(c["id"], deliver(c, "fix_completed", build_payload("fix_completed", project, run=run),
                              f"run:{run_id}", project_id))
            for c in _channels_for(project_id, "fix_completed")]


def send_test(row):
    """A sample new_findings message to one channel: one attempt, sent right away (the admin is waiting), logged
    but not deduplicated. A success closes the channel's circuit breaker."""
    project = {"id": 0, "name": "PatchPilot test", "source_type": "upload"}
    sample = {"package": "jinja2", "version": "2.10", "vuln_id": "GHSA-462w-v97r-4m45", "aliases": ["CVE-2019-10906"],
              "severity": "HIGH", "cvss_score": 8.6, "epss": 0.01, "kev": False, "fixed_in": "2.10.1",
              "summary": "Jinja2 sandbox escape via str.format_map", "source_file": "requirements.txt"}
    p = build_payload("new_findings", project, findings=[sample], test=True)
    p["project"]["url"] = _link("/projects")
    did = db.start_delivery(row["id"], "test", f"test:{secrets.token_hex(8)}", None)
    db.claim_delivery(did)
    ok, code, err, tries = _attempts(row, p, did, 1)
    db.finish_delivery(did, "ok" if ok else "failed", code, tries, err)
    if ok:
        db.channel_ok(row["id"])
    return "ok" if ok else "failed"


if after_scan not in scanner.AFTER_SCAN:
    scanner.AFTER_SCAN.append(after_scan)
