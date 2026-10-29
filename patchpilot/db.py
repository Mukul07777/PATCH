"""SQLite persistence: projects, scans, findings and an audit log.

One shared connection per database path, serialised by a lock (sqlite3 objects are not safe to use from
several threads at once). Schema changes are append-only migrations tracked in schema_version.
"""
import json
import sqlite3
import threading
import time

from . import config

MIGRATIONS = [
    """
    CREATE TABLE projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        source_type TEXT NOT NULL CHECK (source_type IN ('git', 'upload', 'path', 'sample')),
        source TEXT NOT NULL,
        ref TEXT,
        manifest TEXT,
        created_at REAL NOT NULL,
        last_scan_at REAL
    );
    CREATE TABLE scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('scan', 'fix')),
        status TEXT NOT NULL,
        started_at REAL NOT NULL,
        finished_at REAL,
        summary_json TEXT,
        run_id TEXT
    );
    CREATE INDEX scans_project ON scans(project_id, id);
    CREATE INDEX scans_run ON scans(run_id);
    CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
        package TEXT NOT NULL,
        version TEXT,
        vuln_id TEXT NOT NULL,
        aliases TEXT,
        severity TEXT,
        cvss TEXT,
        epss REAL,
        kev INTEGER NOT NULL DEFAULT 0,
        fixed_in TEXT,
        summary TEXT,
        reachable INTEGER
    );
    CREATE INDEX findings_scan ON findings(scan_id);
    CREATE TABLE audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        actor TEXT,
        action TEXT NOT NULL,
        detail TEXT
    );
    """,
    # 2: accounts, encrypted settings, finding lifecycle (new/fixed) and per-project policy
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        name TEXT,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
        created_at REAL NOT NULL
    );
    CREATE TABLE sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at REAL NOT NULL,
        expires_at REAL NOT NULL
    );
    CREATE TABLE api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        prefix TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
        created_at REAL NOT NULL,
        last_used REAL
    );
    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        secret INTEGER NOT NULL DEFAULT 0,
        updated_at REAL NOT NULL,
        updated_by TEXT
    );
    CREATE TABLE finding_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        package TEXT NOT NULL,
        vuln_id TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('open', 'fixed')),
        first_seen_at REAL NOT NULL,
        first_seen_scan INTEGER,
        last_seen_scan INTEGER,
        resolved_at REAL,
        resolved_scan INTEGER,
        UNIQUE (project_id, package, vuln_id)
    );
    CREATE TABLE project_policy (
        project_id INTEGER PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
        severity_threshold TEXT NOT NULL DEFAULT 'low' CHECK (severity_threshold IN ('low', 'moderate', 'high', 'critical')),
        auto_fix INTEGER NOT NULL DEFAULT 0,
        updated_at REAL,
        updated_by TEXT
    );
    CREATE TABLE ignores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        vuln_id TEXT NOT NULL,
        reason TEXT NOT NULL,
        expires_at REAL,
        created_by TEXT,
        created_at REAL NOT NULL
    );
    CREATE INDEX ignores_project ON ignores(project_id)
    """,
    # 3: monorepo sub-folder per project; the manifest each finding came from and its numeric CVSS base score
    """
    ALTER TABLE projects ADD COLUMN subdir TEXT;
    ALTER TABLE findings ADD COLUMN source_file TEXT;
    ALTER TABLE findings ADD COLUMN cvss_score REAL
    """,
    # 4: scheduled re-scans, a lease so only one process schedules, notification channels + delivery log,
    # the manifest line of each finding (SARIF) and a GitHub API response cache (ETags)
    """
    ALTER TABLE project_policy ADD COLUMN schedule TEXT NOT NULL DEFAULT 'off';
    ALTER TABLE project_policy ADD COLUMN schedule_hour INTEGER NOT NULL DEFAULT 3;
    ALTER TABLE project_policy ADD COLUMN next_run_at REAL;
    ALTER TABLE project_policy ADD COLUMN channels TEXT;
    ALTER TABLE findings ADD COLUMN source_line INTEGER;
    CREATE TABLE leases (
        name TEXT PRIMARY KEY,
        holder TEXT NOT NULL,
        expires_at REAL NOT NULL
    );
    CREATE TABLE channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL CHECK (type IN ('slack', 'webhook', 'email')),
        name TEXT NOT NULL,
        config TEXT NOT NULL,
        events TEXT NOT NULL,
        min_severity TEXT NOT NULL DEFAULT 'low',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at REAL NOT NULL,
        updated_at REAL
    );
    CREATE TABLE deliveries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE,
        event TEXT NOT NULL,
        dedupe_key TEXT NOT NULL,
        project_id INTEGER,
        status TEXT NOT NULL,
        response_code INTEGER,
        attempts INTEGER NOT NULL DEFAULT 0,
        error TEXT,
        created_at REAL NOT NULL,
        finished_at REAL,
        UNIQUE (channel_id, dedupe_key)
    );
    CREATE INDEX deliveries_channel ON deliveries(channel_id, id);
    CREATE TABLE gh_cache (
        url TEXT PRIMARY KEY,
        etag TEXT,
        body TEXT NOT NULL,
        fetched_at REAL NOT NULL
    )
    """,
    # 5: asynchronous notification delivery (the payload is kept so a restart resumes pending deliveries) and a
    # per-channel circuit breaker (consecutive failures; deliveries wait until open_until while it is open)
    """
    ALTER TABLE deliveries ADD COLUMN payload TEXT;
    ALTER TABLE deliveries ADD COLUMN max_attempts INTEGER;
    ALTER TABLE deliveries ADD COLUMN next_at REAL;
    ALTER TABLE channels ADD COLUMN failures INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE channels ADD COLUMN open_until REAL;
    CREATE INDEX deliveries_pending ON deliveries(status, next_at)
    """,
]

_lock = threading.RLock()
_conn = None
_conn_path = None


def _connect():
    """The shared connection for config.DB_PATH (reopened if the path changed, e.g. in tests)."""
    global _conn, _conn_path
    path = str(config.DB_PATH)
    if _conn is not None and _conn_path == path:
        return _conn
    close()
    if path != ":memory:":
        config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    _migrate(conn)
    _conn, _conn_path = conn, path
    return conn


def _migrate(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    current = row[0] or 0
    for i, sql in enumerate(MIGRATIONS[current:], start=current + 1):
        conn.execute("BEGIN")
        try:
            for stmt in (s.strip() for s in sql.split(";")):
                if stmt:
                    conn.execute(stmt)
            conn.execute("INSERT INTO schema_version (version) VALUES (?)", (i,))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise


def close():
    global _conn, _conn_path
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn, _conn_path = None, None


def schema_version():
    with _lock:
        return _connect().execute("SELECT MAX(version) FROM schema_version").fetchone()[0]


def _q(sql, args=()):
    with _lock:
        return [dict(r) for r in _connect().execute(sql, args).fetchall()]


def _x(sql, args=()):
    with _lock:
        return _connect().execute(sql, args).lastrowid


# ---------- projects ----------
def create_project(name, source_type, source, ref=None, manifest=None, subdir=None):
    return _x("INSERT INTO projects (name, source_type, source, ref, manifest, created_at, subdir) "
              "VALUES (?, ?, ?, ?, ?, ?, ?)", (name, source_type, source, ref, manifest, time.time(), subdir))


SEVERITIES = ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN")
THRESHOLDS = ("low", "moderate", "high", "critical")
_RANK = {"LOW": 0, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}


def sev_key(s):
    key = (s or "UNKNOWN").upper()
    key = "MODERATE" if key == "MEDIUM" else key
    return key if key in SEVERITIES else "UNKNOWN"


def _empty_counts():
    return {k: 0 for k in SEVERITIES}


def _scan_findings(scan_id, now=None):
    return annotate([_finding_row(f) for f in _q("SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,))],
                    now)


def _counts(scan_id, findings=None):
    """Severity counts of a scan's open findings: suppressed ones (policy threshold / ignore list) are left out."""
    out = _empty_counts()
    for f in _scan_findings(scan_id) if findings is None else findings:
        if not f.get("suppressed"):
            out[sev_key(f["severity"])] += 1
    return out


def _with_last_scan(p):
    p = dict(p)
    p.pop("manifest", None)
    last = _q("SELECT id, status, started_at, finished_at, summary_json FROM scans "
              "WHERE project_id = ? AND kind = 'scan' ORDER BY id DESC LIMIT 1", (p["id"],))
    if last:
        s = last[0]
        s["summary"] = json.loads(s.pop("summary_json") or "null")
        s["counts"] = _counts(s["id"]) if s["status"] == "done" else None
        p["last_scan"] = s
    else:
        p["last_scan"] = None
    return p


def list_projects():
    return [_with_last_scan(p) for p in _q("SELECT * FROM projects ORDER BY id DESC")]


def get_project(pid, with_manifest=False):
    rows = _q("SELECT * FROM projects WHERE id = ?", (pid,))
    if not rows:
        return None
    if with_manifest:
        return rows[0]
    return _with_last_scan(rows[0])


def find_project(source_type, source, ref=None):
    rows = _q("SELECT id FROM projects WHERE source_type = ? AND source = ? AND COALESCE(ref, '') = ?",
              (source_type, source, ref or ""))
    return rows[0]["id"] if rows else None


def delete_project(pid):
    with _lock:
        return _connect().execute("DELETE FROM projects WHERE id = ?", (pid,)).rowcount > 0


# ---------- scans ----------
def create_scan(project_id, kind="scan", status="queued", run_id=None):
    return _x("INSERT INTO scans (project_id, kind, status, started_at, run_id) VALUES (?, ?, ?, ?, ?)",
              (project_id, kind, status, time.time(), run_id))


def update_scan(scan_id, status, summary=None):
    done = status in ("done", "error")
    with _lock:
        _connect().execute(
            "UPDATE scans SET status = ?, summary_json = COALESCE(?, summary_json), finished_at = ? WHERE id = ?",
            (status, json.dumps(summary) if summary is not None else None, time.time() if done else None, scan_id))
        if done:
            _connect().execute("UPDATE projects SET last_scan_at = ? WHERE id = (SELECT project_id FROM scans "
                               "WHERE id = ? AND kind = 'scan')", (time.time(), scan_id))


def finish_run(run_id, ok, summary=None):
    """Close the fix-scan row of an agent run when its done event arrives."""
    with _lock:
        _connect().execute("UPDATE scans SET status = ?, finished_at = ?, summary_json = COALESCE(?, summary_json) "
                           "WHERE run_id = ? AND kind = 'fix'",
                           ("done" if ok else "error", time.time(), json.dumps(summary) if summary else None, run_id))


def active_scan(project_id):
    rows = _q("SELECT id FROM scans WHERE project_id = ? AND kind = 'scan' AND status IN ('queued', 'running')",
              (project_id,))
    return rows[0]["id"] if rows else None


def claim_queued_scan():
    """Atomically move the oldest queued scan-only scan to running; (scan_id, project_id) or None."""
    with _lock:
        conn = _connect()
        row = conn.execute("SELECT id, project_id FROM scans WHERE kind = 'scan' AND status = 'queued' "
                           "ORDER BY id LIMIT 1").fetchone()
        if row is None:
            return None
        conn.execute("UPDATE scans SET status = 'running' WHERE id = ?", (row["id"],))
        return row["id"], row["project_id"]


def requeue_interrupted():
    """After a restart nothing is really running: put running scan-only scans back in the queue."""
    with _lock:
        return _connect().execute("UPDATE scans SET status = 'queued' WHERE kind = 'scan' AND status = 'running'").rowcount


def queued_position(scan_id):
    return _q("SELECT COUNT(*) AS n FROM scans WHERE kind = 'scan' AND status = 'queued' AND id < ?",
              (scan_id,))[0]["n"]


def _scan_row(s):
    s = dict(s)
    s["summary"] = json.loads(s.pop("summary_json") or "null")
    return s


def list_scans(project_id, limit=50):
    out = []
    for s in _q("SELECT * FROM scans WHERE project_id = ? ORDER BY id DESC LIMIT ?", (project_id, limit)):
        s = _scan_row(s)
        s["counts"] = _counts(s["id"]) if s["kind"] == "scan" and s["status"] == "done" else None
        out.append(s)
    return out


def get_scan(scan_id):
    rows = _q("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if not rows:
        return None
    s = _scan_row(rows[0])
    rows = _scan_findings(scan_id)
    if rows and s["project_id"] is not None:
        firsts = {(r["package"], r["vuln_id"]): r["first_seen_scan"] for r in _q(
            "SELECT package, vuln_id, first_seen_scan FROM finding_status WHERE project_id = ?", (s["project_id"],))}
        for f in rows:
            f["new"] = firsts.get((f["package"].lower(), f["vuln_id"])) == scan_id
    s["counts"] = _counts(scan_id, rows)
    s["suppressed"] = sum(1 for f in rows if f.get("suppressed"))
    s["findings"] = rows
    return s


def runs_by_id():
    """run_id -> project_id for agent fix runs linked to a project."""
    return {r["run_id"]: r["project_id"] for r in _q("SELECT run_id, project_id FROM scans WHERE kind = 'fix' AND run_id IS NOT NULL")}


# ---------- findings ----------
def add_findings(scan_id, project_id, rows):
    with _lock:
        conn = _connect()
        conn.execute("BEGIN")
        try:
            conn.executemany(
                "INSERT INTO findings (scan_id, project_id, package, version, vuln_id, aliases, severity, cvss, epss, kev, "
                "fixed_in, summary, reachable, source_file, cvss_score, source_line) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(scan_id, project_id, f["package"], f.get("version"), f["vuln_id"], json.dumps(f.get("aliases") or []),
                  f.get("severity"), f.get("cvss"), f.get("epss"), 1 if f.get("kev") else 0, f.get("fixed_in"),
                  f.get("summary"), None if f.get("reachable") is None else int(bool(f["reachable"])),
                  f.get("source_file"), f.get("cvss_score"), f.get("source_line")) for f in rows])
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise


def _finding_row(f):
    f = dict(f)
    f["aliases"] = json.loads(f["aliases"] or "[]")
    f["kev"] = bool(f["kev"])
    f["reachable"] = None if f["reachable"] is None else bool(f["reachable"])
    return f


# ---------- audit + stats ----------
def audit(actor, action, detail=None):
    _x("INSERT INTO audit_log (ts, actor, action, detail) VALUES (?, ?, ?, ?)",
       (time.time(), actor, action, json.dumps(detail) if detail is not None else None))


def audit_entries(limit=100):
    return _q("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))


def audit_page(page=1, per_page=50):
    total = _q("SELECT COUNT(*) AS n FROM audit_log")[0]["n"]
    rows = _q("SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?", (per_page, (page - 1) * per_page))
    for r in rows:
        try:
            r["detail"] = json.loads(r["detail"]) if r["detail"] else None
        except ValueError:
            pass
    return {"entries": rows, "page": page, "per_page": per_page, "total": total}


def stats():
    """Counts for the landing page: open findings = unsuppressed findings in each project's latest finished scan."""
    projects = _q("SELECT COUNT(*) AS n FROM projects")[0]["n"]
    scans = _q("SELECT COUNT(*) AS n FROM scans WHERE kind = 'scan' AND status = 'done'")[0]["n"]
    open_ = sum(sum(_counts(sid).values()) for sid in _latest_scans().values())
    return {"projects": projects, "scans": scans, "open_findings": open_}


# ---------- settings (secret values arrive here already encrypted) ----------
def get_setting(key):
    rows = _q("SELECT value, secret FROM settings WHERE key = ?", (key,))
    return rows[0] if rows else None


def set_setting(key, value, secret, actor):
    _x("INSERT INTO settings (key, value, secret, updated_at, updated_by) VALUES (?, ?, ?, ?, ?) "
       "ON CONFLICT(key) DO UPDATE SET value = excluded.value, secret = excluded.secret, "
       "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
       (key, value, 1 if secret else 0, time.time(), actor))


def delete_setting(key):
    _x("DELETE FROM settings WHERE key = ?", (key,))


# ---------- finding lifecycle ----------
def track_findings(scan_id, project_id, rows, now=None):
    """Compare a finished scan with the project's known findings: unseen keys open, missing open keys become fixed.

    A finding is keyed by (package, vuln_id), so a version bump that is still vulnerable stays the same open
    finding. A fixed finding that reappears is reopened with a fresh first-seen time. Returns {"new", "fixed"}.
    """
    now = time.time() if now is None else now
    keys = {(f["package"].lower(), f["vuln_id"]) for f in rows}
    new = fixed = 0
    with _lock:
        conn = _connect()
        conn.execute("BEGIN")
        try:
            known = {(r["package"], r["vuln_id"]): r for r in conn.execute(
                "SELECT * FROM finding_status WHERE project_id = ?", (project_id,)).fetchall()}
            for k in keys:
                r = known.get(k)
                if r is None:
                    conn.execute("INSERT INTO finding_status (project_id, package, vuln_id, status, first_seen_at, "
                                 "first_seen_scan, last_seen_scan) VALUES (?, ?, ?, 'open', ?, ?, ?)",
                                 (project_id, k[0], k[1], now, scan_id, scan_id))
                    new += 1
                elif r["status"] == "fixed":
                    conn.execute("UPDATE finding_status SET status = 'open', first_seen_at = ?, first_seen_scan = ?, "
                                 "last_seen_scan = ?, resolved_at = NULL, resolved_scan = NULL WHERE id = ?",
                                 (now, scan_id, scan_id, r["id"]))
                    new += 1
                else:
                    conn.execute("UPDATE finding_status SET last_seen_scan = ? WHERE id = ?", (scan_id, r["id"]))
            for k, r in known.items():
                if k not in keys and r["status"] == "open":
                    conn.execute("UPDATE finding_status SET status = 'fixed', resolved_at = ?, resolved_scan = ? "
                                 "WHERE id = ?", (now, scan_id, r["id"]))
                    fixed += 1
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return {"new": new, "fixed": fixed}


# ---------- policy ----------
SCHEDULES = ("off", "daily", "weekly")


def get_policy(project_id):
    rows = _q("SELECT severity_threshold, auto_fix, schedule, schedule_hour, next_run_at, channels, updated_at, "
              "updated_by FROM project_policy WHERE project_id = ?", (project_id,))
    p = rows[0] if rows else {"severity_threshold": "low", "auto_fix": 0, "schedule": "off", "schedule_hour": 3,
                              "next_run_at": None, "channels": None, "updated_at": None, "updated_by": None}
    p["auto_fix"] = bool(p["auto_fix"])
    p["channels"] = None if p["channels"] is None else json.loads(p["channels"])  # None = every channel
    p["ignores"] = list_ignores(project_id)
    return p


def next_run(schedule, hour, now=None):
    """Next UTC time a schedule fires strictly after `now`: daily at hour:00, weekly on Mondays at hour:00."""
    if schedule not in ("daily", "weekly"):
        return None
    now = time.time() if now is None else now
    t = now - now % 86400 + hour * 3600
    while t <= now or (schedule == "weekly" and time.gmtime(t).tm_wday != 0):
        t += 86400
    return t


def set_policy(project_id, severity_threshold, auto_fix, actor, schedule=None, schedule_hour=None, channels=False,
               now=None):
    """Upsert a project's policy. schedule / schedule_hour left as None (channels: False) keep the stored value;
    changing the schedule recomputes next_run_at. channels None = notify every channel."""
    cur = get_policy(project_id)
    schedule = cur["schedule"] if schedule is None else schedule
    hour = cur["schedule_hour"] if schedule_hour is None else schedule_hour
    chans = cur["channels"] if channels is False else channels
    nxt = cur["next_run_at"]
    if schedule != cur["schedule"] or hour != cur["schedule_hour"] or (schedule != "off" and nxt is None):
        nxt = next_run(schedule, hour, now)
    _x("INSERT INTO project_policy (project_id, severity_threshold, auto_fix, schedule, schedule_hour, next_run_at, "
       "channels, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(project_id) DO UPDATE SET "
       "severity_threshold = excluded.severity_threshold, auto_fix = excluded.auto_fix, schedule = excluded.schedule, "
       "schedule_hour = excluded.schedule_hour, next_run_at = excluded.next_run_at, channels = excluded.channels, "
       "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
       (project_id, severity_threshold, 1 if auto_fix else 0, schedule, hour, nxt,
        None if chans is None else json.dumps(sorted(set(chans))), time.time(), actor))


def due_schedules(now):
    return _q("SELECT project_id, schedule, schedule_hour FROM project_policy WHERE schedule != 'off' "
              "AND next_run_at IS NOT NULL AND next_run_at <= ? ORDER BY next_run_at", (now,))


def set_next_run(project_id, t):
    _x("UPDATE project_policy SET next_run_at = ? WHERE project_id = ?", (t, project_id))


def new_findings(scan_id):
    """Findings of a scan whose (package, vuln) was first seen (or reopened) by that scan, policy-annotated."""
    s = get_scan(scan_id)
    return [f for f in (s or {}).get("findings", []) if f.get("new")]


# ---------- lease (one scheduler across processes) ----------
def acquire_lease(name, holder, ttl, now=None):
    """Take or renew lease `name` for `holder` unless another holder's lease is still live. True when held."""
    now = time.time() if now is None else now
    with _lock:
        conn = _connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute("SELECT holder, expires_at FROM leases WHERE name = ?", (name,)).fetchone()
            if row and row["holder"] != holder and row["expires_at"] > now:
                conn.execute("COMMIT")
                return False
            conn.execute("INSERT INTO leases (name, holder, expires_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE "
                         "SET holder = excluded.holder, expires_at = excluded.expires_at", (name, holder, now + ttl))
            conn.execute("COMMIT")
            return True
        except Exception:
            conn.execute("ROLLBACK")
            raise


def release_lease(name, holder):
    _x("DELETE FROM leases WHERE name = ? AND holder = ?", (name, holder))


# ---------- notification channels + delivery log (channel config arrives already encrypted) ----------
def _channel_row(r):
    r = dict(r)
    r["events"] = json.loads(r["events"])
    r["enabled"] = bool(r["enabled"])
    return r


def list_channels():
    return [_channel_row(r) for r in _q("SELECT * FROM channels ORDER BY id")]


def get_channel(cid):
    rows = _q("SELECT * FROM channels WHERE id = ?", (cid,))
    return _channel_row(rows[0]) if rows else None


def save_channel(cid, type_, name, config_enc, events, min_severity, enabled):
    if cid is None:
        return _x("INSERT INTO channels (type, name, config, events, min_severity, enabled, created_at) "
                  "VALUES (?, ?, ?, ?, ?, ?, ?)", (type_, name, config_enc, json.dumps(events), min_severity,
                                                   1 if enabled else 0, time.time()))
    _x("UPDATE channels SET type = ?, name = ?, config = ?, events = ?, min_severity = ?, enabled = ?, updated_at = ? "
       "WHERE id = ?", (type_, name, config_enc, json.dumps(events), min_severity, 1 if enabled else 0, time.time(), cid))
    return cid


def delete_channel(cid):
    with _lock:
        return _connect().execute("DELETE FROM channels WHERE id = ?", (cid,)).rowcount > 0


def start_delivery(channel_id, event, dedupe_key, project_id, payload=None, max_attempts=None):
    """Claim a delivery; None when this (channel, dedupe_key) was already sent or is in flight (dedupe)."""
    with _lock:
        cur = _connect().execute(
            "INSERT OR IGNORE INTO deliveries (channel_id, event, dedupe_key, project_id, status, created_at, payload, "
            "max_attempts) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)",
            (channel_id, event, dedupe_key, project_id, time.time(), payload, max_attempts))
        return cur.lastrowid if cur.rowcount else None


def get_delivery(did):
    rows = _q("SELECT * FROM deliveries WHERE id = ?", (did,))
    return rows[0] if rows else None


def claim_delivery(did):
    """pending -> sending; False if another worker (or process) already has it."""
    with _lock:
        return _connect().execute("UPDATE deliveries SET status = 'sending' WHERE id = ? AND status = 'pending'",
                                  (did,)).rowcount > 0


def defer_delivery(did, until):
    _x("UPDATE deliveries SET status = 'pending', next_at = ? WHERE id = ?", (until, did))


def due_deliveries(now, limit=200):
    """Pending deliveries whose wait is over, or whose channel's breaker has closed since they were deferred."""
    return [r["id"] for r in _q(
        "SELECT d.id FROM deliveries d JOIN channels c ON c.id = d.channel_id WHERE d.status = 'pending' "
        "AND d.payload IS NOT NULL AND (d.next_at IS NULL OR d.next_at <= ? OR c.open_until IS NULL OR c.open_until <= ?) "
        "ORDER BY d.id LIMIT ?", (now, now, limit))]


def requeue_deliveries():
    """Deliveries that were being sent when the process stopped go back to pending."""
    with _lock:
        return _connect().execute("UPDATE deliveries SET status = 'pending' WHERE status = 'sending'").rowcount


def channel_failed(cid, threshold, now, base, cap):
    """Count one more consecutive failure; opens the breaker (returns open_until) at `threshold`."""
    with _lock:
        c = _connect()
        c.execute("UPDATE channels SET failures = failures + 1 WHERE id = ?", (cid,))
        row = c.execute("SELECT failures FROM channels WHERE id = ?", (cid,)).fetchone()
        if row is None or row[0] < threshold:
            return None
        until = now + min(cap, base * 2 ** (row[0] - threshold))
        c.execute("UPDATE channels SET open_until = ? WHERE id = ?", (until, cid))
        return until


def channel_ok(cid):
    _x("UPDATE channels SET failures = 0, open_until = NULL WHERE id = ?", (cid,))


def finish_delivery(did, status, code, attempts, error=None):
    _x("UPDATE deliveries SET status = ?, response_code = ?, attempts = ?, error = ?, finished_at = ? WHERE id = ?",
       (status, code, attempts, str(error)[:300] if error else None, time.time(), did))


def list_deliveries(channel_id=None, limit=50):
    where, args = ("WHERE d.channel_id = ? ", (channel_id, limit)) if channel_id else ("", (limit,))
    return _q("SELECT d.id, d.channel_id, d.event, d.dedupe_key, d.project_id, d.status, d.response_code, d.attempts, "
              "d.error, d.created_at, d.finished_at, d.next_at, c.name AS channel "
              "FROM deliveries d LEFT JOIN channels c ON c.id = d.channel_id "
              f"{where}ORDER BY d.id DESC LIMIT ?", args)


# ---------- GitHub API response cache ----------
def gh_cache_get(url):
    rows = _q("SELECT etag, body FROM gh_cache WHERE url = ?", (url,))
    return rows[0] if rows else None


def gh_cache_put(url, etag, body):
    _x("INSERT INTO gh_cache (url, etag, body, fetched_at) VALUES (?, ?, ?, ?) ON CONFLICT(url) DO UPDATE SET "
       "etag = excluded.etag, body = excluded.body, fetched_at = excluded.fetched_at", (url, etag, body, time.time()))


def list_ignores(project_id):
    now = time.time()
    rows = _q("SELECT * FROM ignores WHERE project_id = ? ORDER BY id DESC", (project_id,))
    for r in rows:
        r["active"] = r["expires_at"] is None or r["expires_at"] > now
    return rows


def add_ignore(project_id, vuln_id, reason, expires_at, actor):
    return _x("INSERT INTO ignores (project_id, vuln_id, reason, expires_at, created_by, created_at) "
              "VALUES (?, ?, ?, ?, ?, ?)", (project_id, vuln_id, reason, expires_at, actor, time.time()))


def delete_ignore(project_id, ignore_id):
    with _lock:
        return _connect().execute("DELETE FROM ignores WHERE id = ? AND project_id = ?",
                                  (ignore_id, project_id)).rowcount > 0


def annotate(findings, now=None):
    """Set f["suppressed"] to a reason string (or None) from each finding's project policy.

    Suppressed = matched by an unexpired ignore entry (on the advisory id or any alias), or rated below the
    project's severity threshold. Unrated findings are never hidden by the threshold: their severity is unknown.
    """
    now = time.time() if now is None else now
    pols = {}
    for f in findings:
        pid = f.get("project_id")
        if pid not in pols:
            pol = _q("SELECT severity_threshold FROM project_policy WHERE project_id = ?", (pid,))
            ign = {r["vuln_id"].upper(): r["reason"] for r in _q(
                "SELECT vuln_id, reason FROM ignores WHERE project_id = ? AND (expires_at IS NULL OR expires_at > ?) "
                "ORDER BY id DESC", (pid, now))}
            pols[pid] = (THRESHOLDS.index(pol[0]["severity_threshold"]) if pol else 0, ign)
        threshold, ign = pols[pid]
        hit = next((i for i in [f["vuln_id"], *(f.get("aliases") or [])] if i.upper() in ign), None)
        sev = sev_key(f.get("severity"))
        if hit:
            f["suppressed"] = f"ignored: {ign[hit.upper()]}"
        elif sev in _RANK and _RANK[sev] < threshold:
            f["suppressed"] = f"below {THRESHOLDS[threshold]} threshold"
        else:
            f["suppressed"] = None
    return findings


# ---------- dashboard ----------
def _latest_scans(project_ids=None):
    """project_id -> id of its latest finished scan-only scan."""
    rows = _q("SELECT project_id, MAX(id) AS sid FROM scans WHERE kind = 'scan' AND status = 'done' "
              "AND project_id IS NOT NULL GROUP BY project_id")
    return {r["project_id"]: r["sid"] for r in rows if project_ids is None or r["project_id"] in project_ids}


def coverage_state(summary):
    """verified | partial | unverified for a finished scan's summary (older scans without coverage: verified
    when everything was pinned, else partial / unverified from the pinned count)."""
    cov = (summary or {}).get("coverage")
    if cov and cov.get("state"):
        return cov["state"]
    s = summary or {}
    pinned, total = s.get("pinned") or 0, s.get("dependencies") or 0
    return "unverified" if not pinned else "verified" if pinned >= total else "partial"


def _day(t):
    return time.strftime("%Y-%m-%d", time.gmtime(t))


def dashboard(project_ids=None, days=30, now=None):
    """Everything the dashboard shows, computed from stored scans only (no network calls).

    Open findings are the unsuppressed findings of each project's latest finished scan.
    """
    now = time.time() if now is None else now
    projects = {p["id"]: p for p in _q("SELECT id, name FROM projects")
                if project_ids is None or p["id"] in project_ids}
    latest = _latest_scans(set(projects))
    by_sev, kev, suppressed = _empty_counts(), 0, 0
    at_risk, packages, unverified, clean = [], {}, [], 0
    marks_l = ",".join("?" * len(latest)) or "NULL"
    summaries = {r["id"]: json.loads(r["summary_json"] or "null") for r in _q(
        f"SELECT id, summary_json FROM scans WHERE id IN ({marks_l})", tuple(latest.values()))}
    for pid, sid in latest.items():
        state = coverage_state(summaries.get(sid))
        if state != "verified":
            cov = (summaries.get(sid) or {}).get("coverage") or {}
            unverified.append({"id": pid, "name": projects[pid]["name"], "state": state,
                               "checked": cov.get("checked"), "total": cov.get("total")})
        counts, pkev = _empty_counts(), 0
        for f in _scan_findings(sid, now):
            if f["suppressed"]:
                suppressed += 1
                continue
            k = sev_key(f["severity"])
            counts[k] += 1
            pkev += f["kev"]
            pk = packages.setdefault(f["package"].lower(), {"package": f["package"], "findings": 0, "projects": set(),
                                                            "kev": 0, "worst": "UNKNOWN"})
            pk["findings"] += 1
            pk["kev"] += f["kev"]
            pk["projects"].add(pid)
            if SEVERITIES.index(k) < SEVERITIES.index(pk["worst"]):
                pk["worst"] = k
        for k, n in counts.items():
            by_sev[k] += n
        kev += pkev
        total = sum(counts.values())
        if not total and state == "verified":
            clean += 1
        if total:
            score = 10 * counts["CRITICAL"] + 5 * counts["HIGH"] + 2 * counts["MODERATE"] + counts["LOW"] + 10 * pkev
            at_risk.append({"id": pid, "name": projects[pid]["name"], "counts": counts, "total": total, "kev": pkev,
                            "score": score})
    at_risk.sort(key=lambda r: (-r["score"], r["name"]))
    top = sorted(packages.values(), key=lambda p: (-p["findings"], -p["kev"], p["package"].lower()))[:10]
    for p in top:
        p["projects"] = len(p["projects"])

    # trend: open findings per UTC day = sum over projects of their latest scan finished by the end of that day
    scans = [s for s in _q("SELECT id, project_id, finished_at FROM scans WHERE kind = 'scan' AND status = 'done' "
                           "AND finished_at IS NOT NULL ORDER BY finished_at") if s["project_id"] in projects]
    trend = []
    if scans:
        first = max(scans[0]["finished_at"], now - (days - 1) * 86400)
        d = first - first % 86400  # UTC midnight
        state, i, open_of = {}, 0, {}
        while d <= now:
            end = d + 86400
            while i < len(scans) and scans[i]["finished_at"] < end:
                sid = scans[i]["id"]
                if sid not in open_of:
                    open_of[sid] = sum(_counts(sid).values())
                state[scans[i]["project_id"]] = open_of[sid]
                i += 1
            trend.append({"day": _day(d), "open": sum(state.values())})
            d = end

    ids = tuple(projects) or (-1,)
    marks = ",".join("?" * len(ids))
    fixed = _q(f"SELECT first_seen_at, resolved_at FROM finding_status WHERE status = 'fixed' "
               f"AND project_id IN ({marks})", ids)
    week = now - 7 * 86400
    new7 = _q(f"SELECT COUNT(*) AS n FROM finding_status WHERE first_seen_at >= ? AND project_id IN ({marks})",
              (week, *ids))[0]["n"]
    mttr = sum(r["resolved_at"] - r["first_seen_at"] for r in fixed) / len(fixed) if fixed else None
    unverified.sort(key=lambda r: r["name"].lower())
    return {"projects": len(projects), "scanned": len(latest), "open": sum(by_sev.values()), "by_severity": by_sev,
            "clean": clean, "unverified": unverified,
            "kev": kev, "suppressed": suppressed, "at_risk": at_risk[:10], "top_packages": top, "trend": trend,
            "mttr_seconds": mttr, "fixed_total": len(fixed), "new_7d": new7,
            "fixed_7d": sum(1 for r in fixed if r["resolved_at"] >= week)}
