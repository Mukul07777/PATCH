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
def create_project(name, source_type, source, ref=None, manifest=None):
    return _x("INSERT INTO projects (name, source_type, source, ref, manifest, created_at) VALUES (?, ?, ?, ?, ?, ?)",
              (name, source_type, source, ref, manifest, time.time()))


def _counts(scan_id):
    out = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "UNKNOWN": 0}
    for r in _q("SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY severity", (scan_id,)):
        key = (r["severity"] or "UNKNOWN").upper()
        key = "MODERATE" if key == "MEDIUM" else key
        out[key if key in out else "UNKNOWN"] += r["n"]
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
    s["counts"] = _counts(scan_id)
    s["findings"] = [_finding_row(f) for f in _q("SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,))]
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
                "fixed_in, summary, reachable) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(scan_id, project_id, f["package"], f.get("version"), f["vuln_id"], json.dumps(f.get("aliases") or []),
                  f.get("severity"), f.get("cvss"), f.get("epss"), 1 if f.get("kev") else 0, f.get("fixed_in"),
                  f.get("summary"), None if f.get("reachable") is None else int(bool(f["reachable"]))) for f in rows])
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


def stats():
    """Counts for the landing page: open findings = findings in each project's latest finished scan."""
    projects = _q("SELECT COUNT(*) AS n FROM projects")[0]["n"]
    scans = _q("SELECT COUNT(*) AS n FROM scans WHERE kind = 'scan' AND status = 'done'")[0]["n"]
    open_ = _q("""SELECT COUNT(*) AS n FROM findings WHERE scan_id IN (
                    SELECT MAX(id) FROM scans WHERE kind = 'scan' AND status = 'done' GROUP BY project_id)""")[0]["n"]
    return {"projects": projects, "scans": scans, "open_findings": open_}
