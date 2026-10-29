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
def get_policy(project_id):
    rows = _q("SELECT severity_threshold, auto_fix, updated_at, updated_by FROM project_policy WHERE project_id = ?",
              (project_id,))
    p = rows[0] if rows else {"severity_threshold": "low", "auto_fix": 0, "updated_at": None, "updated_by": None}
    p["auto_fix"] = bool(p["auto_fix"])
    p["ignores"] = list_ignores(project_id)
    return p


def set_policy(project_id, severity_threshold, auto_fix, actor):
    _x("INSERT INTO project_policy (project_id, severity_threshold, auto_fix, updated_at, updated_by) "
       "VALUES (?, ?, ?, ?, ?) ON CONFLICT(project_id) DO UPDATE SET severity_threshold = excluded.severity_threshold, "
       "auto_fix = excluded.auto_fix, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
       (project_id, severity_threshold, 1 if auto_fix else 0, time.time(), actor))


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
    at_risk, packages = [], {}
    for pid, sid in latest.items():
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
    return {"projects": len(projects), "scanned": len(latest), "open": sum(by_sev.values()), "by_severity": by_sev,
            "kev": kev, "suppressed": suppressed, "at_risk": at_risk[:10], "top_packages": top, "trend": trend,
            "mttr_seconds": mttr, "fixed_total": len(fixed), "new_7d": new7,
            "fixed_7d": sum(1 for r in fixed if r["resolved_at"] >= week)}
