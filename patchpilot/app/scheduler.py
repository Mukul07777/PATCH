"""Scheduled re-scans: a background thread wakes every INTERVAL seconds and queues a scan for each project whose
schedule (project_policy.schedule = daily | weekly, at schedule_hour UTC) is due.

Only one process schedules at a time: each tick first takes (or renews) the "scheduler" lease row in SQLite,
so two server processes on the same database never queue the same scheduled scan twice. Due scans go through
the ordinary scan queue (scans.status = 'queued'), so MAX_ACTIVE_SCANS and restart recovery still apply.
"""
import logging
import os
import socket
import threading
import time
import uuid

from patchpilot.app import db
from patchpilot.intel import scanner

log = logging.getLogger(__name__)
LEASE = "scheduler"
TTL = 120.0  # seconds a lease stays valid without renewal (a crashed holder is replaced after this)
INTERVAL = 30.0
HOLDER = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
_stop = threading.Event()
_thread = None


def tick(spawn=None, now=None, holder=HOLDER):
    """Queue every due scheduled scan; returns the new scan ids ([] when another process holds the lease)."""
    now = time.time() if now is None else now
    if not db.acquire_lease(LEASE, holder, TTL, now):
        return []
    created = []
    for row in db.due_schedules(now):
        pid = row["project_id"]
        if db.get_project(pid) is not None and not db.active_scan(pid):
            sid = db.create_scan(pid, "scan", "queued")
            db.audit("scheduler", "scan.scheduled", {"project_id": pid, "scan_id": sid, "schedule": row["schedule"]})
            created.append(sid)
        db.set_next_run(pid, db.next_run(row["schedule"], row["schedule_hour"], now))
    if created and spawn is not None:
        for _ in range(min(len(created), scanner.MAX_ACTIVE_SCANS)):
            scanner.kick(spawn)
    return created


def _loop(spawn, interval):
    while not _stop.wait(interval):
        try:
            tick(spawn)
        except Exception:
            log.exception("scheduler tick failed")


def start(spawn, interval=INTERVAL):
    """Start the scheduler thread once per process (PATCHPILOT_SCHEDULER=0 disables it)."""
    global _thread
    if os.getenv("PATCHPILOT_SCHEDULER", "1") == "0" or (_thread and _thread.is_alive()):
        return None
    _stop.clear()
    try:
        tick(spawn)
    except Exception:
        log.exception("first scheduler tick failed")
    _thread = threading.Thread(target=_loop, args=(spawn, interval), daemon=True, name="pp-scheduler")
    _thread.start()
    return _thread


def stop():
    _stop.set()
    try:
        db.release_lease(LEASE, HOLDER)
    except Exception:
        log.debug("could not release scheduler lease", exc_info=True)
