"""Behaviour lock: record what the project's own functions return on the vulnerable pins, replay after the fix.

Tests only check what someone thought to assert. The lock calls the project's public functions with
representative inputs before the upgrade, keeps the outputs that are stable across two runs, and after the
repair checks every one still comes back identical. Changes are fed back into the repair loop, so "green" means
"behaves the same", not just "the existing asserts pass". Works when a repo has no tests at all.
"""
import json
import re
import time

from . import config

LOCK_CASES = ".patchpilot/behaviour_cases.py"
LOCK_RUNNER = ".patchpilot/behaviour_runner.py"

# fixed harness (ours, not model-written): imports the cases file, calls each, prints normalised results as JSON
RUNNER = r'''
import importlib.util, json, os, pathlib, re, sys
root = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root)); os.chdir(root)
spec = importlib.util.spec_from_file_location("pp_behaviour_cases", sys.argv[1])
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

def norm(v, depth=0):
    if depth > 6:
        return "<deep>"
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, (bytes, bytearray)):
        return {"bytes": bytes(v).decode("latin-1")[:500]}
    if isinstance(v, (list, tuple)):
        return [norm(x, depth + 1) for x in v][:50]
    if isinstance(v, (set, frozenset)):
        return sorted((norm(x, depth + 1) for x in v), key=repr)[:50]
    if isinstance(v, dict):
        return {str(k): norm(x, depth + 1) for k, x in sorted(v.items(), key=lambda kv: str(kv[0]))[:50]}
    return {"type": type(v).__name__, "repr": re.sub(r" at 0x[0-9a-fA-F]+", "", repr(v))[:300]}

out = {}
for name, fn in getattr(mod, "CASES", []):
    try:
        out[str(name)] = {"value": norm(fn())}
    except BaseException as e:
        out[str(name)] = {"raises": type(e).__name__}
print(json.dumps(out, sort_keys=True))
'''

SYSTEM = (
    "You write a BEHAVIOUR LOCK for a Python project about to get a security dependency upgrade. Output ONE Python "
    "file that imports the project's own modules and defines CASES = [(name, zero_arg_callable), ...] with 6-12 "
    "entries. Each callable calls a PUBLIC project function that uses the upgraded library, with realistic inputs, "
    "and returns a deterministic, JSON-friendly observation of its behaviour (e.g. a round-trip result, a decoded "
    "field, a bool, an exception being raised is fine too). Never return timestamps, random values, raw tokens or "
    "signatures that embed time; instead round-trip them (encode then decode and return the claims you set). "
    "Avoid inputs that exercise the security vulnerability itself (that behaviour is meant to change). Cover the "
    "normal path and an error path for each function. Import only the project, the standard library and the "
    "project's existing dependencies; no network, no file writes. Names are short snake_case. "
    "Reply with the file in a single ```python code block and nothing else.")


def extract_cases(text):
    """The largest compilable code block in a reply that defines CASES; None if there isn't one."""
    blocks = re.findall(r"```(?:python|py)?[ \t]*\n(.*?)```", text or "", re.S) or [text or ""]
    for code in sorted(blocks, key=len, reverse=True):
        code = code.strip()
        if not re.search(r"^CASES\s*=", code, re.M):
            continue
        try:
            compile(code, "behaviour_cases.py", "exec")
        except SyntaxError:
            continue
        return code + "\n"
    return None


def compare(locked, now):
    """Per-case verdicts: preserved, changed (with before/after) or missing."""
    rows = []
    for name, before in locked.items():
        after = (now or {}).get(name)
        status = "missing" if after is None else "preserved" if after == before else "changed"
        rows.append({"case": name, "status": status, "before": before, "after": after})
    return rows


def describe(rows):
    """Behaviour regressions as text for the repair prompt."""
    bad = [r for r in rows if r["status"] != "preserved"]
    return "\n".join(f"BEHAVIOUR CHANGED in case {r['case']}: before upgrade returned {json.dumps(r['before'])}, "
                     f"now {json.dumps(r['after'])}" for r in bad)


class BehaviourMixin:
    def _lock_run(self, sandbox):
        d = self.work / ".patchpilot"
        d.mkdir(exist_ok=True)
        (self.work / LOCK_RUNNER).write_text(RUNNER, encoding="utf-8")
        ok, out = sandbox.python(str(self.work / LOCK_RUNNER), str(self.work / LOCK_CASES))
        if not ok:
            raise RuntimeError(out.strip().splitlines()[-1] if out.strip() else "runner failed")
        return json.loads(out.strip().splitlines()[-1])

    def _behaviour_lock(self, findings, files, plan, sandbox):
        """Before the upgrade: Super writes cases, the fixed runner records them twice, unstable cases are dropped."""
        self.step("lock", "running", "Recording behaviour lock on the vulnerable pins")
        if config.DEMO:
            self.log("Demo mode: behaviour lock generation skipped", "lock")
            self.step("lock", "failed")
            return None
        pkgs = {f["package"] for f in findings} | {u["package"] for u in plan.get("upgrades", [])}
        src = {p: t for p, t in files.items() if p.endswith(".py") and not p.startswith(("tests/", ".patchpilot/"))
               and "test" not in p.rsplit("/", 1)[-1]}
        try:
            text = self.router.chat("super", SYSTEM, json.dumps({
                "upgrading": sorted(pkgs), "upgrades": plan.get("upgrades", []),
                "vulnerabilities": [v["summary"] for f in findings for v in f["vulns"]][:8],
                "source_files": src}), "Write behaviour lock", max_tokens=16000)
            code = extract_cases(text) or extract_cases(self.router.last_reasoning)
            if not code:
                raise ValueError("no CASES file in reply")
        except Exception as e:  # the lock is a safety net; never block the fix on it
            self.log(f"Behaviour lock skipped: {e}"[:300], "lock")
            self.step("lock", "failed")
            return None
        if self._guard("behaviour", code)["verdict"] == "block":
            self.log("Behaviour lock skipped: blocked by guard", "lock")
            self.step("lock", "failed")
            return None
        try:
            (self.work / ".patchpilot").mkdir(exist_ok=True)
            (self.work / LOCK_CASES).write_text(code, encoding="utf-8")
            first = self._lock_run(sandbox)
            time.sleep(1.1)  # second sample crosses a clock second, so time-dependent outputs show up as unstable
            second = self._lock_run(sandbox)
        except Exception as e:
            self.log(f"Behaviour lock could not run: {e}"[:300], "lock")
            self.step("lock", "failed")
            return None
        locked = {k: v for k, v in first.items() if second.get(k) == v}
        unstable = sorted(set(first) - set(locked))
        if not locked:
            self.log("Behaviour lock: no stable cases recorded", "lock")
            self.step("lock", "failed")
            return None
        lock = {"code": code, "locked": locked, "unstable": unstable}
        self.log(f"Behaviour lock: {len(locked)} case(s) recorded on the vulnerable pins"
                 + (f", {len(unstable)} unstable dropped" if unstable else ""), "lock")
        self._emit({"type": "behaviour", "stage": "before", "cases": locked, "unstable": unstable, "code": code})
        self.step("lock", "done")
        return lock

    def _behaviour_check(self, lock, sandbox, final=False):
        """Replay the lock on the current code; returns the rows that are not preserved."""
        try:
            rows = compare(lock["locked"], self._lock_run(sandbox))
        except Exception as e:
            rows = [{"case": k, "status": "missing", "before": v, "after": {"runner_error": str(e)[:200]}}
                    for k, v in lock["locked"].items()]
        lock["rows"] = rows
        bad = [r for r in rows if r["status"] != "preserved"]
        if final:
            lock["preserved"] = len(rows) - len(bad)
            self._emit({"type": "behaviour", "stage": "after", "rows": rows,
                        "preserved": lock["preserved"], "changed": len(bad)})
            self.log(f"Behaviour lock: {lock['preserved']}/{len(rows)} case(s) behave exactly as before", "lock")
        return bad
