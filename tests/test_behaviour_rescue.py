"""Behaviour lock (record/replay of project calls) and Dependabot PR rescue helpers."""
import json
import subprocess
import sys

import pytest

from patchpilot.agent import behaviour as ab, rescue


def test_extract_cases_picks_compilable_cases_block():
    reply = "notes\n```python\nCASES = [('a', lambda: 1)]\n```\n```python\nCASES = [(\n```"
    assert ab.extract_cases(reply).startswith("CASES = [('a'")
    assert ab.extract_cases("```python\nx = 1\n```") is None


def test_compare_flags_changed_and_missing():
    locked = {"a": {"value": 1}, "b": {"raises": "KeyError"}, "c": {"value": "x"}}
    rows = {r["case"]: r["status"] for r in ab.compare(locked, {"a": {"value": 1}, "b": {"value": None}})}
    assert rows == {"a": "preserved", "b": "changed", "c": "missing"}
    assert "case b" in ab.describe(ab.compare(locked, {"a": {"value": 1}, "b": {"value": None}}))


def test_runner_normalises_values_and_exceptions(tmp_path):
    (tmp_path / "mylib.py").write_text("def f(x):\n    return {'k': x, 'b': b'hi', 's': {2, 1}}\n")
    d = tmp_path / ".patchpilot"
    d.mkdir()
    (d / "behaviour_runner.py").write_text(ab.RUNNER)
    (d / "behaviour_cases.py").write_text("import mylib\nCASES = [('ok', lambda: mylib.f(3)), ('err', lambda: {}['x'])]\n")
    out = subprocess.run([sys.executable, str(d / "behaviour_runner.py"), str(d / "behaviour_cases.py")],
                         capture_output=True, text=True, check=True).stdout
    res = json.loads(out.strip().splitlines()[-1])
    assert res["ok"] == {"value": {"b": {"bytes": "hi"}, "k": 3, "s": [1, 2]}}
    assert res["err"] == {"raises": "KeyError"}


def test_parse_pr_and_bumps():
    assert rescue.parse_pr("https://github.com/o/r/pull/12") == ("o", "r", 12)
    with pytest.raises(ValueError):
        rescue.parse_pr("https://github.com/o/r")
    base = "PyJWT==1.7.1\nrequests==2.25.1 # http\npytest==8.0\n"
    head = "PyJWT==2.10.1\nrequests==2.25.1\npytest==8.0\n"
    assert rescue.bumps(base, head) == [{"package": "PyJWT", "from": "1.7.1", "to": "2.10.1"}]


def test_run_request_accepts_pull_urls():
    from patchpilot.app.server import RunRequest
    assert RunRequest(repo="https://github.com/o/r/pull/7").repo.endswith("/pull/7")
    with pytest.raises(ValueError):
        RunRequest(repo="https://github.com/o/r/pull/x")
