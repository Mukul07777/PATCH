import json
import subprocess
import sys

from patchpilot import drift

SRC = """import requests as rq
import jwt
from jinja2 import Markup
from urllib3.util import Retry as R

def f(tok):
    jwt.decode(tok, "k", algorithms=["HS256"], verify=False)
    rq.get("http://x", timeout=3)
    r = R(total=3, method_whitelist=["GET"])
    return Markup("x"), rq.adapters.HTTPAdapter
"""


def test_usages_imports_aliases_and_kwargs():
    u = drift.usages({"app/main.py": SRC})
    assert u["jwt.decode"]["kwargs"] == ["algorithms", "verify"]
    assert u["jwt.decode"]["sites"] == ["app/main.py:7"]
    assert u["requests.get"]["kwargs"] == ["timeout"]  # alias resolved
    assert "app/main.py:3" in u["jinja2.Markup"]["sites"]  # from-import site
    assert u["urllib3.util.Retry"]["kwargs"] == ["method_whitelist", "total"]  # from-import alias
    assert "requests.adapters.HTTPAdapter" in u  # attribute chain


def test_usages_skips_tests_non_python_and_bad_syntax():
    u = drift.usages({"tests/test_x.py": "import jwt\njwt.decode(1)\n", "README.md": "import jwt",
                      "bad.py": "def (:"})
    assert u == {}


def test_diff_removed_dropped_kwarg_unchanged():
    usage = {"a.X": {"kwargs": [], "sites": ["m.py:1"]}, "a.f": {"kwargs": ["k"], "sites": ["m.py:2"]},
             "a.g": {"kwargs": [], "sites": []}}
    ok = {"exists": True, "missing_kwargs": []}
    old = {"a.X": ok, "a.f": ok, "a.g": ok}
    new = {"a.X": {"exists": False, "missing_kwargs": []}, "a.f": {"exists": True, "missing_kwargs": ["k"]},
           "a.g": ok}
    b = {x["symbol"]: x for x in drift.diff(usage, old, new)}
    assert b["a.X"]["kind"] == "removed" and b["a.X"]["sites"] == ["m.py:1"]
    assert b["a.f"]["kind"] == "signature" and "k=" in b["a.f"]["detail"]
    assert "a.g" not in b
    assert drift.diff(usage, old, old) == []


def _probe(tmp_path, usage, wanted):
    (tmp_path / "u.json").write_text(json.dumps(usage), encoding="utf-8")
    (tmp_path / "probe.py").write_text(drift.PROBE, encoding="utf-8")
    out = subprocess.run([sys.executable, str(tmp_path / "probe.py"), str(tmp_path / "u.json"), json.dumps(wanted)],
                         capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_probe_skips_symbols_without_a_wanted_distribution(tmp_path):
    # json is stdlib: no distribution owns it, so the probe ignores it entirely
    assert _probe(tmp_path, {"json.dumps": {"kwargs": ["indent", "nonexistent"]}}, []) == {}


def test_probe_checks_installed_distribution(tmp_path):
    usage = {"pytest.raises": {"kwargs": ["match"]}, "pytest.no_such_thing": {"kwargs": []}}
    out = _probe(tmp_path, usage, ["pytest"])
    assert out["pytest.no_such_thing"]["exists"] is False
    assert out["pytest.raises"]["exists"] is True
