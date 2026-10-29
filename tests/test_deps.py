from datetime import datetime, timezone
from pathlib import Path

from patchpilot import deps
from patchpilot.agent import Agent

ERR = ("sanitizer/comments.py:3: in <module>\n    from bleach.css_sanitizer import CSSSanitizer\n"
       "E   ModuleNotFoundError: No module named 'tinycss2'\n")


def test_detect_module_not_found():
    assert deps.detect_missing(ERR) == ["tinycss2"]


def test_detect_import_error_submodule_and_dedupe():
    out = "ImportError: No module named yaml\nNo module named 'yaml.cyaml'\nNo module named \"PIL.Image\""
    assert deps.detect_missing(out.replace("named yaml", "named 'yaml'")) == ["yaml", "PIL"]


def test_detect_warning_hint_and_local_modules_ignored():
    assert deps.detect_missing("bleach.sanitizer.NoCssSanitizerWarning: 'style' attribute specified") == ["tinycss2"]
    assert deps.detect_missing("No module named 'sanitizer'", local_modules=["sanitizer"]) == []
    assert deps.detect_missing("4 failed, 1 passed") == []


def test_dist_mapping_and_hints():
    assert deps.dist_for("yaml") == "PyYAML" and deps.dist_for("tinycss2") == "tinycss2"
    h = deps.hints(["tinycss2"])[0]
    assert h["via_extra"] == "bleach[css]" and "requirements.txt" in h["advice"] and "removing" in h["advice"]


OLD = "2015-01-01T00:00:00Z"
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _pypi(releases):
    return {"releases": {v: [{"upload_time_iso_8601": t, "yanked": y, "requires_python": rp}]
                         for v, (t, y, rp) in releases.items()}}


def test_resolve_only_existing_packages():
    def lookup(d):
        if d == "tinycss2":
            return _pypi({"1.4.0": (OLD, False, ">=3.8")})
        raise RuntimeError("404")
    assert deps.resolve("tinycss2", lookup, now=NOW) == ("tinycss2", "1.4.0", None)
    _, v, reason = deps.resolve("nonexistent_pkg_xyz", lookup, original_imports={"nonexistent_pkg_xyz"}, now=NOW)
    assert v is None and "no PyPI package" in reason


def test_hallucinated_module_is_hint_only():
    calls = []
    lookup = lambda d: calls.append(d) or _pypi({"1.0": (OLD, False, None)})
    _, v, reason = deps.resolve("totally_real_helper", lookup, original_imports={"requests"}, now=NOW)
    assert v is None and "not imported" in reason and calls == []  # never even queried PyPI
    assert deps.resolve("totally_real_helper", lookup, original_imports={"totally_real_helper"}, now=NOW)[1] == "1.0"


def test_stdlib_private_and_dotted_names_skipped():
    out = "No module named 'json'\nNo module named '_sqlite3'\nNo module named 'a.b'"
    assert deps.detect_missing(out) == ["a"]
    assert deps.resolve("_sqlite3", lambda d: {}, original_imports={"_sqlite3"})[1] is None
    assert deps.resolve("json", lambda d: {}, original_imports={"json"})[2].startswith("standard-library")


def test_invalid_dist_name_rejected():
    assert deps.resolve("bad name!", lambda d: {}, original_imports={"bad name!"})[2] == "invalid distribution name"


def test_young_or_empty_package_rejected():
    young = _pypi({"0.1": ("2026-09-15T00:00:00Z", False, None)})
    _, v, reason = deps.resolve("newpkg", lambda d: young, original_imports={"newpkg"}, now=NOW)
    assert v is None and "younger than 90 days" in reason
    assert deps.pick_release({"releases": {}}, now=NOW) == (None, "no releases on PyPI")


def test_yanked_prerelease_and_python_mismatch_skipped():
    data = _pypi({"3.0": (OLD, True, None), "2.5rc1": (OLD, False, None),
                  "2.1": (OLD, False, ">=3.99"), "2.0": (OLD, False, ">=3.8"), "1.0": (OLD, False, None)})
    assert deps.pick_release(data, py=(3, 12, 0), now=NOW) == ("2.0", None)
    assert deps.pick_release(_pypi({"1.0": (OLD, True, None)}), now=NOW)[0] is None


def test_python_ok_specs():
    assert deps.python_ok(">=3.8, <4", (3, 12, 1)) and not deps.python_ok(">=3.13", (3, 12, 1))
    assert deps.python_ok("", (3, 12, 1)) and deps.python_ok(None, (3, 12, 1))


def test_top_level_imports():
    files = {"a.py": "import os, yaml.cyaml\nfrom bleach.css import X\nfrom . import local", "b.txt": "import nope",
             "bad.py": "def ("}
    assert deps.top_level_imports(files) == {"os", "yaml", "bleach"}


def test_add_requirements_idempotent(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("bleach==6.0.0\nPyYAML==6.0  # cfg\npytest==8.3.3")
    assert deps.add_requirements(req, [("tinycss2", "1.4.0"), ("pyyaml", "6.0.2")]) == [("tinycss2", "1.4.0")]
    assert req.read_text().endswith("pytest==8.3.3\ntinycss2==1.4.0\n")
    assert deps.add_requirements(req, [("tinycss2", "1.4.0")]) == []


class FakeSandbox:
    def __init__(self, install_ok=True, revert_ok=True):
        self.installs, self.install_ok, self.revert_ok = 0, install_ok, revert_ok

    def install(self):
        self.installs += 1
        return (self.install_ok if self.installs == 1 else self.revert_ok), "boom"

    def test(self):
        return True, "5 passed", "ok"


def _agent(tmp_path, monkeypatch):
    a = Agent.__new__(Agent)
    a.work, a.evidence, a.dep_hints, a.deps_added, a.events = Path(tmp_path), [], [], [], []
    a._emit = a.events.append
    a.log = lambda *x, **k: None
    (tmp_path / "requirements.txt").write_text("bleach==6.0.0\n")
    (tmp_path / "sanitizer").mkdir()
    a.original_imports = {"bleach"}
    monkeypatch.setattr(deps, "resolve", lambda m, **k: ("tinycss2", "1.4.0", None))
    return a


def test_dep_repair_adds_pin_and_retests(tmp_path, monkeypatch):
    a = _agent(tmp_path, monkeypatch)
    ok, summary, _ = a._dep_repair(ERR, FakeSandbox(), False, "1 error")
    assert ok and summary == "5 passed"
    assert "tinycss2==1.4.0" in (tmp_path / "requirements.txt").read_text()
    assert a.deps_added == [{"package": "tinycss2", "version": "1.4.0"}]
    assert any(e["type"] == "deps" for e in a.events) and a.evidence and a.dep_hints


def test_dep_repair_reverts_on_install_failure(tmp_path, monkeypatch):
    a = _agent(tmp_path, monkeypatch)
    ok, _, _ = a._dep_repair(ERR, FakeSandbox(install_ok=False), False, "1 error")
    assert not ok and (tmp_path / "requirements.txt").read_text() == "bleach==6.0.0\n" and not a.deps_added
    assert a.dep_hints  # the model still gets the hint


def test_dep_repair_skips_already_required(tmp_path, monkeypatch):
    a = _agent(tmp_path, monkeypatch)
    (tmp_path / "requirements.txt").write_text("bleach==6.0.0\ntinycss2==1.4.0\n")
    sb = FakeSandbox()
    assert a._dep_repair(ERR, sb, False, "x")[0] is False and sb.installs == 0


def test_fix_prompt_allows_requirements():
    import inspect
    src = inspect.getsource(Agent._fix)
    assert "MAY edit requirements.txt" in src and "dependency_hints" in src


def test_dep_repair_revert_reinstall_failure_stops(tmp_path, monkeypatch):
    a = _agent(tmp_path, monkeypatch)
    sb = FakeSandbox(install_ok=False, revert_ok=False)
    ok, _, _ = a._dep_repair(ERR, sb, False, "1 error")
    assert not ok and sb.installs == 2 and (tmp_path / "requirements.txt").read_text() == "bleach==6.0.0\n"
    assert any(e["type"] == "error" and "dependency repair stopped" in e["msg"] for e in a.events)
    assert a._dep_repair(ERR, sb, False, "1 error")[0] is False and sb.installs == 2  # no further attempts


def test_dep_repair_hallucinated_module_hint_only(tmp_path, monkeypatch):
    a = _agent(tmp_path, monkeypatch)
    monkeypatch.undo()
    monkeypatch.setattr(deps.sources, "pypi_json", lambda d: (_ for _ in ()).throw(AssertionError("queried")))
    sb = FakeSandbox()
    ok, _, _ = a._dep_repair("E   ModuleNotFoundError: No module named 'fancy_sanitize'", sb, False, "1 error")
    assert not ok and sb.installs == 0 and not a.deps_added
    assert a.dep_hints[0]["missing_module"] == "fancy_sanitize"


def test_dep_repair_without_requirements_file_reverts_by_removing(tmp_path, monkeypatch):
    a = _agent(tmp_path, monkeypatch)
    (tmp_path / "requirements.txt").unlink()
    ok, _, _ = a._dep_repair(ERR, FakeSandbox(install_ok=False), False, "1 error")
    assert not ok and not (tmp_path / "requirements.txt").exists() and not a.deps_added


def test_local_modules_include_src_layout_and_packages(tmp_path):
    a = Agent.__new__(Agent)
    a.work = Path(tmp_path)
    for d in ("src/mylib/core", "pkgs/helpers", ".venv/lib/site-packages/requests", "venv/lib/bleach", ".hidden/x"):
        (tmp_path / d).mkdir(parents=True)
        (tmp_path / d / "__init__.py").write_text("")
    (tmp_path / "src" / "single.py").write_text("")
    local = a._local_modules()
    assert {"src", "mylib", "core", "helpers", "single"} <= local
    assert not {"requests", "bleach", "x"} & local
    out = "E   ModuleNotFoundError: No module named 'mylib'\nE   ModuleNotFoundError: No module named 'helpers'"
    assert deps.detect_missing(out, local) == []


def test_pick_release_first_release_younger_than_90_days():
    data = _pypi({"1.0": ("2026-07-10T00:00:00Z", False, None), "1.1": ("2026-09-20T00:00:00Z", False, None)})
    assert deps.pick_release(data, now=NOW) == (None, "first release is younger than 90 days")
    assert deps.pick_release(data, now=datetime(2026, 10, 9, tzinfo=timezone.utc))[0] == "1.1"  # day 91


def test_pick_release_yanked_latest_falls_back_to_previous():
    data = _pypi({"4.0.1": ("2026-09-30T00:00:00Z", True, None), "4.0.0": (OLD, False, None)})
    assert deps.pick_release(data, now=NOW) == ("4.0.0", None)
