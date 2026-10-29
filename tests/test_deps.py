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


def test_resolve_only_existing_packages():
    def lookup(d):
        if d == "tinycss2":
            return "1.4.0"
        raise RuntimeError("404")
    assert deps.resolve("tinycss2", lookup) == ("tinycss2", "1.4.0")
    assert deps.resolve("nonexistent_pkg_xyz", lookup) is None


def test_add_requirements_idempotent(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("bleach==6.0.0\nPyYAML==6.0  # cfg\npytest==8.3.3")
    assert deps.add_requirements(req, [("tinycss2", "1.4.0"), ("pyyaml", "6.0.2")]) == [("tinycss2", "1.4.0")]
    assert req.read_text().endswith("pytest==8.3.3\ntinycss2==1.4.0\n")
    assert deps.add_requirements(req, [("tinycss2", "1.4.0")]) == []


class FakeSandbox:
    def __init__(self, install_ok=True):
        self.installs, self.install_ok = 0, install_ok

    def install(self):
        self.installs += 1
        return (self.install_ok if self.installs == 1 else True), "boom"

    def test(self):
        return True, "5 passed", "ok"


def _agent(tmp_path, monkeypatch):
    a = Agent.__new__(Agent)
    a.work, a.evidence, a.dep_hints, a.deps_added, a.events = Path(tmp_path), [], [], [], []
    a._emit = a.events.append
    a.log = lambda *x, **k: None
    (tmp_path / "requirements.txt").write_text("bleach==6.0.0\n")
    (tmp_path / "sanitizer").mkdir()
    monkeypatch.setattr(deps.sources, "pypi_latest", lambda d: "1.4.0")
    monkeypatch.setattr(deps, "resolve", lambda m: ("tinycss2", "1.4.0"))
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
