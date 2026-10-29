"""Manifest parsers: one fixture per supported format in tests/fixtures/manifests/."""
from pathlib import Path

import pytest

from patchpilot.intel import manifests

FIX = Path(__file__).parent / "fixtures" / "manifests"


def _parse(rel):
    p = FIX / rel
    return {(d.name, d.version, d.pinned) for d in manifests.parse(p.name, p.read_text(encoding="utf-8"))}


def test_requirements_txt():
    got = _parse("requirements.txt")
    assert got == {("Jinja2", "2.10", True), ("requests", "2.19.0", True), ("flask", None, False),
                   ("urllib3", "1.24.1", True), ("numpy", "1.26.0", True)}


def test_requirements_never_follows_includes(tmp_path):
    # -r / -c lines are skipped, never opened (no path traversal through a crafted manifest)
    deps = manifests.parse_requirements("-r /etc/passwd\n--requirement ../secret.txt\n-c c.txt\nsix==1.0\n")
    assert [(d.name, d.version) for d in deps] == [("six", "1.0")]


def test_pyproject_pep621():
    assert _parse("pep621/pyproject.toml") == {("PyJWT", "1.7.1", True), ("requests", None, False),
                                               ("click", "8.0.0", True), ("pywin32", "306", True),
                                               ("pytest", "7.0.0", True), ("ruff", None, False)}


def test_pyproject_poetry():
    assert _parse("poetry/pyproject.toml") == {("django", "3.2.0", True), ("requests", None, False),
                                               ("pillow", "8.0.0", True), ("pytest", None, False)}


def test_poetry_lock_skips_git_sources():
    assert _parse("poetry.lock") == {("django", "3.2.0", True)}


def test_uv_lock_skips_the_project_itself():
    assert _parse("uv.lock") == {("urllib3", "1.26.4", True)}


def test_pipfile_lock():
    assert _parse("Pipfile.lock") == {("jinja2", "2.10", True), ("editable-pkg", None, False), ("pytest", "7.0.0", True)}


@pytest.mark.parametrize("name,text", [("pyproject.toml", "[project\nx"), ("Pipfile.lock", "{nope"), ("Pipfile.lock", "[]")])
def test_invalid_manifests_raise(name, text):
    with pytest.raises(manifests.ManifestError):
        manifests.parse(name, text)


def test_unsupported_filename():
    assert manifests.kind_of("setup.py") is None
    assert manifests.kind_of("requirements-dev.txt") == "requirements"
    with pytest.raises(manifests.ManifestError):
        manifests.parse("setup.py", "")


def test_merge_prefers_pins_and_dedupes():
    D = manifests.Dep
    merged = manifests.merge([D("Requests", None, "pyproject.toml", False), D("requests", "2.0", "uv.lock", True),
                              D("requests", "2.0", "requirements.txt", True), D("flask", None, "a", False)])
    assert [(d.name, d.version) for d in merged] == [("requests", "2.0"), ("flask", None)]
