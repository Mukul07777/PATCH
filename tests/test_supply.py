"""Supply-chain checks, SBOM import, fixed manifests and the signed badge."""
import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from conftest import AUTH, osv_from
from patchpilot.app import db, server
from patchpilot.intel import manifests, remediate, sources, supply

NOW = datetime(2026, 10, 30, tzinfo=timezone.utc)


def _doc(first, last, n=6, license="MIT", yanked=(), classifiers=()):
    rel = {f"1.{i}": [{"upload_time_iso_8601": (first if i == 0 else last if i == n - 1 else first) + "T00:00:00Z",
                       "yanked": f"1.{i}" in yanked}] for i in range(n)}
    return {"info": {"version": f"1.{n - 1}", "license": license, "classifiers": list(classifiers)}, "releases": rel}


def test_typosquat_catches_attacks_and_spares_popular_names():
    for bad, target in (("reqeusts", "requests"), ("python-requests", "requests"), ("urlib3", "urllib3"),
                        ("crypt0graphy", "cryptography"), ("requests-py", "requests")):
        assert supply.typosquat(bad)["imitates"] == target, bad
    for good in ("requests", "tomli", "toml", "flask", "black", "six", "my-internal-tool"):
        assert supply.typosquat(good) is None, good


def test_license_classes():
    assert supply.license_of({"license_expression": "GPL-3.0-only"})[1] == "strong-copyleft"
    assert supply.license_of({"classifiers": ["License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)"]})[1] == "weak-copyleft"
    assert supply.license_of({"license": "BSD-3-Clause"})[1] == "permissive"
    assert supply.license_of({})[1] == "unknown"


def test_health_flags_yanked_stale_new():
    h = supply.health(_doc("2015-01-01", "2016-01-01", yanked=("1.2",)), "1.2", NOW)
    assert h["yanked"] and h["stale"] and not h["new"] and h["releases"] == 6
    h = supply.health(_doc("2026-09-01", "2026-10-01", n=2), "1.0", NOW)
    assert h["new"] and not h["stale"]


def test_analyse_only_flags_lookalikes_without_history(monkeypatch):
    docs = {"reqeusts": {"error": "HTTPStatusError"},
            "authlib": _doc("2018-01-01", "2026-06-01", n=40, license="BSD-3-Clause"),
            "pyqt5": _doc("2016-01-01", "2026-01-01", n=30, license="GPL v3")}
    monkeypatch.setattr(supply, "_pypi", lambda n: docs[n.lower()])
    r = supply.analyse([("reqeusts", "1.0"), ("authlib", "1.0"), ("PyQt5", "1.0")], {"reqeusts": ["MAL-2024-1"]})
    by = {p["package"]: {f["kind"] for f in p["flags"]} for p in r["packages"]}
    assert by["reqeusts"] == {"malicious", "typosquat", "not-on-pypi"}
    assert by["authlib"] == set() and "license" in by["PyQt5"]
    assert r["summary"]["malicious"] == 1 and r["packages"][0]["package"] == "reqeusts"  # worst first


def test_sbom_cyclonedx_and_spdx():
    cdx = {"bomFormat": "CycloneDX", "metadata": {}, "components": [
        {"name": "jinja2", "version": "2.10", "purl": "pkg:pypi/jinja2@2.10"},
        {"name": "lodash", "version": "4", "purl": "pkg:npm/lodash@4"},
        {"name": "app", "components": [{"name": "requests", "version": "2.19.0"}]}]}
    deps, warn = manifests.parse_ex("app.cdx.json", json.dumps(cdx))
    assert [(d.name, d.version) for d in deps] == [("jinja2", "2.10"), ("requests", "2.19.0")]
    assert "1 non-Python" in warn[0]
    spdx = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "PyJWT", "versionInfo": "1.7.1", "externalRefs": [
        {"referenceType": "purl", "referenceLocator": "pkg:pypi/pyjwt@1.7.1"}]}]}
    assert [(d.name, d.version) for d in manifests.parse("sbom.spdx.json", json.dumps(spdx))] == [("pyjwt", "1.7.1")]
    assert manifests.size_limit("bom.json") == manifests.MAX_LOCK


def test_fixed_requirements_rewrites_only_vulnerable_pins():
    text = "# app\njinja2==2.10  # templates\nrequests == 2.19.0 ; python_version >= '3.8'\nsix==1.16.0\n"
    out, changes = remediate.fixed_requirements(text, {("jinja2", "2.10"): "3.1.6", ("requests", "2.19.0"): "2.32.4"})
    lines = out.splitlines()
    assert lines[0] == "# app" and lines[3] == "six==1.16.0"
    assert lines[1].startswith("jinja2==3.1.6") and "templates" in lines[1]
    assert lines[2].startswith("requests==2.32.4 ; python_version >= '3.8'")
    assert [c["to"] for c in changes] == ["3.1.6", "2.32.4"]


def test_fixed_manifest_supply_and_badge_endpoints(monkeypatch):
    monkeypatch.setattr(server, "_spawn", lambda fn, *a: fn(*a))
    monkeypatch.setattr(sources, "osv_batch", osv_from(lambda n, v: [
        {"id": "GHSA-1", "cve": "", "severity": "HIGH", "fixed": ["3.1.6"], "summary": "x"}] if n == "jinja2" else []))
    monkeypatch.setattr(sources, "pypi_latest", lambda n: "3.1.6")
    monkeypatch.setattr(supply, "_pypi", lambda n: _doc("2015-01-01", "2026-01-01"))
    c = TestClient(server.app, headers={**AUTH, "X-Requested-With": "patchpilot"})
    pid = c.post("/api/projects", json={"filename": "requirements.txt", "content": "jinja2==2.10\nsix==1.0\n"}).json()["id"]
    assert c.get(f"/api/projects/{pid}/supply").status_code == 409  # not scanned yet
    c.post(f"/api/projects/{pid}/scan")
    fm = c.get(f"/api/projects/{pid}/fixed-manifest")
    assert fm.status_code == 200 and fm.text.startswith("jinja2==3.1.6") and fm.headers["x-patchpilot-changes"] == "1"
    assert c.get(f"/api/projects/{pid}/supply").json()["checked"] == 2
    path = c.get(f"/api/projects/{pid}/badge").json()["path"]
    anon = TestClient(server.app)
    assert "1 vulnerability" in anon.get(path).text
    assert anon.get(f"/badge/{pid}/0000.svg").status_code == 404
    assert db.get_project(pid) is not None
