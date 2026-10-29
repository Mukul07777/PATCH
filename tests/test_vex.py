import json

import pytest
from fastapi.testclient import TestClient

from conftest import AUTH

from patchpilot.core import config
from patchpilot.app import server
from patchpilot.intel import vex

FINDINGS = [
    {"package": "Jinja2", "current": "3.1.2", "vulns": [{"id": "GHSA-h5c8-rqwp-cp95", "cve": "CVE-2024-22195"}]},
    {"package": "urllib3", "current": "1.26.5", "vulns": [{"id": "GHSA-34jh-p97f-mpxf", "cve": "CVE-2024-37891"}]},
    {"package": "pyyaml", "current": "5.3", "vulns": [{"id": "PYSEC-1", "cve": None}]},
]
PLAN = {"upgrades": [{"package": "Jinja2", "to": "3.1.4"}, {"package": "urllib3", "to": "1.26.19"}]}
REACH = {"GHSA-h5c8-rqwp-cp95": {"status": "reachable", "source": "osv"},
         "GHSA-34jh-p97f-mpxf": {"status": "imported", "source": "osv"},
         "PYSEC-1": {"status": "not reachable", "source": None, "note": "package never imported by project code"}}
LEDGER = {"certificate": "pp-0123456789abcdef"}
EXPLOIT = {"advisory": "CVE-2024-22195", "verdict": "proven closed"}


def _by(doc):
    return {s["vulnerability"]["name"]: s for s in doc["statements"]}


def test_statuses_and_required_fields():
    doc = vex.build("r1", FINDINGS, PLAN, REACH, ["CVE-2024-37891"], True, LEDGER, EXPLOIT)
    assert vex.validate(doc) and doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    s = _by(doc)
    assert s["CVE-2024-22195"]["status"] == "fixed"
    assert s["CVE-2024-22195"]["products"][0]["@id"] == "pkg:pypi/jinja2@3.1.2"
    assert "pp-0123456789abcdef" in s["CVE-2024-22195"]["status_notes"]
    assert "proven closed" in s["CVE-2024-22195"]["status_notes"]
    assert s["CVE-2024-37891"]["status"] == "affected" and s["CVE-2024-37891"]["action_statement"]
    assert s["PYSEC-1"]["status"] == "not_affected"
    assert s["PYSEC-1"]["justification"] == "vulnerable_code_not_in_execute_path"


def test_red_tests_mean_not_fixed():
    s = _by(vex.build("r1", FINDINGS, PLAN, REACH, [], False, LEDGER))
    assert s["CVE-2024-22195"]["status"] == "affected"


def test_rescan_failure_not_fixed():
    s = _by(vex.build("r1", FINDINGS, PLAN, REACH, ["urllib3: OSV re-scan failed"], True))
    assert s["CVE-2024-37891"]["status"] == "affected" and s["CVE-2024-22195"]["status"] == "fixed"


def test_never_not_affected_from_llm_inferred():
    reach = dict(REACH, **{"PYSEC-1": {"status": "not reachable", "source": "llm-inferred"}})
    assert _by(vex.build("r1", FINDINGS, PLAN, reach, [], True))["PYSEC-1"]["status"] == "affected"
    reach = dict(REACH, **{"PYSEC-1": {"status": "imported", "source": "osv"}})
    assert _by(vex.build("r1", FINDINGS, PLAN, reach, [], True))["PYSEC-1"]["status"] == "affected"


def test_validate_rejects_bad_docs():
    doc = vex.build("r1", FINDINGS, PLAN, REACH, [], True)
    for mutate in (lambda d: d.pop("@id"), lambda d: d["statements"][0].update(status="bogus"),
                   lambda d: d["statements"][0].update(products=[]),
                   lambda d: d["statements"][2].pop("justification") and d["statements"][2].pop("impact_statement")):
        bad = json.loads(json.dumps(doc))
        mutate(bad)
        with pytest.raises(ValueError):
            vex.validate(bad)


def test_vex_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path)
    doc = vex.build("r1", FINDINGS, PLAN, REACH, [], True)
    (tmp_path / "withvex.jsonl").write_text(json.dumps({"type": "vex", "document": doc}) + "\n", encoding="utf-8")
    (tmp_path / "novex.jsonl").write_text(json.dumps({"type": "done"}) + "\n", encoding="utf-8")
    c = TestClient(server.app, headers=AUTH)
    assert c.get("/api/runs/withvex/vex").json() == doc
    assert c.get("/api/runs/novex/vex").status_code == 404
    assert c.get("/api/runs/missing/vex").status_code == 404
