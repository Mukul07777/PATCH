"""Release trust check against recorded deps.dev v3 responses (no network)."""
import pytest

from patchpilot.intel import sources
from patchpilot.agent.pipeline import Agent

# trimmed from real api.deps.dev responses (2026-10)
OLD = {"publishedAt": "2018-12-07T13:40:06Z", "attestations": [], "slsaProvenances": [],
       "links": [{"label": "SOURCE_REPO", "url": "http://github.com/jpadilla/pyjwt"}],
       "relatedProjects": [{"projectKey": {"id": "github.com/jpadilla/pyjwt"}, "relationType": "SOURCE_REPO"}]}
NEW = {"publishedAt": "2026-09-28T18:40:41Z", "slsaProvenances": [],
       "attestations": [{"type": "https://docs.pypi.org/attestations/publish/v1", "verified": True,
                         "sourceRepository": "https://github.com/jpadilla/pyjwt", "commit": "7d5ef55"}],
       "relatedProjects": [{"projectKey": {"id": "github.com/jpadilla/pyjwt"}, "relationType": "SOURCE_REPO"}]}
PROJ = {"scorecard": {"date": "2026-08-24T00:00:00Z", "overallScore": 6.9, "checks": [
    {"name": "Code-Review", "score": 3}, {"name": "Maintained", "score": 1},
    {"name": "Signed-Releases", "score": -1}, {"name": "Dangerous-Workflow", "score": 10},
    {"name": "Fuzzing", "score": 0}]}}
DEPS_OLD = {"nodes": [{"versionKey": {"name": "pyjwt"}, "relation": "SELF"}]}
DEPS_NEW = {"nodes": [{"versionKey": {"name": "pyjwt"}, "relation": "SELF"},
                      {"versionKey": {"name": "cryptography"}, "relation": "DIRECT"},
                      {"versionKey": {"name": "cffi"}, "relation": "INDIRECT"}]}


@pytest.fixture
def fake(monkeypatch):
    table = {"/systems/pypi/packages/pyjwt/versions/1.7.1": OLD,
             "/systems/pypi/packages/pyjwt/versions/2.4.0": NEW,
             "/systems/pypi/packages/pyjwt/versions/1.7.1:dependencies": DEPS_OLD,
             "/systems/pypi/packages/pyjwt/versions/2.4.0:dependencies": DEPS_NEW,
             "/projects/github.com%2Fjpadilla%2Fpyjwt": PROJ}
    monkeypatch.setattr(sources, "_depsdev_get", lambda p: table.get(p))
    return table


def _agent():
    a = Agent.__new__(Agent)
    a.evidence, a.drift, a.trust = [], [], {}
    return a


PLAN = {"upgrades": [{"package": "PyJWT", "from": "1.7.1", "to": "2.4.0"}]}


def test_release_trust_fields(fake):
    t = sources.release_trust("PyJWT", "2.4.0")
    assert t["provenance"] is True and t["provenance_commit"] == "7d5ef55"
    assert t["scorecard"] == 6.9 and t["source_repo"] == "github.com/jpadilla/pyjwt"
    assert t["checks"] == {"Code-Review": 3, "Maintained": 1, "Signed-Releases": -1, "Dangerous-Workflow": 10}
    assert t["deps"] == ["cffi", "cryptography"]
    assert sources.release_trust("PyJWT", "1.7.1")["provenance"] is False


def test_release_trust_missing(fake):
    t = sources.release_trust("nope", "1.0")
    assert t["found"] is False and t["provenance"] is None


def test_agent_trust_risk_and_ledger(fake, monkeypatch):
    a = _agent()
    pk = a._trust(PLAN)["PyJWT"]
    assert pk["provenance"] is True and pk["had_provenance"] is False
    assert pk["new_deps"] == ["cffi", "cryptography"]
    pts, detail = a._trust_points()
    assert pts == 4 and "1/1" in detail
    monkeypatch.setattr(sources, "osv_vulns", lambda *a: [])
    led = a._ledger([], PLAN, True, "1 passed", "1 passed", None, None, "")
    c = next(c for c in led["claims"] if c["claim"] == "Fix release provenance checked")
    assert c["status"] == "verified" and "verified PyPI attestation" in c["evidence"]


def test_trust_unavailable_never_raises(monkeypatch):
    monkeypatch.setattr(sources, "_depsdev_get", lambda p: None)
    a = _agent()
    assert a._trust(PLAN)["PyJWT"]["provenance"] is None
    assert a._trust_points()[0] == 0
    monkeypatch.setattr(sources, "osv_vulns", lambda *a: [])
    led = a._ledger([], PLAN, True, "", "", None, None, "")
    assert next(c for c in led["claims"] if c["claim"] == "Fix release provenance checked")["status"] == "unverified"
    a2 = _agent()
    assert a2._trust({"upgrades": [{"package": "x"}]})["x"]["provenance"] is None  # malformed plan
