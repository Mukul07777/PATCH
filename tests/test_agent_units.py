from patchpilot.core import config
from patchpilot.intel import exploits, sources
from patchpilot.agent.pipeline import Agent, extract_test_code


def test_extract_fenced_block():
    code = extract_test_code("Here:\n```python\ndef test_x():\n    assert 1\n```\n")
    assert code == "def test_x():\n    assert 1\n"


def test_extract_reasoning_salvage():
    assert extract_test_code("import os\n\ndef test_y():\n    assert os\n").startswith("import os")


def test_extract_rejects_syntax_error_and_missing_test():
    assert extract_test_code("```python\ndef test_x(:\n    pass\n```") is None
    assert extract_test_code("```python\ndef helper():\n    pass\n```") is None
    assert extract_test_code(None) is None


def _agent():
    a = Agent.__new__(Agent)
    a.evidence, a.drift = [], []
    return a


PLAN = {"upgrades": [{"package": "PyJWT", "from": "1.7.1", "to": "2.4.0"}]}
DIFF = "--- a/requirements.txt\n+++ b/requirements.txt\n-PyJWT==1.7.1\n+PyJWT==2.4.0\n"


def test_risk():
    a = _agent()
    r = a._risk(DIFF, PLAN, 1, True, {"verdict": "proven closed"})
    f = {x["name"]: x["points"] for x in r["factors"]}
    assert f["Major version jumps"] == 12 and f["Exploit proof"] == -10 and f["Test result"] == 0
    assert r["level"] == "low"
    bad = a._risk(DIFF, PLAN, 4, False, None)
    assert bad["score"] > r["score"] and bad["level"] in ("medium", "high")


def test_ledger(monkeypatch):
    monkeypatch.setattr(sources, "osv_vulns", lambda pkg, ver: [])
    findings = [{"package": "PyJWT", "vulns": [{"cve": "CVE-2022-29217", "id": "GHSA-x"}]}]
    ex = {"advisory": "CVE-2022-29217", "source": "curated", "before": "failed", "after": "passed",
          "verdict": "proven closed"}
    led = _agent()._ledger(findings, PLAN, True, "3 passed", "3 passed", ex, None, DIFF)
    status = {c["claim"]: c["status"] for c in led["claims"]}
    assert status["All reported advisories resolved"] == "verified"
    assert status["Exploit CVE-2022-29217 closed"] == "verified"
    assert led["certificate"].startswith("pp-") and 0 <= led["trust"] <= 100

    monkeypatch.setattr(sources, "osv_vulns", lambda pkg, ver: [{"cve": "CVE-2022-29217", "id": "GHSA-x"}])
    led = _agent()._ledger(findings, PLAN, False, "3 passed", "1 passed", None, None, DIFF)
    status = {c["claim"]: c["status"] for c in led["claims"]}
    assert status["All reported advisories resolved"] == "unverified"
    assert status["No tests lost"] == "partial"


def test_exploits_find_and_mutations():
    cve, code = exploits.find({"id": "GHSA-ffqj", "aliases": ["CVE-2022-29217"]})
    assert cve == "CVE-2022-29217" and "def test" in code
    assert exploits.find({"id": "GHSA-none", "cve": "CVE-1999-0001"}) is None
    assert "def test" in exploits.mutations("CVE-2022-29217")
    assert exploits.mutations("CVE-1999-0001") is None


def test_done_meta_and_provider(monkeypatch):
    a = _agent()
    a.router = type("R", (), {"models": {"nano": "m"}})()
    monkeypatch.setattr(config, "NEBIUS_BASE_URL", "https://openrouter.ai/api/v1")
    assert a._meta() == {"provider": "OpenRouter", "models": {"nano": "m"}}
    assert config.provider_name("https://api.tokenfactory.nebius.com/v1") == "Token Factory"
