from patchpilot import reach
from patchpilot.agent import Agent
from patchpilot.drift import usages


FILES = {
    "app.py": "import jwt\nfrom PIL import ImageFont\n\ndef f(t):\n    return jwt.decode(t, 'k')\n",
    "templates/x.html": "<div {{ attrs|xmlattr }}>\n",
}


def test_parse_imports_shapes():
    assert reach.parse_imports([{"attribute": "ImageFont", "modules": ["PIL"]}]) == ["PIL.ImageFont"]
    assert reach.parse_imports([{"module": "jwt.api_jwt", "symbols": ["decode", "encode"]}]) == [
        "jwt.api_jwt.decode", "jwt.api_jwt.encode"]
    assert reach.parse_imports(None) == [] and reach.parse_imports(["junk"]) == []


def test_statuses():
    u = usages(FILES)
    advs = {
        "A": {"package": "PyJWT", "symbols": ["jwt.decode"], "source": "osv"},
        "B": {"package": "PyJWT", "symbols": ["jwt.encode"], "source": "osv"},
        "C": {"package": "urllib3", "symbols": ["urllib3.PoolManager"], "source": "osv"},
        "D": {"package": "PyJWT", "symbols": [], "source": "osv"},
        "E": {"package": "Pillow", "symbols": ["PIL.ImageFont"], "source": "llm-inferred"},
        "F": {"package": "PyJWT", "symbols": ["jwt.api_jwt.decode"], "source": "osv"},
    }
    r = reach.analyse(u, advs, FILES)
    assert r["A"]["status"] == "reachable" and r["A"]["sites"] == ["app.py:5"]
    assert r["B"]["status"] == "imported"
    assert r["C"]["status"] == "not reachable"
    assert r["D"]["status"] == "unknown" and r["D"]["source"] is None
    assert r["E"]["status"] == "reachable" and r["E"]["source"] == "llm-inferred"
    assert r["F"]["status"] == "reachable"  # re-export jwt.decode -> jwt.api_jwt.decode
    assert reach.counts(r) == {"reachable": 3, "imported": 1, "not reachable": 1, "unknown": 1}


def test_template_filter():
    files = {"app.py": "import jinja2\njinja2.Environment()\n"}
    adv = {"X": {"package": "Jinja2", "symbols": ["jinja2.filters.do_xmlattr"], "source": "osv"}}
    assert reach.analyse(usages(files), adv, files)["X"]["status"] == "unknown"
    files["t.html"] = "<p {{ a | xmlattr }}>"
    r = reach.analyse(usages(files), adv, files)["X"]
    assert r["status"] == "reachable" and r["sites"] == ["t.html:1"]


class _BoomRouter:
    def chat_json(self, *a, **k):
        raise RuntimeError("429 rate limited")


def test_agent_reachability_survives_llm_error():
    a = Agent.__new__(Agent)
    a.evidence, a.drift, a.events = [], [], []
    a.router = _BoomRouter()
    a._emit = a.events.append
    findings = [{"package": "PyJWT", "vulns": [
        {"id": "G1", "summary": "s", "details": "d", "symbols": ["jwt.decode"]},
        {"id": "G2", "summary": "s", "details": "d", "symbols": []}]}]
    r = a._reachability(findings, FILES)
    assert r["G1"]["status"] == "reachable" and r["G2"]["status"] == "unknown"
    ev = [e for e in a.events if e.get("type") == "reachability"][0]
    assert ev["counts"]["reachable"] == 1
    a.reach = r
    risk = a._risk("", {"upgrades": []}, 1, True, None)
    assert risk["urgency"] == "high"
