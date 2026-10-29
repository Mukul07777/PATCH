"""Speed plan: reasoning control, provider fallback, Tavily-score rerank, triage skip, concurrency, uv."""
import json
import threading

import httpx
import pytest

from patchpilot.core import config, llm, sandbox
from patchpilot.intel import sources
from patchpilot.agent.pipeline import Agent

OK = {"choices": [{"message": {"content": '{"a": 1}'}}], "usage": {"prompt_tokens": 3, "completion_tokens": 2}}


def _router(monkeypatch, base, handler):
    monkeypatch.setattr(config, "NEBIUS_BASE_URL", base)
    monkeypatch.setattr(config, "MODEL_OVERRIDES", {"nano": "m", "super": "m", "ultra": "m"})
    r = llm.Router(lambda e: None)
    r._client = httpx.Client(base_url=base, transport=httpx.MockTransport(handler))
    return r


def _capture(bodies, reject=None):
    def handler(req):
        body = json.loads(req.content)
        bodies.append(body)
        if reject and reject in body:
            return httpx.Response(400, json={"error": f"Unrecognized request argument: {reject}"})
        return httpx.Response(200, json=OK)
    return handler


def test_openrouter_reasoning_shapes(monkeypatch):
    bodies = []
    r = _router(monkeypatch, "https://openrouter.ai/api/v1", _capture(bodies))
    r.chat("nano", "s", "u", "p", reasoning="off")
    r.chat("nano", "s", "u", "p", reasoning="low")
    r.chat("nano", "s", "u", "p")
    assert bodies[0]["reasoning"] == {"enabled": False, "exclude": True}
    assert bodies[1]["reasoning"] == {"effort": "low", "exclude": True}
    assert "reasoning" not in bodies[2] and "chat_template_kwargs" not in bodies[2]


def test_nim_reasoning_and_other_hosts(monkeypatch):
    bodies = []
    r = _router(monkeypatch, "https://integrate.api.nvidia.com/v1", _capture(bodies))
    r.chat("nano", "s", "u", "p", reasoning="off")
    r.chat("nano", "s", "u", "p", reasoning="low")  # NIM has no "low" switch: no-op
    assert bodies[0]["chat_template_kwargs"] == {"enable_thinking": False}
    assert "chat_template_kwargs" not in bodies[1]
    bodies.clear()
    r = _router(monkeypatch, "https://api.tokenfactory.nebius.com/v1", _capture(bodies))
    r.chat("nano", "s", "u", "p", reasoning="off")  # Token Factory is vLLM: same switch as NIM
    assert bodies[0]["chat_template_kwargs"] == {"enable_thinking": False}
    bodies.clear()
    r = _router(monkeypatch, "https://example.com/v1", _capture(bodies))
    r.chat("nano", "s", "u", "p", reasoning="off")
    assert set(bodies[0]) == {"model", "messages", "max_tokens", "temperature"}


def test_rejected_param_retried_and_remembered(monkeypatch):
    bodies = []
    r = _router(monkeypatch, "https://openrouter.ai/api/v1", _capture(bodies, reject="reasoning"))
    assert r.chat_json("nano", "s", "u", "p", reasoning="off") == {"a": 1}
    assert "reasoning" in bodies[0] and "reasoning" not in bodies[1]
    assert bodies[1]["response_format"] == {"type": "json_object"}  # only the rejected field is dropped
    r.chat("nano", "s", "u", "p", reasoning="off")
    assert len(bodies) == 3 and "reasoning" not in bodies[2]  # not sent again for this model


def test_json_mode_fallback(monkeypatch):
    bodies = []
    r = _router(monkeypatch, "https://example.com/v1", _capture(bodies, reject="response_format"))
    assert r.chat_json("nano", "s", "u", "p") == {"a": 1}
    assert "response_format" in bodies[0] and "response_format" not in bodies[1]


def test_timeout_raises_llmerror(monkeypatch):
    def handler(req):
        raise httpx.ReadTimeout("slow", request=req)
    r = _router(monkeypatch, "https://openrouter.ai/api/v1", handler)
    with pytest.raises(llm.LLMError, match="timed out"):
        r.chat("super", "s", "u", "p", timeout=1)


def _agent():
    a = Agent.__new__(Agent)
    a.evidence, a.drift, a.reach, a.events = [], [], {}, []
    a._emit = a.events.append
    return a


class NoLLM:
    models = {}
    last_reasoning = ""

    def chat(self, *a, **k):
        raise AssertionError("no model call expected")

    chat_json = chat


def test_rerank_uses_tavily_score():
    a = _agent()
    a.router = NoLLM()
    hits = [{"title": "answer", "url": "", "content": "x"}] + [
        {"title": f"d{i}", "url": f"https://x/{i}", "content": "c", "tavily_score": s}
        for i, s in enumerate([0.2, 0.9, 0.5, 0.1, 0.7])]
    out = a._rerank("q", hits, keep=3)
    assert [h["title"] for h in out] == ["answer", "d1", "d4", "d2"]
    assert out[1]["score"] == 9.0


def test_triage_skipped_when_reachability_conclusive():
    a = _agent()
    a.router = NoLLM()
    a.reach = {"G1": {"status": "reachable"}, "G2": {"status": "not reachable"}}
    findings = [{"package": "PyJWT", "vulns": [
        {"id": i, "cve": "CVE-" + i, "summary": "s", "details": "d", "fixed": ["2"]} for i in ("G1", "G2")]}]
    tri = a._triage(findings, {})
    assert {t["id"]: t["affected"] for t in tri} == {"G1": True, "G2": False}
    assert any("skipped" in e.get("msg", "") for e in a.events)


def test_triage_calls_nano_when_unknown():
    a = _agent()
    seen = {}

    class R(NoLLM):
        def chat_json(self, tier, system, user, purpose, **kw):
            seen.update(kw, tier=tier)
            return {"advisories": [{"id": "G1", "affected": True}]}
    a.router = R()
    a.reach = {"G1": {"status": "unknown"}}
    findings = [{"package": "x", "vulns": [{"id": "G1", "cve": "", "summary": "s", "details": "d", "fixed": []}]}]
    assert a._triage(findings, {}) == [{"id": "G1", "affected": True}]
    assert seen["reasoning"] == "off" and seen["max_tokens"] == 1500 and seen["tier"] == "nano"


def test_triage_and_research_run_concurrently(monkeypatch):
    a = _agent()
    a.router = NoLLM()
    gate = threading.Barrier(3, timeout=5)  # triage chain + 2 research tasks must all be in flight together
    findings = [{"package": p, "current": "1", "latest": "2", "vulns": []} for p in ("a", "b")]

    def reach_fn(f, o):
        gate.wait()
        return {}
    monkeypatch.setattr(a, "_reachability", reach_fn, raising=False)
    monkeypatch.setattr(a, "_triage", lambda f, o: [{"id": "x"}], raising=False)
    monkeypatch.setattr(sources, "tavily_search", lambda q, max_results=8: (gate.wait(), [])[1])
    triage, research = a._analyse(findings, {})
    assert triage == [{"id": "x"}] and research == {"a": [], "b": []}
    steps = [(e["key"], e["status"]) for e in a.events if e.get("type") == "step"]
    assert ("triage", "done") in steps and ("research", "done") in steps
    assert any(e.get("type") == "triage" for e in a.events)


def test_uv_detection(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox.shutil, "which", lambda n: "/bin/uv" if n == "uv" else None)
    assert sandbox.Sandbox(tmp_path / "r", print).uv == "/bin/uv"
    monkeypatch.setattr(sandbox.shutil, "which", lambda n: None)
    assert sandbox.Sandbox(tmp_path / "r", print).uv is None


def test_prepare_joins_background_install(monkeypatch, tmp_path):
    sb = sandbox.Sandbox(tmp_path / "r", print)
    monkeypatch.setattr(sb, "install", lambda: (True, "installed"))
    sb.prepare()
    assert sb.wait_ready() == (True, "installed")
