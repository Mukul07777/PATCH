import pytest

from patchpilot.llm import LLMError, parse_json, strip_thinking


def test_parse_json_variants():
    assert parse_json('{"a": 1}') == {"a": 1}
    assert parse_json('Sure:\n```json\n{"a": 2}\n```\nDone') == {"a": 2}
    assert parse_json('Here you go {"a": 3} hope it helps') == {"a": 3}
    assert parse_json('{"a": 4} and also {"b": 5}') == {"a": 4}
    assert parse_json('<think>{"no": 1}</think>{"a": 6}') == {"a": 6}


def test_parse_json_invalid():
    with pytest.raises(LLMError):
        parse_json("no json here {oops")


def test_strip_thinking():
    assert strip_thinking("<think>hmm\nlong</think>  answer ") == "answer"
    assert strip_thinking("plain") == "plain"


def test_discover_matches_nebius_ids(monkeypatch):
    from patchpilot import config, llm

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [{"id": i} for i in (
                "meta-llama/Llama-3.3-70B-Instruct", "nvidia/Nemotron-3_5-Lightning",
                "nvidia/nemotron-3-super-120b-a12b", "nvidia/Nemotron-3-Ultra-550b-a55b")]}

    monkeypatch.setattr(config, "MODEL_OVERRIDES", {"nano": "", "super": "", "ultra": ""})
    r = llm.Router(lambda e: None)
    monkeypatch.setattr(r._client, "get", lambda path: Resp())
    assert r.discover() == {"nano": "nvidia/Nemotron-3_5-Lightning", "super": "nvidia/nemotron-3-super-120b-a12b",
                            "ultra": "nvidia/Nemotron-3-Ultra-550b-a55b"}


def test_discover_mini_hint(monkeypatch):
    from patchpilot import config, llm

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [{"id": "nvidia/nemotron-mini-4b-instruct"}, {"id": "nvidia/nemotron-super-49b"}]}

    monkeypatch.setattr(config, "MODEL_OVERRIDES", {"nano": "", "super": "", "ultra": ""})
    r = llm.Router(lambda e: None)
    monkeypatch.setattr(r._client, "get", lambda path: Resp())
    m = r.discover()
    assert m["nano"] == "nvidia/nemotron-mini-4b-instruct" and m["ultra"] == "nvidia/nemotron-super-49b"


def test_token_factory_gets_thinking_switch():
    from patchpilot.llm import reasoning_style
    assert reasoning_style("https://api.tokenfactory.nebius.com/v1") == "nim"
    assert reasoning_style("https://openrouter.ai/api/v1") == "openrouter"
    assert reasoning_style("https://example.com/v1") is None


def test_parse_json_fence_inside_string():
    # a quoted shell snippet from research (with its own ``` fence) must not be mistaken for the reply's fence
    body = r'{"files": [], "evidence": [{"quote": "install the extra:\n```\npip install bleach[css]\n```"}]}'
    assert parse_json(body)["evidence"][0]["quote"].startswith("install")
    assert parse_json("```json\n" + body + "\n```")["files"] == []
    assert parse_json("Here:\n```json\n" + body + "\n```\nthanks")["files"] == []


def test_parse_json_any_fence_language_tag():
    assert parse_json('```JSON\n[{"a": 1}, {"b": 2}]\n```') == [{"a": 1}, {"b": 2}]
    assert parse_json('Result:\n```jsonc\n{"a": 7}\n```') == {"a": 7}
