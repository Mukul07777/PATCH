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
