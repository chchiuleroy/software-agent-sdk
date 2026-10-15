"""The MCP tool fingerprint (governance_mcp_fingerprint.py).

What matters is that a change to anything the server says about a tool changes the
fingerprint, and that nothing which is not about the tool does. The golden value pins
the canonical form: if it ever changes, every fingerprint ever stored is invalid.
"""

from __future__ import annotations

import hashlib
import math

import pytest

from openhands.agent_server.governance_mcp_fingerprint import (
    FINGERPRINT_PREFIX,
    mcp_tool_fingerprint,
)


SCHEMA = {
    "type": "object",
    "properties": {"text": {"type": "string", "description": "what to count"}},
    "required": ["text"],
}


def fp(name="word_count", description="Count the words.", schema=None):
    return mcp_tool_fingerprint(name, description, SCHEMA if schema is None else schema)


def test_the_canonical_form_is_pinned_by_a_golden_value():
    """Worked out by hand from the canonical text below (keys sorted, no spaces), not
    by calling the function: if the canonical form ever changes, every fingerprint
    stored before is wrong, and this fails first."""
    canonical = (
        '{"description":"Count the words.","input_schema":{"properties":{"text":'
        '{"description":"what to count","type":"string"}},"required":["text"],'
        '"type":"object"},"name":"word_count"}'
    )
    assert fp() == "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()
    assert (
        fp()
        == "sha256:ef4eeb763f524e69da9f8054e1f030abe86573f3818f0e1fe7ce433dfdee0313"
    )


def test_it_has_the_documented_shape_and_is_deterministic():
    value = fp()
    assert value.startswith(FINGERPRINT_PREFIX)
    assert len(value) == len(FINGERPRINT_PREFIX) + 64
    assert value == fp()


def test_a_change_of_name_description_or_schema_changes_it():
    base = fp()
    assert fp(name="word_count2") != base
    assert fp(description="Count the words!") != base
    assert fp(description=None) != base
    changed = {**SCHEMA, "required": []}
    assert fp(schema=changed) != base
    wider = {
        **SCHEMA,
        "properties": {**SCHEMA["properties"], "extra": {"type": "integer"}},
    }
    assert fp(schema=wider) != base


def test_the_description_being_absent_is_not_the_same_as_empty():
    assert fp(description=None) != fp(description="")


def test_the_order_of_object_keys_does_not_matter():
    reordered = {
        "required": ["text"],
        "properties": {"text": {"description": "what to count", "type": "string"}},
        "type": "object",
    }
    assert fp(schema=reordered) == fp()


def test_the_order_of_list_items_does_matter():
    """A server that reorders `required` is a change: a spurious re-confirmation is
    cheaper than a missed one."""
    two = {"type": "object", "required": ["a", "b"]}
    flipped = {"type": "object", "required": ["b", "a"]}
    assert fp(schema=two) != fp(schema=flipped)


def test_text_that_looks_alike_is_not_the_same_text():
    assert fp(description="café") != fp(description="café")  # NFC vs NFD
    assert fp(description="a b") != fp(description="a b")  # no-break space


def test_a_schema_that_is_not_plain_json_cannot_be_fingerprinted():
    with pytest.raises(ValueError):
        fp(schema={"x": math.nan})
    with pytest.raises(ValueError):
        fp(schema={"x": math.inf})
    with pytest.raises(TypeError):
        fp(schema={"x": object()})
    with pytest.raises(TypeError):
        fp(schema={1, 2})  # type: ignore[arg-type]


def test_a_non_string_key_is_refused_not_turned_into_a_string():
    """json.dumps would give {1: 'x'} the same bytes as {'1': 'x'}."""
    with pytest.raises(TypeError):
        fp(schema={"properties": {1: {"type": "string"}}})  # type: ignore[dict-item]
    with pytest.raises(TypeError):
        fp(schema={"anyOf": [{2: "x"}]})  # type: ignore[dict-item]
    assert fp(schema={"1": "x"})  # the string key is fine


def test_a_tuple_is_refused_not_given_the_fingerprint_of_the_same_list():
    """json.dumps writes (1, 2) and [1, 2] identically; only a list is JSON."""
    assert fp(schema={"x": [1, 2]})
    with pytest.raises(TypeError):
        fp(schema={"x": (1, 2)})
    with pytest.raises(TypeError):
        fp(schema={"anyOf": [{"enum": (1, 2)}]})


def test_what_is_hashed_is_the_tool_and_nothing_around_it():
    """The same three fields give the same fingerprint however the caller got them."""
    a = mcp_tool_fingerprint("t", "d", {"type": "object"})
    b = mcp_tool_fingerprint(name="t", description="d", input_schema={"type": "object"})
    assert a == b
