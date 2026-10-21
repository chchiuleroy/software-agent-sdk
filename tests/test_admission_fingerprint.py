"""Admission fingerprints. Pure functions; no database.

The golden values were produced by the DEVICE implementation (openhands-sdk-governed,
``governance_mcp_fingerprint.mcp_tool_fingerprint``). If a golden test here fails,
central and the devices no longer agree on what "this exact tool" means: nothing
approved here would match what a device computes, and the device would refuse all of
it (or, worse, a drift in one direction could make two different tools look the same).
Change an algorithm only in both repositories at once.
"""

from __future__ import annotations

import math

import pytest

from central_governance_api.admission.fingerprint import (
    PREFIX,
    manifest_fingerprint,
    mcp_server_fingerprint,
    mcp_tool_fingerprint,
)


SCHEMA = {
    "type": "object",
    "properties": {"text": {"type": "string", "description": "what to count"}},
    "required": ["text"],
}

# Produced by the device implementation, 2026-10-20.
GOLDEN_TOOL = "sha256:ef4eeb763f524e69da9f8054e1f030abe86573f3818f0e1fe7ce433dfdee0313"
GOLDEN_TOOL_NO_DESCRIPTION = (
    "sha256:c11c34eb88cb8d04af58eccfe8d6f481f965a9d1ae205db2ed53ebc5e9b5d2d9"
)
GOLDEN_TOOL_NON_ASCII = (
    "sha256:09f033521dbfd2e872605255d9c1f8832875f32c349dd5ee049a3645b1e92674"
)


def test_a_tool_fingerprint_equals_what_the_device_computes():
    assert mcp_tool_fingerprint("word_count", "Count the words.", SCHEMA) == GOLDEN_TOOL
    assert (
        mcp_tool_fingerprint("word_count", None, SCHEMA) == GOLDEN_TOOL_NO_DESCRIPTION
    )
    assert (
        mcp_tool_fingerprint("t", "d", {"k": "é☃", "a": [2, 1]})
        == GOLDEN_TOOL_NON_ASCII
    )


def test_no_description_is_not_the_same_as_an_empty_one():
    assert mcp_tool_fingerprint("t", None, {}) != mcp_tool_fingerprint("t", "", {})


def test_the_order_of_object_keys_does_not_matter_but_list_order_does():
    a = mcp_tool_fingerprint("t", "d", {"x": 1, "y": 2})
    b = mcp_tool_fingerprint("t", "d", {"y": 2, "x": 1})
    assert a == b
    assert mcp_tool_fingerprint("t", "d", {"r": [1, 2]}) != mcp_tool_fingerprint(
        "t", "d", {"r": [2, 1]}
    )


@pytest.mark.parametrize(
    "schema",
    [
        {"x": math.nan},
        {"x": math.inf},
        {1: "a"},
        {"x": (1, 2)},
        {"nested": {2: "b"}},
    ],
)
def test_a_schema_json_cannot_hold_is_refused(schema):
    with pytest.raises((TypeError, ValueError)):
        mcp_tool_fingerprint("t", "d", schema)


def test_a_server_fingerprint_does_not_depend_on_tool_order_but_on_the_set():
    one = mcp_tool_fingerprint("a", "x", {})
    two = mcp_tool_fingerprint("b", "y", {})
    assert mcp_server_fingerprint([one, two]) == mcp_server_fingerprint([two, one])
    assert mcp_server_fingerprint([one, two]) != mcp_server_fingerprint([one])
    assert mcp_server_fingerprint([one]).startswith(PREFIX)


def test_a_server_with_a_repeated_tool_is_refused():
    one = mcp_tool_fingerprint("a", "x", {})
    with pytest.raises(ValueError):
        mcp_server_fingerprint([one, one])


FILES = [("SKILL.md", "a" * 64), (".hidden/payload.sh", "b" * 64)]


def test_a_manifest_fingerprint_does_not_depend_on_listing_order():
    assert manifest_fingerprint(FILES) == manifest_fingerprint(list(reversed(FILES)))


@pytest.mark.parametrize(
    "changed",
    [
        [("SKILL.md", "a" * 64), (".hidden/payload.sh", "c" * 64)],  # a byte changed
        [("SKILL.md", "a" * 64)],  # a hidden file removed
        FILES + [(".git/hooks/pre-commit", "d" * 64)],  # a hidden file added
        [("SKILL.md", "a" * 64), (".hidden/renamed.sh", "b" * 64)],  # renamed
    ],
)
def test_any_change_to_any_file_including_hidden_ones_changes_the_fingerprint(changed):
    # Why: scanners are known to skip hidden and build directories, so the fingerprint
    # must not.
    assert manifest_fingerprint(changed) != manifest_fingerprint(FILES)


def test_a_manifest_with_a_repeated_path_is_refused():
    with pytest.raises(ValueError):
        manifest_fingerprint([("a", "1" * 64), ("a", "2" * 64)])
