"""The admission snapshot (roy_admission). Module state is process-wide, so every test
resets it. Each test names the guarantee it protects."""

from __future__ import annotations

import pytest

from openhands.sdk.security import roy_admission as admission


@pytest.fixture(autouse=True)
def _reset_state():
    admission.reset()
    yield
    admission.reset()


TOOL = "sha256:" + "a" * 64
SKILL = "sha256:" + "b" * 64
PLUGIN = "sha256:" + "c" * 64


def _snapshot(*, fetched_at: float = 100.0, max_age: float = 60.0):
    return admission.AdmissionSnapshot(
        mcp_tool_fingerprints=frozenset({TOOL}),
        skill_fingerprints=frozenset({SKILL}),
        plugin_fingerprints=frozenset({PLUGIN}),
        revision="r1",
        max_age_seconds=max_age,
        fetched_at=fetched_at,
    )


def test_when_enforcement_is_off_everything_is_admitted_as_before():
    # Why: personal mode and a server that has not opted in must behave exactly as
    # they always did.
    assert admission.is_enforcing() is False
    unknown = "sha256:" + "f" * 64
    assert admission.is_mcp_tool_admitted(unknown) is True
    assert admission.is_skill_admitted(unknown) is True
    assert admission.is_plugin_admitted(unknown) is True
    assert admission.has_current_list() is True


def test_when_enforcing_with_no_list_nothing_is_admitted():
    # Why: a server that has not heard from central yet must not let anything in.
    admission.set_enforcing(True)
    assert admission.has_current_list() is False
    for check in (
        admission.is_mcp_tool_admitted,
        admission.is_skill_admitted,
        admission.is_plugin_admitted,
    ):
        assert check(TOOL) is False


def test_a_listed_fingerprint_is_admitted_and_an_unlisted_one_is_not():
    admission.set_enforcing(True)
    admission.set_snapshot(_snapshot())
    assert admission.is_mcp_tool_admitted(TOOL, now=110.0) is True
    assert admission.is_skill_admitted(SKILL, now=110.0) is True
    assert admission.is_plugin_admitted(PLUGIN, now=110.0) is True
    other = "sha256:" + "9" * 64
    assert admission.is_mcp_tool_admitted(other, now=110.0) is False


def test_the_three_kinds_are_separate_lists():
    # Why: an approved skill must not let an MCP tool with the same bytes in, or the
    # other way round; each kind was checked as that kind.
    admission.set_enforcing(True)
    admission.set_snapshot(_snapshot())
    assert admission.is_mcp_tool_admitted(SKILL, now=110.0) is False
    assert admission.is_skill_admitted(TOOL, now=110.0) is False
    assert admission.is_plugin_admitted(SKILL, now=110.0) is False


def test_a_list_older_than_its_max_age_admits_nothing():
    # Why: a device cut off from central must lose what it was allowed, not keep an
    # old list for ever (a revocation has to be able to reach it).
    admission.set_enforcing(True)
    admission.set_snapshot(_snapshot(fetched_at=100.0, max_age=60.0))
    assert admission.is_mcp_tool_admitted(TOOL, now=160.0) is True  # exactly 60 s
    assert admission.is_mcp_tool_admitted(TOOL, now=160.1) is False
    assert admission.has_current_list(now=160.1) is False


def test_reset_goes_back_to_not_enforcing_and_forgets_the_list():
    admission.set_enforcing(True)
    admission.set_snapshot(_snapshot())
    admission.reset()
    assert admission.is_enforcing() is False
    assert admission.get_snapshot() is None


def test_a_snapshot_cannot_be_edited_after_it_is_stored():
    # Why: the answer is shared by every thread that asks; it must not change under
    # them.
    snapshot = _snapshot()
    with pytest.raises(AttributeError):
        snapshot.revision = "other"  # type: ignore[misc]
    assert isinstance(snapshot.mcp_tool_fingerprints, frozenset)
