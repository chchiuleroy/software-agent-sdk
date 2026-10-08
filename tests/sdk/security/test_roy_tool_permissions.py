"""Process-level department tool permissions and their hook in the analyzer.

The module state is process-wide on purpose (sub-agents share the process and
so inherit the parent's permissions), which means these tests must reset it,
or one test's snapshot would decide the next test's outcome.
"""

import pytest

from openhands.sdk.security import roy_tool_permissions as permissions
from openhands.sdk.security.risk import SecurityRisk
from openhands.sdk.security.roy_governance import RoyPathPayloadSecurityAnalyzer
from openhands.sdk.security.roy_tool_permissions import ToolPermissionSnapshot
from openhands.tools.file_editor.definition import FileEditorAction

from .test_roy_governance_analyzer import _event


@pytest.fixture(autouse=True)
def _reset_state():
    permissions.reset()
    yield
    permissions.reset()


def _snapshot(*tools: str, fetched_at: float = 1000.0, max_age: float = 600.0):
    return ToolPermissionSnapshot(
        tools=frozenset(tools),
        revision="r1",
        department_name="Finance",
        max_age_seconds=max_age,
        fetched_at=fetched_at,
    )


def test_everything_is_permitted_while_enforcement_is_off():
    # Why: personal mode, and a team server that has not opted in, must behave
    # exactly as before this feature existed.
    assert permissions.is_enforcing() is False
    assert permissions.is_permitted("terminal") is True
    assert permissions.denial_reason("terminal") is None


def test_nothing_fetched_means_only_the_pure_built_ins():
    # Why: fail closed. Before the first successful fetch there is no list to
    # trust, and "no list" must never read as "everything".
    permissions.set_enforcing(True)
    assert permissions.is_permitted("finish", now=1.0) is True
    assert permissions.is_permitted("think", now=1.0) is True
    assert permissions.is_permitted("terminal", now=1.0) is False
    assert "no current list" in (permissions.denial_reason("terminal") or "")


def test_only_listed_tools_are_permitted_while_the_list_is_fresh():
    permissions.set_enforcing(True)
    permissions.set_snapshot(_snapshot("file_editor", "grep"))
    assert permissions.is_permitted("file_editor", now=1100.0) is True
    assert permissions.is_permitted("terminal", now=1100.0) is False
    reason = permissions.denial_reason("terminal", now=1100.0) or ""
    assert "not permitted" in reason
    # Why: the reason goes back to the agent; it must name neither the tool
    # nor the department.
    assert "terminal" not in reason
    assert "Finance" not in reason


def test_an_expired_list_permits_nothing_but_the_pure_built_ins():
    # Why: this is what makes a revocation take effect on a device that cannot
    # reach central: it loses its permissions instead of keeping stale ones.
    permissions.set_enforcing(True)
    permissions.set_snapshot(_snapshot("file_editor", max_age=600.0))
    assert permissions.is_permitted("file_editor", now=1600.0) is True  # at the limit
    assert permissions.is_permitted("file_editor", now=1600.1) is False  # past it
    assert permissions.is_permitted("finish", now=99999.0) is True


def test_the_always_permitted_set_is_exactly_the_side_effect_free_built_ins():
    # Why: invoke_skill / switch_llm / vision_inspect read files, change the
    # model or load content; they must need an explicit grant.
    assert permissions.ALWAYS_PERMITTED == frozenset({"finish", "think"})
    permissions.set_enforcing(True)
    for name in ("invoke_skill", "switch_llm", "vision_inspect"):
        assert permissions.is_permitted(name, now=1.0) is False


def test_reset_returns_to_not_enforcing_and_forgets_the_list():
    permissions.set_enforcing(True)
    permissions.set_snapshot(_snapshot("grep"))
    permissions.reset()
    assert permissions.is_enforcing() is False
    assert permissions.get_snapshot() is None


# --- the analyzer hook ---------------------------------------------------------


def _in_workspace_edit(analyzer: RoyPathPayloadSecurityAnalyzer):
    path = analyzer.workspace_root + "/notes.txt"
    return _event("file_editor", FileEditorAction(command="view", path=path))


def test_a_harmless_in_workspace_call_stays_low_risk_when_permitted(tmp_path):
    analyzer = RoyPathPayloadSecurityAnalyzer(workspace_root=str(tmp_path))
    event = _in_workspace_edit(analyzer)
    assert analyzer.security_risk(event) == SecurityRisk.LOW

    import time

    permissions.set_enforcing(True)
    permissions.set_snapshot(_snapshot("file_editor", fetched_at=time.monotonic()))
    assert analyzer.security_risk(event) == SecurityRisk.LOW


def test_the_same_call_becomes_high_risk_when_the_tool_is_not_permitted(tmp_path):
    # Why: a LOW-risk action never reaches the approval path at all, so
    # without this it would run unchecked. HIGH forces it to the point where
    # the device refuses it.
    import time

    analyzer = RoyPathPayloadSecurityAnalyzer(workspace_root=str(tmp_path))
    event = _in_workspace_edit(analyzer)
    permissions.set_enforcing(True)
    permissions.set_snapshot(_snapshot("grep", fetched_at=time.monotonic()))
    assert analyzer.security_risk(event) == SecurityRisk.HIGH


def test_before_the_first_fetch_even_a_harmless_call_needs_confirmation(tmp_path):
    analyzer = RoyPathPayloadSecurityAnalyzer(workspace_root=str(tmp_path))
    permissions.set_enforcing(True)
    assert analyzer.security_risk(_in_workspace_edit(analyzer)) == SecurityRisk.HIGH
