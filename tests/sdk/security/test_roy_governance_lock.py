"""Tests for the machine-level governance lock (roy_governance_lock) and its
enforcement in ConversationConfig.

Covers: parsing ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE /
ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER (roy_governance_lock.py), and that
ConversationConfig's _apply_roy_governance_config_locks validator actually
overrides caller-supplied confirmation_policy/security_analyzer when a lock
is configured — regardless of what the caller (raw REST API, Agent Canvas
GUI request body, or ConversationSettings-derived payload) supplies.
"""

import json

import pytest

from openhands.sdk.conversation.request import (
    ConversationConfig,
    StartConversationRequest,
)
from openhands.sdk.security import roy_governance_lock
from openhands.sdk.security.confirmation_policy import (
    AlwaysConfirm,
    ConfirmRisky,
    NeverConfirm,
)
from openhands.sdk.security.roy_governance import RoyPathPayloadSecurityAnalyzer
from openhands.sdk.workspace import LocalWorkspace


# --- roy_governance_lock parsing --------------------------------------------


def test_locked_confirmation_mode_unset_returns_none(monkeypatch) -> None:
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", raising=False)
    assert roy_governance_lock.locked_confirmation_mode() is None


def test_locked_confirmation_mode_parses_true_variants(monkeypatch) -> None:
    for value in ("true", "True", "1", "yes"):
        monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", value)
        assert roy_governance_lock.locked_confirmation_mode() is True


def test_locked_confirmation_mode_parses_false_variants(monkeypatch) -> None:
    for value in ("false", "False", "0", "no"):
        monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", value)
        assert roy_governance_lock.locked_confirmation_mode() is False


def test_locked_confirmation_mode_unrecognized_value_raises(monkeypatch) -> None:
    # A set-but-unparseable value must fail loudly, not be silently treated
    # as "unlocked" — this is a governance boundary, and a deployment typo
    # silently disabling protection is exactly the failure mode to avoid.
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", "maybe")
    with pytest.raises(ValueError, match="ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE"):
        roy_governance_lock.locked_confirmation_mode()


def test_locked_security_analyzer_unset_returns_none(monkeypatch) -> None:
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", raising=False)
    assert roy_governance_lock.locked_security_analyzer() is None


def test_locked_security_analyzer_parses_known_values(monkeypatch) -> None:
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "LLM")
    assert roy_governance_lock.locked_security_analyzer() == "llm"
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "none")
    assert roy_governance_lock.locked_security_analyzer() == "none"


def test_locked_security_analyzer_unrecognized_value_raises(monkeypatch) -> None:
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "some-other-analyzer")
    with pytest.raises(ValueError, match="ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER"):
        roy_governance_lock.locked_security_analyzer()


# --- ConversationConfig enforcement ------------------------------------------


def _config(**overrides):
    return ConversationConfig(workspace=LocalWorkspace(working_dir="."), **overrides)


def test_no_lock_leaves_caller_choices_untouched(monkeypatch) -> None:
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", raising=False)
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", raising=False)

    cfg = _config(confirmation_policy=NeverConfirm(), security_analyzer=None)

    assert isinstance(cfg.confirmation_policy, NeverConfirm)
    assert cfg.security_analyzer is None


def test_lock_security_analyzer_none_overrides_caller_supplied_analyzer(
    monkeypatch,
) -> None:
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "none")

    cfg = _config(security_analyzer=RoyPathPayloadSecurityAnalyzer())

    assert cfg.security_analyzer is None


def test_lock_security_analyzer_llm_overrides_caller_supplied_none(
    monkeypatch,
) -> None:
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "llm")

    cfg = _config(security_analyzer=None)

    assert isinstance(cfg.security_analyzer, RoyPathPayloadSecurityAnalyzer)


def test_lock_security_analyzer_llm_discards_caller_workspace_root_override(
    monkeypatch,
) -> None:
    # workspace_root decides which paths count as "inside the workspace" —
    # an overly broad caller-supplied root would render the lock
    # meaningless, so it must always be discarded and rederived.
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "llm")
    overly_broad = RoyPathPayloadSecurityAnalyzer(workspace_root="/")

    cfg = _config(security_analyzer=overly_broad)

    assert cfg.security_analyzer is not overly_broad
    assert cfg.security_analyzer.workspace_root != "/"


def test_lock_security_analyzer_llm_still_binds_workspace_root_when_defaulted(
    monkeypatch,
) -> None:
    # Regression guard for validator ordering: if the lock constructs a
    # fresh RoyPathPayloadSecurityAnalyzer, the existing
    # _bind_roy_analyzer_workspace validator must still run afterwards and
    # bind it to this conversation's actual workspace.
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "llm")

    cfg = ConversationConfig(
        workspace=LocalWorkspace(working_dir="/custom/workspace"),
        security_analyzer=None,
    )

    assert cfg.security_analyzer.workspace_root == "/custom/workspace"


def test_lock_confirmation_mode_on_upgrades_never_confirm(monkeypatch) -> None:
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", "true")

    cfg = _config(confirmation_policy=NeverConfirm())

    assert isinstance(cfg.confirmation_policy, ConfirmRisky)


def test_lock_confirmation_mode_on_normalizes_weaker_confirm_risky(monkeypatch) -> None:
    # A ConfirmRisky with confirm_unknown=False is the right class but
    # weaker than the governance baseline — the lock must normalize it,
    # not just check the class name.
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", "true")
    weaker = ConfirmRisky(confirm_unknown=False)

    cfg = _config(confirmation_policy=weaker)

    assert cfg.confirmation_policy is not weaker
    assert isinstance(cfg.confirmation_policy, ConfirmRisky)
    assert cfg.confirmation_policy.confirm_unknown is True


def test_lock_confirmation_mode_on_preserves_stricter_caller_choice(
    monkeypatch,
) -> None:
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", "true")

    cfg = _config(confirmation_policy=AlwaysConfirm())

    assert isinstance(cfg.confirmation_policy, AlwaysConfirm)


def test_lock_confirmation_mode_off_overrides_caller_choice(monkeypatch) -> None:
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", "false")

    cfg = _config(confirmation_policy=AlwaysConfirm())

    assert isinstance(cfg.confirmation_policy, NeverConfirm)


def test_lock_applies_through_start_conversation_request_subclass(monkeypatch) -> None:
    # StartConversationRequest is what the agent-server actually parses
    # GUI/REST request bodies as — confirm the lock applies there too, not
    # just on the bare ConversationConfig base class.
    from pydantic import SecretStr

    from openhands.sdk.agent.agent import Agent
    from openhands.sdk.llm import LLM

    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", "false")

    request = StartConversationRequest(
        workspace=LocalWorkspace(working_dir="."),
        agent=Agent(
            llm=LLM(model="gpt-4o", api_key=SecretStr("x"), usage_id="t"), tools=[]
        ),
        confirmation_policy=AlwaysConfirm(),
    )

    assert isinstance(request.confirmation_policy, NeverConfirm)


# --- LocalConversation setter enforcement ------------------------------------
#
# Regression tests for the review finding that the initial lock only
# protected conversation *creation* (the request-model layer above): the
# agent-server's runtime confirmation_policy/security_analyzer update REST
# endpoints and the conversation resume path both call
# LocalConversation.set_confirmation_policy()/set_security_analyzer()
# directly, bypassing ConversationConfig's validator entirely. The fix
# pushes the same apply_*_lock() functions into those setters themselves, so
# every caller — REST endpoint, resume, or any future one — is protected
# without needing to be individually patched.


def _local_conversation(tmp_path):
    from pydantic import SecretStr

    from openhands.sdk.agent.agent import Agent
    from openhands.sdk.conversation import Conversation
    from openhands.sdk.llm import LLM

    llm = LLM(model="gpt-4o", api_key=SecretStr("x"), usage_id="test")
    agent = Agent(llm=llm, tools=[])
    return Conversation(agent=agent, workspace=str(tmp_path))


def test_set_confirmation_policy_enforces_lock(monkeypatch, tmp_path) -> None:
    # Simulates the runtime REST endpoint / resume bypass the review found:
    # this calls the setter directly, the same way
    # agent_server/conversation_router.py's confirmation_policy endpoint and
    # event_service.py's resume path do — not via ConversationConfig at all.
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", "true")
    conversation = _local_conversation(tmp_path)

    conversation.set_confirmation_policy(NeverConfirm())

    assert isinstance(conversation.state.confirmation_policy, ConfirmRisky)


def test_set_confirmation_policy_no_lock_is_unaffected(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", raising=False)
    conversation = _local_conversation(tmp_path)

    conversation.set_confirmation_policy(NeverConfirm())

    assert isinstance(conversation.state.confirmation_policy, NeverConfirm)


def test_set_security_analyzer_enforces_lock(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "none")
    conversation = _local_conversation(tmp_path)

    conversation.set_security_analyzer(RoyPathPayloadSecurityAnalyzer())

    assert conversation.state.security_analyzer is None


def test_set_security_analyzer_lock_discards_wide_workspace_root(
    monkeypatch, tmp_path
) -> None:
    # The same workspace_root bypass the review found for the creation-time
    # lock, exercised at the setter instead.
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "llm")
    conversation = _local_conversation(tmp_path)

    conversation.set_security_analyzer(
        RoyPathPayloadSecurityAnalyzer(workspace_root="/")
    )

    assert conversation.state.security_analyzer.workspace_root != "/"
    assert conversation.state.security_analyzer.workspace_root == str(tmp_path)


def test_fresh_conversation_applies_lock_at_construction(monkeypatch, tmp_path) -> None:
    # A raw SDK Conversation(...) call never invokes
    # set_confirmation_policy()/set_security_analyzer(), so the initial
    # state must be canonicalized independently of those setters.
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", "true")
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "llm")

    conversation = _local_conversation(tmp_path)

    assert isinstance(conversation.state.confirmation_policy, ConfirmRisky)
    assert isinstance(
        conversation.state.security_analyzer, RoyPathPayloadSecurityAnalyzer
    )
    assert conversation.state.security_analyzer.workspace_root == str(tmp_path)


def test_resumed_conversation_applies_lock_to_persisted_state(
    monkeypatch, tmp_path
) -> None:
    # A conversation persisted before any lock was configured (weak
    # NeverConfirm/no-analyzer state) must be canonicalized when resumed
    # after a lock is turned on — not just at fresh construction.
    from pydantic import SecretStr

    from openhands.sdk.agent.agent import Agent
    from openhands.sdk.conversation import LocalConversation
    from openhands.sdk.llm import LLM

    persistence_dir = tmp_path / "persistence"
    workspace_dir = tmp_path / "workspace"
    llm = LLM(model="gpt-4o", api_key=SecretStr("x"), usage_id="test")

    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", raising=False)
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", raising=False)
    first = LocalConversation(
        agent=Agent(llm=llm, tools=[]),
        workspace=str(workspace_dir),
        persistence_dir=str(persistence_dir),
        visualizer=None,
    )
    conversation_id = first.state.id
    assert isinstance(first.state.confirmation_policy, NeverConfirm)
    assert first.state.security_analyzer is None
    first.close()

    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", "true")
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "llm")
    resumed = LocalConversation(
        agent=None,
        workspace=str(workspace_dir),
        persistence_dir=str(persistence_dir),
        conversation_id=conversation_id,
        visualizer=None,
    )

    assert isinstance(resumed.state.confirmation_policy, ConfirmRisky)
    assert isinstance(resumed.state.security_analyzer, RoyPathPayloadSecurityAnalyzer)
    resumed.close()


# --- admin_audit content coverage --------------------------------------------
#
# Regression tests for the review finding that set_confirmation_policy()/
# set_security_analyzer() (and the constructor's initial-state application)
# wrote an admin_audit record unconditionally — even on a resume/init call
# that re-applies an already-current value, which is not an admin changing
# anything. The fix (_apply_and_audit_confirmation_policy/
# _apply_and_audit_security_analyzer in local_conversation.py) only writes
# when the effective value actually changed.


def _read_admin_audit_records(audit_dir) -> list[dict]:
    path = audit_dir / "admin_audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_set_confirmation_policy_writes_admin_audit_when_changed(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", raising=False)
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _local_conversation(tmp_path)

    conversation.set_confirmation_policy(AlwaysConfirm())

    records = [
        r
        for r in _read_admin_audit_records(audit_dir)
        if r["field"] == "confirmation_policy"
    ]
    assert len(records) == 1
    assert records[0]["value"] == repr(AlwaysConfirm())


def test_set_confirmation_policy_skips_admin_audit_when_unchanged(
    monkeypatch, tmp_path
) -> None:
    # Simulates the agent server's resume/init path, which always calls this
    # setter with the persisted value — re-applying an unchanged value is not
    # an admin action and must not produce a spurious record.
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", raising=False)
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _local_conversation(tmp_path)
    default_policy = conversation.state.confirmation_policy

    conversation.set_confirmation_policy(default_policy)

    assert _read_admin_audit_records(audit_dir) == []


def test_set_security_analyzer_writes_admin_audit_when_changed(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", raising=False)
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _local_conversation(tmp_path)

    conversation.set_security_analyzer(RoyPathPayloadSecurityAnalyzer())

    records = [
        r
        for r in _read_admin_audit_records(audit_dir)
        if r["field"] == "security_analyzer"
    ]
    assert len(records) == 1


def test_set_security_analyzer_skips_admin_audit_when_unchanged(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", raising=False)
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _local_conversation(tmp_path)

    conversation.set_security_analyzer(None)  # SDK default is already None

    assert _read_admin_audit_records(audit_dir) == []


def test_fresh_conversation_with_lock_writes_admin_audit_at_construction(
    monkeypatch, tmp_path
) -> None:
    # Regression guard for the review finding that raw SDK construction's
    # initial lock application bypassed admin_audit entirely (it mutated
    # self._state directly instead of going through an audited helper).
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", "true")
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))

    _local_conversation(tmp_path)

    records = [
        r
        for r in _read_admin_audit_records(audit_dir)
        if r["field"] == "confirmation_policy"
    ]
    assert len(records) == 1


def test_fresh_conversation_without_lock_writes_no_admin_audit(
    monkeypatch, tmp_path
) -> None:
    # No lock configured means the constructor's lock application is a no-op
    # (SDK default in, same value out) — must not look like an admin change.
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", raising=False)
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", raising=False)
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))

    _local_conversation(tmp_path)

    assert _read_admin_audit_records(audit_dir) == []
