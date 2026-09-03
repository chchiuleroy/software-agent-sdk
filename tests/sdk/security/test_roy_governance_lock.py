"""Tests for the machine-level governance lock (roy_governance_lock) and its
enforcement in ConversationConfig.

Covers: parsing ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE /
ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER (roy_governance_lock.py), and that
ConversationConfig's _apply_roy_governance_config_locks validator actually
overrides caller-supplied confirmation_policy/security_analyzer when a lock
is configured — regardless of what the caller (raw REST API, Agent Canvas
GUI request body, or ConversationSettings-derived payload) supplies.
"""

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
    # Regression test for a real finding from Codex review (2026-09-03):
    # the first version preserved a caller-supplied workspace_root when the
    # analyzer was already the right kind. But workspace_root directly
    # decides which paths count as "inside the workspace" — a caller could
    # set it to a disk root or other overly broad ancestor directory,
    # making the analyzer classify everything as LOW risk and rendering
    # the lock meaningless. The lock must always rebuild a fresh instance
    # so workspace_root is only ever derived from the conversation's real
    # workspace (via _bind_roy_analyzer_workspace below), never taken from
    # the request body.
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
    # Regression test for a real finding from Codex review (2026-09-03):
    # "not NeverConfirm" is not the same as "confirmation is actually
    # enforced" — a caller can pass a ConfirmRisky that is technically the
    # right *class* but configured weaker than the governance baseline
    # (confirm_unknown=False skips confirmation for UNKNOWN-risk actions).
    # The lock must normalize any non-AlwaysConfirm policy to the canonical
    # baseline rather than trusting the class name alone.
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
