"""Tests for the machine-level governance lock (roy_governance_lock) and its
enforcement in ConversationConfig.

Covers: parsing ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE /
ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER (roy_governance_lock.py), and that
ConversationConfig's _apply_roy_governance_config_locks validator actually
overrides caller-supplied confirmation_policy/security_analyzer when a lock
is configured — regardless of what the caller (raw REST API, Agent Canvas
GUI request body, or ConversationSettings-derived payload) supplies.
"""

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


def test_locked_confirmation_mode_unrecognized_value_returns_none(monkeypatch) -> None:
    # An unparseable value must not be silently treated as either direction.
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE", "maybe")
    assert roy_governance_lock.locked_confirmation_mode() is None


def test_locked_security_analyzer_unset_returns_none(monkeypatch) -> None:
    monkeypatch.delenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", raising=False)
    assert roy_governance_lock.locked_security_analyzer() is None


def test_locked_security_analyzer_parses_known_values(monkeypatch) -> None:
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "LLM")
    assert roy_governance_lock.locked_security_analyzer() == "llm"
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "none")
    assert roy_governance_lock.locked_security_analyzer() == "none"


def test_locked_security_analyzer_unrecognized_value_returns_none(monkeypatch) -> None:
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "some-other-analyzer")
    assert roy_governance_lock.locked_security_analyzer() is None


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


def test_lock_security_analyzer_llm_preserves_caller_workspace_root_override(
    monkeypatch,
) -> None:
    # The lock forces the *kind* of analyzer, not a specific instance — a
    # caller-supplied RoyPathPayloadSecurityAnalyzer with an explicit
    # workspace_root is a legitimate technical override (which directory
    # counts as safe), not a governance bypass, and must survive.
    monkeypatch.setenv("ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER", "llm")
    explicit = RoyPathPayloadSecurityAnalyzer(workspace_root="/explicit/root")

    cfg = _config(security_analyzer=explicit)

    assert cfg.security_analyzer is explicit
    assert cfg.security_analyzer.workspace_root == "/explicit/root"


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
