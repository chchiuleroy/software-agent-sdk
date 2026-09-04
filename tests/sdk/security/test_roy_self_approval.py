"""Unit tests for roy_self_approval.py's pure functions.

Integration coverage (run()/arun()/reject_pending_actions() actually calling
these) lives in test_roy_user_approval_audit.py, next to the audit-writing
tests they share fixtures with.
"""

import pytest

from openhands.sdk.security.roy_self_approval import (
    SelfApprovalDeniedError,
    check_not_self_approval,
    requester_identity_for_conversation,
)


def test_requester_identity_unset_returns_none(monkeypatch):
    monkeypatch.delenv("ROY_GOVERNANCE_IDENTITY", raising=False)
    assert requester_identity_for_conversation() is None


def test_requester_identity_reads_env_var(monkeypatch):
    monkeypatch.setenv("ROY_GOVERNANCE_IDENTITY", "roy")
    assert requester_identity_for_conversation() == "roy"


def test_requester_identity_blank_after_strip_treated_as_unset(monkeypatch):
    # A whitespace-only value is as good as unset — don't let a stray
    # ROY_GOVERNANCE_IDENTITY="   " silently make every check_not_self_approval
    # call a no-op for a different, confusing reason (empty-string equality).
    monkeypatch.setenv("ROY_GOVERNANCE_IDENTITY", "   ")
    assert requester_identity_for_conversation() is None


def test_check_allows_when_requester_is_none():
    # Fail-open: no ROY_GOVERNANCE_IDENTITY on this machine means nothing to
    # compare against, regardless of what the caller claims as approver.
    check_not_self_approval(None, "roy")


def test_check_allows_when_approver_is_none():
    # Fail-open: today's Agent Canvas GUI never sends approver_identity.
    check_not_self_approval("roy", None)


def test_check_allows_different_identities():
    check_not_self_approval("roy", "test-approver")


def test_check_blocks_identical_identities():
    with pytest.raises(ValueError, match="self-approval not allowed"):
        check_not_self_approval("roy", "roy")


def test_check_blocks_case_and_whitespace_insensitive_match():
    with pytest.raises(ValueError, match="self-approval not allowed"):
        check_not_self_approval("Roy", "  roy  ")


def test_check_blocks_with_specific_error_type():
    # api.py registers a FastAPI handler on this specific subclass (not on
    # ValueError generally) to map a blocked self-approval to a clean 403 —
    # confirm the raised type is actually this subclass, not a bare
    # ValueError that would fall through to the generic 500 handler.
    with pytest.raises(SelfApprovalDeniedError):
        check_not_self_approval("roy", "roy")
