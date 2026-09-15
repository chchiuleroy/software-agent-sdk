"""Tests for the RBAC authorization matrix (no DB, no HTTP).

Every case names the security property it protects, not just the
expected allow/deny outcome — e.g. the self-approval tests exist to catch
a regression that would let *any* role bypass that one check, which is a
materially different failure than "the matrix has the wrong role for some
action".
"""

from __future__ import annotations

import pytest

from central_governance_api.approvals.authorize import (
    ApprovalAction,
    ApprovalOwnership,
    AuthorizationDeniedError,
    authorize_create,
    authorize_on_record,
)
from central_governance_api.auth.oidc import Principal


ISSUER = "https://keycloak.example.invalid/realms/roy-governance"


def _principal(sub: str, *roles: str) -> Principal:
    return Principal(
        issuer=ISSUER,
        sub=sub,
        display_name=sub,
        roles=frozenset(roles),
        azp=None,
    )


REQUESTER = _principal("alice")
OTHER_OPERATOR = _principal("bob", "agent.operator")
APPROVER = _principal("carol", "agent.approver")
ADMIN = _principal("dave", "governance.admin")
NO_ROLES = _principal("eve")


def _record_owned_by(principal: Principal) -> ApprovalOwnership:
    return ApprovalOwnership(requester_subject=principal.subject)


# --- CREATE --------------------------------------------------------------


@pytest.mark.parametrize(
    "principal",
    [_principal("alice", "agent.operator"), _principal("dave", "governance.admin")],
)
def test_create_allowed_for_operator_and_admin(principal):
    authorize_create(principal)  # must not raise


@pytest.mark.parametrize("principal", [APPROVER, NO_ROLES])
def test_create_denied_without_operator_or_admin_role(principal):
    with pytest.raises(AuthorizationDeniedError) as exc_info:
        authorize_create(principal)
    assert exc_info.value.action is ApprovalAction.CREATE


# --- DECIDE ----------------------------------------------------------------


def test_decide_allowed_for_approver_on_someone_elses_request():
    record = _record_owned_by(REQUESTER)
    authorize_on_record(APPROVER, ApprovalAction.DECIDE, record)


def test_decide_allowed_for_admin_on_someone_elses_request():
    record = _record_owned_by(REQUESTER)
    authorize_on_record(ADMIN, ApprovalAction.DECIDE, record)


def test_decide_denied_for_plain_operator_role():
    """agent.operator alone (no approver, no admin) must not be able to
    decide — only create/claim/report/cancel their own requests."""
    record = _record_owned_by(REQUESTER)
    with pytest.raises(AuthorizationDeniedError):
        authorize_on_record(OTHER_OPERATOR, ApprovalAction.DECIDE, record)


def test_self_approval_denied_for_approver():
    """The requester holding agent.approver may not decide their own
    request — this is the core privilege-escalation guard the whole
    identity-aware self-approval feature exists for."""
    self_approver = _principal("alice", "agent.approver")
    record = _record_owned_by(self_approver)
    with pytest.raises(AuthorizationDeniedError) as exc_info:
        authorize_on_record(self_approver, ApprovalAction.DECIDE, record)
    assert "self-approval" in exc_info.value.reason


def test_self_approval_denied_even_for_governance_admin():
    """No role bypasses self-approval, including governance.admin — an
    admin approving their own request would be the same privilege
    escalation with extra steps."""
    self_admin = _principal("alice", "governance.admin")
    record = _record_owned_by(self_admin)
    with pytest.raises(AuthorizationDeniedError) as exc_info:
        authorize_on_record(self_admin, ApprovalAction.DECIDE, record)
    assert "self-approval" in exc_info.value.reason


# --- CLAIM / REPORT_RESULT --------------------------------------------------


@pytest.mark.parametrize("action", [ApprovalAction.CLAIM, ApprovalAction.REPORT_RESULT])
def test_claim_and_report_result_allowed_for_owning_operator(action):
    requester = _principal("alice", "agent.operator")
    record = _record_owned_by(requester)
    authorize_on_record(requester, action, record)


@pytest.mark.parametrize("action", [ApprovalAction.CLAIM, ApprovalAction.REPORT_RESULT])
def test_claim_and_report_result_denied_for_non_owning_operator(action):
    record = _record_owned_by(REQUESTER)
    with pytest.raises(AuthorizationDeniedError) as exc_info:
        authorize_on_record(OTHER_OPERATOR, action, record)
    assert "owner" in exc_info.value.reason


@pytest.mark.parametrize("action", [ApprovalAction.CLAIM, ApprovalAction.REPORT_RESULT])
def test_claim_and_report_result_have_no_admin_bypass(action):
    """Design decision: execution is device-bound (Track 1: 分散執行、
    集中治理), so governance.admin cannot claim or report on someone
    else's request even though it can decide or cancel it — an admin
    can't make a different principal's device execute an action. If this
    test starts failing because someone "fixed" claim/report to allow
    admin, that regression should be caught here, not discovered in
    production as an admin token being able to move another user's
    approved action.
    """
    record = _record_owned_by(REQUESTER)
    with pytest.raises(AuthorizationDeniedError):
        authorize_on_record(ADMIN, action, record)


@pytest.mark.parametrize("action", [ApprovalAction.CLAIM, ApprovalAction.REPORT_RESULT])
def test_claim_and_report_result_denied_for_approver(action):
    record = _record_owned_by(REQUESTER)
    with pytest.raises(AuthorizationDeniedError):
        authorize_on_record(APPROVER, action, record)


# --- CANCEL ------------------------------------------------------------------


def test_cancel_allowed_for_owning_operator():
    requester = _principal("alice", "agent.operator")
    record = _record_owned_by(requester)
    authorize_on_record(requester, ApprovalAction.CANCEL, record)


def test_cancel_allowed_for_admin_as_kill_switch():
    """Unlike claim/report-result, cancel doesn't require executing
    anything on anyone's behalf, so the admin bypass is kept — an admin
    can cancel a stuck or suspicious pending request without needing to
    impersonate the requester's device."""
    record = _record_owned_by(REQUESTER)
    authorize_on_record(ADMIN, ApprovalAction.CANCEL, record)


def test_cancel_denied_for_non_owning_operator():
    record = _record_owned_by(REQUESTER)
    with pytest.raises(AuthorizationDeniedError):
        authorize_on_record(OTHER_OPERATOR, ApprovalAction.CANCEL, record)


def test_cancel_denied_for_approver():
    record = _record_owned_by(REQUESTER)
    with pytest.raises(AuthorizationDeniedError):
        authorize_on_record(APPROVER, ApprovalAction.CANCEL, record)


# --- RECONCILIATION FINDINGS -------------------------------------------------


def test_reconcile_as_admin_allowed_only_for_admin():
    record = _record_owned_by(REQUESTER)
    authorize_on_record(ADMIN, ApprovalAction.RECONCILE_AS_ADMIN, record)


def test_reconcile_as_admin_denied_for_owning_operator():
    """The requester cannot self-certify an admin_verified finding just
    by also owning the request — admin_verified must come from someone
    holding governance.admin, otherwise the distinction between
    requester_assertion and admin_verified is meaningless."""
    requester = _principal("alice", "agent.operator")
    record = _record_owned_by(requester)
    with pytest.raises(AuthorizationDeniedError):
        authorize_on_record(requester, ApprovalAction.RECONCILE_AS_ADMIN, record)


def test_reconcile_as_requester_allowed_for_owning_operator():
    requester = _principal("alice", "agent.operator")
    record = _record_owned_by(requester)
    authorize_on_record(requester, ApprovalAction.RECONCILE_AS_REQUESTER, record)


def test_reconcile_as_requester_denied_for_non_owner():
    record = _record_owned_by(REQUESTER)
    with pytest.raises(AuthorizationDeniedError):
        authorize_on_record(
            OTHER_OPERATOR, ApprovalAction.RECONCILE_AS_REQUESTER, record
        )


def test_reconcile_as_requester_allowed_for_admin_too():
    record = _record_owned_by(REQUESTER)
    authorize_on_record(ADMIN, ApprovalAction.RECONCILE_AS_REQUESTER, record)


def test_reconcile_as_requester_denied_for_approver():
    record = _record_owned_by(REQUESTER)
    with pytest.raises(AuthorizationDeniedError):
        authorize_on_record(APPROVER, ApprovalAction.RECONCILE_AS_REQUESTER, record)


def test_reconcile_as_requester_denied_for_no_roles():
    record = _record_owned_by(REQUESTER)
    with pytest.raises(AuthorizationDeniedError):
        authorize_on_record(NO_ROLES, ApprovalAction.RECONCILE_AS_REQUESTER, record)


# --- RECONCILE_LATE_REPORT ----------------------------------------------
#
# Kept authorization-identical to CLAIM/REPORT_RESULT (operator + owner,
# no admin bypass) but as its own action rather than folded into
# RECONCILE_AS_REQUESTER — see authorize.py module docstring design
# decision 3. These tests exist specifically to catch a regression back
# to the folded-in version code review flagged: admin must NOT be able to
# file a late_report finding, because admin is definitionally not the
# original execution endpoint a late report claims to be.


def test_reconcile_late_report_allowed_for_owning_operator():
    requester = _principal("alice", "agent.operator")
    record = _record_owned_by(requester)
    authorize_on_record(requester, ApprovalAction.RECONCILE_LATE_REPORT, record)


def test_reconcile_late_report_denied_for_non_owner():
    record = _record_owned_by(REQUESTER)
    with pytest.raises(AuthorizationDeniedError) as exc_info:
        authorize_on_record(
            OTHER_OPERATOR, ApprovalAction.RECONCILE_LATE_REPORT, record
        )
    assert "owner" in exc_info.value.reason


def test_reconcile_late_report_has_no_admin_bypass():
    """The one test this whole action exists to make possible — admin
    filing a late_report would misrepresent the finding's evidence
    source as coming from the original execution endpoint."""
    record = _record_owned_by(REQUESTER)
    with pytest.raises(AuthorizationDeniedError):
        authorize_on_record(ADMIN, ApprovalAction.RECONCILE_LATE_REPORT, record)


def test_reconcile_late_report_denied_for_approver():
    record = _record_owned_by(REQUESTER)
    with pytest.raises(AuthorizationDeniedError):
        authorize_on_record(APPROVER, ApprovalAction.RECONCILE_LATE_REPORT, record)


# --- Owning the request is not enough without the right role -----------
#
# A principal whose `sub` happens to match `requester_subject` but who
# lost (or never had) `agent.operator` must still be denied — ownership
# alone is not a role. This matters concretely: `governance.admin` is
# also, separately, tested below to confirm holding an *extra* role on
# top of `agent.operator` does not turn into a blanket bypass for actions
# that check ownership.


@pytest.mark.parametrize(
    "action",
    [
        ApprovalAction.CLAIM,
        ApprovalAction.REPORT_RESULT,
        ApprovalAction.CANCEL,
        ApprovalAction.RECONCILE_AS_REQUESTER,
        ApprovalAction.RECONCILE_LATE_REPORT,
    ],
)
def test_owner_without_operator_role_is_still_denied(action):
    owner_no_role = _principal("alice")  # same sub as REQUESTER, no roles
    record = _record_owned_by(owner_no_role)
    with pytest.raises(AuthorizationDeniedError) as exc_info:
        authorize_on_record(owner_no_role, action, record)
    assert "requires role" in exc_info.value.reason


@pytest.mark.parametrize("action", [ApprovalAction.CLAIM, ApprovalAction.REPORT_RESULT])
def test_admin_plus_operator_role_still_requires_ownership(action):
    """Holding governance.admin *in addition to* agent.operator must not
    silently become "any admin-looking token bypasses ownership" —
    claim/report-result's admin-less design (decision 1) has to survive
    a principal who happens to also hold agent.operator.
    """
    admin_and_operator = _principal("dave", "governance.admin", "agent.operator")
    record = _record_owned_by(REQUESTER)  # owned by alice, not dave
    with pytest.raises(AuthorizationDeniedError) as exc_info:
        authorize_on_record(admin_and_operator, action, record)
    assert "owner" in exc_info.value.reason


# --- CREATE must go through authorize_create(), not authorize_on_record() --


def test_create_via_authorize_on_record_raises_programmer_error():
    record = _record_owned_by(REQUESTER)
    with pytest.raises(ValueError):
        authorize_on_record(ADMIN, ApprovalAction.CREATE, record)
