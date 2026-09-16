"""RBAC authorization matrix for approval-workflow actions.

v11 §11 step 2 (second half — "RBAC 授權矩陣"). Deliberately separate from
``auth/dependencies.py``'s ``require_role()``: that dependency only
answers "does this principal hold role X at all", which is enough for a
role-only endpoint (reading audit events) but not for an action scoped to
one specific ``PendingApprovalRecord``, where the *same* role
(``agent.operator``) is allowed on your own request and denied on someone
else's. FastAPI dependency injection resolves before a handler has loaded
the record from the DB, so "load the record, then check ownership" can't
be expressed as a bare ``Depends(require_role(...))`` chain — this module
is called explicitly inside each router handler once it has the record.

Zero SQLAlchemy/FastAPI imports by design, so the whole matrix is unit-
testable without a DB or an HTTP request — see :class:`ApprovalOwnership`,
a plain dataclass carrying only the facts an authorization decision
actually needs, not the ORM row.

Design decisions below are reconstructed from the wiki narrative of the
v11 review, not copied verbatim from the (uncommitted, scratchpad-only)
design document. The first round of this module was code-reviewed
(``codex exec --sandbox read-only``, read-only, no files touched) before
any DB/router code was built on top of it; findings from that review are
folded in directly below rather than kept as a separate changelog.

1. **CLAIM and REPORT_RESULT have no ``governance.admin`` bypass.**
   Every other action lets ``governance.admin`` act on anyone's record,
   but claiming/reporting execution is inherently tied to *whose device is
   actually going to run the action* — this is the core premise of the
   "Track 1: 分散執行、集中治理" architecture pivot (each principal's own
   agent-server executes; the central API only ever decides, audits, and
   arbitrates). An admin "claiming" someone else's approved action would
   mean the admin's own device somehow executes a tool call defined by
   another principal's conversation/workspace context, which the
   distributed-execution architecture doesn't support at all.

   Review correction: the reasoning above is about *requester identity*,
   not actual device binding — ``ApprovalOwnership`` only carries the
   requester's ``(issuer, sub)``, and ``DeviceRegistration`` (models.py)
   is explicitly documented as "not a cryptographic device proof". So
   what this module actually guarantees is narrower than "only the
   originating device can execute": it's "only a principal holding
   ``agent.operator`` whose *identity* matches the requester's can
   claim/report" — the same principal authenticated from a second device
   would still pass.
   If "must be the literal originating device" ever becomes a real
   requirement, it needs its own check against ``origin_device_id`` at
   the router layer; this module doesn't attempt it. A device going
   offline mid-flight is NOT a reason to add an admin bypass here either
   — the safe recovery paths are (a) before claim: wait for
   ``execution_deadline`` to lapse (→ EXPIRED) or design an explicit,
   audited admin reassignment/requeue transition that rebinds the
   execution context, not a silent bypass; (b) after claim: lease expiry
   already fails closed to ``failed_unknown`` (see state_machine.py); (c)
   an admin who wants to assert what actually happened does so through
   ``RECONCILE_AS_ADMIN`` (evidence), never by impersonating the
   requester's own report.
2. **CANCEL keeps the admin bypass** (kill-switch for a stuck or
   suspicious pending request) since cancelling doesn't require executing
   anything on anyone's behalf.
3. **``late_report`` gets its own authorization path,
   :data:`ApprovalAction.RECONCILE_LATE_REPORT` — NOT folded into
   ``RECONCILE_AS_REQUESTER``.** An earlier version of this module folded
   it in on the reasoning that "a late report is still fundamentally the
   requester's own device eventually reporting what happened", but review
   caught that ``RECONCILE_AS_REQUESTER`` also accepts ``governance.admin``
   — and admin is definitionally *not* the original execution endpoint,
   so letting admin through the same path as a late report lets the
   finding's ``finding_type`` misrepresent its own evidence source. The
   two are kept authorization-identical on purpose (operator + owner
   only, no admin bypass — the same shape as CLAIM/REPORT_RESULT, for the
   same reason: this is the requester's own device speaking, nobody
   else's) but as a distinct action so a router mistake can't silently
   let an admin file something the wire format claims came from the
   requester. Content-level checks this module can't do — a late report
   should reference the record's actual ``execution_attempt_id`` and only
   be legal from a record that actually reached ``failed_unknown`` — are
   the router/state-machine layer's job, not this one's; this module only
   answers "may this principal attempt to file this kind of finding at
   all".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from central_governance_api.auth.oidc import Principal


class ApprovalAction(StrEnum):
    CREATE = "create"
    DECIDE = "decide"
    CLAIM = "claim"
    REPORT_RESULT = "report_result"
    CANCEL = "cancel"
    WAIT = "wait"
    RECONCILE_AS_REQUESTER = "reconcile_as_requester"
    RECONCILE_AS_ADMIN = "reconcile_as_admin"
    RECONCILE_LATE_REPORT = "reconcile_late_report"


class AuthorizationDeniedError(Exception):
    """Callers map this to HTTP 403. Carries a stable, machine-readable
    ``reason`` (rather than requiring callers to string-match the message)
    so routers and tests don't depend on prose wording."""

    def __init__(self, *, action: ApprovalAction, reason: str) -> None:
        self.action = action
        self.reason = reason
        super().__init__(f"{action.value} denied: {reason}")


@dataclass(frozen=True)
class ApprovalOwnership:
    """The minimal ownership fact an authorization decision needs.

    Deliberately not the ORM row itself, so this module never imports
    SQLAlchemy: a router builds one of these from a loaded
    ``PendingApprovalRecord``'s ``requester_issuer``/``requester_sub``
    columns once it has the row. Two fields, not one concatenated string
    — ``(issuer, sub)`` is the actual OIDC identity key; see
    ``auth/oidc.py``'s ``Principal.subject`` docstring on why the
    concatenated string form isn't meant for security-relevant
    comparisons (code-review finding, fixed 2026-09-15 — this dataclass
    used to be exactly that concatenated-string mistake).
    """

    requester_issuer: str
    requester_sub: str


def authorize_create(principal: Principal) -> None:
    """CREATE has no record yet, so there is nothing to own — governance.admin
    and agent.operator may both submit a new approval request. The
    resulting row's ``requester_issuer``/``requester_sub`` must always be
    set to ``principal.issuer``/``principal.sub`` server-side by the
    caller; this function does not (and cannot) enforce that — it only
    answers "may this principal create at all".
    """
    if "governance.admin" in principal.roles or "agent.operator" in principal.roles:
        return
    raise AuthorizationDeniedError(
        action=ApprovalAction.CREATE,
        reason="requires role governance.admin or agent.operator",
    )


def authorize_on_record(
    principal: Principal,
    action: ApprovalAction,
    record: ApprovalOwnership,
) -> None:
    """Authorize an action against an existing record. Raises
    :class:`AuthorizationDeniedError` if not allowed; returns ``None`` if
    allowed. Use :func:`authorize_create` for ``ApprovalAction.CREATE``
    instead — that action has no record to check ownership against.

    This function only decides *who may attempt* the action — whether the
    record's current ``status`` actually supports it is a separate
    question answered by ``approvals.state_machine.next_status()``. A
    request can be authorized here and still get 409 Conflict from the
    state machine (e.g. an ``agent.approver`` who is allowed to decide,
    attempting to decide a request someone already decided).
    """
    if action is ApprovalAction.CREATE:
        raise ValueError("authorize_create() handles CREATE, not this function")

    is_admin = "governance.admin" in principal.roles
    is_owner = (principal.issuer, principal.sub) == (
        record.requester_issuer,
        record.requester_sub,
    )

    if action is ApprovalAction.DECIDE:
        if not (is_admin or "agent.approver" in principal.roles):
            raise AuthorizationDeniedError(
                action=action,
                reason="requires role governance.admin or agent.approver",
            )
        if is_owner:
            # Self-approval is denied unconditionally, including for
            # governance.admin — this is the one check no role can bypass,
            # matching the existing identity-aware self-approval design
            # this service supersedes for the multi-principal case (see
            # wiki "Identity-aware self-approval 落地實作" — same
            # invariant, now server-verified instead of cooperative).
            raise AuthorizationDeniedError(
                action=action, reason="self-approval is not allowed"
            )
        return

    if action in (ApprovalAction.CLAIM, ApprovalAction.REPORT_RESULT):
        # No admin bypass — see module docstring, design decision 1.
        if "agent.operator" not in principal.roles:
            raise AuthorizationDeniedError(
                action=action, reason="requires role agent.operator"
            )
        if not is_owner:
            raise AuthorizationDeniedError(
                action=action, reason="not this request's owner"
            )
        return

    if action is ApprovalAction.WAIT:
        # Step 3 (v11 §11) addition — not attested in the recovered v11
        # narrative at all (it never got far enough to describe /wait's
        # authorization), so this is reasoned from first principles rather
        # than reconstructed from lost text. Reading/blocking on a
        # record's status is strictly less sensitive than any action that
        # changes it, so this is deliberately the widest-open check in
        # this module: governance.admin (oversight), any agent.approver
        # (the class of principals entitled to decide ANY record, so
        # entitled to check whether someone already beat them to it), or
        # the record's own owner holding agent.operator (the same
        # role/ownership pairing CLAIM/REPORT_RESULT require — the owner's
        # own agent-server, waiting to learn when to proceed to CLAIM, is
        # /wait's primary intended caller; see approvals/notify.py).
        if is_admin or "agent.approver" in principal.roles:
            return
        if "agent.operator" in principal.roles and is_owner:
            return
        raise AuthorizationDeniedError(
            action=action,
            reason="requires role governance.admin or agent.approver, or "
            "agent.operator on your own request",
        )

    if action is ApprovalAction.CANCEL:
        if is_admin:
            return
        if "agent.operator" not in principal.roles:
            raise AuthorizationDeniedError(
                action=action,
                reason="requires role governance.admin or agent.operator",
            )
        if not is_owner:
            raise AuthorizationDeniedError(
                action=action, reason="not this request's owner"
            )
        return

    if action is ApprovalAction.RECONCILE_AS_ADMIN:
        if is_admin:
            return
        raise AuthorizationDeniedError(
            action=action, reason="requires role governance.admin"
        )

    if action is ApprovalAction.RECONCILE_AS_REQUESTER:
        if is_admin:
            return
        if "agent.operator" not in principal.roles:
            raise AuthorizationDeniedError(
                action=action,
                reason="requires role governance.admin or agent.operator",
            )
        if not is_owner:
            raise AuthorizationDeniedError(
                action=action, reason="not this request's owner"
            )
        return

    if action is ApprovalAction.RECONCILE_LATE_REPORT:
        # No admin bypass — see module docstring, design decision 3. A
        # late report claims to be the requester's own execution endpoint
        # speaking; admin filing one under this action would misrepresent
        # the finding's evidence source. An admin who wants to assert
        # something uses RECONCILE_AS_ADMIN instead.
        if "agent.operator" not in principal.roles:
            raise AuthorizationDeniedError(
                action=action, reason="requires role agent.operator"
            )
        if not is_owner:
            raise AuthorizationDeniedError(
                action=action, reason="not this request's owner"
            )
        return

    raise AssertionError(f"unhandled action: {action}")  # pragma: no cover
