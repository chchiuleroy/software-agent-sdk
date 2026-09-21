"""Action-bound atomic accept for team-mode central governance, sibling to
``roy_self_approval.py`` (see that module's docstring for the identity side
of the same feature). This module solves a different, narrower problem:
self-approval answers "is the approver a different identity from the
requester"; this module answers "is the pending action about to be executed
still the exact same one a central approval was granted for".

Background: when agent-server is wired to
central-governance-api, a human approves a *description* of an action on a
separate device, days or seconds before agent-server actually resumes
execution. In that gap the conversation's real pending action could have
changed (user rejected and a new one appeared, the agent re-planned, etc.).
Without this check, a stale central approval could authorize whatever
happens to be pending *now*, not what was actually shown to the approver.

Design mirrors ``roy_self_approval.py`` deliberately:

1. Two-stage, off by default. ``check_action_binding()`` is a no-op whenever
   ``expected`` is ``None`` — exactly personal mode's/today's behavior,
   unaffected. Only team-mode callers that pass a real ``ActionBinding``
   engage this at all.
2. Cooperative, not a hard security boundary against a malicious caller
   inside this process — ``expected`` is supplied by whoever calls
   ``run()``/``arun()``, same as ``approver_identity``. The actual boundary
   for external callers is the REST layer (``config.governance_deployment_
   mode``/``authorize_confirmation_response`` in agent-server, already
   shipped) which decides whether an ``ActionBinding`` is even constructed
   for a given request.
3. Known limitation, stated plainly rather than solved (matching
   ``roy_self_approval.py``'s own precedent of listing gaps rather than
   overclaiming): a caller driving this ``LocalConversation`` directly
   in-process (not through agent-server's REST layer) can simply omit
   ``expected_binding`` and bypass this check entirely, the same way a
   direct caller can omit ``approver_identity`` to bypass self-approval.
   Closing that would require the SDK itself to persist "this pending
   action requires central governance" as conversation state, atomically
   with the transition into ``WAITING_FOR_CONFIRMATION`` — deferred; the
   REST-facing boundary is what's actually exposed to untrusted callers.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from openhands.sdk.event import ActionEvent


_COMMITMENT_SCHEMA_VERSION = 1


class ActionBindingMismatchError(ValueError):
    """Raised when the pending action about to execute no longer matches
    the one a central approval was granted for — either a different action
    is now pending, or its content changed.

    ``ValueError`` subclass, not a fresh hierarchy, for the same reason as
    ``SelfApprovalDeniedError``: existing code that already catches
    ``ValueError`` around ``run()``/``arun()`` keeps working unchanged, and
    the subclass lets ``api.py`` register a specific handler mapping this
    to a clean 4xx instead of the generic 500 every other unhandled
    ``ValueError`` gets.
    """


class ExecutionLeaseExpiredError(ValueError):
    """Raised when the central execution lease (the time window a claimed
    approval is valid for) has already passed by the time this process was
    about to actually start the action. ``ValueError`` subclass for the
    same reason as ``ActionBindingMismatchError``.
    """


class ActionCountMismatchError(ValueError):
    """Raised when more or fewer than exactly one action is pending —
    this MVP slice only supports a single-pending-action confirmation
    under central governance; batch confirmations are out of scope (see
    the wiki page's "誠實列出這次仍未解決" sections across the design
    iterations). ``ValueError`` subclass for the same reason as the two
    errors above.
    """

    def __init__(self, count: int) -> None:
        self.count = count
        super().__init__(
            f"central governance requires exactly one pending action, found {count}"
        )


@dataclass(frozen=True)
class ActionBinding:
    """What a central approval was actually granted for, captured once when
    the approval record is created and carried through claim/execute.

    ``execution_commitment`` is computed locally (see
    ``compute_execution_commitment`` below) and never sent to
    central-governance-api — only the redacted display fields go there
    (see that service's ``approvals/digest.py`` module docstring for why:
    "this service never receives the canonical (unredacted) action
    payload"). Re-verifying this commitment against the *current* pending
    action, right before executing, is this process's own responsibility
    precisely because central can't do it.
    """

    central_approval_id: str
    action_event_id: str
    execution_commitment: str
    execution_attempt_id: str | None = None
    executing_lease_expires_at: datetime | None = None

    def fingerprint(self) -> str:
        """Stable identity for "is this the same in-flight governed
        execution" — used by ``EventService`` to decide whether a repeated
        call is a genuine idempotent replay (same fingerprint) or a
        conflicting concurrent request (different fingerprint), rather
        than comparing ``central_approval_id`` alone (which does not by
        itself prove the action content hasn't changed underneath it).
        """
        canonical = {
            "schema_version": _COMMITMENT_SCHEMA_VERSION,
            "central_approval_id": self.central_approval_id,
            "action_event_id": self.action_event_id,
            "execution_commitment": self.execution_commitment,
        }
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def compute_execution_commitment(action: ActionEvent, conversation_id: str) -> str:
    """SHA-256 hex digest over a canonical JSON encoding of the exact
    action content this process is about to execute.

    Deliberately plain SHA-256, not HMAC: an earlier design iteration used
    an HMAC with a per-record local key, but since this value never leaves
    local memory/disk and is never displayed back to any caller (see
    ``api.py``'s exception handlers for this module — they must never echo
    binding details), a keyed hash adds secret-management surface for no
    real benefit. This is a versioned canonical-content equality check,
    not a tamper-evidence mechanism.
    """
    canonical: dict[str, Any] = {
        "schema_version": _COMMITMENT_SCHEMA_VERSION,
        "conversation_id": conversation_id,
        "action_event_id": action.id,
        "tool_name": action.tool_name,
        "tool_call_id": action.tool_call_id,
        # `action.action` is None for a non-executable ActionEvent (see
        # ActionEvent.action's docstring) — a pending confirmation should
        # never reach this with one, but this stays a stable, non-crashing
        # value rather than assuming that invariant holds forever.
        "canonical_args": (
            action.action.model_dump(mode="json") if action.action is not None else None
        ),
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def check_action_binding(
    expected: ActionBinding | None,
    pending_actions: list[ActionEvent],
    conversation_id: str,
) -> None:
    """Verifies the currently pending action(s) still match a central
    approval's binding, right before a governed confirmation is allowed to
    proceed to execution.

    A no-op when ``expected`` is ``None`` — see this module's docstring,
    point 1. Call this under the same conversation state lock that reads
    ``pending_actions`` and is about to flip execution status to
    ``RUNNING``, so the check and the transition are atomic (no window for
    the pending action set to change in between).

    Raises:
        ActionCountMismatchError: not exactly one action is pending.
        ActionBindingMismatchError: the pending action's identity or
            content no longer matches ``expected``.
        ExecutionLeaseExpiredError: ``expected``'s central execution lease
            has already passed.
    """
    if expected is None:
        return
    if len(pending_actions) != 1:
        raise ActionCountMismatchError(len(pending_actions))
    (action,) = pending_actions
    if action.id != expected.action_event_id:
        raise ActionBindingMismatchError(
            "pending action was replaced since central approval was granted"
        )
    if (
        expected.executing_lease_expires_at is not None
        and datetime.now(UTC) > expected.executing_lease_expires_at
    ):
        raise ExecutionLeaseExpiredError(
            "central execution lease expired before this action could start"
        )
    recomputed = compute_execution_commitment(action, conversation_id)
    if recomputed != expected.execution_commitment:
        raise ActionBindingMismatchError(
            "pending action's content changed since central approval was granted"
        )
