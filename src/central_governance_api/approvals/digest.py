"""Digest-envelope computation for approval requests.

v11 round-10 Critical (folded into this implementation): the digest must
bind BOTH halves of the approval envelope together — the
``approval_display`` half (what the approver is shown: ``action_summary``,
``action_payload``) and the ``execution_binding`` half (what governs what
can execute: ``action_type``, ``tool_name``, ``policy_revision``) — so
that mutating either half after the digest was computed is detectable.
Before that fix (per the wiki record), a digest computed over
execution_binding alone couldn't catch a display swapped out from under
an approver: two different summaries could hash identically as long as
the execution-binding fields matched.

This service never receives the canonical (unredacted) action payload —
only the requester's own device does (v9: "canonical payload 不再送進中
央 DB（只送 redacted + digest）") — so **this module cannot verify a
digest was computed over the true canonical payload**; only the
requester's own device, which retains that payload, can do that at
execution time (claim/report-result). What this module DOES verify,
enforced at CREATE time (see ``routers/approvals.py``): the client-
submitted ``action_payload_digest`` is provably a hash of the exact
display/binding fields this service is about to store and later show an
approver. That's the actual fix for the round-10 bug — it's no longer
possible to submit a digest computed over content different from what
gets displayed, because the server independently recomputes and checks
it against what it's storing. After creation, nothing in this API ever
mutates ``action_summary``/``action_payload``/``action_type``/
``tool_name``/``policy_revision``/``digest_salt``, so a digest verified
correct at creation stays correct for the record's lifetime — a direct
DB write bypassing this API is out of scope, matching this project's
established threat-model boundary elsewhere (see e.g.
``roy_governance_lock.py``'s docstring in the sibling SDK repo).

This is a narrower, server-side-only interpretation of the round-10 fix,
reconstructed without the verbatim v11 text — flagged for review like the
approvals/state_machine.py and approvals/authorize.py design decisions.
A stronger version (the approver's own client independently attesting
what it rendered, not just trusting what this API returned) is a possible
future strengthening, not implemented here.

Threat-model limitation confirmed by code review, stated explicitly here
rather than left implicit: this digest is computed over the fields THIS
SERVICE stores (display + execution-binding *metadata*), never over the
canonical payload itself — so it cannot prove the canonical payload a
requester's device ultimately executes is the same one an approver's
decision was based on. It only protects against THIS SERVICE'S OWN
records diverging from what was originally submitted (the round-10 bug:
a digest not tied to what gets displayed). A compromised or buggy
requester device could, in principle, show an approver an innocuous
summary, get it accepted, and then execute a different canonical payload
at claim/report-result time — this module has no way to detect that,
because it never sees canonical payloads on either side of that gap. This
is an acceptable gap ONLY under this project's actual Track 1 ("分散執
行、集中治理") architecture, where the requester and the execution
endpoint are the same principal's own device by construction — the
central API isn't brokering trust between two different parties for
execution, only for the human-approval step. If a future deployment ever
lets a *different* device execute on a requester's behalf, this
assumption breaks and the stronger two-commitment scheme mentioned above
(a separate, requester-attested execution digest, verified by whichever
device actually executes) would stop being optional.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def compute_display_digest(
    *,
    action_type: str,
    tool_name: str,
    policy_revision: str,
    action_summary: str,
    action_payload: dict[str, Any],
    digest_salt: str | None,
) -> str:
    """SHA-256 hex digest over a canonical JSON encoding of every field
    that makes up this service's stored half of the approval envelope.

    Field *names* are fixed explicitly in the dict literal below (not
    derived from kwargs order or dict iteration) precisely so this
    function's output only depends on the field *values*, never on
    incidental call-site or JSON key ordering — ``json.dumps(...,
    sort_keys=True)`` further guarantees ``action_payload``'s own nested
    keys don't affect the digest based on how they happened to be
    inserted.
    """
    canonical = {
        "action_type": action_type,
        "tool_name": tool_name,
        "policy_revision": policy_revision,
        "action_summary": action_summary,
        "action_payload": action_payload,
        "digest_salt": digest_salt,
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def verify_display_digest(
    *,
    action_type: str,
    tool_name: str,
    policy_revision: str,
    action_summary: str,
    action_payload: dict[str, Any],
    digest_salt: str | None,
    expected_digest: str,
) -> bool:
    return (
        compute_display_digest(
            action_type=action_type,
            tool_name=tool_name,
            policy_revision=policy_revision,
            action_summary=action_summary,
            action_payload=action_payload,
            digest_salt=digest_salt,
        )
        == expected_digest
    )
