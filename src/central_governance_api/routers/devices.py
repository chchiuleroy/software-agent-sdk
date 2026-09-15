"""Device inventory endpoints — register and revoke.

v11 §2/§4: `DeviceRegistration`/`DeviceDenylistEntry` are explicitly NOT a
security control (see `models.py`'s docstrings on both tables) — this
inventory doesn't itself make claim/report-result "device-bound"; it's a
registration hint an admin can audit, and a place to remember that a
given (owner, device_id) pair was deliberately revoked so it can't
silently come back.

Schemas and error types live directly in this file rather than in a
`devices/` subpackage mirroring `approvals/` — two endpoints and five
small, single-purpose exception classes don't earn the extra structure
yet (YAGNI); if this surface grows, splitting into a subpackage then is a
mechanical refactor, same as `commit_or_replay`/`RequestModel` already
were once a second consumer showed up (see `approvals/idempotency.py`
and `schemas_base.py`).

Both write endpoints follow the same idempotency-check -> ... -> single
commit-or-replay shape as `routers/approvals.py` — see that module's
docstring for the full rationale; not repeated here.

Code-review disclosed gap, not fixed in this pass: any authenticated
principal may self-register a device with no quota or rate limit (see
`register_device`'s own docstring for the reasoning on why no *role* is
required). Review confirmed this is a legitimate resource-exhaustion /
namespace-squatting surface — an attacker with any valid token could
register a large number of never-reused, permanently-occupied device_id
values (see the DeviceRegistration table's own docstring: revoke never
deletes a row) — not merely a theoretical nitpick. Mitigations review
suggested (per-principal registration quota, unpredictable/system-
generated device_id values instead of caller-chosen ones, or scoping
device_id uniqueness per-owner instead of globally) are all real feature/
policy decisions, not mechanical fixes, so they're deliberately left for
Roy to weigh rather than picked here unilaterally.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Path
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.approvals.idempotency import (
    check_replay_or_raise,
    commit_or_replay,
    find_replayed_response,
    fingerprint_request,
    record_response,
)
from central_governance_api.auth.dependencies import get_current_principal
from central_governance_api.auth.oidc import Principal
from central_governance_api.clock import now_utc
from central_governance_api.db import get_db_session
from central_governance_api.http_params import IdempotencyKeyHeader
from central_governance_api.models import (
    AdminAuditEvent,
    DeviceDenylistEntry,
    DeviceRegistration,
)
from central_governance_api.schemas_base import RequestModel


# Non-empty, URL-safe (no `/`, `?`, `#`, whitespace, or control characters)
# — code-review Medium: without this, an empty or path-unsafe device_id
# could be written by register but never addressed by revoke's
# `{device_id}` path segment, and would permanently occupy the (globally
# unique, never-deleted — see DeviceRegistration's docstring) namespace.
_DEVICE_ID_PATTERN = r"^[A-Za-z0-9._-]{1,64}$"


router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


# --- Errors (see module docstring on why these live here, not a shared module) --


class DeviceNotFoundError(Exception):
    """Maps to HTTP 404. REVOKE also raises this — deliberately, not just
    when the device truly doesn't exist — for a caller who is neither the
    device's owner nor ``governance.admin``: see ``revoke_device``'s own
    comment on why that case is folded into "not found" rather than a
    distinguishable 403 (code-review Low: existence-enumeration risk).
    """

    def __init__(self, *, device_id: str) -> None:
        self.device_id = device_id
        super().__init__(f"no registered device with id {device_id!r}")


class DeviceAlreadyRegisteredError(Exception):
    """CREATE only: ``device_id`` already exists in ``device_registrations``
    — the column is globally unique (not scoped per owner), so this
    covers both "someone else already registered this device_id" and "you
    already registered it yourself" alike. Maps to HTTP 409.
    """

    def __init__(self, *, device_id: str) -> None:
        self.device_id = device_id
        super().__init__(f"device_id {device_id!r} is already registered")


class DeviceRevokedError(Exception):
    """CREATE only: this exact ``(owner_subject, device_id)`` pair is on
    the denylist (see ``models.DeviceDenylistEntry``'s docstring) — the
    device was deliberately revoked and this service intentionally never
    lets it quietly come back via a fresh register call. Maps to HTTP 409.
    """

    def __init__(self, *, device_id: str) -> None:
        self.device_id = device_id
        super().__init__(
            f"device_id {device_id!r} was previously revoked and denylisted"
        )


class DeviceAlreadyRevokedError(Exception):
    """REVOKE only: the conditional UPDATE's ``WHERE revoked_at IS NULL``
    affected zero rows — same "request doesn't match current resource
    state" family as ``approvals.errors.ConcurrentModificationError``,
    kept separate because it's scoped to a different table/resource.
    Maps to HTTP 409.
    """

    def __init__(self, *, device_id: str) -> None:
        self.device_id = device_id
        super().__init__(f"device_id {device_id!r} was already revoked")


# --- Schemas -------------------------------------------------------------


class DeviceRegisterRequest(RequestModel):
    device_id: str = Field(pattern=_DEVICE_ID_PATTERN)


class DeviceRegisterResponse(BaseModel):
    id: uuid.UUID
    device_id: str
    owner_subject: str
    registered_at: datetime


class DeviceRevokeResponse(BaseModel):
    device_id: str
    revoked_at: datetime
    revoked_by_subject: str


# --- REGISTER --------------------------------------------------------------

_REGISTER_ENDPOINT = "POST /devices/register"


@router.post("/register", response_model=DeviceRegisterResponse, status_code=201)
async def register_device(
    body: DeviceRegisterRequest,
    idempotency_key: IdempotencyKeyHeader,
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
) -> DeviceRegisterResponse:
    """Any authenticated principal may self-register a device, regardless
    of role — device inventory isn't a security control (see module
    docstring), so there's no privilege to gate here, and requiring a
    role would just add onboarding friction for none of the usual
    reasons (least privilege doesn't apply to a hint). ``owner_subject``
    is always ``principal.subject``, never taken from the request body —
    nobody can register a device on someone else's behalf. See the module
    docstring for the disclosed, not-fixed-here quota/namespace-abuse gap
    this permissive posture implies.
    """
    fingerprint = fingerprint_request(body.model_dump(mode="json"))
    replayed = await find_replayed_response(
        session,
        principal_subject=principal.subject,
        endpoint=_REGISTER_ENDPOINT,
        resource_id=body.device_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return DeviceRegisterResponse.model_validate(replayed)

    denylisted = await session.scalar(
        select(DeviceDenylistEntry).where(
            DeviceDenylistEntry.owner_subject == principal.subject,
            DeviceDenylistEntry.device_id == body.device_id,
        )
    )
    if denylisted is not None:
        raise DeviceRevokedError(device_id=body.device_id)

    device = DeviceRegistration(
        owner_subject=principal.subject, device_id=body.device_id
    )
    session.add(device)
    try:
        await session.flush()  # trip the device_id UNIQUE constraint now,
        # deterministically, rather than only discovering it much later
        # when the final commit runs (see the DeviceRegistration table's
        # own docstring: device_id is globally unique, not per-owner).
    except IntegrityError:
        await session.rollback()
        # Code-review High: a bare "unique violation -> already
        # registered" here would misreport a genuine concurrent retry of
        # THIS SAME request (same principal+device_id+idempotency key) as
        # a conflict, because under Postgres's default Read Committed
        # isolation the losing concurrent request's flush() blocks on the
        # winner's uncommitted insert and then fails once the winner
        # commits — indistinguishable, from the failure alone, from a
        # genuinely different registration attempt for this device_id.
        # check_replay_or_raise re-checks whether the winner was actually
        # this same idempotency key before concluding it's a real
        # conflict. See idempotency.py's docstring for full detail; this
        # specific race-recovery branch is unverified by an automated
        # test (see tests/test_devices_router.py's module docstring).
        replayed = await check_replay_or_raise(
            session,
            principal_subject=principal.subject,
            endpoint=_REGISTER_ENDPOINT,
            resource_id=body.device_id,
            idempotency_key=idempotency_key,
            request_fingerprint=fingerprint,
            conflict_error=DeviceAlreadyRegisteredError(device_id=body.device_id),
        )
        return DeviceRegisterResponse.model_validate(replayed)

    response = DeviceRegisterResponse(
        id=device.id,
        device_id=device.device_id,
        owner_subject=device.owner_subject,
        registered_at=device.registered_at,
    )
    record_response(
        session,
        principal_subject=principal.subject,
        endpoint=_REGISTER_ENDPOINT,
        resource_id=body.device_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    replayed = await commit_or_replay(
        session,
        principal_subject=principal.subject,
        endpoint=_REGISTER_ENDPOINT,
        resource_id=body.device_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return DeviceRegisterResponse.model_validate(replayed)
    return response


# --- REVOKE ------------------------------------------------------------------

_REVOKE_ENDPOINT = "POST /devices/{device_id}/revoke"


@router.post("/{device_id}/revoke", response_model=DeviceRevokeResponse)
async def revoke_device(
    device_id: Annotated[str, Path(pattern=_DEVICE_ID_PATTERN)],
    idempotency_key: IdempotencyKeyHeader,
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
) -> DeviceRevokeResponse:
    """Owner or ``governance.admin`` may revoke — cancel's admin bypass
    reasoning applies here too (see ``approvals/authorize.py``'s module
    docstring, design decision 2): revoking doesn't require executing
    anything on anyone's behalf, so admin-as-kill-switch is safe to allow.
    """
    fingerprint = fingerprint_request({})
    replayed = await find_replayed_response(
        session,
        principal_subject=principal.subject,
        endpoint=_REVOKE_ENDPOINT,
        resource_id=device_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return DeviceRevokeResponse.model_validate(replayed)

    device = await session.scalar(
        select(DeviceRegistration).where(DeviceRegistration.device_id == device_id)
    )
    is_admin = "governance.admin" in principal.roles
    is_owner = device is not None and principal.subject == device.owner_subject
    if device is None or not (is_admin or is_owner):
        # Code-review Low: deliberately the SAME error, same status code,
        # for "doesn't exist" and "exists but you're not the owner" —
        # distinguishing them would let any authenticated principal
        # enumerate the device inventory by probing IDs and reading which
        # error comes back (403 vs 404). Only `governance.admin` or the
        # true owner ever learns whether a given device_id is real.
        raise DeviceNotFoundError(device_id=device_id)

    now = now_utc()
    result = await session.execute(
        update(DeviceRegistration)
        .where(
            DeviceRegistration.device_id == device_id,
            DeviceRegistration.revoked_at.is_(None),
        )
        .values(revoked_at=now, revoked_by_subject=principal.subject)
        .returning(DeviceRegistration.id)
    )
    if result.scalar_one_or_none() is None:
        # Code-review High — same race as register_device's flush()
        # except block, different shape: two concurrent revoke calls with
        # the SAME idempotency key can both pass the initial replay check
        # and both reach this UPDATE; only one matches `revoked_at IS
        # NULL`, and the loser must not report "already revoked" without
        # first checking whether "already revoked" actually means "my own
        # concurrent retry already won". See check_replay_or_raise's
        # docstring; this branch has the same untested-by-automation
        # caveat as register's.
        replayed = await check_replay_or_raise(
            session,
            principal_subject=principal.subject,
            endpoint=_REVOKE_ENDPOINT,
            resource_id=device_id,
            idempotency_key=idempotency_key,
            request_fingerprint=fingerprint,
            conflict_error=DeviceAlreadyRevokedError(device_id=device_id),
        )
        return DeviceRevokeResponse.model_validate(replayed)

    # See models.DeviceDenylistEntry's docstring: this is what actually
    # stops the same (owner, device_id) pair from quietly re-registering
    # — device_id's own UNIQUE constraint on DeviceRegistration already
    # blocks a literal re-INSERT forever (revoke never deletes the row),
    # but the denylist gives register_device() a specific, friendly
    # "this was revoked" error instead of an opaque conflict.
    session.add(
        DeviceDenylistEntry(owner_subject=device.owner_subject, device_id=device_id)
    )
    session.add(
        AdminAuditEvent(
            event_type="device_revoked",
            actor_subject=principal.subject,
            origin_device_id=device_id,
        )
    )

    response = DeviceRevokeResponse(
        device_id=device_id, revoked_at=now, revoked_by_subject=principal.subject
    )
    record_response(
        session,
        principal_subject=principal.subject,
        endpoint=_REVOKE_ENDPOINT,
        resource_id=device_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    replayed = await commit_or_replay(
        session,
        principal_subject=principal.subject,
        endpoint=_REVOKE_ENDPOINT,
        resource_id=device_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return DeviceRevokeResponse.model_validate(replayed)
    return response
