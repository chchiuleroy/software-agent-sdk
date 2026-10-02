"""Device inventory endpoints — register and revoke.

v11 §2/§4: `DeviceRegistration`/`DeviceDenylistEntry` are explicitly NOT a
security control (see `models.py`'s docstrings on both tables) — this
inventory doesn't itself make claim/report-result "device-bound"; it's a
registration hint an admin can audit, and a place to remember that a
given (owner, device_id) pair was deliberately revoked so it can't
silently come back. By default nothing consults it when an approval is
created or claimed; ``config.device_binding_enforced`` (2026-10-02, off by
default) makes :func:`ensure_device_bound` do exactly that, so a revoked or
never-registered device id is refused — still a registration check, not a
cryptographic device proof.

Schemas and error types live directly in this file rather than in a
`devices/` subpackage mirroring `approvals/` — two endpoints and six
small, single-purpose exception classes don't earn the extra structure
yet (YAGNI); if this surface grows, splitting into a subpackage then is a
mechanical refactor, same as `commit_or_replay`/`RequestModel` already
were once a second consumer showed up (see `approvals/idempotency.py`
and `schemas_base.py`).

Both write endpoints follow the same idempotency-check -> ... -> single
commit-or-replay shape as `routers/approvals.py` — see that module's
docstring for the full rationale; not repeated here.

Code-review resource-exhaustion finding, fixed 2026-09-15 (Roy's decision
after weighing the three mitigations review raised): ``device_id``
uniqueness is now scoped per-owner rather than global (models.py), and
``register_device`` enforces a per-principal registration quota
(``config.device_registration_quota``). Roy explicitly declined the third
option (server-generated, non-caller-chosen device_id) — a caller-chosen
name is more useful in the admin audit trail than an opaque UUID, and
nothing in this service ties ``device_id`` to anything security-relevant
(see the "NOT a security control" framing above) that a predictable name
would actually endanger.

Per-owner uniqueness has one structural consequence worth calling out:
``device_id`` is no longer a value that identifies a single row *service-
wide* (two different owners can each have their own "laptop"). REVOKE
therefore addresses a specific registration by its own row id (returned
from ``register_device``'s response), not by the ``device_id`` string —
the same pattern ``routers/approvals.py`` already uses (server-issued
UUID in the path, not the client-chosen ``request_id``).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
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
from central_governance_api.config import Settings, get_settings_dependency
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
# could be written by register but never addressed anywhere that expects a
# clean path/display value, and would permanently occupy the per-owner
# namespace (revoke never deletes the row — see DeviceRegistration's
# docstring). Revoke itself now addresses by server-issued registration_id
# (UUID), not this string, but device_id still appears in audit records,
# the denylist, and response bodies, so the format constraint still earns
# its keep independent of revoke's addressing scheme.
_DEVICE_ID_PATTERN = r"^[A-Za-z0-9._-]{1,64}$"


router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


def _display_subject(issuer: str, sub: str) -> str:
    """Builds the same ``f"{issuer}#{sub}"`` shape ``Principal.subject``
    computes, for response bodies only — DB storage and security
    comparisons use the separate issuer/sub columns (see models.py's
    module docstring); this is purely a human-readable convenience so the
    HTTP response shape doesn't have to change just because the storage
    layer did.
    """
    return f"{issuer}#{sub}"


def _quota_lock_key(issuer: str, sub: str) -> int:
    """A stable signed-64-bit key for ``pg_advisory_xact_lock``, derived
    from the principal's ``(issuer, sub)`` — see that call site in
    ``register_device`` for why this lock exists (code-review Medium: the
    count-then-insert quota check below is not atomic on its own).
    """
    digest = hashlib.sha256(f"{issuer}\x00{sub}".encode()).digest()[:8]
    return int.from_bytes(digest, byteorder="big", signed=True)


# --- Errors (see module docstring on why these live here, not a shared module) --


class DeviceNotFoundError(Exception):
    """Maps to HTTP 404. REVOKE also raises this — deliberately, not just
    when the registration truly doesn't exist — for a caller who is
    neither the device's owner nor ``governance.admin``: see
    ``revoke_device``'s own comment on why that case is folded into "not
    found" rather than a distinguishable 403 (code-review Low: existence-
    enumeration risk).
    """

    def __init__(self, *, identifier: str) -> None:
        self.identifier = identifier
        super().__init__(f"no registered device with id {identifier!r}")


class DeviceAlreadyRegisteredError(Exception):
    """CREATE only: this ``device_id`` is already registered *for this
    owner* — uniqueness is per-owner (models.py), so this never fires
    because of a different principal's device_id choice, only your own.
    Maps to HTTP 409.
    """

    def __init__(self, *, device_id: str) -> None:
        self.device_id = device_id
        super().__init__(f"device_id {device_id!r} is already registered")


class DeviceRevokedError(Exception):
    """CREATE only: this exact ``(owner, device_id)`` pair is on the
    denylist (see ``models.DeviceDenylistEntry``'s docstring) — the
    device was deliberately revoked and this service intentionally never
    lets it quietly come back via a fresh register call. Maps to HTTP 409.
    """

    def __init__(self, *, device_id: str) -> None:
        self.device_id = device_id
        super().__init__(
            f"device_id {device_id!r} was previously revoked and denylisted"
        )


class DeviceQuotaExceededError(Exception):
    """CREATE only: this principal has already registered
    ``config.device_registration_quota`` devices (revoked ones count too
    — see ``DeviceRegistration``'s docstring on why revocation doesn't
    free the slot). Code-review finding, Roy's decision 2026-09-15: bound
    total registrations per principal now that per-owner uniqueness alone
    doesn't stop one account from unbounded row growth. Maps to HTTP 429.
    """

    def __init__(self, *, quota: int) -> None:
        self.quota = quota
        super().__init__(f"device registration quota ({quota}) exceeded")


class DeviceNotBoundError(Exception):
    """CREATE/CLAIM of an *approval* only (raised by
    :func:`ensure_device_bound`, not by any ``/devices`` endpoint): with
    ``config.device_binding_enforced`` on, the approval's
    ``origin_device_id`` is not an active registration owned by the
    calling principal. Covers "never registered", "registered by a
    different principal", and "registered but revoked" identically on
    purpose, so the response doesn't tell a caller which of another
    principal's device ids exist. Maps to HTTP 403.
    """

    def __init__(self, *, device_id: str) -> None:
        self.device_id = device_id
        super().__init__(
            f"device_id {device_id!r} is not an active registered device of "
            "the calling principal"
        )


class DeviceAlreadyRevokedError(Exception):
    """REVOKE only: the conditional UPDATE's ``WHERE revoked_at IS NULL``
    affected zero rows — same "request doesn't match current resource
    state" family as ``approvals.errors.ConcurrentModificationError``,
    kept separate because it's scoped to a different table/resource.
    Maps to HTTP 409.
    """

    def __init__(self, *, registration_id: uuid.UUID) -> None:
        self.registration_id = registration_id
        super().__init__(f"device registration {registration_id} was already revoked")


# --- Schemas -------------------------------------------------------------


class DeviceRegisterRequest(RequestModel):
    device_id: str = Field(pattern=_DEVICE_ID_PATTERN)


class DeviceRegisterResponse(BaseModel):
    id: uuid.UUID
    device_id: str
    owner_subject: str
    registered_at: datetime


class DeviceRevokeResponse(BaseModel):
    id: uuid.UUID
    device_id: str
    revoked_at: datetime
    revoked_by_subject: str


# --- Device binding (used by the approvals router) ---------------------------


async def ensure_device_bound(
    session: AsyncSession,
    principal: Principal,
    device_id: str,
    *,
    enforced: bool,
) -> None:
    """Refuse an approval CREATE/CLAIM whose ``origin_device_id`` is not an
    active registration of *this* principal — when ``enforced``.

    ``enforced=False`` (``config.device_binding_enforced``'s default) is a
    pure no-op, so today's behavior is unchanged until an operator opts in.
    "Active" means ``revoked_at IS NULL``; ownership is the
    ``(owner_issuer, owner_sub)`` pair, never either column alone (the same
    identity rule as everywhere else in this service). This makes revocation
    actually bite — a revoked device can no longer create or claim approvals —
    but it is still a registration check, not a cryptographic device proof
    (see ``DeviceRegistration``'s docstring).

    Raises:
        DeviceNotBoundError: 403, for every not-active-and-owned case alike.
    """
    if not enforced:
        return
    stmt = (
        select(DeviceRegistration.id)
        .where(
            DeviceRegistration.owner_issuer == principal.issuer,
            DeviceRegistration.owner_sub == principal.sub,
            DeviceRegistration.device_id == device_id,
            DeviceRegistration.revoked_at.is_(None),
        )
        .limit(1)
    )
    if (await session.execute(stmt)).first() is None:
        raise DeviceNotBoundError(device_id=device_id)


# --- REGISTER --------------------------------------------------------------

_REGISTER_ENDPOINT = "POST /devices/register"


@router.post("/register", response_model=DeviceRegisterResponse, status_code=201)
async def register_device(
    body: DeviceRegisterRequest,
    idempotency_key: IdempotencyKeyHeader,
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> DeviceRegisterResponse:
    """Any authenticated principal may self-register a device, regardless
    of role — device inventory isn't a security control (see module
    docstring), so there's no privilege to gate here, and requiring a
    role would just add onboarding friction for none of the usual
    reasons (least privilege doesn't apply to a hint). ``owner_issuer``/
    ``owner_sub`` are always the caller's own, never taken from the
    request body — nobody can register a device on someone else's behalf.
    Bounded instead by ``device_registration_quota`` (see module
    docstring) rather than a role gate.
    """
    fingerprint = fingerprint_request(body.model_dump(mode="json"))
    replayed = await find_replayed_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_REGISTER_ENDPOINT,
        resource_id=body.device_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return DeviceRegisterResponse.model_validate(replayed)

    denylisted = await session.scalar(
        select(DeviceDenylistEntry).where(
            DeviceDenylistEntry.owner_issuer == principal.issuer,
            DeviceDenylistEntry.owner_sub == principal.sub,
            DeviceDenylistEntry.device_id == body.device_id,
        )
    )
    if denylisted is not None:
        raise DeviceRevokedError(device_id=body.device_id)

    # Code-review Medium: a bare `SELECT count(*)` followed by a separate
    # INSERT is not atomic under PostgreSQL's default Read Committed
    # isolation — two concurrent registrations for the same principal
    # (different device_id values, so the per-owner UNIQUE constraint
    # doesn't help) can both read the same count, both pass the check, and
    # both insert, overshooting the quota by more than "slightly". This is
    # meant as a real per-principal resource-exhaustion bound (module
    # docstring), not a soft statistic, so we serialize concurrent
    # registrations for the same (issuer, sub) with a transaction-scoped
    # advisory lock before counting — a blocking, self-releasing lock
    # (held until this transaction commits or rolls back) rather than
    # `SELECT ... FOR UPDATE`, since there's no existing row to lock when
    # a principal has zero registrations yet.
    await session.execute(
        select(
            func.pg_advisory_xact_lock(_quota_lock_key(principal.issuer, principal.sub))
        )
    )

    # Code-review Medium (round-5 confirmation review): the lock above
    # closes the count/insert race, but opens a narrower one against
    # idempotent retries specifically — if this request's own concurrent
    # retry (same idempotency key) is what filled the last quota slot
    # while we were blocked waiting for the lock, the initial
    # find_replayed_response() call above ran before that retry committed
    # and legitimately saw nothing yet. Without re-checking here, we'd
    # raise DeviceQuotaExceededError instead of replaying that retry's own
    # success — a safe retry must always replay, never surface as a
    # quota conflict. Re-running the read now (past the lock) sees a fresh
    # Read Committed snapshot that includes the winner's commit.
    replayed = await find_replayed_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_REGISTER_ENDPOINT,
        resource_id=body.device_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return DeviceRegisterResponse.model_validate(replayed)

    existing_count = await session.scalar(
        select(func.count())
        .select_from(DeviceRegistration)
        .where(
            DeviceRegistration.owner_issuer == principal.issuer,
            DeviceRegistration.owner_sub == principal.sub,
        )
    )
    quota = settings.device_registration_quota
    if existing_count is not None and existing_count >= quota:
        raise DeviceQuotaExceededError(quota=quota)

    device = DeviceRegistration(
        owner_issuer=principal.issuer,
        owner_sub=principal.sub,
        device_id=body.device_id,
    )
    session.add(device)
    try:
        await session.flush()  # trip the (owner, device_id) UNIQUE
        # constraint now, deterministically, rather than only discovering
        # it much later when the final commit runs.
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
            principal_issuer=principal.issuer,
            principal_sub=principal.sub,
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
        owner_subject=_display_subject(device.owner_issuer, device.owner_sub),
        registered_at=device.registered_at,
    )
    record_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_REGISTER_ENDPOINT,
        resource_id=body.device_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    replayed = await commit_or_replay(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_REGISTER_ENDPOINT,
        resource_id=body.device_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return DeviceRegisterResponse.model_validate(replayed)
    return response


# --- REVOKE ------------------------------------------------------------------

_REVOKE_ENDPOINT = "POST /devices/{registration_id}/revoke"


@router.post("/{registration_id}/revoke", response_model=DeviceRevokeResponse)
async def revoke_device(
    registration_id: uuid.UUID,
    idempotency_key: IdempotencyKeyHeader,
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
) -> DeviceRevokeResponse:
    """Owner or ``governance.admin`` may revoke — cancel's admin bypass
    reasoning applies here too (see ``approvals/authorize.py``'s module
    docstring, design decision 2): revoking doesn't require executing
    anything on anyone's behalf, so admin-as-kill-switch is safe to allow.

    Addressed by the registration's own server-issued ``id``, not the
    caller-chosen ``device_id`` string — see module docstring on why
    per-owner uniqueness makes ``device_id`` alone ambiguous service-wide.
    """
    resource_id = str(registration_id)
    fingerprint = fingerprint_request({})
    replayed = await find_replayed_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_REVOKE_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return DeviceRevokeResponse.model_validate(replayed)

    device = await session.get(DeviceRegistration, registration_id)
    is_admin = "governance.admin" in principal.roles
    is_owner = device is not None and (principal.issuer, principal.sub) == (
        device.owner_issuer,
        device.owner_sub,
    )
    if device is None or not (is_admin or is_owner):
        # Code-review Low: deliberately the SAME error, same status code,
        # for "doesn't exist" and "exists but you're not the owner" —
        # distinguishing them would let any authenticated principal
        # enumerate the device inventory by probing IDs and reading which
        # error comes back (403 vs 404). Only `governance.admin` or the
        # true owner ever learns whether a given registration is real.
        raise DeviceNotFoundError(identifier=resource_id)

    now = now_utc()
    result = await session.execute(
        update(DeviceRegistration)
        .where(
            DeviceRegistration.id == registration_id,
            DeviceRegistration.revoked_at.is_(None),
        )
        .values(
            revoked_at=now,
            revoked_by_issuer=principal.issuer,
            revoked_by_sub=principal.sub,
        )
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
            principal_issuer=principal.issuer,
            principal_sub=principal.sub,
            endpoint=_REVOKE_ENDPOINT,
            resource_id=resource_id,
            idempotency_key=idempotency_key,
            request_fingerprint=fingerprint,
            conflict_error=DeviceAlreadyRevokedError(registration_id=registration_id),
        )
        return DeviceRevokeResponse.model_validate(replayed)

    # See models.DeviceDenylistEntry's docstring: this is what actually
    # stops the same (owner, device_id) pair from quietly re-registering
    # — the (owner, device_id) UNIQUE constraint on DeviceRegistration
    # already blocks a literal re-INSERT forever (revoke never deletes
    # the row), but the denylist gives register_device() a specific,
    # friendly "this was revoked" error instead of an opaque conflict.
    session.add(
        DeviceDenylistEntry(
            owner_issuer=device.owner_issuer,
            owner_sub=device.owner_sub,
            device_id=device.device_id,
        )
    )
    session.add(
        AdminAuditEvent(
            event_type="device_revoked",
            actor_issuer=principal.issuer,
            actor_sub=principal.sub,
            origin_device_id=device.device_id,
        )
    )

    response = DeviceRevokeResponse(
        id=registration_id,
        device_id=device.device_id,
        revoked_at=now,
        revoked_by_subject=_display_subject(principal.issuer, principal.sub),
    )
    record_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_REVOKE_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    replayed = await commit_or_replay(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_REVOKE_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return DeviceRevokeResponse.model_validate(replayed)
    return response
