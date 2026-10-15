"""Registers this agent-server's ``origin_device_id`` with central (team mode).

Central refuses a create/claim whose ``origin_device_id`` is not an active
registration of the calling service account when it runs with
``CGA_DEVICE_BINDING_ENFORCED``. Until now an operator had to register the id by
hand (``POST /api/v1/devices/register``, with this process's own credentials);
this module does it at startup, in the background.

It never blocks startup and never raises. Until the registration is done a
create can still be answered 403 ``device_not_bound`` and park the record in
NEEDS_ATTENTION; the existing attention flow retries it. The result is kept in a
:class:`DeviceRegistrationStatus` that the status endpoint shows, so a revoked
or refused id is visible without reading logs.

What each answer means (device ids are unique per owner, so "already
registered" can only be this process's own registration):

- 201, or 409 ``device_already_registered``  -> registered. The second is what
  every restart gets.
- 409 ``device_revoked``                      -> revoked. Never retried, never
  renamed: a revocation must not be undone by restarting.
- any other permanent answer (quota, 401/403, ...) -> failed, not retried: it
  needs a configuration change and a restart.
- a transient failure (network, 5xx)          -> retried with backoff.

Logs carry the error code or the exception class only, never response text.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from typing import Literal

from openhands.agent_server.governance_client import (
    GovernanceApiError,
    GovernanceClient,
    GovernancePermanentError,
)
from openhands.sdk.logger import get_logger


logger = get_logger(__name__)

# What agent-server reports when no device id is configured. It is not a real
# identity and is never registered.
UNSET_DEVICE_ID = "unset-device-id"

RegistrationState = Literal["pending", "registered", "revoked", "failed"]

INITIAL_RETRY_SECONDS = 5.0
MAX_RETRY_SECONDS = 60.0


@dataclass
class DeviceRegistrationStatus:
    state: RegistrationState = "pending"
    # A central error_code, or an exception class name; never a message.
    error_code: str | None = None


async def register_once(
    client: GovernanceClient, device_id: str, status: DeviceRegistrationStatus
) -> bool:
    """One attempt. Returns True once the outcome is final (no point trying
    again), False for a transient failure. Never raises."""
    try:
        # A fresh key per attempt, on purpose. A fixed key would make central
        # replay the first 201 for ever, including after the device was revoked
        # (the replay is looked up before the denylist), and this module would
        # then report a revoked device as registered. A retry after a request
        # that did succeed gets a 409 "already registered", which is also fine.
        await client.register_device(
            device_id, idempotency_key=f"device-register-{uuid.uuid4()}"
        )
    except GovernancePermanentError as exc:
        if exc.error_code == "device_already_registered":
            status.state, status.error_code = "registered", None
        elif exc.error_code == "device_revoked":
            status.state, status.error_code = "revoked", exc.error_code
            logger.error(
                "device %r was revoked in central; it will not be registered "
                "again. Choose a new OH_GOVERNANCE_ORIGIN_DEVICE_ID.",
                device_id,
            )
        else:
            code = exc.error_code or f"http_{exc.status_code}"
            status.state, status.error_code = "failed", code
            logger.error(
                "registering device %r failed permanently (%s)", device_id, code
            )
        return True
    except GovernanceApiError as exc:
        # Transient: network, 5xx, concurrent_modification.
        status.error_code = exc.error_code or type(exc).__name__
        logger.warning(
            "registering device %r failed (%s); will retry",
            device_id,
            status.error_code,
        )
        return False
    except Exception as exc:  # a dead task would leave the state "pending" forever
        status.state, status.error_code = "failed", type(exc).__name__
        logger.error(
            "registering device %r failed unexpectedly (%s)",
            device_id,
            type(exc).__name__,
        )
        return True
    status.state, status.error_code = "registered", None
    logger.info("device %r is registered with central", device_id)
    return True


async def run(
    client: GovernanceClient, device_id: str, status: DeviceRegistrationStatus
) -> None:
    delay = INITIAL_RETRY_SECONDS
    while not await register_once(client, device_id, status):
        await asyncio.sleep(delay)
        delay = min(delay * 2, MAX_RETRY_SECONDS)
