"""Governance endpoints: read-only status for the desktop GUI, the list of
conversations whose governance outbox needs an operator (``GET /attention``),
and the operator's way to act on one (``POST /attention/{id}/resolve``).

Status: without this, a team-mode server whose central-governance-api is down (or
whose client credentials were revoked) looks identical to a healthy one until
an action hangs waiting for a central approval that was never created. The
GUI reads this to show which mode it is in and, in team mode, whether the
central API is actually usable — and to know that the local "Continue" button
is not the approval path there (central's decision drives the run instead).
"""

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from openhands.agent_server.config import Config, missing_team_mode_settings
from openhands.agent_server.conversation_service import ConversationService
from openhands.agent_server.dependencies import get_conversation_service
from openhands.agent_server.governance_attention import (
    AttentionItem,
    ResolveError,
    ResolveRequest,
    ResolveResponse,
    scan_needs_attention,
)


governance_router = APIRouter(prefix="/governance", tags=["Governance"])

# Bounds one status request; the GUI polls, so a hung central API must not
# pile up long-lived requests (GovernanceClient's own timeout is 30s).
_PROBE_TIMEOUT_SECONDS = 5.0


class CentralApiStatus(BaseModel):
    reachable: bool | None = Field(
        description="None when not probed (client not configured)."
    )
    credentials_ok: bool | None = Field(
        description="Whether the configured client credentials obtained an "
        "IdP token; None when the API was unreachable or not probed."
    )
    error: str | None = Field(
        description="Short, secret-free reason (exception class or HTTP status)."
    )
    checked_at: datetime


class GovernanceStatus(BaseModel):
    deployment_mode: Literal["personal", "team"]
    missing_settings: list[str] = Field(
        description="Team-mode env var names still unset (names only, never "
        "values). Empty in personal mode."
    )
    central_api: CentralApiStatus | None = Field(
        description="Present only in team mode."
    )


@governance_router.get("/status", response_model=GovernanceStatus)
async def get_governance_status(
    request: Request,
    conversation_service: ConversationService = Depends(get_conversation_service),
) -> GovernanceStatus:
    config: Config = request.app.state.config
    if config.governance_deployment_mode != "team":
        return GovernanceStatus(
            deployment_mode="personal", missing_settings=[], central_api=None
        )

    checked_at = datetime.now(UTC)
    client = conversation_service.governance_client
    if client is None:
        return GovernanceStatus(
            deployment_mode="team",
            missing_settings=missing_team_mode_settings(config),
            central_api=CentralApiStatus(
                reachable=None,
                credentials_ok=None,
                error="central API client is not configured",
                checked_at=checked_at,
            ),
        )

    try:
        probe = await asyncio.wait_for(
            client.check_health(), timeout=_PROBE_TIMEOUT_SECONDS
        )
    except TimeoutError:
        probe = {
            "reachable": False,
            "credentials_ok": None,
            "error": f"status probe timed out after {_PROBE_TIMEOUT_SECONDS:g}s",
        }
    return GovernanceStatus(
        deployment_mode="team",
        missing_settings=missing_team_mode_settings(config),
        central_api=CentralApiStatus(**probe, checked_at=checked_at),
    )


@governance_router.get("/attention", response_model=list[AttentionItem])
async def list_needs_attention(
    request: Request,
    conversation_service: ConversationService = Depends(get_conversation_service),
) -> list[AttentionItem]:
    """Conversations whose governance outbox is parked in NEEDS_ATTENTION, each
    with the follow-up actions that are safe for it. Empty outside team mode:
    personal mode has no outbox."""
    config: Config = request.app.state.config
    if config.governance_deployment_mode != "team":
        return []
    # Reads one small file per conversation; keep it off the event loop.
    return await asyncio.to_thread(
        scan_needs_attention, conversation_service.conversations_dir
    )


# Everything not listed is a 409: the request was understood but the record is
# not in a state where it can be applied. Central being unusable is 424, not a
# 5xx: the app replaces the body of every 5xx with "Internal Server Error", which
# would hide exactly what the operator needs (central refused, or is not
# configured), and nothing here is a fault of this server.
_RESOLVE_STATUS = {
    "not_found": 404,
    "not_team_mode": 404,
    "central_failed": 424,
    "central_client_unavailable": 424,
}


@governance_router.post(
    "/attention/{conversation_id}/resolve", response_model=ResolveResponse
)
async def resolve_needs_attention(
    conversation_id: uuid.UUID,
    body: ResolveRequest,
    request: Request,
    conversation_service: ConversationService = Depends(get_conversation_service),
) -> ResolveResponse:
    """Act on a conversation whose governance outbox is parked in NEEDS_ATTENTION:
    ``retry`` the step that failed, ``abandon`` the approval (only where nothing
    can have run), or ``dismiss`` the record. Quote the ``request_id`` from the
    listing; the request is refused if the record has changed since."""
    config: Config = request.app.state.config
    if config.governance_deployment_mode != "team":
        raise HTTPException(
            status_code=404,
            detail={
                "error_code": "not_team_mode",
                "detail": "governance is not in team mode",
            },
        )
    event_service = await conversation_service.get_event_service(conversation_id)
    if event_service is None:
        raise HTTPException(
            status_code=404,
            detail={"error_code": "not_found", "detail": "no such conversation"},
        )
    try:
        return await event_service.resolve_needs_attention(
            body.action,
            expected_request_id=body.expected_request_id,
            note=body.note,
        )
    except ResolveError as exc:
        raise HTTPException(
            status_code=_RESOLVE_STATUS.get(exc.error_code, 409),
            detail={
                "error_code": exc.error_code,
                "detail": exc.detail,
                "allowed_actions": exc.allowed_actions,
            },
        ) from exc
