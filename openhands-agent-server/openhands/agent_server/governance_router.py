"""Read-only governance status for the desktop GUI.

Without this, a team-mode server whose central-governance-api is down (or
whose client credentials were revoked) looks identical to a healthy one until
an action hangs waiting for a central approval that was never created. The
GUI reads this to show which mode it is in and, in team mode, whether the
central API is actually usable — and to know that the local "Continue" button
is not the approval path there (central's decision drives the run instead).
"""

import asyncio
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from openhands.agent_server.config import Config, missing_team_mode_settings
from openhands.agent_server.conversation_service import ConversationService
from openhands.agent_server.dependencies import get_conversation_service


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
