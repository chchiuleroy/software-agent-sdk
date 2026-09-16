import secrets
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import APIKeyCookie, APIKeyHeader

from openhands.agent_server.bash_service import BashEventService
from openhands.agent_server.config import Config
from openhands.agent_server.conversation_service import ConversationService
from openhands.agent_server.event_service import EventService


# Cookie name used to authenticate the workspace static-file routes.
# Intentionally distinct from the header name: the cookie is ONLY honored
# by the workspace router (so iframes / <img> can load workspace files),
# and is rejected by every other API endpoint.
WORKSPACE_SESSION_COOKIE_NAME = "oh_workspace_session_key"

_SESSION_API_KEY_HEADER = APIKeyHeader(name="X-Session-API-Key", auto_error=False)
_WORKSPACE_SESSION_COOKIE = APIKeyCookie(
    name=WORKSPACE_SESSION_COOKIE_NAME, auto_error=False
)


def check_session_api_key(
    request: Request,
    session_api_key: str | None = Depends(_SESSION_API_KEY_HEADER),
) -> None:
    """Reject the request if the supplied key is not in the current session keys.

    Reads ``session_api_keys`` from ``request.app.state.config`` at request time
    so that keys delivered via ``POST /api/init`` take effect immediately without
    restarting the server or re-registering routes.
    """
    config: Config = request.app.state.config
    if config.session_api_keys and session_api_key not in config.session_api_keys:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED)


def check_workspace_session(
    request: Request,
    header_key: str | None = Depends(_SESSION_API_KEY_HEADER),
    cookie_key: str | None = Depends(_WORKSPACE_SESSION_COOKIE),
) -> None:
    """Auth dependency for the workspace static-file routes.

    Accepts EITHER the standard ``X-Session-API-Key`` header OR the
    ``oh_workspace_session_key`` cookie (minted by
    ``POST /api/auth/workspace-session``).
    The cookie is required because browsers cannot attach custom headers to
    ``<iframe src>`` or ``<img src>`` requests, which is how the canvas
    frontend embeds workspace artifacts. The cookie is deliberately scoped
    to this router only; no other endpoint honors it.
    """
    config: Config = request.app.state.config
    if not config.session_api_keys:
        return
    for candidate in (header_key, cookie_key):
        if candidate and candidate in config.session_api_keys:
            return
    raise HTTPException(status.HTTP_401_UNAUTHORIZED)


def governance_bridge_token_header(
    token: str | None = Header(default=None, alias="X-Governance-Bridge-Token"),
) -> str | None:
    """Extracts the raw ``X-Governance-Bridge-Token`` header value, if any.

    Deliberately a plain ``Header`` dependency, not a second
    ``APIKeyHeader`` security scheme: this header is not an alternative to
    session-key auth (a request must still satisfy ``check_session_api_key``
    regardless), it is a *conditionally required extra header* enforced by
    ``authorize_confirmation_response`` below. Two unnamed ``APIKeyHeader``
    instances collapse into the same OpenAPI security scheme name and
    FastAPI represents multiple schemes as an OR of alternatives — neither
    of which matches this header's actual semantics, and it would leave
    ``X-Governance-Bridge-Token`` undocumented in the generated OpenAPI
    contract (a typed client generated from it would have no way to know
    this header exists).
    """
    return token


def authorize_confirmation_response(
    config: Config, *, accept: bool, supplied_token: str | None
) -> None:
    """Gates the ``accept=True`` path of ``respond_to_confirmation`` in team mode.

    Only ``governance_deployment_mode == "team"`` and ``accept=True`` trigger
    any check at all:

    - ``personal`` mode (the default): always a no-op, today's behavior is
      completely unchanged, matching ``roy_self_approval.py``'s own
      "unset env var means untracked, not enforced" precedent.
    - ``team`` mode, ``accept=False`` (reject): always a no-op. Rejecting a
      pending action cannot grant elevated privilege, so it is never gated
      — the same asymmetry ``roy_self_approval.py``'s
      ``check_not_self_approval`` already has (it only ever blocks accept).
    - ``team`` mode, ``accept=True``: requires ``supplied_token`` to match
      ``config.governance_bridge_token`` via a constant-time comparison.
      If ``config.governance_bridge_token`` is unset, this path is refused
      for *every* caller — deliberately fail closed rather than treating
      "no token configured" as "no check needed" (an unconfigured secret
      must never silently become an open door).

    Raises:
        HTTPException: 403 if the accept=True path in team mode is not
            authorized by a valid bridge token.
    """
    if config.governance_deployment_mode != "team" or not accept:
        return
    expected = config.governance_bridge_token
    if expected is None or supplied_token is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN)
    if not secrets.compare_digest(
        supplied_token.encode("utf-8"),
        expected.get_secret_value().encode("utf-8"),
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN)


def get_conversation_service(request: Request) -> ConversationService:
    service = getattr(request.app.state, "conversation_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Conversation service is not available",
        )
    return service


def get_bash_event_service(request: Request) -> BashEventService:
    service = getattr(request.app.state, "bash_event_service", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Bash event service is not available",
        )
    return service


async def get_event_service(
    conversation_id: UUID,
    conversation_service: ConversationService = Depends(get_conversation_service),
) -> EventService:
    event_service = await conversation_service.get_event_service(conversation_id)
    if event_service is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Conversation not found: {conversation_id}",
        )
    return event_service
