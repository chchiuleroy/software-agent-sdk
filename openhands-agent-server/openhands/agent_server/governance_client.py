"""Thin async client for central-governance-api, used by agent-server when
``Config.governance_deployment_mode == "team"``.

Scope note (MVP slice): this client is the *only* caller of create/claim/
report-result/cancel/reconciliation-findings — one process, one set of
credentials, for the same reason central-governance-api's own authorization
rules require it (``authorize.py``: CLAIM/REPORT_RESULT/late-report all
require the *same* ``(issuer, sub)`` principal that created the record).
There is deliberately no separate "bridge" identity for these calls in this
slice; the bridge (a separate process — see ``ops/`` in the
central-governance-api repo) only ever calls this agent-server's own
``respond_to_confirmation`` endpoint, gated by ``X-Governance-Bridge-Token``
(see ``dependencies.py``), and never talks to central-governance-api's
mutating endpoints directly.

Error classification follows central-governance-api's own stable
``error_code`` table (``main.py``'s ``_ERROR_STATUS``), not raw HTTP status
codes — see ``GovernanceApiError`` subclasses below.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

from openhands.sdk.logger import get_logger


logger = get_logger(__name__)

# Matches central_governance_api.approvals.digest.compute_display_digest
# byte-for-byte — see that module's docstring for why this is duplicated
# rather than cross-imported (a separate uv project/deployment unit). A
# shared golden-vectors test file would be the way to keep the two in
# sync automatically; not built yet.
_DIGEST_SCHEMA_FIELDS = (
    "action_type",
    "tool_name",
    "policy_revision",
    "action_summary",
    "action_payload",
    "digest_salt",
)


def compute_display_digest(
    *,
    action_type: str,
    tool_name: str,
    policy_revision: str,
    action_summary: str,
    action_payload: dict[str, Any],
    digest_salt: str | None,
    execution_commitment: str | None = None,
) -> str:
    canonical = {
        "action_type": action_type,
        "tool_name": tool_name,
        "policy_revision": policy_revision,
        "action_summary": action_summary,
        "action_payload": action_payload,
        "digest_salt": digest_salt,
    }
    if execution_commitment is not None:
        # Added only when present, exactly as central does, so a record with
        # no commitment hashes as it always did.
        canonical["execution_commitment"] = execution_commitment
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class GovernanceApiError(Exception):
    """Base for every classified central-governance-api error. Carries the
    response's ``error_code`` (``None`` for network-level failures that
    never got a response body at all) so callers can log/branch on it
    without string-matching ``str(exc)``."""

    def __init__(
        self, message: str, *, error_code: str | None, status_code: int | None
    ):
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(message)


class GovernanceTransientError(GovernanceApiError):
    """Safe to retry with backoff, same Idempotency-Key: network failure,
    5xx, or central's own ``concurrent_modification`` (whose error message
    says exactly this — see central-governance-api's ``errors.py``)."""


class GovernancePermanentError(GovernanceApiError):
    """Retrying the exact same request will not help: schema/validation
    error, authorization failure, not-found, idempotency-key reuse with a
    different body, device-registration errors. Maps to a
    ``needs_attention`` outbox transition, not a retry loop."""


class GovernanceRecordNotTerminalError(GovernanceApiError):
    """reconciliation-findings only: the record hasn't reached a resolved
    status yet. Not "retry the same call sooner" — the caller should wait
    for central's expiry sweep to actually resolve it first."""


# error_code -> classification, straight from central-governance-api's own
# main.py::_ERROR_STATUS table (single source of truth there; duplicated
# here as a lookup rather than cross-imported for the same "separate
# deployment unit" reason as compute_display_digest above).
_PERMANENT_ERROR_CODES = frozenset(
    {
        "authorization_denied",
        "illegal_transition",
        "execution_attempt_mismatch",
        "record_not_found",
        "digest_mismatch",
        "execution_commitment_mismatch",
        "execution_commitment_required",
        "idempotency_key_reused",
        "device_not_found",
        "device_already_registered",
        "device_revoked",
        "device_quota_exceeded",
        "device_already_revoked",
    }
)


def _classify_response(response: httpx.Response) -> None:
    """Raises the appropriately classified error for a non-2xx response;
    returns normally for 2xx (including an idempotent replay, which
    central returns as an ordinary success body — see
    ``routers/approvals.py``'s ``find_replayed_response``)."""
    if response.is_success:
        return
    try:
        body = response.json()
        error_code = body.get("error_code")
        detail = body.get("detail", response.text)
    except ValueError:
        error_code = None
        detail = response.text
    message = f"central-governance-api {response.status_code} ({error_code}): {detail}"
    if error_code == "record_not_terminal":
        raise GovernanceRecordNotTerminalError(
            message, error_code=error_code, status_code=response.status_code
        )
    if error_code == "concurrent_modification" or response.status_code >= 500:
        raise GovernanceTransientError(
            message, error_code=error_code, status_code=response.status_code
        )
    if error_code in _PERMANENT_ERROR_CODES or response.status_code in (
        400,
        401,
        403,
        404,
        409,
        422,
        429,
    ):
        raise GovernancePermanentError(
            message, error_code=error_code, status_code=response.status_code
        )
    # An error_code this client doesn't recognize is treated as permanent —
    # fail closed to needs_attention rather than guessing it's safe to retry.
    raise GovernancePermanentError(
        message, error_code=error_code, status_code=response.status_code
    )


@dataclass
class _CachedToken:
    access_token: str
    expires_at_monotonic: float


class GovernanceClient:
    """One instance per agent-server process, holding the single operator
    credential used for every central-governance-api call this process
    makes (see module docstring, point 1)."""

    def __init__(
        self,
        *,
        base_url: str,
        token_url: str,
        client_id: str,
        client_secret: str,
        http_client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._http = http_client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_http_client = http_client is None
        self._cached_token: _CachedToken | None = None

    async def aclose(self) -> None:
        if self._owns_http_client:
            await self._http.aclose()

    async def check_health(self) -> dict[str, Any]:
        """Probe central-governance-api for the status endpoint; never raises.

        Two independent facts: is the API reachable (unauthenticated
        ``/healthz``), and do the configured client credentials still get a
        token from the IdP. ``error`` carries only an exception class name or
        an HTTP status code — never a response body or a credential, since
        the result is shown in the GUI.
        """
        try:
            response = await self._http.get(f"{self._base_url}/healthz")
        except httpx.HTTPError as exc:
            return {
                "reachable": False,
                "credentials_ok": None,
                "error": f"central API unreachable ({type(exc).__name__})",
            }
        if not response.is_success:
            return {
                "reachable": False,
                "credentials_ok": None,
                "error": f"central API /healthz returned HTTP {response.status_code}",
            }
        try:
            await self._access_token()
        except GovernanceApiError as exc:
            reason = (
                f"HTTP {exc.status_code}"
                if exc.status_code is not None
                else "token endpoint unreachable"
            )
            return {
                "reachable": True,
                "credentials_ok": False,
                "error": f"token request failed ({reason})",
            }
        return {"reachable": True, "credentials_ok": True, "error": None}

    async def _access_token(self) -> str:
        # 30s safety margin so a token doesn't expire mid-request.
        if (
            self._cached_token is not None
            and self._cached_token.expires_at_monotonic - 30.0 > time.monotonic()
        ):
            return self._cached_token.access_token
        # This talks to the IdP, not central-governance-api, so
        # _classify_response()'s error_code table doesn't apply here — but
        # a failure here must still honor the same transient/permanent
        # contract every other call site on this client relies on, rather
        # than leaking a raw httpx/parsing exception past it.
        try:
            response = await self._http.post(
                self._token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
        except httpx.HTTPError as exc:
            raise GovernanceTransientError(
                f"network error fetching OIDC token from {self._token_url}: {exc}",
                error_code=None,
                status_code=None,
            ) from exc
        if not response.is_success:
            # Bad credentials or a malformed request will never succeed on
            # retry (client_id/client_secret are static); a flaky/
            # overloaded IdP (5xx) might.
            error_cls = (
                GovernanceTransientError
                if response.is_server_error
                else GovernancePermanentError
            )
            raise error_cls(
                f"OIDC token endpoint {self._token_url} returned "
                f"{response.status_code}: {response.text}",
                error_code=None,
                status_code=response.status_code,
            )
        try:
            body = response.json()
            access_token = body["access_token"]
        except (ValueError, KeyError) as exc:
            raise GovernancePermanentError(
                f"OIDC token endpoint {self._token_url} returned an "
                f"unparseable response: {exc}",
                error_code=None,
                status_code=response.status_code,
            ) from exc
        self._cached_token = _CachedToken(
            access_token=access_token,
            expires_at_monotonic=time.monotonic() + float(body.get("expires_in", 60)),
        )
        return self._cached_token.access_token

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        """``timeout`` overrides this client's own constructor default for
        this one call — needed by ``wait()``, whose server-side long-poll
        deadline (``wait_max_timeout_seconds``, currently the same 30s as
        this client's own default request timeout) would otherwise race
        this client's timeout against the server actually responding at
        its own deadline, with no margin for network latency in between."""
        token = await self._access_token()
        headers = {"Authorization": f"Bearer {token}"}
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        # httpx distinguishes "omit this kwarg" (falls back to the client's
        # own constructor timeout) from an explicit timeout=None (disables
        # timeout entirely — infinite wait). Only build the kwarg when a
        # caller actually wants an override, so every other call site here
        # keeps this client's real default instead of silently losing its
        # timeout protection.
        request_kwargs: dict[str, Any] = {
            "json": json_body,
            "params": params,
            "headers": headers,
        }
        if timeout is not None:
            request_kwargs["timeout"] = timeout
        try:
            response = await self._http.request(
                method, f"{self._base_url}{path}", **request_kwargs
            )
        except httpx.HTTPError as exc:
            raise GovernanceTransientError(
                f"network error calling central-governance-api {method} {path}: {exc}",
                error_code=None,
                status_code=None,
            ) from exc
        _classify_response(response)
        return response

    async def create_approval(
        self, body: dict[str, Any], *, idempotency_key: str
    ) -> dict[str, Any]:
        response = await self._request(
            "POST", "/api/v1/approvals", json_body=body, idempotency_key=idempotency_key
        )
        return response.json()

    async def claim(
        self,
        approval_id: str,
        *,
        idempotency_key: str,
        execution_commitment: str | None = None,
    ) -> dict[str, Any]:
        # No body at all for a record that has no commitment, so a claim for
        # one is byte-for-byte what it always was.
        response = await self._request(
            "POST",
            f"/api/v1/approvals/{approval_id}/claim",
            json_body=(
                {"execution_commitment": execution_commitment}
                if execution_commitment is not None
                else None
            ),
            idempotency_key=idempotency_key,
        )
        return response.json()

    async def report_result(
        self,
        approval_id: str,
        *,
        idempotency_key: str,
        execution_attempt_id: str | None = None,
        outcome: str | None = None,
        executed_commitment: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if execution_attempt_id is not None:
            body["execution_attempt_id"] = execution_attempt_id
            body["outcome"] = outcome
            if executed_commitment is not None:
                body["executed_commitment"] = executed_commitment
        response = await self._request(
            "POST",
            f"/api/v1/approvals/{approval_id}/report-result",
            json_body=body,
            idempotency_key=idempotency_key,
        )
        return response.json()

    async def wait(
        self,
        approval_id: str,
        *,
        known_status: str,
        timeout_seconds: int = 25,
    ) -> dict[str, Any]:
        """Long-polls ``GET .../{approval_id}/wait`` — blocks server-side
        until the approval's status differs from ``known_status``, or
        ``timeout_seconds`` elapses (server clamps this to its own
        ``wait_max_timeout_seconds``, currently 30s — see that endpoint's
        own docstring), whichever comes first. Returns ``{"id", "status",
        "changed"}``; ``changed=False`` is not an error, just "still
        pending, call again".

        Not idempotency-key-guarded — a GET that only reads is already
        safe to call repeatedly (see the endpoint's own docstring for why).

        Adds a fixed 10s margin on top of the server's own deadline for
        this call's client-side timeout, rather than reusing this client's
        constructor default — see ``_request()``'s own comment for why an
        unpadded match would let this client's timeout race the server's.
        """
        response = await self._request(
            "GET",
            f"/api/v1/approvals/{approval_id}/wait",
            params={"known_status": known_status, "timeout_seconds": timeout_seconds},
            timeout=timeout_seconds + 10.0,
        )
        return response.json()

    async def cancel(self, approval_id: str, *, idempotency_key: str) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/v1/approvals/{approval_id}/cancel",
            idempotency_key=idempotency_key,
        )
        return response.json()

    async def reconciliation_finding(
        self,
        approval_id: str,
        *,
        idempotency_key: str,
        finding_type: str,
        conclusion: str | None = None,
        note: str = "",
    ) -> dict[str, Any]:
        response = await self._request(
            "POST",
            f"/api/v1/approvals/{approval_id}/reconciliation-findings",
            json_body={
                "finding_type": finding_type,
                "conclusion": conclusion,
                "note": note,
            },
            idempotency_key=idempotency_key,
        )
        return response.json()
