"""Tests for GovernanceClient's token caching and error classification.

Uses httpx.MockTransport so these run without any real network calls or
real central-governance-api/Keycloak instance — the actual end-to-end
wiring against real infra is covered by the manual smoke test in
central-governance-api's ops/ directory (not part of the pytest suite).
"""

from __future__ import annotations

import time

import httpx
import pytest

from openhands.agent_server.governance_client import (
    GovernanceClient,
    GovernancePermanentError,
    GovernanceRecordNotTerminalError,
    GovernanceTransientError,
    compute_display_digest,
)


def _token_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"access_token": "fake-token", "expires_in": 3600})


def _make_client(handler) -> GovernanceClient:
    transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(transport=transport)
    return GovernanceClient(
        base_url="http://central.example",
        token_url="http://keycloak.example/token",
        client_id="cid",
        client_secret="secret",
        http_client=http_client,
    )


@pytest.mark.asyncio
async def test_create_approval_success():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if str(request.url) == "http://keycloak.example/token":
            return _token_response(request)
        assert str(request.url) == "http://central.example/api/v1/approvals"
        assert request.headers["Authorization"] == "Bearer fake-token"
        assert request.headers["Idempotency-Key"] == "key-1"
        return httpx.Response(201, json={"id": "approval-1", "status": "pending"})

    client = _make_client(handler)
    result = await client.create_approval({"request_id": "r1"}, idempotency_key="key-1")

    assert result == {"id": "approval-1", "status": "pending"}
    await client.aclose()


@pytest.mark.asyncio
async def test_token_is_cached_across_calls():
    token_calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://keycloak.example/token":
            token_calls.append(1)
            return _token_response(request)
        return httpx.Response(200, json={"status": "ok"})

    client = _make_client(handler)
    await client.claim("a1", idempotency_key="k1")
    await client.claim("a2", idempotency_key="k2")

    assert len(token_calls) == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_expired_token_is_refreshed():
    token_calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://keycloak.example/token":
            token_calls.append(1)
            return httpx.Response(
                200, json={"access_token": f"token-{len(token_calls)}", "expires_in": 1}
            )
        return httpx.Response(200, json={"status": "ok"})

    client = _make_client(handler)
    await client.claim("a1", idempotency_key="k1")
    # Force the cached token to look expired (past the 30s safety margin)
    # without an actual sleep.
    client._cached_token.expires_at_monotonic = time.monotonic() - 1  # type: ignore[union-attr]
    await client.claim("a2", idempotency_key="k2")

    assert len(token_calls) == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_concurrent_modification_is_transient():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://keycloak.example/token":
            return _token_response(request)
        return httpx.Response(
            409,
            json={"error_code": "concurrent_modification", "detail": "retry"},
        )

    client = _make_client(handler)
    with pytest.raises(GovernanceTransientError) as exc_info:
        await client.claim("a1", idempotency_key="k1")
    assert exc_info.value.error_code == "concurrent_modification"
    await client.aclose()


@pytest.mark.asyncio
async def test_record_not_terminal_is_its_own_type():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://keycloak.example/token":
            return _token_response(request)
        return httpx.Response(
            409,
            json={"error_code": "record_not_terminal", "detail": "not resolved yet"},
        )

    client = _make_client(handler)
    with pytest.raises(GovernanceRecordNotTerminalError):
        await client.reconciliation_finding(
            "a1", idempotency_key="k1", finding_type="late_report"
        )
    await client.aclose()


@pytest.mark.asyncio
async def test_authorization_denied_is_permanent():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://keycloak.example/token":
            return _token_response(request)
        return httpx.Response(
            403, json={"error_code": "authorization_denied", "detail": "nope"}
        )

    client = _make_client(handler)
    with pytest.raises(GovernancePermanentError) as exc_info:
        await client.claim("a1", idempotency_key="k1")
    assert exc_info.value.error_code == "authorization_denied"
    await client.aclose()


@pytest.mark.asyncio
async def test_unrecognized_error_code_fails_closed_to_permanent():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://keycloak.example/token":
            return _token_response(request)
        return httpx.Response(
            418, json={"error_code": "something_never_seen_before", "detail": "?"}
        )

    client = _make_client(handler)
    with pytest.raises(GovernancePermanentError):
        await client.claim("a1", idempotency_key="k1")
    await client.aclose()


@pytest.mark.asyncio
async def test_5xx_is_transient():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://keycloak.example/token":
            return _token_response(request)
        return httpx.Response(500, text="internal error, no json body")

    client = _make_client(handler)
    with pytest.raises(GovernanceTransientError):
        await client.claim("a1", idempotency_key="k1")
    await client.aclose()


@pytest.mark.asyncio
async def test_network_error_is_transient():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://keycloak.example/token":
            return _token_response(request)
        raise httpx.ConnectError("connection refused")

    client = _make_client(handler)
    with pytest.raises(GovernanceTransientError) as exc_info:
        await client.claim("a1", idempotency_key="k1")
    assert exc_info.value.error_code is None
    await client.aclose()


@pytest.mark.asyncio
async def test_token_endpoint_network_error_is_transient():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://keycloak.example/token"
        raise httpx.ConnectError("connection refused")

    client = _make_client(handler)
    with pytest.raises(GovernanceTransientError):
        await client.claim("a1", idempotency_key="k1")
    await client.aclose()


@pytest.mark.asyncio
async def test_token_endpoint_5xx_is_transient():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://keycloak.example/token"
        return httpx.Response(503, text="idp overloaded")

    client = _make_client(handler)
    with pytest.raises(GovernanceTransientError):
        await client.claim("a1", idempotency_key="k1")
    await client.aclose()


@pytest.mark.asyncio
async def test_token_endpoint_401_is_permanent():
    """Bad client_id/client_secret will never succeed on retry — must fail
    closed to needs_attention, not spin a transient-error retry loop
    against static credentials that are simply wrong."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://keycloak.example/token"
        return httpx.Response(401, json={"error": "invalid_client"})

    client = _make_client(handler)
    with pytest.raises(GovernancePermanentError):
        await client.claim("a1", idempotency_key="k1")
    await client.aclose()


@pytest.mark.asyncio
async def test_token_endpoint_malformed_response_is_permanent():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://keycloak.example/token"
        return httpx.Response(200, text="not json")

    client = _make_client(handler)
    with pytest.raises(GovernancePermanentError):
        await client.claim("a1", idempotency_key="k1")
    await client.aclose()


@pytest.mark.asyncio
async def test_request_omits_timeout_kwarg_by_default():
    """httpx distinguishes an explicit timeout=None (disables timeout
    entirely) from omitting the kwarg (falls back to the client's own
    constructor default) — regression test for the bug where _request()
    used to pass timeout=None unconditionally, silently disabling the
    30s default timeout on every ordinary call (create/claim/
    report_result), not just wait()'s own deliberate override."""

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://keycloak.example/token":
            return _token_response(request)
        return httpx.Response(200, json={"status": "ok"})

    client = _make_client(handler)
    original_request = client._http.request
    captured: list[dict] = []

    async def spy_request(*args, **kwargs):
        captured.append(kwargs)
        return await original_request(*args, **kwargs)

    client._http.request = spy_request  # type: ignore[method-assign]

    await client.claim("a1", idempotency_key="k1")

    # _access_token()'s own token fetch goes through self._http.post(),
    # which httpx implements in terms of .request() internally — filter
    # that call out (its kwargs include "data", the claim call's don't)
    # to isolate the one _request() call this test actually cares about.
    claim_calls = [kw for kw in captured if "data" not in kw]
    assert len(claim_calls) == 1
    assert "timeout" not in claim_calls[0]
    await client.aclose()


@pytest.mark.asyncio
async def test_wait_passes_explicit_timeout_override():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://keycloak.example/token":
            return _token_response(request)
        return httpx.Response(
            200, json={"id": "a1", "status": "pending", "changed": False}
        )

    client = _make_client(handler)
    original_request = client._http.request
    captured: list[dict] = []

    async def spy_request(*args, **kwargs):
        captured.append(kwargs)
        return await original_request(*args, **kwargs)

    client._http.request = spy_request  # type: ignore[method-assign]

    await client.wait("a1", known_status="pending", timeout_seconds=25)

    # See test_request_omits_timeout_kwarg_by_default's comment for why
    # the token fetch's own .request() call must be filtered out first.
    wait_calls = [kw for kw in captured if "data" not in kw]
    assert len(wait_calls) == 1
    assert wait_calls[0]["timeout"] == 35.0  # timeout_seconds + 10.0 margin
    await client.aclose()


def test_compute_display_digest_matches_known_vector():
    # This literal was independently computed by calling central-
    # governance-api's own compute_display_digest() (central_governance_
    # api/approvals/digest.py) with these exact inputs — not derived from
    # this file's own implementation. Pinning it here means a future
    # accidental change to *either* copy's canonicalization (field order,
    # json.dumps separators, sort_keys, etc — see governance_client.py's
    # module docstring on why this function is duplicated rather than
    # imported) shows up as a failing assertion here, instead of only in
    # production when a create request gets rejected with
    # digest_mismatch. A "call the function twice and compare" version of
    # this test would not catch that: both copies could each drift the
    # same way and still agree with themselves.
    digest = compute_display_digest(
        action_type="terminal_command",
        tool_name="bash",
        policy_revision="v1",
        action_summary="echo mvp-smoke-test",
        action_payload={"command": "echo mvp-smoke-test"},
        digest_salt=None,
    )
    assert digest == "829d1940a8b171535575c5a76aff4bbee75570948c6c4e7851844b50d97759bf"
