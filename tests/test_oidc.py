"""Tests for the async OIDC resolver. Pattern mirrors
``tests/agent_server/test_oidc_principal.py`` in openhands-sdk-governed:
synthetic RSA keys, no network, no running IdP — plus new coverage for the
v11 fixes this module adds on top of that Phase 0 module (negative-kid
cache, pinned single algorithm, token length cap, azp allowlist).
"""

from __future__ import annotations

import time

import pytest
from joserfc import jwk, jwt

from central_governance_api.auth.oidc import (
    KNOWN_ROLES,
    OIDCPrincipalResolver,
    PrincipalResolutionError,
)
from central_governance_api.config import Settings

from .conftest import AUDIENCE, ISSUER


def _sign(
    signing_key: jwk.RSAKey,
    claims: dict,
    *,
    alg: str = "RS256",
    kid: str | None = None,
) -> str:
    header: dict[str, str] = {"alg": alg}
    if kid is not None:
        header["kid"] = kid
    else:
        existing_kid = signing_key.as_dict(private=False).get("kid")
        if isinstance(existing_kid, str):
            header["kid"] = existing_kid
    return jwt.encode(header, claims, signing_key)


def _valid_claims(**overrides: object) -> dict:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": "user-123",
        "aud": AUDIENCE,
        "exp": now + 3600,
        "iat": now,
        "roles": ["agent.operator"],
    }
    claims.update(overrides)
    return claims


@pytest.fixture
def resolver(settings: Settings, public_jwks) -> OIDCPrincipalResolver:
    return OIDCPrincipalResolver(
        settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )


async def test_valid_token_resolves_principal(resolver, signing_key):
    token = _sign(signing_key, _valid_claims())
    principal = await resolver.resolve(token)
    assert principal.issuer == ISSUER
    assert principal.sub == "user-123"
    assert principal.roles == {"agent.operator"}
    assert principal.subject == f"{ISSUER}#user-123"


async def test_unknown_roles_are_dropped_not_trusted(resolver, signing_key):
    token = _sign(
        signing_key, _valid_claims(roles=["agent.operator", "totally-made-up-role"])
    )
    principal = await resolver.resolve(token)
    assert principal.roles == {"agent.operator"}


async def test_all_known_roles_pass_through(resolver, signing_key):
    token = _sign(signing_key, _valid_claims(roles=sorted(KNOWN_ROLES)))
    principal = await resolver.resolve(token)
    assert principal.roles == KNOWN_ROLES


async def test_wrong_issuer_rejected(resolver, signing_key):
    token = _sign(signing_key, _valid_claims(iss="https://attacker.invalid/realm"))
    with pytest.raises(PrincipalResolutionError):
        await resolver.resolve(token)


async def test_wrong_audience_rejected(resolver, signing_key):
    token = _sign(signing_key, _valid_claims(aud="some-other-service"))
    with pytest.raises(PrincipalResolutionError):
        await resolver.resolve(token)


async def test_expired_token_rejected(resolver, signing_key):
    # Well outside the resolver's leeway_seconds (default 30) — a small
    # negative offset would be a clock-skew false positive, not a real test.
    now = int(time.time())
    token = _sign(signing_key, _valid_claims(exp=now - 3600, iat=now - 7200))
    with pytest.raises(PrincipalResolutionError):
        await resolver.resolve(token)


async def test_iss_as_array_rejected(resolver, signing_key):
    # JWTClaimsRegistry's array-membership check would accept this; the
    # explicit isinstance(iss, str) check must still reject it.
    token = _sign(signing_key, _valid_claims(iss=[ISSUER, "https://attacker.invalid"]))
    with pytest.raises(PrincipalResolutionError):
        await resolver.resolve(token)


async def test_aud_as_array_containing_audience_accepted(resolver, signing_key):
    token = _sign(signing_key, _valid_claims(aud=["some-other-aud", AUDIENCE]))
    principal = await resolver.resolve(token)
    assert principal.sub == "user-123"


@pytest.mark.parametrize("bad_roles", [{"not": "a list"}, "roles-as-string", 42, None])
async def test_non_list_roles_claim_rejected(resolver, signing_key, bad_roles):
    token = _sign(signing_key, _valid_claims(roles=bad_roles))
    if bad_roles is None:
        # None collapses to "no roles claim at all" upstream (`or []`);
        # that's valid (an empty-roles token), not a rejection case.
        principal = await resolver.resolve(token)
        assert principal.roles == frozenset()
    else:
        with pytest.raises(PrincipalResolutionError):
            await resolver.resolve(token)


async def test_alg_none_forgery_rejected(resolver):
    # Hand-construct an unsigned token — joserfc's `alg: none` handling
    # (or the explicit pinned-algorithm allowlist) must reject this
    # regardless, since `None` is never in `_SAFE_SIGNING_ALGORITHMS`.
    import base64
    import json

    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(json.dumps(_valid_claims()).encode()).rstrip(
        b"="
    )
    forged = header.decode() + "." + payload.decode() + "."
    resolver_instance = resolver
    with pytest.raises(PrincipalResolutionError):
        await resolver_instance.resolve(forged)


async def test_untrusted_signing_key_rejected(resolver, settings: Settings):
    attacker_key = jwk.RSAKey.generate_key(2048, parameters={"kid": "attacker-key"})
    token = _sign(attacker_key, _valid_claims(), kid="attacker-key")
    with pytest.raises(PrincipalResolutionError):
        await resolver.resolve(token)


async def test_empty_bearer_token_rejected(resolver):
    with pytest.raises(PrincipalResolutionError):
        await resolver.resolve("")


async def test_token_exceeding_max_length_rejected(resolver, settings: Settings):
    huge_token = "x" * (settings.bearer_max_token_length + 1)
    with pytest.raises(PrincipalResolutionError, match="maximum accepted length"):
        await resolver.resolve(huge_token)


async def test_unknown_kid_then_repeat_uses_negative_cache(
    resolver, signing_key, public_jwks
):
    """Round 8/10 fix: a second request with the same never-valid kid must
    not trigger another JWKS fetch — verified indirectly here by confirming
    it still raises cleanly (the resolver is `never_refresh_keys=True`, so
    if this reached a real fetch attempt it would hang/fail differently).
    """
    token = _sign(signing_key, _valid_claims(), kid="never-registered-kid")
    with pytest.raises(PrincipalResolutionError):
        await resolver.resolve(token)
    # second call with the same bogus kid should short-circuit via the
    # negative cache rather than re-attempting a JWKS force-refresh
    with pytest.raises(PrincipalResolutionError):
        await resolver.resolve(token)


async def test_azp_allowlist_rejects_unlisted_client(
    settings: Settings, public_jwks, signing_key
):
    scoped_settings = settings.model_copy(
        update={"oidc_azp_allowlist": ("desktop-app",)}
    )
    scoped_resolver = OIDCPrincipalResolver(
        scoped_settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    token = _sign(signing_key, _valid_claims(azp="some-other-client"))
    with pytest.raises(PrincipalResolutionError, match="authorized party"):
        await scoped_resolver.resolve(token)


async def test_azp_allowlist_accepts_listed_client(
    settings: Settings, public_jwks, signing_key
):
    scoped_settings = settings.model_copy(
        update={"oidc_azp_allowlist": ("desktop-app",)}
    )
    scoped_resolver = OIDCPrincipalResolver(
        scoped_settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    token = _sign(signing_key, _valid_claims(azp="desktop-app"))
    principal = await scoped_resolver.resolve(token)
    assert principal.azp == "desktop-app"


def test_config_rejects_unsafe_signing_algorithm():
    with pytest.raises(ValueError, match="not in the safe set"):
        OIDCPrincipalResolver(
            Settings(
                oidc_issuer=ISSUER,
                oidc_jwks_url="https://x.invalid/certs",
                oidc_audience=AUDIENCE,
                oidc_signing_algorithm="none",
            )
        )


def test_settings_reject_http_urls_by_default():
    """Regression (found running the real MVP deployment, 2026-09-16): a
    local ``.env`` with ``CGA_OIDC_REQUIRE_HTTPS=false`` — exactly what
    README's own ``cp .env.example .env`` step produces once uncommented
    for local dev against the known http-enabled Keycloak instance — was
    silently satisfying this test's "reject by default" assertion via
    dotenv, not the field default this test exists to prove. `.env`
    values sit below explicit environment variables in pydantic-settings'
    precedence, so pinning ``CGA_OIDC_REQUIRE_HTTPS`` here the same way
    the other three vars already are is what actually isolates this test
    from whatever `.env` happens to exist on the machine running it.
    """
    with pytest.raises(ValueError, match="oidc_require_https"):
        import os

        from central_governance_api.config import get_settings

        env_vars = (
            "CGA_OIDC_ISSUER",
            "CGA_OIDC_JWKS_URL",
            "CGA_OIDC_AUDIENCE",
            "CGA_OIDC_REQUIRE_HTTPS",
        )
        env_backup = {k: os.environ.pop(k) for k in env_vars if k in os.environ}
        os.environ["CGA_OIDC_ISSUER"] = "http://insecure.invalid/realm"
        os.environ["CGA_OIDC_JWKS_URL"] = "http://insecure.invalid/certs"
        os.environ["CGA_OIDC_AUDIENCE"] = AUDIENCE
        os.environ["CGA_OIDC_REQUIRE_HTTPS"] = "true"
        try:
            get_settings()
        finally:
            for k in env_vars:
                os.environ.pop(k, None)
            os.environ.update(env_backup)
