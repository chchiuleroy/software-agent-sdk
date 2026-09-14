"""Tests for the Phase 0 OIDC Principal resolver (oidc_principal.py).

All tests sign tokens against a locally generated RSA key — no network
access or running IdP is required, matching the module's own preloaded-
JWKS testability design.
"""

import time

import pytest
from joserfc import jwk, jwt

from openhands.agent_server.oidc_principal import (
    _SAFE_SIGNING_ALGORITHMS,
    OIDCPrincipalResolver,
    OIDCVerifierConfig,
    PrincipalResolutionError,
)


ISSUER = "https://idp.example.test/"
AUDIENCE = "agent-server"


@pytest.fixture(scope="module")
def signing_key() -> jwk.RSAKey:
    return jwk.RSAKey.generate_key(2048, parameters={"kid": "test-kid"}, private=True)


@pytest.fixture
def public_jwks(signing_key: jwk.RSAKey) -> jwk.KeySetSerialization:
    return {"keys": [signing_key.as_dict(private=False)]}


@pytest.fixture
def resolver(public_jwks: jwk.KeySetSerialization) -> OIDCPrincipalResolver:
    config = OIDCVerifierConfig(
        issuer=ISSUER,
        jwks_url="https://idp.example.test/jwks.json",
        audience=AUDIENCE,
    )
    return OIDCPrincipalResolver(config, preloaded_keys=public_jwks)


def _sign(
    signing_key: jwk.RSAKey,
    claims: dict,
    *,
    alg: str = "RS256",
    kid: str | None = "test-kid",
) -> str:
    header = {"alg": alg}
    if kid is not None:
        header["kid"] = kid
    return jwt.encode(header, claims, signing_key)


def _valid_claims(**overrides) -> dict:
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-1",
        "exp": int(time.time()) + 600,
        "roles": ["agent.operator"],
    }
    claims.update(overrides)
    return claims


def test_valid_token_resolves_principal(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey
):
    token = _sign(signing_key, _valid_claims(name="Roy"))

    principal = resolver.resolve(token)

    assert principal.issuer == ISSUER
    assert principal.sub == "user-1"
    assert principal.subject == f"{ISSUER}#user-1"
    assert principal.display_name == "Roy"
    assert principal.roles == frozenset({"agent.operator"})


def test_display_name_falls_back_to_preferred_username_then_sub(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey
):
    token = _sign(signing_key, _valid_claims(preferred_username="roy.chiu"))
    assert resolver.resolve(token).display_name == "roy.chiu"

    token_no_name = _sign(signing_key, _valid_claims())
    assert resolver.resolve(token_no_name).display_name == "user-1"


def test_unknown_role_claim_values_are_dropped_not_trusted(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey
):
    token = _sign(
        signing_key,
        _valid_claims(roles=["agent.operator", "totally-made-up-role", "superadmin"]),
    )

    principal = resolver.resolve(token)

    assert principal.roles == frozenset({"agent.operator"})


def test_wrong_issuer_rejected(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey
):
    token = _sign(signing_key, _valid_claims(iss="https://attacker.example/"))

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(token)


def test_wrong_audience_rejected(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey
):
    token = _sign(signing_key, _valid_claims(aud="some-other-service"))

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(token)


def test_expired_token_rejected(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey
):
    token = _sign(signing_key, _valid_claims(exp=int(time.time()) - 3600))

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(token)


def test_missing_sub_claim_rejected(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey
):
    claims = _valid_claims()
    del claims["sub"]
    token = _sign(signing_key, claims)

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(token)


def test_roles_claim_not_a_list_rejected(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey
):
    token = _sign(signing_key, _valid_claims(roles="agent.operator"))

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(token)


def test_alg_none_token_rejected(resolver: OIDCPrincipalResolver):
    """The classic JWT "alg: none" bypass must never succeed.

    A crafted unsigned token with the same claims as a valid one, if
    accepted, would let any caller mint their own identity/roles without
    ever holding a real IdP-issued token.
    """
    import base64
    import json

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(_valid_claims()).encode())
    forged_token = f"{header}.{payload}."

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(forged_token)


def test_token_signed_by_untrusted_key_rejected(resolver: OIDCPrincipalResolver):
    """A token signed by a key that isn't in the trusted JWKS must be rejected."""
    other_key = jwk.RSAKey.generate_key(
        2048, parameters={"kid": "test-kid"}, private=True
    )
    forged_token = _sign(other_key, _valid_claims())

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(forged_token)


def test_empty_bearer_token_rejected(resolver: OIDCPrincipalResolver):
    with pytest.raises(PrincipalResolutionError):
        resolver.resolve("")


def test_preloaded_jwks_avoids_network_fetch(
    public_jwks: jwk.KeySetSerialization, signing_key: jwk.RSAKey
):
    """Sanity check that preloaded_keys really is honored (no network I/O).

    Uses an unreachable jwks_url — if the resolver ever fell back to
    fetching it, this test would hang/fail on a connection error instead
    of resolving successfully.
    """
    config = OIDCVerifierConfig(
        issuer=ISSUER,
        jwks_url="https://this-host-does-not-exist.invalid/jwks.json",
        audience=AUDIENCE,
    )
    resolver = OIDCPrincipalResolver(config, preloaded_keys=public_jwks)

    principal = resolver.resolve(_sign(signing_key, _valid_claims()))

    assert principal.sub == "user-1"


# --- Claim type-confusion, key-rotation, and algorithm-scoping coverage ---


def test_iss_as_array_rejected(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey
):
    """joserfc's claims-registry value matching treats an array claim as
    "is the expected value contained in it" — so a forged `iss` array
    containing the trusted issuer among other values must still be
    rejected, not silently accepted as if it were the plain string.
    """
    token = _sign(signing_key, _valid_claims(iss=[ISSUER, "https://attacker.example/"]))

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(token)


@pytest.mark.parametrize(
    "bad_sub", [123, {"nested": "object"}, ["a", "list"], "", None]
)
def test_non_string_or_empty_sub_rejected(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey, bad_sub
):
    claims = _valid_claims()
    if bad_sub is None:
        del claims["sub"]
    else:
        claims["sub"] = bad_sub
    token = _sign(signing_key, claims)

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(token)


def test_aud_as_valid_multi_value_array_accepted(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey
):
    token = _sign(signing_key, _valid_claims(aud=[AUDIENCE, "some-other-service"]))

    principal = resolver.resolve(token)

    assert principal.sub == "user-1"


@pytest.mark.parametrize(
    "bad_aud", [123, {"nested": "object"}, [], [AUDIENCE, 123], ""]
)
def test_malformed_aud_rejected(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey, bad_aud
):
    token = _sign(signing_key, _valid_claims(aud=bad_aud))

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(token)


@pytest.mark.parametrize(
    "bad_roles",
    [
        ["agent.operator", {"role": "governance.admin"}],
        ["agent.operator", ["nested", "list"]],
        ["agent.operator", 42],
        ["agent.operator", None],
    ],
)
def test_roles_with_non_string_elements_rejected_not_typeerror(
    resolver: OIDCPrincipalResolver, signing_key: jwk.RSAKey, bad_roles
):
    """A non-string role element must cleanly reject the whole token, not
    raise an uncaught TypeError from the set/frozenset membership checks
    (unhashable dict/list elements would otherwise blow up there).
    """
    token = _sign(signing_key, _valid_claims(roles=bad_roles))

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(token)


def test_hmac_confusion_token_rejected(resolver: OIDCPrincipalResolver):
    """A token forged with HS256, using (for example) the RSA public key's
    modulus as an HMAC secret, is a classic algorithm-confusion attack
    against verifiers that don't pin the accepted algorithm set. HS256 is
    not in the safe algorithm allowlist, so this must be rejected before
    any attempt to treat the public key material as an HMAC secret.
    """
    forged = (
        base64_url_encode(b'{"alg":"HS256","typ":"JWT"}')
        + "."
        + base64_url_encode(_json_dumps(_valid_claims()).encode())
        + ".fake-signature"
    )

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(forged)


def test_unknown_kid_triggers_refresh_and_retry_succeeds(
    resolver: OIDCPrincipalResolver,
    signing_key: jwk.RSAKey,
    monkeypatch: pytest.MonkeyPatch,
):
    """If the IdP rotates its signing key mid-TTL, a token signed with the
    new key must still verify after one forced refresh — not be rejected
    until the cache naturally expires up to JWKS_CACHE_TTL_SECONDS later.
    """
    rotated_key = jwk.RSAKey.generate_key(
        2048, parameters={"kid": "rotated-kid"}, private=True
    )

    def _fetch_with_rotated_key_added(self) -> None:
        self._keys = {
            "keys": [
                signing_key.as_dict(private=False),
                rotated_key.as_dict(private=False),
            ]
        }
        self._fetched_at = time.monotonic()

    monkeypatch.setattr(
        resolver._jwks_cache.__class__, "_fetch_jwks", _fetch_with_rotated_key_added
    )

    token = _sign(rotated_key, _valid_claims(), kid="rotated-kid")

    principal = resolver.resolve(token)

    assert principal.sub == "user-1"


def test_unknown_kid_still_rejected_if_refresh_does_not_add_it(
    public_jwks: jwk.KeySetSerialization, signing_key: jwk.RSAKey
):
    """A kid that isn't in the JWKS even after a forced refresh must still
    be rejected cleanly, not loop or raise something other than
    PrincipalResolutionError. Uses never_refresh_keys=True so the "refresh"
    triggered by the retry is a hermetic no-op instead of a real network
    call to the fixture's fake jwks_url.
    """
    config = OIDCVerifierConfig(
        issuer=ISSUER, jwks_url="https://idp.example.test/jwks.json", audience=AUDIENCE
    )
    resolver = OIDCPrincipalResolver(
        config, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    never_registered_key = jwk.RSAKey.generate_key(
        2048, parameters={"kid": "never-registered"}, private=True
    )
    token = _sign(never_registered_key, _valid_claims(), kid="never-registered")

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(token)


def test_empty_jwks_rejects_cleanly(signing_key: jwk.RSAKey):
    config = OIDCVerifierConfig(
        issuer=ISSUER, jwks_url="https://idp.example.test/jwks.json", audience=AUDIENCE
    )
    resolver = OIDCPrincipalResolver(
        config, preloaded_keys={"keys": []}, never_refresh_keys=True
    )
    token = _sign(signing_key, _valid_claims())

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(token)


def test_per_issuer_algorithm_restriction_narrower_than_global_default(
    public_jwks: jwk.KeySetSerialization, signing_key: jwk.RSAKey
):
    """A per-issuer signing_algorithms restriction narrower than the global
    safe set must be honored — a token using an algorithm outside that
    issuer's own restriction is rejected even though the algorithm itself
    would otherwise be globally safe.
    """
    config = OIDCVerifierConfig(
        issuer=ISSUER,
        jwks_url="https://idp.example.test/jwks.json",
        audience=AUDIENCE,
        signing_algorithms=frozenset({"RS512"}),
    )
    resolver = OIDCPrincipalResolver(config, preloaded_keys=public_jwks)

    # Signed with RS256, but this issuer is pinned to RS512 only.
    token = _sign(signing_key, _valid_claims(), alg="RS256")

    with pytest.raises(PrincipalResolutionError):
        resolver.resolve(token)


@pytest.mark.parametrize(
    "unsafe_algorithms", [frozenset({"none"}), frozenset({"HS256"}), frozenset()]
)
def test_config_rejects_unsafe_or_empty_algorithms_at_construction(unsafe_algorithms):
    with pytest.raises(ValueError):
        OIDCVerifierConfig(
            issuer=ISSUER,
            jwks_url="https://idp.example.test/jwks.json",
            audience=AUDIENCE,
            signing_algorithms=unsafe_algorithms,
        )


def test_default_signing_algorithms_match_safe_set():
    config = OIDCVerifierConfig(
        issuer=ISSUER, jwks_url="https://idp.example.test/jwks.json", audience=AUDIENCE
    )
    assert config.signing_algorithms == _SAFE_SIGNING_ALGORITHMS


def base64_url_encode(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _json_dumps(obj: dict) -> str:
    import json

    return json.dumps(obj)
