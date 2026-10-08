"""Async OIDC bearer-token verification for the central governance API.

This is a fresh, standalone implementation for this service rather than an
import of ``openhands.agent_server.oidc_principal`` — pulling that module in
would drag this service's dependency surface onto all of
``openhands-agent-server`` (docker, uvicorn, conversation/tool machinery) for
~150 lines of JWT verification, and this service is intentionally a
separate deployable per v11 §3 / repo ``AGENTS.md``'s cross-repository
boundary note. The verification *logic* mirrors the Phase 0 module closely
(same joserfc pattern, same claim-validation strictness, same
``KNOWN_ROLES`` allowlist-not-trust posture) since that module already has
37 unit tests plus a real-Keycloak end-to-end pass behind it — but the
transport is properly async (``httpx.AsyncClient``) instead of the sync
``httpx.Client``-wrapped-in-a-thread-pool-dependency workaround the v11
design doc describes for literal reuse, and it folds in the v11
round-9/10/11 fixes below.

v11 fixes folded in here that the Phase 0 module doesn't have:
- unknown-role log line no longer includes the role strings themselves
  (round 10 found this: logging attacker-controlled unknown role values
  violates the log-hygiene rule the design itself sets)
- unknown-``kid`` handling adds a bounded, TTL'd negative cache instead of
  refetching JWKS on every unknown kid (round 8/10: unbounded refetch is a
  JWKS-endpoint DoS amplifier)
- single pinned signing algorithm, not the full safe set (round 10)
- a hard token-length cap before parsing (round 10)
- optional ``azp`` allowlist check (off by default — v11 已知實作時待辦 #7,
  desktop client isn't registered in Keycloak yet)
"""

from __future__ import annotations

import base64
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass

import httpx
from joserfc import jwk, jwt
from joserfc.errors import InvalidKeyIdError, JoseError

from central_governance_api.config import Settings


logger = logging.getLogger(__name__)

# The three governance roles from the design doc. An IdP-side roles claim
# is untrusted input filtered against this closed set, never trusted
# verbatim — matches oidc_principal.py's KNOWN_ROLES.
#
# ``governance.superadmin`` (account requests / departments) is deliberately
# NOT a superset of ``governance.admin``: nothing in approvals/authorize.py
# checks it, so granting it widens no existing approval power.
KNOWN_ROLES = frozenset(
    {"governance.admin", "agent.operator", "agent.approver", "governance.superadmin"}
)

_SAFE_SIGNING_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
)


class PrincipalResolutionError(Exception):
    """Bearer token failed verification. Maps to HTTP 401 (see auth/dependencies.py)."""


@dataclass(frozen=True)
class Principal:
    """A verified actor identity, resolved from an OIDC access token."""

    issuer: str
    sub: str
    display_name: str
    roles: frozenset[str]
    azp: str | None
    # Account-request flow (docs/account-requests-departments-design-v1.md):
    # ``email`` is lower-cased; ``email_verified`` is True only when the IdP
    # sent the JSON boolean ``true`` (a string "true" is not trusted).
    email: str | None = None
    email_verified: bool = False

    @property
    def subject(self) -> str:
        """Issuer-qualified identity for storage/comparison.

        Callers doing a security-relevant comparison (e.g. self-approval —
        see design v11 §6) should compare ``(issuer, sub)`` as a tuple, not
        this concatenated string: if either half could ever contain ``#``
        the concatenation could theoretically collide two distinct
        identities. This property exists for logging, DB indexing, and
        display, not for that comparison.
        """
        return f"{self.issuer}#{self.sub}"


class _NegativeKidCache:
    """Bounded, TTL'd cache of key IDs confirmed absent from the JWKS.

    Round 8/10 review: without this, a token carrying a random/unknown
    ``kid`` forces a real JWKS fetch on every request (the Phase 0 module's
    "force refresh once on InvalidKeyIdError" retry), which is an
    amplification DoS surface against the IdP's JWKS endpoint. This cache
    makes repeated requests with the *same* unknown kid cheap, without
    caching so long that a legitimate key rotation gets stuck rejecting
    valid tokens (TTL matches the JWKS cache TTL, not longer).
    """

    def __init__(self, *, capacity: int, ttl_seconds: int) -> None:
        self._capacity = capacity
        self._ttl_seconds = ttl_seconds
        self._entries: OrderedDict[str, float] = OrderedDict()

    def is_known_absent(self, kid: str) -> bool:
        expiry = self._entries.get(kid)
        if expiry is None:
            return False
        if time.monotonic() > expiry:
            del self._entries[kid]
            return False
        return True

    def mark_absent(self, kid: str) -> None:
        self._entries[kid] = time.monotonic() + self._ttl_seconds
        self._entries.move_to_end(kid)
        while len(self._entries) > self._capacity:
            self._entries.popitem(last=False)


class _AsyncJWKSCache:
    """Async JWKS cache for one issuer. Not thread-safe across event loops
    by design — this service runs a single asyncio event loop per process.
    """

    def __init__(
        self,
        jwks_url: str,
        *,
        ttl_seconds: int,
        preloaded_keys: jwk.KeySetSerialization | None = None,
        never_refresh: bool = False,
    ) -> None:
        self._jwks_url = jwks_url
        self._ttl_seconds = ttl_seconds
        self._never_refresh = never_refresh
        if preloaded_keys is not None:
            self._keys: jwk.KeySetSerialization = preloaded_keys
            self._fetched_at: float | None = time.monotonic()
        else:
            self._keys = {"keys": []}
            self._fetched_at = None

    async def get_key_set(self, *, force_refresh: bool = False) -> jwk.KeySet:
        if self._should_refresh(force_refresh=force_refresh):
            await self._fetch_jwks()
        return jwk.KeySet.import_key_set(self._keys)

    def _should_refresh(self, *, force_refresh: bool) -> bool:
        if self._fetched_at is None:
            return True
        if self._never_refresh:
            return False
        if force_refresh:
            return True
        return (time.monotonic() - self._fetched_at) > self._ttl_seconds

    async def _fetch_jwks(self) -> None:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(self._jwks_url)
                response.raise_for_status()
                self._keys = response.json()
                self._fetched_at = time.monotonic()
        except Exception as e:
            raise PrincipalResolutionError(
                f"Failed to fetch JWKS from {self._jwks_url}: {e}"
            ) from e


class OIDCPrincipalResolver:
    """Verifies a bearer access token against the configured trusted issuer."""

    def __init__(
        self,
        settings: Settings,
        *,
        preloaded_keys: jwk.KeySetSerialization | None = None,
        never_refresh_keys: bool = False,
    ) -> None:
        """``preloaded_keys``/``never_refresh_keys`` let tests (or a
        pinned-JWKS deployment) seed the cache without a network round
        trip — mirrors ``oidc_principal.py``'s constructor for the same
        reason: unit tests should not depend on a running IdP.
        """
        if settings.oidc_signing_algorithm not in _SAFE_SIGNING_ALGORITHMS:
            raise ValueError(
                f"oidc_signing_algorithm={settings.oidc_signing_algorithm!r} "
                f"is not in the safe set {sorted(_SAFE_SIGNING_ALGORITHMS)}"
            )
        self._settings = settings
        self._jwks_cache = _AsyncJWKSCache(
            settings.oidc_jwks_url,
            ttl_seconds=settings.jwks_cache_ttl_seconds,
            preloaded_keys=preloaded_keys,
            never_refresh=never_refresh_keys,
        )
        self._negative_kid_cache = _NegativeKidCache(
            capacity=settings.jwks_negative_cache_capacity,
            ttl_seconds=settings.jwks_cache_ttl_seconds,
        )

    async def resolve(self, bearer_token: str) -> Principal:
        if not bearer_token or not bearer_token.strip():
            raise PrincipalResolutionError("Empty bearer token")
        if len(bearer_token) > self._settings.bearer_max_token_length:
            raise PrincipalResolutionError(
                "Bearer token exceeds maximum accepted length "
                f"({self._settings.bearer_max_token_length} chars)"
            )

        token = await self._decode_token(bearer_token)

        try:
            claims_registry = jwt.JWTClaimsRegistry(
                leeway=self._settings.oidc_leeway_seconds,
                iss={"essential": True, "value": self._settings.oidc_issuer},
                aud={"essential": True, "value": self._settings.oidc_audience},
                exp={"essential": True},
                sub={"essential": True},
            )
            claims_registry.validate(token.claims)
        except JoseError as e:
            raise PrincipalResolutionError(f"Token verification failed: {e}") from e

        # As in oidc_principal.py: JWTClaimsRegistry's array-membership
        # check for `iss` would accept `iss: [trusted, attacker]`. OIDC
        # Core requires iss/sub to be plain strings; enforce that.
        iss = token.claims.get("iss")
        sub = token.claims.get("sub")
        aud = token.claims.get("aud")
        if not isinstance(iss, str) or not iss:
            raise PrincipalResolutionError("'iss' claim must be a non-empty string")
        if not isinstance(sub, str) or not sub:
            raise PrincipalResolutionError("'sub' claim must be a non-empty string")
        if not _is_valid_audience(aud):
            raise PrincipalResolutionError(
                "'aud' claim must be a string or a non-empty list of strings"
            )

        azp = token.claims.get("azp")
        if not isinstance(azp, str):
            azp = None
        if self._settings.oidc_azp_allowlist and azp not in (
            self._settings.oidc_azp_allowlist
        ):
            raise PrincipalResolutionError(
                "Token's authorized party ('azp') is not on this API's allowlist"
            )

        raw_roles = token.claims.get(self._settings.oidc_roles_claim) or []
        if not isinstance(raw_roles, list) or not all(
            isinstance(r, str) for r in raw_roles
        ):
            raise PrincipalResolutionError(
                f"'{self._settings.oidc_roles_claim}' claim must be a list of strings"
            )
        roles = frozenset(r for r in raw_roles if r in KNOWN_ROLES)
        unknown_count = len(frozenset(raw_roles) - roles)
        if unknown_count:
            # v11 round-10 fix: do NOT log the unknown role strings (or any
            # other claim content) — they're attacker/IdP-controlled input,
            # and the design's own log-hygiene rule forbids putting
            # untrusted claim content in logs. A bare count is enough to
            # notice drift without leaking anything.
            logger.warning("Ignoring %d unrecognized role claim(s)", unknown_count)

        display_name = sub
        name = token.claims.get("name")
        preferred_username = token.claims.get("preferred_username")
        if isinstance(preferred_username, str) and preferred_username:
            display_name = preferred_username
        if isinstance(name, str) and name:
            display_name = name

        raw_email = token.claims.get("email")
        email = (
            raw_email.strip().lower()
            if isinstance(raw_email, str) and raw_email.strip()
            else None
        )
        email_verified = token.claims.get("email_verified") is True

        return Principal(
            issuer=iss,
            sub=sub,
            display_name=display_name,
            roles=roles,
            azp=azp,
            email=email,
            email_verified=email_verified,
        )

    async def _decode_token(self, bearer_token: str) -> jwt.Token:
        algorithms = [self._settings.oidc_signing_algorithm]
        kid = _peek_kid(bearer_token)
        if kid is not None and self._negative_kid_cache.is_known_absent(kid):
            raise PrincipalResolutionError(
                "Token references a key ID already confirmed absent from JWKS"
            )
        try:
            key_set = await self._jwks_cache.get_key_set()
            return jwt.decode(bearer_token, key_set, algorithms=algorithms)
        except InvalidKeyIdError:
            try:
                key_set = await self._jwks_cache.get_key_set(force_refresh=True)
                return jwt.decode(bearer_token, key_set, algorithms=algorithms)
            except InvalidKeyIdError as e:
                if kid is not None:
                    self._negative_kid_cache.mark_absent(kid)
                raise PrincipalResolutionError(f"Token verification failed: {e}") from e
            except JoseError as e:
                raise PrincipalResolutionError(f"Token verification failed: {e}") from e
        except JoseError as e:
            raise PrincipalResolutionError(f"Token verification failed: {e}") from e


def _is_valid_audience(aud: object) -> bool:
    if isinstance(aud, str):
        return bool(aud)
    if isinstance(aud, list):
        return bool(aud) and all(isinstance(a, str) and a for a in aud)
    return False


def _peek_kid(bearer_token: str) -> str | None:
    """Best-effort, failure-tolerant read of the unverified JWT header's `kid`.

    Only used as a cache key for the negative-kid cache — never trusted for
    any authorization decision. If the token is malformed this returns
    None and the normal decode path below raises the real error.
    """
    try:
        header_b64 = bearer_token.split(".", 1)[0]
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
        kid = header.get("kid")
        return kid if isinstance(kid, str) else None
    except Exception:
        return None
