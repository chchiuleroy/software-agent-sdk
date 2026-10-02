"""OIDC-based Principal resolution — Phase 0 scaffold.

Part of the SSO/OIDC/RBAC design tracked in the roy_km wiki
(``project_openhands_governance_platform.md``, "SSO/OIDC/RBAC 架構規劃").
This module implements only the Phase 0 foundation: a ``Principal`` model
and a standalone token verifier. It intentionally does NOT touch
``dependencies.py``, ``sockets.py``, or any existing route — per the
second-round design review, wiring a deployment-mode switch into the
running application requires mode-specific composition (separate router/
dependency assembly for ``personal`` vs ``team``), not a drop-in
replacement of a single dependency. That wiring is scoped to later phases.

Status note (2026-10-02, identity model B): the agent-server deliberately
does NOT authenticate humans itself. Under ``team`` mode this process
acts as one *device* identity (its own ``governance_client_id`` /
``client_credentials`` token, see ``governance_client.py``) when it talks to
central-governance-api, and the human approver is verified there, at
decision time, from their OIDC token (recorded as the decision actor).
So nothing in the request path calls this resolver, by design. It is kept
as the building block for the alternative "per-user token reaches the
agent-server" model (GUI login), which would wire it at the single
``check_session_api_key`` dependency; that model is not implemented.

Verification follows the same JWKS + joserfc pattern already used by
``openhands.sdk.llm.auth.openai`` for OpenAI's subscription OAuth flow
(JWKS caching, ``jwt.decode`` + ``JWTClaimsRegistry``), generalized to an
arbitrary trusted OIDC issuer instead of a hardcoded OpenAI endpoint.

This module deliberately does not distinguish an OIDC access-token profile
(RFC 9068, ``typ: at+jwt``) from an ID-token profile — which one a given
deployment's bearer tokens actually are is an IdP-specific contract that
can only be confirmed against a running IdP, and is left as an open
decision for whoever wires this into a route (Phase 1+).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import httpx
from joserfc import jwk, jwt
from joserfc.errors import InvalidKeyIdError, JoseError

from openhands.sdk.logger import get_logger


logger = get_logger(__name__)

JWKS_CACHE_TTL_SECONDS = 300

# Deliberately excludes "none" and the HMAC (HS*) algorithms: JWKS endpoints
# publish public keys, so only asymmetric algorithms make sense here, and
# "none" must never be accepted for a bearer token used as an auth decision.
# This is also the ceiling that OIDCVerifierConfig.signing_algorithms is
# validated against — no per-issuer config can widen it back out.
_SAFE_SIGNING_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
)

# The three governance roles defined in the design doc. Kept here (not in
# config) because the enforcement code that will consume these roles
# (Phase 4) needs a closed set to check membership against — an IdP-side
# `roles` claim is untrusted input and must be filtered against this
# allowlist, never trusted verbatim.
KNOWN_ROLES = frozenset({"governance.admin", "agent.operator", "agent.approver"})


class PrincipalResolutionError(Exception):
    """Raised when a bearer token cannot be resolved to a verified Principal."""


@dataclass(frozen=True)
class Principal:
    """A verified actor identity, resolved from an OIDC token.

    ``subject`` is issuer-qualified (``<issuer>#<sub>``) rather than a bare
    ``sub``: a bare ``sub`` can collide across issuers (e.g. if the IdP is
    later replaced, or multiple issuers are ever trusted at once).
    """

    issuer: str
    sub: str
    display_name: str
    roles: frozenset[str]

    @property
    def subject(self) -> str:
        return f"{self.issuer}#{self.sub}"


class _JWKSCache:
    """Thread-safe JWKS cache for one issuer.

    ``preloaded_keys`` lets a caller (tests, or a static/pinned-JWKS
    deployment) seed the cache without an HTTP round trip. By default the
    preload is just a warm start — it still expires and refetches after
    ``JWKS_CACHE_TTL_SECONDS`` like normal. Pass ``never_refresh=True`` for
    a genuinely static keyset that is fetched (or seeded) exactly once and
    never refreshed — appropriate for pinned-JWKS deployments, not for a
    normal issuer whose keys can rotate.
    """

    def __init__(
        self,
        jwks_url: str,
        *,
        preloaded_keys: jwk.KeySetSerialization | None = None,
        never_refresh: bool = False,
    ) -> None:
        self._jwks_url = jwks_url
        self._never_refresh = never_refresh
        self._lock = threading.Lock()
        if preloaded_keys is not None:
            self._keys: jwk.KeySetSerialization = preloaded_keys
            self._fetched_at: float | None = time.monotonic()
        else:
            self._keys = {"keys": []}
            self._fetched_at = None

    def get_key_set(self, *, force_refresh: bool = False) -> jwk.KeySet:
        with self._lock:
            if self._should_refresh(force_refresh=force_refresh):
                self._fetch_jwks()
            return jwk.KeySet.import_key_set(self._keys)

    def _should_refresh(self, *, force_refresh: bool) -> bool:
        if self._fetched_at is None:
            return True
        if self._never_refresh:
            return False
        if force_refresh:
            return True
        return (time.monotonic() - self._fetched_at) > JWKS_CACHE_TTL_SECONDS

    def _fetch_jwks(self) -> None:
        try:
            with httpx.Client(timeout=10) as client:
                response = client.get(self._jwks_url)
                response.raise_for_status()
                self._keys = response.json()
                self._fetched_at = time.monotonic()
                key_count = len(self._keys.get("keys", []))
                logger.debug(f"Fetched JWKS from {self._jwks_url}: {key_count} keys")
        except Exception as e:
            raise PrincipalResolutionError(
                f"Failed to fetch JWKS from {self._jwks_url}: {e}"
            ) from e


@dataclass
class OIDCVerifierConfig:
    """Static configuration for one trusted OIDC issuer.

    Deliberately does not read ``ROY_GOVERNANCE_OIDC_*`` environment
    variables itself — deciding *whether* team mode is active, and
    constructing this config, is the job of the deployment-mode
    composition root (Phase 1), not this module.
    """

    issuer: str
    jwks_url: str
    audience: str
    roles_claim: str = "roles"
    leeway_seconds: int = 30
    # Scoped to this issuer's actual registered algorithm(s) where known;
    # defaults to the full safe set for issuers that haven't pinned one.
    signing_algorithms: frozenset[str] = field(
        default_factory=lambda: _SAFE_SIGNING_ALGORITHMS
    )

    def __post_init__(self) -> None:
        unsafe = frozenset(self.signing_algorithms) - _SAFE_SIGNING_ALGORITHMS
        if unsafe:
            raise ValueError(
                f"signing_algorithms contains unsupported/unsafe algorithm(s): "
                f"{sorted(unsafe)}"
            )
        if not self.signing_algorithms:
            raise ValueError("signing_algorithms must not be empty")


class OIDCPrincipalResolver:
    """Verifies a bearer token against one trusted issuer and returns a Principal.

    Standalone and unit-testable without a running IdP (see
    ``preloaded_keys`` on ``_JWKSCache``). Not yet wired into any FastAPI
    dependency chain — see module docstring.
    """

    def __init__(
        self,
        config: OIDCVerifierConfig,
        *,
        preloaded_keys: jwk.KeySetSerialization | None = None,
        never_refresh_keys: bool = False,
    ) -> None:
        self._config = config
        self._jwks_cache = _JWKSCache(
            config.jwks_url,
            preloaded_keys=preloaded_keys,
            never_refresh=never_refresh_keys,
        )

    def resolve(self, bearer_token: str) -> Principal:
        if not bearer_token or not bearer_token.strip():
            raise PrincipalResolutionError("Empty bearer token")

        token = self._decode_token(bearer_token)

        try:
            claims_registry = jwt.JWTClaimsRegistry(
                leeway=self._config.leeway_seconds,
                iss={"essential": True, "value": self._config.issuer},
                aud={"essential": True, "value": self._config.audience},
                exp={"essential": True},
                sub={"essential": True},
            )
            claims_registry.validate(token.claims)
        except JoseError as e:
            raise PrincipalResolutionError(f"Token verification failed: {e}") from e

        # JWTClaimsRegistry's value-matching treats a claim that happens to
        # be an array as "is the expected value contained in it" — so e.g.
        # `iss: ["<trusted issuer>", "<attacker issuer>"]` would pass the
        # check above. OIDC Core requires iss/sub/aud to be strings (aud
        # may also be an array of strings); enforce that explicitly rather
        # than trusting the registry's looser array-membership semantics.
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

        raw_roles = token.claims.get(self._config.roles_claim) or []
        if not isinstance(raw_roles, list) or not all(
            isinstance(r, str) for r in raw_roles
        ):
            claim_name = self._config.roles_claim
            raise PrincipalResolutionError(
                f"'{claim_name}' claim must be a list of strings"
            )
        # Never trust an IdP-side roles claim verbatim — only values that
        # match a known local role name are honored. Elements are already
        # guaranteed to be strings (hashable) by the check above.
        roles = frozenset(r for r in raw_roles if r in KNOWN_ROLES)
        unknown = frozenset(raw_roles) - roles
        if unknown:
            logger.warning(
                f"Ignoring unrecognized role claim(s) for {sub}: {sorted(unknown)}"
            )

        display_name = sub
        name = token.claims.get("name")
        preferred_username = token.claims.get("preferred_username")
        if isinstance(preferred_username, str) and preferred_username:
            display_name = preferred_username
        if isinstance(name, str) and name:
            display_name = name

        return Principal(
            issuer=iss,
            sub=sub,
            display_name=display_name,
            roles=roles,
        )

    def _decode_token(self, bearer_token: str) -> jwt.Token:
        algorithms = list(self._config.signing_algorithms)
        try:
            key_set = self._jwks_cache.get_key_set()
            return jwt.decode(bearer_token, key_set, algorithms=algorithms)
        except InvalidKeyIdError:
            # The signing key may have rotated at the IdP since our last
            # JWKS fetch. Refresh once and retry before giving up, so a
            # mid-TTL key rotation doesn't reject otherwise-valid tokens
            # for up to a full cache TTL.
            try:
                key_set = self._jwks_cache.get_key_set(force_refresh=True)
                return jwt.decode(bearer_token, key_set, algorithms=algorithms)
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
