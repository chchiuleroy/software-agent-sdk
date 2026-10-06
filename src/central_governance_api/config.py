"""Environment-driven settings for the central governance API.

Field defaults mirror the values already validated against a real Keycloak
instance in Phase 0 (``oidc_principal.py``, `project_openhands_governance_platform.md`
"SSO/OIDC/RBAC 架構規劃" — real-IdP checks confirmed ``leeway_seconds=30``
works, the realm's protocol mapper flattens roles into a claim named
``roles``, and Keycloak's actual token ``typ`` is ``"Bearer"`` — not the
RFC 9068 ``at+jwt`` profile this module deliberately does not assume).
"""

from __future__ import annotations

from fastapi import Request
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CGA_", env_file=".env")

    # --- Database ---
    database_url: str = Field(
        default="postgresql+asyncpg://cga:cga@localhost:5432/central_governance",
        description="Async SQLAlchemy connection string. Production deployments "
        "must point this at a role with least-privilege grants on this "
        "service's own schema only (v11 §3 deployment condition #14).",
    )

    # --- OIDC / trusted issuer (single issuer — v11 §3: "not multi-tenant") ---
    oidc_issuer: str = Field(description="Keycloak realm issuer URL.")
    oidc_jwks_url: str = Field(description="Keycloak realm JWKS endpoint.")
    oidc_audience: str = Field(
        description="Resource-server identifier this API expects in `aud`. "
        "Must be a dedicated audience for this API, not shared with the "
        "desktop agent-server's own client — this is the primary "
        "ID-token-vs-access-token confusion defense given Keycloak's "
        "tokens don't carry RFC 9068's `typ: at+jwt` (v11 已知實作時待辦 #9)."
    )
    oidc_roles_claim: str = Field(
        default="roles",
        description="Claim name carrying the flattened role list. Matches "
        "the Phase 0 Keycloak protocol mapper's actual output claim name "
        "('roles'); change only if that mapper is reconfigured.",
    )
    oidc_leeway_seconds: int = Field(default=30)
    oidc_signing_algorithm: str = Field(
        default="RS256",
        description="Single pinned algorithm (v11: 'don't accept the full "
        "safe set in production'). Must match the realm's actual key type.",
    )
    oidc_azp_allowlist: tuple[str, ...] = Field(
        default=(),
        description="Authorized-party (`azp`) client IDs allowed to call "
        "this API. Empty = not enforced (v11 已知實作時待辦 #7: pin this "
        "once the desktop client is registered in Keycloak — §9 not done "
        "yet as of v11).",
    )
    oidc_require_https: bool = Field(
        default=True,
        description="Reject an issuer/JWKS URL that isn't https://. The "
        "Phase 0 Keycloak instance currently runs http-enabled=true for "
        "single-machine internal testing (see wiki) — set this False only "
        "for that known, accepted local-dev configuration, never for a "
        "real deployment.",
    )
    inbox_oidc_client_id: str | None = Field(
        default=None,
        description="Keycloak PUBLIC client id the browser approvals inbox "
        "(GET /inbox) logs in with (Authorization Code + PKCE). Unset = the "
        "inbox is disabled and every /inbox route answers 404. The client "
        "needs: Standard flow with PKCE S256, the exact redirect URI "
        "<this server's origin>/inbox, and that origin under Web Origins "
        "(the browser calls the token endpoint). Its tokens must also carry "
        "this API's audience and the roles claim (the same mappers as the "
        "service clients), and, if oidc_azp_allowlist is set, its client id "
        "must be in it.",
    )
    jwks_cache_ttl_seconds: int = Field(default=300)
    jwks_negative_cache_capacity: int = Field(
        default=256,
        description="Max distinct unknown-kid entries cached at once, "
        "keyed by kid (v11: bounded, to prevent memory-growth DoS from "
        "random kids).",
    )
    bearer_max_token_length: int = Field(
        default=8192,
        description="Reject a Bearer token longer than this before "
        "attempting to parse it (v11 §3 resource-limit requirement).",
    )

    # --- Device inventory (v10/v11: explicitly NOT a security control) ---
    device_denylist_enabled: bool = Field(default=True)
    device_binding_enforced: bool = Field(
        default=False,
        description="When True, CREATE and CLAIM on an approval require "
        "origin_device_id to be an ACTIVE (not revoked) device registered by "
        "the calling principal itself (POST /api/v1/devices/register with "
        "the same token); otherwise 403 device_not_bound. This is what makes "
        "revoking a device actually stop it: a revoked device can no longer "
        "create or claim approvals. It is still NOT a cryptographic device "
        "proof — whoever holds the principal's credentials can use any of "
        "that principal's registered device ids. Default False keeps today's "
        "behavior (origin_device_id is an unverified string), so turning it "
        "on requires each agent-server's service account to register its "
        "governance_origin_device_id first.",
    )
    require_execution_commitment: bool = Field(
        default=False,
        description="When True, CREATE must carry an execution_commitment, "
        "otherwise 400 execution_commitment_required and nothing is written. "
        "Without it a device that omits the field (an older agent-server, or "
        "a bug) silently falls back to the unprotected path: the approval is "
        "created, but nothing is registered to compare at claim and "
        "report-result. Default False so a freshly deployed central keeps "
        "accepting agent-servers that do not send one yet; turn it on after "
        "every agent-server has been updated. Applies to new approvals only — "
        "records already stored without a commitment stay claimable.",
    )
    device_registration_quota: int = Field(
        default=20,
        gt=0,
        description="Max devices one principal may register in total "
        "(counts revoked rows too — device_id is per-owner unique but "
        "never freed by revocation, see DeviceRegistration's docstring, "
        "so this bounds total namespace consumption, not just active "
        "devices). Code-review finding: zero-role self-registration with "
        "no bound at all is a real resource-exhaustion surface, not "
        "merely theoretical. Default is a reasoned guess for the "
        "'internal small-scale validation' deployment this service "
        "currently targets, not a value attested anywhere in the "
        "recovered v11 narrative. Must be positive — zero or negative "
        "would silently fail-closed every registration, a misconfiguration "
        "outage rather than a deliberate quota (code-review Low).",
    )

    # --- Approval workflow deadlines (v11 §11 step 2) ---
    # No specific values are attested anywhere in the recovered v11
    # narrative — these three are this implementation's own reasoned
    # defaults, not copied from a spec, and deliberately conservative
    # (short) rather than generous: a HIGH-risk action sitting unclaimed
    # or unresolved for a long time is itself worth surfacing, not
    # quietly tolerating.
    approval_decision_ttl_seconds: int = Field(
        default=3600,
        description="PENDING -> EXPIRED if nobody decides within this "
        "window (expires_at = created_at + this).",
    )
    approval_execution_window_seconds: int = Field(
        default=900,
        description="ACCEPTED -> EXPIRED if nobody claims within this "
        "window after a decision (execution_deadline = decided_at + "
        "this).",
    )
    approval_execution_lease_seconds: int = Field(
        default=300,
        description="EXECUTING -> FAILED_UNKNOWN if no report-result "
        "arrives within this window after claim (executing_lease_"
        "expires_at = claimed_at + this) — fail-closed, per v10's "
        "'crash 後無法確認就 fail closed'.",
    )

    # --- /wait (v11 §11 step 3, LISTEN/NOTIFY long-poll) ---
    # Neither value is attested anywhere in the recovered v11 narrative —
    # the design record only confirms a `/wait` endpoint exists and that a
    # "LISTEN/commit 邊界" bug in it was fixed in round 10, not the actual
    # wire contract (see approvals/notify.py's module docstring). Both are
    # this implementation's own reasoned defaults.
    wait_default_timeout_seconds: int = Field(
        default=25,
        gt=0,
        description="How long GET .../{id}/wait blocks when the caller "
        "omits `timeout_seconds`. Chosen to sit safely under common "
        "reverse-proxy/load-balancer default idle timeouts (60s) while "
        "still meaningfully cutting poll frequency versus a fixed-"
        "interval poll loop.",
    )
    wait_max_timeout_seconds: int = Field(
        default=30,
        gt=0,
        description="Hard ceiling on the caller-supplied `timeout_seconds` "
        "query parameter — a request for longer is silently clamped down "
        "to this, not rejected: a long-poll client's correct response to "
        "a timed-out `/wait` is to just call again immediately, so "
        "clamping costs it nothing but one extra round trip.",
    )

    # --- Background expiry sweep (v11 §11 step 3) ---
    expiry_sweep_interval_seconds: float = Field(
        default=10.0,
        gt=0,
        description="How often approvals/sweep.py checks for PENDING/"
        "ACCEPTED/EXECUTING rows whose relevant deadline has lapsed and "
        "applies the state machine's EXPIRE event. This is what makes "
        "those deadlines actually enforced over time rather than merely "
        "defensively checked by each write endpoint's own conditional "
        "UPDATE — without this sweep a lapsed PENDING row just sits "
        "showing `pending` forever unless some caller happens to hit an "
        "endpoint on it again. Not attested in the recovered v11 "
        "narrative; a reasoned default balancing DB load against how "
        "promptly a `/wait` caller learns a record expired.",
    )

    @field_validator("oidc_issuer", "oidc_jwks_url")
    @classmethod
    def _check_https(cls, v: str, info) -> str:  # noqa: ARG003
        # Validated again at Settings-construction time against
        # oidc_require_https in get_settings(), since field order isn't
        # guaranteed here; this validator only rejects obviously-malformed
        # values (empty, no scheme).
        if not v or "://" not in v:
            raise ValueError(f"must be a full URL, got: {v!r}")
        return v


def get_settings() -> Settings:
    # pydantic-settings resolves required fields from the environment at
    # runtime (CGA_OIDC_ISSUER etc.) — pyright can't see that and flags
    # this as missing constructor arguments.
    settings = Settings()  # pyright: ignore[reportCallIssue]
    if settings.oidc_require_https:
        for name, url in (
            ("oidc_issuer", settings.oidc_issuer),
            ("oidc_jwks_url", settings.oidc_jwks_url),
        ):
            if not url.startswith("https://"):
                raise ValueError(
                    f"{name}={url!r} is not https:// and "
                    "oidc_require_https is True. Set CGA_OIDC_REQUIRE_HTTPS=false "
                    "only for the known local-dev http Keycloak instance."
                )
    return settings


def get_settings_dependency(request: Request) -> Settings:
    """FastAPI dependency reading the ``Settings`` constructed once at app
    startup off ``app.state`` (see ``main.py``'s lifespan) — mirrors
    ``auth/dependencies.get_oidc_resolver``'s pattern. Promoted here from a
    private ``_get_settings`` duplicated in ``routers/approvals.py`` once
    ``routers/devices.py`` needed the identical dependency, same reason
    ``commit_or_replay``/``RequestModel`` were promoted (see
    ``approvals/idempotency.py``/``schemas_base.py``).
    """
    return request.app.state.settings
