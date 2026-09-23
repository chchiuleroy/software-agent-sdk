# Track 1 Extension — Per-Request Delegated Governance Identity (v1)

**Status: SUPERSEDED (2026-09-23). Not being pursued.** Round 1 review confirmed
the token-exchange choice (§1) was sound but found 2 Critical implementation gaps
(§9) — safely propagating a per-request identity through a shared, concurrent,
crash-recoverable async pipeline turned out to be a much bigger problem than
initially scoped, with a design/review cost approaching Track 1's own 11-round
SSO/OIDC/RBAC effort. Given Roy's actual deployment scale (a handful of bound
users, not a large multi-tenant SaaS), Roy chose the simpler alternative instead:
**one agent-server process per bound user**, not one process dynamically switching
between delegated identities. This sidesteps the entire concurrency-safety and
crash-recovery problem class documented in §9 by construction — there is no
shared mutable identity state to race on, because each process only ever has one
identity, exactly like today's already-proven single-operator model. The
per-process cost (N users → N processes/containers) is acceptable at this scale.

This document is kept for its investigation (§0) and the concrete reasons the
delegated-identity approach doesn't hold up (§9) — useful if a much larger
multi-tenant scale ever makes per-user processes impractical and this gets
revisited. It is not being implemented now.

**Consequence for Track 2 Slack design**: `track2-slack-design-v1.md` §0's
Critical is resolved by this architectural choice, not by building anything from
this document — see that file's updated status. It also **revises** the earlier
Track 2 decision "one container per bot platform/team" (2026-09-23,
`AskUserQuestion`) to **one container per bound user**; "team"/workspace becomes an
organizational grouping over a set of per-user containers rather than a shared
execution unit. Flagging this explicitly since it changes an earlier Roy decision
as a side effect, rather than silently reinterpreting it.

---

Below is the original document, kept as-is for reference.

This document exists because Track 2's Slack design (`track2-slack-design-v1.md`)
hit a confirmed Critical blocker: today, every approval an agent-server process
makes is attributed to that process's single service-account/env-var identity, no
matter how many distinct human users are actually driving it. Roy chose
(2026-09-23, `AskUserQuestion`) to design and build this extension *before*
returning to finish the Slack design.

## 0. Confirmed starting point (verified against source, 2026-09-23)

- `requester_identity_for_conversation()` (`openhands-sdk/openhands/sdk/security/roy_self_approval.py:91-101`)
  does a literal `os.environ.get("ROY_GOVERNANCE_IDENTITY")` read — process-wide,
  no per-request concept at all.
- `LocalConversation.__init__()` reads this once, at line 365, into
  `self._requester_identity`. **This is a plausible, low-risk extension point**:
  `__init__` already takes 20+ keyword args and ends with `**_: object` for
  forward-compat, so adding an optional `requester_identity` param that falls back
  to the env-var read when absent is additive, not a rewrite.
- `GovernanceClient` (`openhands-agent-server/openhands/agent_server/governance_client.py`)
  caches one token in `self._cached_token`, refreshed in `_access_token()`
  (201-257) with a 30s expiry margin — but this cache is scoped to the
  `GovernanceClient` instance, and that instance is itself effectively a
  per-agent-server-process singleton (`conversation_service.py`'s module docstring,
  quoted by the investigating agent: "One instance per agent-server process, holding
  the single operator credential used for every central-governance-api call this
  process makes"). One process, one token, no per-caller distinction — this is the
  actual mechanism behind the bug, not just the env var.
- `_request()` (governance_client.py:259-303) is the **single chokepoint** all six
  mutating calls (`create_approval`, `claim`, `report_result`, `cancel`,
  `reconciliation_finding`, `wait`) route through — it calls `_access_token()`
  then sets `Authorization: Bearer <token>`. Substituting a per-call token only
  needs a change here, not in each of the six methods.
- `central-governance-api`'s `authorize_create()`/`authorize_on_record()`
  (`approvals/authorize.py:133-280`) derive ownership purely from
  `Principal.issuer`/`Principal.sub`, itself resolved purely from bearer-token JWT
  validation (`auth/oidc.py`'s `OIDCPrincipalResolver.resolve()`) — no header, no
  request-body field, no delegation concept exists anywhere in this module today.
  `PendingApprovalRecord.requester_issuer`/`requester_sub` (`models.py:87-88`) are
  populated directly from the verified token at write time
  (`routers/approvals.py:210-211`) — the client's JSON payload carries no requester
  field at all currently.

**The existing "identity" mechanism in this codebase to explicitly avoid copying**:
`roy_self_approval.py`'s own docstring disclaims itself as *not* a security
boundary — it's a cooperative check where the caller can just assert a different
`approver_identity` string. That gap is exactly what `central-governance-api`'s
`Principal`-based RBAC was built to close, and exactly what this design must not
reintroduce for the multi-user case.

## 1. Chosen mechanism: standard OAuth 2.0 Token Exchange (RFC 8693), subject-swap
semantics — not Keycloak's experimental delegation feature

Two Keycloak features could plausibly serve this design; only one should be used:

- **Standard Token Exchange, "V2"** (RFC 8693-compliant) — became **officially
  supported (GA)** starting **Keycloak 26.2**
  ([Keycloak blog, 2026-05](https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2)).
  The instance already deployed for Track 1 is confirmed **26.7.3** — so this
  feature is available and stable, but needs the "Standard token exchange" toggle
  enabled per relevant client (not on by default; V1, the older non-RFC-8693
  exchange, is what's still default, and is deprecated as of 26.6.0 but not yet
  removed). Base token exchange (subject_token supplied, no actor_token) yields a
  new access token whose `sub` **is the subject_token's own subject** — i.e. plain
  impersonation semantics, no special claim needed.
- **`token-exchange-delegation`** — a **separate, experimental** feature
  introduced in **Keycloak 26.7.0**, purpose-built for "act" claim / nested-actor
  delegation (a service token that represents itself as *acting for* a distinct
  subject, preserving both identities). It requires an explicit
  `--features=token-exchange-delegation` startup flag and is off by default —
  **not GA**.

**Recommendation: use plain standard token exchange (subject-swap), not the
experimental delegation feature.** Reasoning:

1. OHS's actual need is simpler than what the experimental feature solves. We
   don't need to preserve "agent-server acted, on behalf of user X" as two
   separate identities in the same token — we need the **approval to be correctly
   attributed to the real end user**, full stop. Plain subject-swap token exchange
   already does exactly that: exchange the agent-server's own client credentials
   plus the end user's own access token (`subject_token`) for a new access token
   whose `sub`/`iss` are the end user's — present *that* token to
   `central-governance-api` instead of the service-account token.
2. **Zero schema change needed** at `central-governance-api`: since the exchanged
   token's `sub` already *is* the real end user, `authorize_create()` naturally
   writes the correct `requester_issuer`/`requester_sub` with no new columns, no
   `act`-claim parsing, no changes to `Principal` or `authorize_on_record()` at
   all. The existing code already does the right thing once it's handed the right
   token.
3. Not depending on a feature explicitly marked experimental for something this
   security-sensitive (approval ownership) — an unstable feature's behavior can
   change or be pulled in a future Keycloak release. If a future need arises to
   record *both* "which process executed this" and "which user it was for"
   simultaneously (richer audit semantics), that's a genuine reason to revisit the
   `act`-claim feature once/if it reaches GA — not now.

## 2. Where the delegated token enters the system

**Recommendation: attach it at conversation-creation time, not per-message.** A
conversation already has a natural single-identity lifetime — the OpenAI-compatible
endpoint's existing `X-OpenHands-ServerConversation-ID` header establishes exactly
this pattern (identity/state that persists across a thread's calls, not re-asserted
every message). Concretely:

- New optional request header on `POST /v1/chat/completions`,
  e.g. `X-OpenHands-Delegated-Subject-Token`, parsed the same way the existing
  conversation-id/observability headers already are
  (`openai/router.py`'s `create_chat_completion`, `Header(alias=...)` pattern).
- Threaded through `run_chat_completion()` → `_conversation_request()` →
  `StartConversationRequest` → into a new optional `LocalConversation(requester_identity=..., delegated_subject_token=...)`
  constructor param (falls back to the current env-var read when absent — fully
  backward compatible with today's single-operator flow).
- `EventService` already reaches into `self._conversation._requester_identity` via
  `getattr` (agent_server/event_service.py, ~line 1893) as a private-attribute
  seam rather than owning this state itself — the same seam should be extended to
  also carry the delegated subject token through to whatever eventually calls
  `GovernanceClient`'s methods for this conversation.
- **On this header's authentication weight**: the OpenAI-compatible endpoint's own
  auth (`check_openai_api_key`) is a shared session-API-key check, not a per-user
  JWT check. That's fine here specifically because the header's *content* is the
  end user's own Keycloak-issued access token — its authenticity comes from being
  a real, independently-verifiable JWT (checked at exchange time against
  Keycloak's JWKS), not from anything the session-API-key layer asserts. A bare
  identity *string* header (no token backing it) would be exactly as spoofable as
  `roy_self_approval.py`'s `approver_identity` — this design must not do that;
  the header must carry an actual bearer token that gets independently validated
  during token exchange, never a bare claimed identity.

## 3. `governance_client.py` changes

- `_access_token()` needs to become **keyed per delegated identity**, not a single
  `self._cached_token` field — e.g. a small dict cache keyed by the delegated
  subject (falling back to the existing single-token behavior when no delegation
  is present for a given call, so personal/single-operator mode is untouched).
- When a delegated subject token is present for a conversation, `_access_token()`
  (or a new sibling method) performs the RFC 8693 exchange: presents the
  agent-server's own client credentials (as today) plus
  `subject_token=<the delegated token>`,
  `subject_token_type=urn:ietf:params:oauth:token-type:access_token`,
  `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` to Keycloak's token
  endpoint, and caches the resulting exchanged token (respecting *its* expiry, not
  the service-account token's).
- `_request()`'s single chokepoint (259-303) stays the natural place to set the
  `Authorization` header, but **which credential to use cannot be a mutable
  instance attribute on `GovernanceClient`** (round 1 review, Critical — see
  §9/C1): `GovernanceClient` is one shared instance across all conversations in
  the process, and async I/O (the exchange call itself, or the subsequent HTTP
  call) yields control between setting and using that attribute — a second
  conversation's call can overwrite it before the first one's request goes out,
  handing conversation A's approval call conversation B's credential. The
  credential context must be threaded as an **explicit, immutable per-call
  value** (a parameter, or an immutable conversation-scoped façade object) —
  not shared mutable state. This is not an implementation detail; it's the part
  of this design that actually has to be correct for the whole extension to be
  safe, and v1 underspecified it.

## 4. Handling the live end-user token safely

The delegated subject token is a real, currently-valid credential for a real
person — treat it with the same care as any secret:

- Never log it (request/response logging must redact this header and the
  exchanged token alike).
- Cache in memory only, keyed per conversation, with a lifetime bounded by the
  token's own expiry — do not persist to disk.
- This does **not** solve token *refresh* for long-running conversations that
  outlive the original token's lifetime, nor does it solve *revocation
  propagation* (if the end user's Keycloak session is killed mid-conversation, the
  agent-server has no mechanism today to notice and stop using the now-invalid
  delegated identity for further approval calls in that conversation). Both are
  explicitly **not solved by this v1** — flagged as follow-up work, not silently
  assumed away.

## 5. Backward compatibility — this is purely additive

When no delegated subject token is supplied for a conversation (today's only
mode — the existing single-operator/personal deployment), every code path
described here degrades to exactly current behavior: env-var-derived requester
identity, single process-wide service-account token, no token exchange call ever
made. Nothing about Track 1's existing behavior changes unless a caller
deliberately opts into supplying a delegated identity for a conversation.

## 6. Keycloak configuration prerequisite (not yet done)

Track 1's existing realm setup script (`create_keycloak_test_identities.bat`) only
creates service-account clients. Before this design can be implemented end-to-end,
the relevant client(s) need **"Standard token exchange" enabled** in the Keycloak
admin console (the V2/GA feature from §1) — **not** the experimental
`token-exchange-delegation` server feature flag, which this design deliberately
avoids depending on. This has not been configured or tested yet.

## 7. What this document does not solve

- Revocation propagation and token refresh for long conversations (§4).
- The Track 2 Slack-specific questions this doesn't touch at all: how the Slack
  adapter obtains the end user's token in the first place (Device Authorization
  Grant, per `track2-slack-design-v1.md` §4), and how it forwards that token into
  the new header described in §2 — that plumbing belongs back in the Slack design
  once this extension exists.
- Any UI/observability for "this approval was made via a delegated identity" —
  not designed here; `requester_issuer`/`requester_sub` will simply show the real
  end user's identity, indistinguishable at the data level from a direct Track-1
  GUI/REST approval by that same person, which is arguably correct but hasn't been
  explicitly decided as a goal.

## 8. Relationship back to Track 2

Once this extension is implemented and reviewed, `track2-slack-design-v1.md`
resumes: the Slack adapter's Device Authorization Grant flow (already designed
there) supplies exactly the "end user's own access token" this document assumes
as input, via the new per-conversation header from §2.

## 9. Round 1 review findings (2026-09-23) — why v1 is not buildable as written

Full review verdict: keep the "GA standard token exchange, not experimental
delegation" direction, but the propagation design has 2 Critical gaps that would
either reproduce the original bug in a worse form (cross-user credential misuse,
not just misattribution) or silently fall back to the service account on restart.

### Critical

- **C1 — the credential-selection mechanism itself is a race condition.**
  `GovernanceClient` is one instance shared by every conversation in the process
  (built once in `conversation_service.py`'s `_governance_client_from_config()`).
  §3's original wording ("an instance attribute... exact shape is an
  implementation detail") would mean: conversation A sets the shared attribute to
  Alice's credential, yields on the exchange/HTTP await, conversation B's call
  overwrites it with Bob's, A resumes and creates/claims/reports **using Bob's
  credential**. This is not a corner case — it's concurrent-by-default, and it's
  worse than today's bug (wrong attribution) because it's actual cross-user
  credential misuse. **Fixed in §3 above**: credential context must be an
  explicit, immutable per-call value, never shared mutable state, and every
  background path (relay, claim-redispatch, failure-reporting, reconciliation —
  not just the foreground call) must carry the same immutable context.
- **C2 — in-memory-only tokens are incompatible with the existing durable-outbox
  crash-recovery design.** `EventService._relay_outbox_once()` persists pending
  governance operations and retries `create`/`claim`/`report` after a restart.
  This document's own security requirement (§4: never persist the delegated
  token) means that credential is gone after any restart. Two failure modes
  follow: a retried `PENDING_CREATE` could fall back to the service-account
  token and create an approval with the **wrong owner**; or a record that already
  has the real owner recorded will permanently fail `claim`/`report` after
  restart, since `authorize_on_record()` requires an exact `(issuer, sub)` match
  and the service-account identity won't match. **Not solved by this v1** — a v2
  needs the outbox to persist an unforgeable *credential-binding reference*
  (not the token itself) and must fail closed (surface as
  needs-re-authentication / needs-attention) rather than silently falling back
  to the service account when that binding can't be re-established after
  restart.

### High

- **H1 — caching by subject alone is unsafe.** The same `(issuer, sub)` can carry
  multiple valid tokens differing in audience, `azp`, roles/scope, session,
  expiry, or sender-constraint. A cache keyed only by subject risks reusing a
  higher-privilege or wrong-session token for an unrelated later request. A v2
  needs the cache key to include an unforgeable fingerprint of the *input*
  credential plus target audience/scope/requester client, with bounded size,
  per-key single-flight (to avoid redundant concurrent exchanges), and defined
  eviction.
- **H2 — the Keycloak prerequisite (§6) is incomplete; the exchange as described
  likely won't work as-is.** Missing conditions the review confirmed against
  `central-governance-api/src/central_governance_api/auth/oidc.py`'s actual
  validation logic and Keycloak's own docs: the `subject_token`'s audience must
  include the exchange-requesting client; the *exchanged* token must carry
  central-governance-api's expected audience; central also checks an `azp`
  allowlist when configured; the exchanged token must produce the roles claim
  central expects (a real `agent.operator`-equivalent role, not just "login
  succeeded"); and Keycloak's `audience` request parameter filters existing
  audiences rather than adding new ones, so client scope/audience mappers need
  correct upfront configuration. None of this exists in the current
  `create_keycloak_test_identities.bat` provisioning.
- **H3 — "it's a real JWT, not a bare string" overstates the security this header
  provides.** True that Keycloak-side validation is stronger than an unverified
  identity claim, but an access token is still a *bearer* credential — token
  exchange does not invalidate the input token or bind it to this specific
  request/conversation/session (RFC 8693 explicitly does not create that tight
  linkage), so within the token's validity window, anyone able to obtain it
  (e.g. another holder of the shared session API key who also has that token)
  could replay it. §2 needs to state as **mandatory deployment invariants**, not
  optional hardening: end-to-end TLS with no plaintext fallback, redaction of
  this header and the exchanged token across every log/proxy/APM/exception-dump
  path, and — where feasible — a sender-constrained (DPoP-bound) token, noting
  Keycloak's DPoP requirements add their own constraint that the exchange
  requester must match the original token's client.
- **H4 — the reusable-conversation API has no multi-user ownership boundary.**
  §2 only defines identity binding at conversation *creation*. Undefined: what
  happens if a later call on the same conversation supplies a *different*
  subject token (reject? ignore?); whether a resume call with no token at all
  still proceeds under the previously-bound identity; and — since the
  OpenAI-compatible endpoint's only auth is the shared session API key — whether
  any other holder of that key who knows the conversation id can keep driving a
  conversation bound to someone else's identity. A v2 needs: atomic binding of
  `(issuer, sub, credential-binding-id)` at creation, and either re-proof of the
  same subject on every resume, or a real per-user authenticated session
  providing a conversation ACL — not just a shared key.

### Medium

- **M1 — "zero schema change" is only true if the audit requirement is "who
  owns this," not "who/what executed this."** Subject-swap makes the audit trail
  read as if the real end user called `claim`/`report` directly — it erases the
  fact that an agent-server process executed it on their behalf. Whether that's
  acceptable is a **policy decision that hasn't been made**, not a technical
  given. If execution-actor tracking turns out to matter, plain subject-swap
  alone is insufficient (though full `act`-claim/experimental-delegation
  semantics still aren't required — verified `azp` plus an agent-server
  instance/device-origin field added to the audit schema could suffice).
- **M2 — revocation/refresh gaps (§4/§7) were honestly flagged but incomplete.**
  Also needed: behavior on logout/role-removal/account-disable/consent-withdrawal
  for an already-exchanged token (RFC 8693 doesn't tightly link output-token
  validity to input-token state); Keycloak `not-before`/session-change handling;
  a defined retry-vs-needs-attention policy when the token-exchange endpoint
  itself is unavailable; cache eviction tied to conversation close; and behavior
  for in-flight background tasks when credentials rotate mid-flight.
- **M3 — "a small, low-risk, localized change" doesn't hold.** Full identity
  propagation spans `router → OpenAI service → StartConversationRequest →
  ConversationService → LocalConversation → EventService → durable
  outbox/background recovery → GovernanceClient`, and governance calls happen not
  just in the foreground request path but via relay, claim-redispatch,
  failure-reporting, and reconciliation background tasks too — this is a
  lifecycle-spanning change, not an `_access_token()` dict addition. Also:
  `LocalConversation.__init__()`'s trailing `**_: object` **silently discards**
  unrecognized kwargs — if a new field is passed by an upstream caller before
  it's explicitly declared and consumed, that value vanishes with no error,
  which is a real footgun specifically for this kind of additive-parameter
  change.

### Low

- **L1 — imprecise description of where JWT validation happens.** Corrected:
  the agent-server hands the subject token to *Keycloak's token endpoint*
  (Keycloak validates it per its own token/session rules) — the agent-server
  itself does not JWKS-validate the incoming header. Only the resulting
  *exchanged* access token later gets independently JWKS-validated by
  `central-governance-api`.
- **L2 — two imprecisions in §0**: `_request()` is the chokepoint for
  `GovernanceClient`'s own outbound HTTP calls, but (per C1/M3) not the only
  point that needs modification for full identity propagation; and "six
  mutating calls" is inaccurate — `wait()` is a read-only long-poll, not a
  mutation.

### Race-condition assessment

The review found no reproduction of central-governance-api's known DB-level
races from earlier Track 1 rounds (quota/idempotency) — ownership comparison
there stays a simple request-local verified-principal-vs-immutable-record-owner
check. The **new** races this design introduces are agent-server-side: per-call
identity selection on a singleton client (C1), concurrent exchange of the same
input credential, token cache updates, conversation-close/credential-eviction
racing background relay, and credential loss during crash recovery (C2) — none
of which central-governance-api's existing transaction/idempotency protections
cover, because they're a layer below where those protections apply.

### What a v2 needs to address before implementation

1. Explicit, immutable per-call credential context — no mutable shared state on
   `GovernanceClient` (C1).
2. A durable, unforgeable credential-binding reference in the outbox (not the
   raw token) with a defined fail-closed policy on restart (C2).
3. Conversation ownership binding at creation + a defined resume/reuse
   verification policy (H4).
4. Cache key design (fingerprint + audience/scope/client, not bare subject),
   bounded size, single-flight, eviction (H1).
5. Complete Keycloak client/audience/role configuration, verified against
   `oidc.py`'s actual checks (H2).
6. A stated threat model and mandatory deployment invariants for the delegated
   token in transit (TLS, redaction, replay exposure, sender-constraint
   feasibility) (H3).
7. A decided policy on delegated-subject vs. execution-actor audit semantics
   before claiming "zero schema change" (M1).
8. A complete revocation/refresh/retry policy, not just refresh/revocation named
   as open items (M2).
