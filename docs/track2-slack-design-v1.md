# Track 2 — Slack Integration Design (v1)

Status: **Round 1 reviewed and UNBLOCKED (2026-09-23).** §0's Critical is resolved
— not by the delegated-identity extension originally pursued
(`track1-delegated-identity-v1.md`, superseded, too costly for this deployment
scale), but by an architectural choice: **each bound user runs their own
agent-server process**, not a shared process with per-request identity switching.
See the updated §0 and §5 below. Scope: Slack only. Teams and LINE are explicitly
out of scope for this version — they require a publicly reachable HTTPS endpoint
(see "Why Slack first" below), which this design does not attempt to solve yet.

## 0. Round 1 review verdict — CONFIRMED CRITICAL BLOCKER for multi-user scope

> "這份草稿的 OpenAI-compatible contract 大致正確，Device Authorization 的方向也合理；
> 但『Slack 使用者可直接當成既有 device 接入、無需治理資料流調整』不成立。現行
> agent-server 是 process principal，不具備 per-request requester identity。這是目前
> 阻止多使用者共用 agent-server 的實質架構阻斷點。"

This is not the "open question, unverified" framing §3 originally used — it is a
**confirmed** finding, with source evidence:

- `LocalConversation.__init__()` reads the requester identity once via
  `requester_identity_for_conversation()` at conversation build/resume time — a
  process-level value, not derived from an HTTP request context
  (`openhands-sdk/openhands/sdk/conversation/impl/local_conversation.py`).
- Neither `StartConversationRequest` nor the OpenAI-compatible request model carries
  a trusted requester-principal field; `run_chat_completion()` only forwards model,
  messages, conversation id, and observability overrides.
- `governance_client.py` (agent-server side) explicitly uses **one shared
  client-credentials credential per process** for every create/claim/report-result
  call to `central-governance-api`.
- `central-governance-api`'s `approvals/authorize.py` (`authorize_create()` /
  `authorize_on_record()`) derives approval ownership from the **bearer token's**
  `(issuer, sub)` — it does not accept a caller-supplied requester at all.

Net effect: even if every Slack user completes OAuth binding and registers a
device (§4), the actual approval request that reaches central governance is
attributed to the agent-server's single service-account principal, and any local
self-approval audit trail is attributed to whatever the process-level
`ROY_GOVERNANCE_IDENTITY` happens to be — **not** to the individual Slack user who
sent the message. The two identities can even disagree with each other.

**This changes what "v1" can honestly claim to deliver.** Per the reviewer's
recommendation, this design is repositioned as two separable pieces:

1. **Slack transport layer** (§§1-2, 5-8 below) — can be built now, independent of
   the identity gap. Proves the Socket Mode → OHS OpenAI-compatible bridge pattern.
2. **Per-request delegated governance identity** — a **Track 1 extension**
   (delegated-user-token or token-exchange model reaching all the way into
   `central-governance-api`'s approval-ownership check), which is a **prerequisite**
   for letting more than one real person's actions be correctly attributed through
   the bot — not a "nice to have" deferred item. Until this exists, Track 2 Slack
   should be treated as **single-operator** in practice (whoever's identity the
   agent-server process is running as), regardless of how many Slack users
   technically complete the OAuth binding step.

**Resolved (2026-09-23)**: Roy first chose to design the Track 1 delegated-identity
extension (option 2 above). That extension's own round 1 review found the
propagation problem itself (safely handing off identity across a shared,
concurrent, crash-recoverable pipeline) was a much bigger design/review effort
than initially scoped — approaching Track 1's own 11-round SSO/OIDC/RBAC design
cost (`track1-delegated-identity-v1.md`, now superseded). Given actual deployment
scale (a handful of bound users, not a large multi-tenant SaaS), **Roy chose a
simpler architecture instead: one agent-server process per bound user**, not a
shared process with per-request identity switching. This resolves the Critical by
construction — a process with exactly one identity has no shared mutable identity
state to race on, and it reuses the already-proven single-operator model
unchanged. See the revised §5 for what this means for multi-tenancy.

## 1. Why Slack first

Of the three Track 2 platforms, only Slack has an integration mode — **Socket Mode**
(Bolt SDK, outbound WebSocket connection using an App-Level Token) — that needs no
inbound public endpoint at all. Teams (Bot Framework Connector) and LINE (Messaging
API webhook) both mandate a publicly reachable HTTPS URL. Starting with Slack lets
this design prove the core pattern — "bot adapter talks to OHS agent-server's
OpenAI-compatible endpoint" — without touching the reverse-proxy/TLS decision Roy
already made for Teams/LINE (self-hosted reverse proxy + self-managed TLS), which
is deferred to a later design pass.

## 2. Confirmed OHS agent-server contract (verified against source, 2026-09-23;
corrected per round 1 review)

`openhands-agent-server/openhands/agent_server/openai/router.py`, mounted in
`api.py`:

- `POST /v1/chat/completions`, `GET /v1/models`.
- Auth: `X-Session-API-Key` header **or** `Authorization: Bearer <key>`, checked
  against `config.session_api_keys` (`check_openai_api_key`). The dependency is
  wired at the router-mount level in `api.py` (`app.include_router(openai_router,
  dependencies=[Depends(check_openai_api_key)])`), not per-handler — same
  conclusion, corrected citation. **Correction**: if `config.session_api_keys` is
  empty, the check passes with no key required at all — auth is not unconditional,
  it depends on that config actually being populated.
- `model` must be `openhands_<profile_name>` — it maps to an LLM profile that must
  already exist, created beforehand via the native `POST /api/profiles/{name}`
  endpoint. It is **not** an arbitrary passthrough model id like real OpenAI.
- **This is not a stateless endpoint.** A custom response header
  `X-OpenHands-ServerConversation-ID` is returned; if the caller wants a multi-turn
  conversation, it must capture that header and resend it as a *request* header on
  the next call. If omitted, every call starts a brand-new OpenHands conversation.
  The OpenAI wire format has no field for this — a bot adapter must track and
  replay this header itself, per Slack thread. **Correction**: if a supplied
  conversation id doesn't match an existing event service, the implementation
  attempts to *create* a conversation using that id rather than simply rejecting
  it — the adapter must never treat a conversation id as an authorization
  credential (it is caller-suppliable and not verified as "belonging" to anyone).
- `stream: true` is faked server-side (full run completes, then replayed as
  synthetic SSE events) — not real token-by-token streaming. **Correction**: not
  literally "2-3 chunks" — the implementation emits a fixed small set of
  synthetic events (role, content, finish, optionally usage, then a terminator);
  don't cite an exact count. Irrelevant for a first version either way: Slack
  messages arrive as complete blocks, so the adapter should call non-streaming and
  post the finished response.
- Working reference client: `examples/02_remote_agent_server/15_openai_compatible_gateway.py`.

**Implication for the adapter**: it must (a) have already provisioned one LLM
profile via `/api/profiles/{name}` for whichever OHS agent-server instance it talks
to, (b) authenticate with a session API key via `Authorization: Bearer`, and (c)
maintain its own mapping of **Slack thread → OHS conversation id**, persisted
across adapter restarts (a plain key-value store handles the storage — but see §6b
for the concurrency/delivery contract that storage choice alone does not solve).

## 3. Relationship to Track 1's identity/governance stack (corrected per round 1
review — original "just register as a device" framing did not hold)

Track 1 already built real, reusable pieces: OIDC principal resolution
(`oidc_principal.py`), device registration with per-owner quota (`routers/devices.py`),
and the approval/audit pipeline (`governance_client.py` / `governance_outbox.py` on
the agent-server side). The original draft of this section claimed a bound Slack
user could simply "register as a new device" and thereby ride the existing
quota/scope machinery with no schema changes. **The reviewer confirmed this is
wrong**, reading `devices.py`/`models.py` directly:

- Device registration is an **inventory/audit hint, not a security control**. It
  attaches a device to whichever principal owns the *bearer token used to call the
  registration endpoint* — it does not itself grant that device's "user" any
  independent authority.
- `device_id` is a caller-chosen label, not a credential. Approval claim/report-result
  authorization checks principal ownership only; it does not verify
  `origin_device_id` at all.
- `governance_outbox.py` confirms the current integration does not auto-register
  devices — `origin_device_id` is set once, in process config, by whoever operates
  the agent-server.

So OIDC resolution, quota, the approval state machine, and the audit schema are all
genuinely reusable — but "Slack user → device registration" is not, by itself, an
identity delegation mechanism. It's inventory bookkeeping on top of whatever
identity is *already* making the underlying API calls (see §0: today, that's the
agent-server's single process-level/service-account identity, not the individual
Slack user).

**What this section does not attempt to solve**: designing the actual delegated-identity
mechanism (delegated user tokens, OAuth token exchange, or an explicit
"trusted-service-acting-on-behalf-of-user" contract added to central-governance-api)
is out of scope for this transport-layer design — see §0's decision point.

## 4. Self-service OAuth binding — Device Authorization Grant confirmed viable,
follow-through to governance identity still undesigned

Roy's decision: first-time Slack users get a link to complete OAuth binding via
Keycloak, no manual mapping table. The standard OAuth **authorization-code +
redirect** flow needs a browser-reachable `redirect_uri`. **Correction (round 1
review)**: the reasoning that led to preferring Device Flow is right, but the
original claim "standard redirect always needs a *public* callback" was too
absolute — the callback only needs to be reachable by the *user's own browser*
(localhost, an internal network address, or an existing controlled web frontend
could all work). The real justification for choosing Device Flow here is **avoiding
deploying any browser-reachable callback service at all**, not that redirect flows
are inherently impossible in this setup.

**Recommended: OAuth 2.0 Device Authorization Grant** (RFC 8628) — the user gets a
short code and a verification URL, opens it manually, enters the code, logs in — no
callback URL involved. **Confirmed (round 1 review)**: the Keycloak instance already
installed for Track 1 is **version 26.7.3** (`kc.bat --version`), and Keycloak's own
admin docs confirm Device Authorization Grant support at this version. **Not yet
confirmed**: the Track 1 realm's existing setup script (`create_keycloak_test_identities.bat`)
only creates service-account clients — no client has Device Authorization enabled or
tested yet. Status going into implementation: *capability confirmed, configuration
and an actual end-to-end flow test still pending.*

Flow sketch:
1. Slack user DMs the bot (or the bot detects an unbound user on first message).
2. Adapter calls Keycloak's device authorization endpoint, gets `device_code` +
   `user_code` + `verification_uri`.
3. Adapter posts back to Slack: "please visit `<verification_uri>` and enter code
   `<user_code>`" (ephemeral, DM-only — never in a shared channel).
4. Adapter polls Keycloak's token endpoint until the user completes login (or the
   code expires).
5. On success, adapter registers a device for the resulting principal (see §3) and
   persists a `(slack_workspace_id, slack_user_id) ↔ device/principal` mapping —
   **corrected key shape**, see §4a.
6. The user's original message (or a "you're bound now, try again" prompt) proceeds
   through the normal pipeline.

### 4a. New High-severity gaps surfaced by round 1 review (not designed yet)

- **What survives the binding beyond "it happened"?** The draft above says the
  adapter "registers a device and persists a mapping" but never specifies what it
  does with the token(s) Keycloak issued. Three options, none chosen yet: (a) keep
  only the principal/device id and discard tokens — but then the adapter has no way
  to act as that user on later messages, so this doesn't actually solve §0's
  delegation gap; (b) persist a refresh token — but this turns the adapter into a
  high-value credential store needing its own encryption-at-rest, rotation,
  revocation-on-logout, and leak-response design, none of which exists yet; (c) keep
  the agent-server on its service-account identity regardless (today's behavior) —
  in which case Device Flow only builds a side mapping table and does not change
  who approvals are attributed to. **This decision cannot be deferred past the
  identity-delegation design in §0** — it's the same problem from a different angle.
  Also unaddressed: does a successful Keycloak login even carry the roles/audience
  central-governance-api requires (e.g. an `agent.operator`-equivalent role) — "login
  succeeded" is not the same claim as "is authorized."
- **Binding key must include workspace, not just Slack user id.** A bare
  `slack_user_id` can collide or get misattributed once a second Slack workspace is
  onboarded; the identity key should be `(workspace_id, user_id)`, and the OHS
  conversation key should include workspace + channel + thread root, not just a
  thread id.
- **Lifecycle not designed**: can a bound identity be rebound to a different
  Keycloak subject; who can unbind it; what happens on Keycloak account
  deactivation or on the user leaving the Slack workspace; and — a correctness
  requirement, not just a nice-to-have — the flow must verify that whoever completes
  the Device Flow login is the *same* Slack subject that initiated it (prevent
  code/session mix-up between two different Slack users bound close together in
  time).

## 5. Multi-tenant granularity — REVISED (2026-09-23): one process per bound
user, not one container per team

**This revises the earlier Track 2 decision** ("one container per bot
platform/team," `AskUserQuestion`, 2026-09-23 earlier same day). That decision was
made before the identity-delegation investigation (§0/§3) surfaced how unsafe and
costly it is to share one agent-server process's identity across multiple people.
Once Roy chose "each bound user runs their own agent-server process" to resolve
§0's Critical (see `track1-delegated-identity-v1.md`'s superseded note), the
natural multi-tenant granularity became **per-user**, not per-team — a "team"
(Slack workspace) is now an organizational grouping over a set of per-user
processes/containers, not a shared execution unit itself.

Concretely: **Slack `(team_id, user_id)` maps to one dedicated agent-server
process**, each with its own `ROY_GOVERNANCE_IDENTITY`, its own credentials, its
own workspace/storage — exactly today's already-proven single-operator model,
just instantiated once per bound user instead of once total. This fully resolves
the round 1 review's Low finding that a bare `team_id` routing key wasn't a real
security boundary (credentials/storage/profile/principal were still process-wide
shared) — there is no longer anything shared across users to worry about, by
construction.

**Cost accepted at this scale**: N bound users → N processes/containers, rather
than N users sharing one process. For a Slack-only v1 with a handful of
collaborators in one workspace, this is a handful of lightweight containers, not
a scaling concern. It becomes a real cost question only if/when this needs to
scale to many more concurrent users per workspace — not a v1 problem.

**What the Slack adapter needs to route on**: once a Slack user completes the
Device Authorization Grant binding (§4), the adapter needs to route that user's
subsequent messages to *their* dedicated agent-server process — see §5a for the
full provisioning/eviction design.

## 5a. Per-user process lifecycle — ROUND 18 REVISION — IMPLEMENTATION-READY (2026-09-24)

History: rounds 1-5 (see round 5's own summary — `executing` recovery
converged to a classification fix, not new engineering) → round 6 (0
Critical; the ownership-lease, `STOPPED_UNCLEAN`, and trust-boundary fixes
from round 5 were each real progress but each had one remaining sharp edge:
no fencing against a recovered "stale" owner, no distinction between
"confirmed stopped" and "stopped status unknown," and an overstated claim
about what environment sanitization actually protects) → round 7 (closed the
`STOPPED_UNCLEAN`/`STOP_STATE_UNKNOWN` core safety rule and the trust-boundary
overclaim, but the registry-row fencing added for H1 turned out to guard the
*registry* only) → round 8 (added a fenced "operation-slot" DB claim
immediately before each external call, decided the rejection-reconciliation
canonical key, made `STOP_STATE_UNKNOWN`'s resolution concrete, and precisely
scoped the marker/`STOP_STATE_UNKNOWN` overlap — round 8's review confirmed
the latter three closed, but found the operation-slot claim itself
structurally insufficient: **3 new High** — (a) a DB claim and the external
call it guards are two actions in the same process, and that process can
still be arbitrarily paused between them, so "immediately adjacent" narrows
but cannot close a cross-boundary race; (b) `docker stop`'s claimed
idempotence doesn't cover a stale stop landing *after* a new owner's
`start`, which can kill a legitimately running replacement; (c) the manual
`STOP_STATE_UNKNOWN` runbook has its own TOCTOU between an operator's
observation and the CAS that acts on it — plus **2 Medium** (the
operation-slot's own lifecycle/takeover rules were unspecified, and a
healthy container from a superseded epoch could be promoted straight back to
`READY`). Reviewer's own conclusion: this needs "an external enforcement
point... not tighter wording." Round 9 (this revision) builds that
enforcement point — a single per-host proxy that becomes the only component
allowed to call Docker/Slack — which closes all five by construction, not by
a fourth attempt at narrowing the same window) → round 9 (introduced the
proxy; reviewer's verdict was **worse, not better — 5 new High + 4 Medium +
1 Low, "not converged"**: the proxy's own in-process lock serialized *other
proxy requests* but did nothing to block an ownership takeover happening
independently in the database — "the same race, just moved location," per
the reviewer — plus the proxy itself had no enforced singleton mechanism
(H2), `docker stop`/`start` reordering wasn't actually closed (H3), a proxy
crash mid-operation had no durable intent for Docker or Slack outbound
calls to reconcile from (H4), and UDS requests carried no caller
authorization beyond an epoch value anyone on the host could observe (H5)).
Reviewer's own diagnosis: "ownership takeover and mutation must share the
same keyed lock, or use a real distributed mutex" — surfaced to Roy again
via `AskUserQuestion` (options: adopt that exact fix using Postgres advisory
locks; accept the round-9 design's residual risk as a known limitation and
stop; or pause and hand this off). **Roy chose the advisory-lock fix.**
Round 10 replaced the proxy's in-process lock with a Postgres session-level
advisory lock shared by *both* takeover and mutation — reviewer confirmed
the primitive is sound, but found **1 new Critical**: the lock was keyed
per `(workspace_id, user_id)` while this document's own architecture has
ownership takeover happen at the *workspace* level, so takeover and
mutation still never contended for the same key — the exact round 9 race,
just hidden behind a lock that didn't cover it. Plus **5 new High**
(re-validation-after-lock-acquisition left unspecified; the durable intent
write wasn't actually guaranteed durable, since it shared a transaction
with the outcome it was meant to survive a crash of; the intent record
had no way to find a container whose creation crashed before its ID was
recorded; a hung lock holder's only documented remedy was killing the DB
session, which doesn't stop the process itself from still issuing the
call; and session-affinity/connection-pooling requirements for a
session-level lock were entirely unstated) + **4 Medium** (the singleton
lock's own connection-loss case, lock-key derivation, UID-sharing caller
isolation, and lock reentrancy/monitoring discipline) + **1 Low** (an
overstated claim about connection-death detection speed). Reviewer's own
framing: the advisory-lock architecture itself is validated as correct;
what's missing is granularity alignment plus five concrete, well-specified
engineering gaps — "complete these five points, the core fencing mechanism
is likely to converge." Round 11 re-keyed the lock to `workspace_id`
(matching the existing ownership model). Reviewer's verdict: **0 Critical —
the granularity fix closed it, and the core workspace-level advisory-lock
mechanism itself is confirmed converged** — but **2 new High**: (a) "the
next mutation can't acquire the lock until the outcome commits" is only
true while the original holder is alive; a crash releases the lock via
session death precisely when an intent is left unresolved, and round 11 had
no explicit gate requiring a new holder to check for and resolve this before
proceeding; (b) the hung-holder runbook's "make the old process structurally
incapable of acting" gave illustrative examples (SIGKILL, revoke socket
permissions) rather than a verifiable condition — signal delivery isn't
proof of death (PID reuse), permission revocation doesn't close existing
connections, and the wording only covered Docker, not Slack egress. Plus
**2 Medium** (the post-lock "fresh re-read" needed an explicit
transaction/isolation-level requirement to actually guarantee freshness; the
intent record's invariants — uniqueness, at-most-one-unresolved-per-workspace
— were described procedurally rather than enforced by the database schema)
and **1 Low** (round 11's own summary overclaimed "closes all six findings"
against round 10's actual 1 Critical + 5 High + 4 Medium + 1 Low tally).
Round 12 introduced an explicit
`PREPARED → APPLIED | NOT_APPLIED | AMBIGUOUS → RECONCILED` intent state
machine with a DB-enforced partial unique constraint and a mandatory
reconciliation-only gate, plus verifiable process-death/egress-isolation
criteria for the hung-holder runbook. Reviewer's verdict: closed M1 and L1,
substantially improved H1/H2, but **2 new High** remained — (a) treating an
elapsed retry/backoff window as proof an old Docker request would never
land was unsound (Docker gives this design no daemon-side idempotent
operation key or ordered completion acknowledgment; "waited and didn't see
it" isn't "can never arrive"), which could let a delayed `stop` land after
a new `start` and re-open the exact stale-stop-after-new-start race this
whole effort exists to close; (b) confirming process death only proves the
old holder can't issue *new* requests, not that a request the daemon
*already accepted* won't still complete — and the runbook's Slack-isolation
step contradicted this document's own earlier statement that Slack outbound
gets no durable intent. Plus **3 Medium** (reconciliation evidence was
written as one universal rule when the `operation_id` label is only ever
written for `create`, not `start`/`stop`; the state machine lacked complete
retry/abandon transitions and correct constraint DDL; "retry later" had no
defined durable executor) and **1 Low** (the held/maintenance state's
persistence and enforcement point needed to be named as a DB column, not
implied). Reviewer's own framing: the remaining gap is real but narrow — a
provable completion barrier for external-call fencing, not a reason to
revisit the lock architecture. Round 13 made `start`/`stop` reconciliation
reuse the existing `STOP_STATE_UNKNOWN` human-confirmation runbook rather
than any timer, kept `create`'s timer-based `NOT_APPLIED`-and-retry path
with its residual risk named honestly, split reconciliation evidence by
operation kind, completed the state machine and DB constraints, reframed
hung-holder isolation as reducing interference rather than proving
completion, and added a durable `next_retry_at`-driven reconciliation path.
Reviewer's verdict: **0 Critical, 1 new High** — a genuinely subtle point:
confirming a container's *current* state via `docker inspect` is not the
same evidence as proving a *specific past request* the daemon already
accepted will never still complete — an inspect only shows what's true at
the moment it runs, not that no `stop` from before the crash is still
in-flight. Reusing `STOP_STATE_UNKNOWN`'s runbook was directionally right
but invoked too early: nothing in round 13 established that enough time had
passed for such a request to have necessarily concluded one way or another.
Plus **3 Medium** (a delayed `create` duplicate landing *after* the
original intent reached `RECONCILED` had nothing left watching for it, so
"caught on the next reconciliation pass" wasn't actually guaranteed; the
schema let `operation_id` be simultaneously globally unique and reused
across retries — two claims that directly contradict each other, blocking a
retry's own insert; the background reconciliation worker's lock-acquisition
obligations were only implied, not stated) and **1 Low** (the held state
was still only described as "the workspace stays held," never actually
defined as a database column). Round 14 introduced a **quiescence window**
for `start`/`stop` — Docker's stop grace period plus margin for `stop`, a
named operational bound for `start` — measured from the intent's
`started_at` with the daemon confirmed reachable throughout, before the
human-mediated inspection runs. It also made `create`'s duplicate-watch
durable past `RECONCILED`, split `operation_id` from a new
`intent_attempt_id`, split `outcome_classification` from `gate_state`,
made the background worker's lock-acquisition duty explicit, and introduced
a named `hold_state` column. Reviewer's verdict: **0 Critical, 1 new
High** — round 14's own "quiescence window" conflated two different
things: Docker's stop grace period bounds the wait *after* the daemon's
handler has already started executing a stop, not the unbounded delay
*before* that (network delay, daemon load, a blocked handler) that nothing
in Docker bounds or exposes; `start`'s "operational bound" was an
assumption stated with more confidence than it had. Plus **3 Medium** (the
duplicate-watch "window" would need the exact same unprovable
completion-time bound just shown not to exist, so giving it a fixed
duration was equally unsound; the `outcome_classification` value list
excluded `PREPARED`, the very value a fresh intent is created with; the
`hold_state` clearance rule only covered the case where a pending intent
existed, leaving no path for a hung holder that got stuck before ever
creating one) and **0 Low**. Reviewer's own framing: the lock architecture
itself remains sound; what's left is specific and narrow. Round 15 removed
the unsound timer claims: `start`/`stop` ambiguity would resolve immediately
when transport-level evidence proved a request never reached the daemon,
and otherwise required genuine out-of-band human investigation with no
formulaic timer. Reviewer's verdict: **0 Critical, 1 new High** — the
transport-level "never reached the daemon" evidence was itself too
permissive (a transport-layer acknowledgment gap doesn't prove the
application handler never accepted the request), and the human
investigation's release predicate only required "a confident answer"
rather than specifically proving the old request had terminated or been
positively isolated — round 14's own counterexample (an old `stop` handler
that hasn't yet sent its signal) survives a bare "container looks fine now"
check. Plus **2 Medium** (tying `create`'s duplicate-watch lifetime to
ordinary tombstone GC was itself an unproven implicit expiry — GC reasons
about containers that already exist, not a delayed `create` that hasn't
landed yet and might still create one after the watched entry is GC'd; the
new transport-level `NOT_APPLIED` shortcut had nowhere valid to transition
to, since the formal state machine still restricted `NOT_APPLIED` to
`create`) and **1 Low** (§9 should state the availability cost of
indefinite fail-closed more directly, as a core v1 operating
characteristic, not folded into a generic infrastructure/SPOF cost line).
Round 16 narrowed the transport-level shortcut to only
connection-never-established or provably-zero-bytes-delivered cases,
tightened the human investigation's release predicate, added an evidence-
gated `NOT_APPLIED` transition for `start`/`stop`, freed `create`'s
duplicate-watch from ordinary tombstone GC, and added §9's availability-cost
sentence. Reviewer's verdict: **0 Critical, 1 new High** — "request
terminated with known effect" collapsed two different outcomes (the old
request had no effect vs. it successfully applied its change) into one
wrong classification (`NOT_APPLIED` for both), and didn't cross-check a
claimed "applied" effect against a fresh inspect of current reality — an
old `stop` confirmed by investigation to have completed, but a fresh
inspect showing the container still running, needs its own resolution path,
not a blind classification either way. Plus **1 Medium** (the round-16 fix
was described in prose alongside the transport tiers but the document's
single formal state-machine table further down was never updated to match,
still saying `NOT_APPLIED` was `create`-only and referencing the retired
"quiescence-gated" mechanism — two contradictory normative sources for the
same transitions) and **0 Low** (the reviewer separately confirmed the
"two-tier" structure isn't hollow, but noted its practical scope is narrow
with off-the-shelf Docker clients — worth a deployment note, not a
finding). Round 17 made outcome mapping three-way (no-effect →
`NOT_APPLIED`; applied-and-fresh-inspect-confirms → `APPLIED`;
applied-but-inspect-disagrees → stays `AMBIGUOUS`/held) and updated the
single normative state-machine table to state these rules directly, plus
added a deployment note on tier 1's narrow practical scope. Reviewer's
verdict: **0 Critical, 0 High, 1 Medium, 0 Low** — explicitly confirming
the core architecture (advisory lock, crash-recovery gate, three-way
outcome mapping, inspect-failure fail-closed behavior, and `APPLIED`'s
registry convergence) is sound, with only two textual sync points left:
the table's own first transition still read `PREPARED → {AMBIGUOUS,
APPLIED}` without the direct `NOT_APPLIED` path tier 1's transport proof
is conclusive enough to use immediately (no need to detour through
`AMBIGUOUS` first), and one sentence elsewhere still referenced the
retired "quiescence-window-gated" mechanism instead of the current tier
1/tier 2 language. Round 18 (this revision) closes both — the reviewer's
own framing: "this advisory-lock/crash-recovery direction can converge
once these two sync points are fixed, no need to open another
architecture round."

### `executing`/`applied` — DE-ESCALATED from "hard blocker needing new
recovery logic" to "already safe, just needs correct classification"

A dedicated trace of `event_service.py`'s claim/dispatch path and
`central-governance-api`'s claim handler (`routers/approvals.py:364-436`)
changes the picture round 3/4 had:

- Central's `accepted → executing` transition happens **only** in direct
  response to *this same agent-server's own* `POST /approvals/{id}/claim`
  call (a conditional `UPDATE ... WHERE status='accepted'`) — it is never
  something central does independently. So observing `executing` at all
  implies this agent-server already initiated a claim for this approval.
- Recovery for an ambiguous claim **already exists**, keyed by idempotency:
  `_relay_outbox_once()`'s `CLAIM_INFLIGHT` branch re-calls `client.claim()`
  with the same `idempotency_key`; central's claim handler checks
  `find_replayed_response` before re-evaluating status, so a retried claim
  after an already-successful one **replays** the original
  `execution_attempt_id`/lease rather than erroring or double-claiming.
- **The specific double-execution risk is provably closed across two distinct
  crash windows, not one blended argument (round 5 review corrected this
  precision issue)**: `_apply_claim()` (writing local `CLAIMED`) always
  completes strictly *before* `_dispatch_claimed_run()`/`self.run()` in
  `_claim_and_run_governed()` — so a crash while local state is
  `CLAIM_INFLIGHT` provably never reached the run-dispatch step on this
  device.
  - **Window A — crash before the conversation ever reaches `RUNNING`**:
    recovered by the *existing* durable `CLAIMED`-redispatch path itself
    (`event_service.py` around lines 759/826) — a persisted `CLAIMED` record
    with no corresponding run in progress gets redispatched on the next pass,
    not by any startup-recovery logic.
  - **Window B — crash after reaching `RUNNING`, before an observation is
    recorded**: this is what startup's stale-`RUNNING → ERROR` conversion
    actually covers — synchronously, with no `await` in between, before the
    scheduled redispatch task can get CPU time — and
    `maybe_report_governance_result()` reads that same event log immediately
    after to report `failure_unknown` to central.
  - The original draft of this section attributed both windows to the same
    stale-`RUNNING` mechanism, which isn't precise (window A never reaches
    `RUNNING` at all, so that recovery path wouldn't even trigger for it) —
    corrected here; the conclusion (no new recovery logic needed) is
    unchanged by this correction.
- **Conclusion**: `_wait_for_decision_loop` observing `executing` (or
  `applied`, its later terminal-ish successor) needs **no new recovery
  logic** — the existing outbox relay and SDK crash-recovery paths already
  safely converge it. The actual bug is narrower than rounds 3-4 framed it:
  `_wait_for_decision_loop`'s current code wrongly classifies `executing`
  into the same "unexpected status → `NEEDS_ATTENTION`" bucket used for truly
  unhandled cases. **Fix**: give it its own branch that does nothing but log
  and return cleanly (no reject, no `NEEDS_ATTENTION`) — rejecting would
  actively be *wrong* here (the action was already accepted and is
  proceeding), and `NEEDS_ATTENTION` incorrectly signals a problem where
  there isn't one. This closes the Track 2 eviction-safety concern (a
  conversation observing `executing` will transition out of
  `WAITING_FOR_CONFIRMATION` via the normal dispatch-to-`RUNNING` path, which
  Track 2's existing "never evict `RUNNING`" rule already covers) without any
  new invented mechanism.
- **One residual point not fully traced, flagged honestly rather than
  assumed**: whether `self.run()` itself refuses to re-dispatch a tool
  action that already has a matching observation/error event in its history.
  The ordering argument above is strong circumstantial evidence this is
  fine, but wasn't confirmed end-to-end in `local_conversation.py`'s resume
  logic. Recommend a targeted unit test (crash-inject between `CLAIMED` and
  dispatch, verify no double tool execution) before relying on this in
  production — cheap to verify, not being deferred as unknowable.
- `applied`/`failed_definite`/`failed_unknown`: by the same reasoning (they
  are strictly downstream of `executing`, which is already shown safe),
  treated the same way — recognized, logged, no reject/`NEEDS_ATTENTION`.

### `EventService.close()`'s worker-thread gap — fixable, not architectural

Confirmed: "nobody wired up the join," not a deep limitation. The
`ThreadPoolExecutor` is shared across all conversations
(`ConversationService`-owned), shut down with `shutdown(wait=False)` — an
explicit non-blocking choice — and no code retains the
`concurrent.futures.Future` from a dispatched run outside the coroutine that
awaits it. **Fix**: capture that future at dispatch time, store it on the
`EventService`, and have `close()` await/join it with a bounded timeout before
considering shutdown complete. A timeout here is a genuine "drain did not
finish," not success — matches this section's existing drain-success
discipline. This closes round 4's H1 (drain marker resting on an
unenforced assumption) at the actual source, rather than working around it.

### Drain-completion marker — refined per round 4's H2/H3/H4

- **Generation-bound, single-use receipt**: the marker includes
  `workspace_id`, `user_id`, `generation`, the actual container ID, and a
  random `drain_attempt_id`; any prior marker is invalidated before a new
  drain attempt begins. Written via temp-file + `fsync` + atomic rename +
  `fsync` on the parent directory (not "file exists" as the check).
  **Round 5 review found a direct contradiction here and it's fixed now**:
  the draft said timeout is a genuine failure, then separately said the
  marker could be written after the worker-thread join "completed **or
  definitively timed out**" — meaning a timed-out join could still produce
  what looks like a clean marker. **Corrected**: a *clean* marker is written
  **only** on a successful join (container stopped accepting new work, join
  succeeded, outbox/conversation writes flushed) — a timeout or exception
  during join **never** produces a clean marker, full stop; that path goes
  directly to `STOPPED_UNCLEAN` (below) with no marker at all, or at most a
  clearly distinct, differently-named failure/diagnostic record that the
  clean-marker verification step cannot mistake for success.
- **Trust boundary — round 6 correctly rejected round 5's "actual enforcement
  mechanism" framing as overstated; downgraded to what it actually is**:
  `conversations_path` and the agent's tool-execution workspace
  (`workspace_path`) are sibling directories under one shared `workspace/`
  root, and the spawned tool subprocess shares the **same mount namespace**
  as agent-server — so absolute paths remain discoverable regardless of
  environment variables (filesystem enumeration, `/proc/*/mountinfo`,
  process arguments, open file descriptors, or error messages can all reveal
  where `control_state` lives), and the marker's core operation is a
  filesystem *write* — if the volume is writable by the subprocess's UID, no
  API credential is even needed to interfere with it. Round 5's claim that
  stripping the session API key and `control_state` path from the tool
  subprocess's environment "substantially raises the bar" and functions as
  "actual enforcement" was **too strong** — correctly called out. **Honest
  framing (round 6)**: this is **credential redaction and
  accidental-interference hygiene only** — worth keeping (it's good practice
  regardless, and reduces the chance of an LLM-directed shell command
  stumbling into that path by coincidence during some broad or recursive
  operation, malicious or not), but it provides **no marker-integrity
  guarantee**. Real integrity requires OS-level isolation this design does
  not build (distinct UID/GID or mount namespace between agent-server and
  its spawned tool subprocesses) or an external supervisor that verifies
  drain state independent of anything written inside the container —
  tracked as the same pre-existing, separately-flagged sandbox-runtime
  question from Track 2's earlier planning (gVisor/Firecracker/Hyper-V-class
  isolation), not invented or resolved here. **Because this trust boundary is
  not actually closed, it cannot be treated as "a known limitation" in
  isolation — it is precisely why the `STOP_STATE_UNKNOWN` split above must
  never permit a same-volume recovery mount**: the system's real safety
  property isn't "the marker can't be forged," it's "when the system cannot
  independently confirm the container is gone via Docker itself, it refuses
  to act as though it has clean state, regardless of what any marker (forged
  or not) might claim."
- **`STOPPED_UNCLEAN` vs. `STOP_STATE_UNKNOWN` — split into two states (round
  6 correctly found conflating them let a replacement mount a volume the
  prior container might still be writing to)**: the distinguishing question
  is not "was the join clean" but **"does Docker confirm the container
  process is actually gone at all"** — those are answered by different
  mechanisms and must not share a recovery path.
  - **`STOPPED_UNCLEAN`**: `docker stop`/inspection *successfully confirms*
    the container process is gone — whether via a graceful exit or a
    force-kill after the grace period — but there is no valid, matching clean
    marker (missing entirely, or present but mismatched on
    generation/`drain_attempt_id`/container ID, which is treated identically
    to missing — never trusted partially). This is the case a worker-thread
    join timeout inside `close()` actually produces: Docker's own `stop`
    semantics guarantee the OS-level process is gone by the time `docker
    stop` returns success, regardless of whether the *internal* drain was
    clean — so this case is confirmed-safe to recover from. Alerting:
    immediate (abnormal at this deployment's scale). Recovery: an explicit,
    manually-triggered "recovery mode" provisioning path may mount the same
    durable volume, relying on the SDK's own existing crash-recovery behavior
    (stale `RUNNING → ERROR` conversion on startup) rather than assuming the
    prior container's in-memory state was consistent. Only after that
    recovery container reports healthy does the registry advance to a fresh
    `READY` generation, invalidating the old marker so it can never be
    replayed against the new one.
  - **`STOP_STATE_UNKNOWN`**: the `docker stop`/inspection call *itself*
    fails, errors, or times out — Docker cannot confirm whether the
    container process is running or gone at all (e.g. a Docker daemon/API
    partition), even after the existing stale-`DRAINING` reconciliation retry
    (round 4's M-A) also fails to get a confirmed answer. **This state must
    never permit mounting the same durable volume for any replacement or
    recovery container** — doing so risks two writers on the same volume if
    the original process is in fact still alive.
    **Resolution — made concrete (round 8, closes round 7's M2, which found
    the "out-of-band confirmation" language correct in principle but not
    implementable as written)**: for v1's single-host Docker deployment
    (not a cluster, so an unreachable Docker daemon means something is wrong
    with *this host*, not a routing problem elsewhere), the design does not
    invent a new automated confirmation channel — if Docker's own local API
    can't be trusted, no other automated component on the same host is a
    more trustworthy witness without assuming a different failure domain
    (e.g. out-of-band SSH access, or a cloud provider's independent
    instance/container status API, neither of which this design assumes is
    available). **Authority**: a human operator, following a documented
    runbook (out-of-band host access — SSH or provider console — to run
    `docker ps`/`docker inspect` or equivalent directly against the host),
    confirms the container's actual status. **Evidence recorded** alongside
    the transition: operator identity, a DB-server-clock timestamp (same
    clock source as heartbeats, for the same clock-skew reason), the
    confirmation method used, and the raw command output observed — not a
    bare status flip. **Transition mechanism**: an explicit admin-only
    action that performs the *same* fenced, generation-checked CAS as every
    other transition in this design (carries the current epoch; an operator
    acting on stale information about a since-superseded generation is
    rejected the same way a stale process would be) — the evidence fields
    are written atomically with the state change, not as a separate,
    droppable audit log entry. **TOCTOU between observation and CAS — closed
    in round 9, not round 8**: round 8's version let an operator act on
    whatever they'd observed at any earlier moment, so Docker/the prior
    owner could change the container's real state between that observation
    and the CAS actually committing. Round 9 routes this admin action
    through the same enforcement proxy introduced below: the proxy holds a
    maintenance lock on the workspace for the duration, performs a fresh
    `docker inspect` *immediately adjacent to, inside the same locked
    section as* the CAS itself (not "whatever an operator saw earlier"),
    and includes that freshly observed container state and ID in the CAS
    predicate — see "External enforcement proxy" below for the mechanism.
    **Two-person confirmation is a recommended,
    deferred policy knob, not built for v1**: named explicitly here as a
    known simplification at this deployment's scale, not silently implied
    by "a human confirmed it." **Deployment requirement, not an assumption**:
    the container's Docker restart policy must be `no` (never
    `unless-stopped`/`always`) — otherwise a container that was merely
    partitioned, not actually dead, could self-resurrect and resume acting
    *after* being manually confirmed "gone," defeating the confirmation
    step entirely. **Outcome mapping — the classification table round 7 left
    incomplete**: confirmed gone → `STOPPED_UNCLEAN`, follows that recovery
    path; confirmed still alive and healthy → back to live `READY`; confirmed
    still alive but a stop was genuinely in progress → back to `DRAINING` to
    retry the stop through the normal path. No third permanent state is
    needed for the "still alive" outcomes — they are reconciliation retries
    into existing states, not new terminal ones. **Reused, not duplicated,
    for §5a's `start`/`stop` intent reconciliation (round 13)**: an
    `AMBIGUOUS` `start`/`stop` intent (below) is the same underlying
    problem — Docker's true state can't be confirmed, and only an
    out-of-band human check resolves it — so it is resolved through this
    exact runbook rather than a separately invented mechanism.
  - Both states are reached only via the same generation-checked, fenced CAS
    as every other transition in this design (see the ownership-fencing
    mechanism above) — a stale actor can never overwrite a newer generation's
    state, and neither state is ever recycled through the normal
    tombstone/pool-refill path automatically.

### Outbox termination for locally-rejected approvals — simplified

Round 4 found `REJECTED_LOCALLY` isn't a real fix target: it exists as an
`OutboxState` enum value but is **dead code** — never constructed anywhere in
either repo, in neither `TERMINAL_STATES` nor `RETRIABLE_STATES`. Rather than
wiring up an unused enum value across every consistency-critical branch,
**reuse the already-correctly-wired `CANCELLED` terminal state** for all three
locally-rejected outcomes (`rejected`, `expired`, `cancelled`) — semantically
consistent (none of them result in the action executing) and touches less
code, matching this project's own "don't mix conventions" norm rather than
reviving a parallel, never-tested state value. Fix, applied to **both** the
existing `rejected` branch and the new `expired`/`cancelled` branch:

1. Call `reject_pending_actions()` (idempotent — a conversation already
   `IDLE` with no pending actions is a safe no-op).
2. Transition the outbox record to `CANCELLED`.
3. **Crash-consistency**: these are two separate persisted writes, not one
   transaction. If step 1 succeeds and step 2 doesn't complete before a
   crash, the outbox is left at `CREATED` while the conversation is already
   `IDLE`. Rather than assuming atomicity, the periodic reconciliation pass
   (already needed for registry health-checking) also re-derives outbox
   state from the conversation's actual event history on each pass. **Round
   5 review correctly required a precise matching rule here, not a coarse
   conversation-level check**: the reconciliation pass must match against
   the target of an actual `UserRejectObservation` in the conversation's
   history — checking only "conversation is `IDLE`" or "a rejection exists
   somewhere in history" risks wrongly terminalizing an outbox record whose
   action is unrelated to whichever rejection happened to be observed,
   especially once a single conversation has had multiple governed actions
   over its lifetime. **Canonical correlation key — decided (round 8, closes
   round 7's M1, which correctly found "`action_event_id`/`tool_call_id`" was
   two candidate fields, not a decision)**: the outbox record's canonical
   correlation field is **`action_event_id`** — the identifier OHS assigns to
   the specific governed action (the confirmation-gated tool call) at the
   point it enters `WAITING_FOR_CONFIRMATION`, already the natural join key
   since it is what the outbox record is created *for* in the first place.
   `tool_call_id` is not used as the correlation key; it is retained on the
   outbox record only as a diagnostic/display field. **Cardinality rule**: a
   single governed action corresponds to exactly one `action_event_id` and
   exactly one outbox record — the design does not create multiple outbox
   records against one governed action, so the match is always 1:1, never
   many-to-one; a conversation with multiple governed actions over its
   lifetime simply has multiple, independently-keyed outbox records, each
   matched against its own `UserRejectObservation` by exact
   `action_event_id` equality. **If `action_event_id` is missing or
   unparseable** on either side (legacy data, a malformed event), the
   reconciliation pass leaves that outbox record non-terminal and raises an
   alert — it never guesses a match from conversation-level or
   temporal proximity alone. This is the same "idempotent convergence over
   assumed atomicity" pattern used elsewhere in this revision, now specified
   precisely enough to implement correctly.

### Eviction eligibility, process lifecycle state machine, provisioning,
registry (unchanged from round 4 except as noted above)

Never evict while `RUNNING`, `WAITING_FOR_CONFIRMATION`, `PAUSED`, or
`DELETING`; eligible only when every conversation is `IDLE`, `FINISHED`,
`ERROR`, or `STUCK`, plus the idle-timeout window elapsed. The
`executing`/`applied` classification fix above removes the last *known* gap
in "conversations always eventually leave `WAITING_FOR_CONFIRMATION`" —
**round 6 correctly objected to calling this "safe without qualification"**
while this section still lists one unconfirmed point (whether `self.run()`
refuses to re-dispatch an already-observed action, see below): that
qualifier is real and shouldn't be dropped from the eligibility rule's own
safety claim. **Fix**: the targeted crash-injection test mentioned below is
promoted to an explicit **implementation acceptance criterion** for this
eligibility rule specifically — `RUNNING`/`WAITING_FOR_CONFIRMATION` exclusion
should not be described as unconditionally safe until that test passes;
until then, treat it as "safe under the strong circumstantial evidence
traced in this document, pending one targeted test." `READY → DRAINING →
STOPPED`/`STOPPED_UNCLEAN`/`STOP_STATE_UNKNOWN` lifecycle, full-tuple
fenced CAS, per-`(workspace_id, user_id)` single-flight lock separate from
§6b's per-thread lock, bounded-wait queuing during `DRAINING` rather than
concurrent generations, and the deployment invariant that v1 runs exactly
one adapter process per workspace (enforced, not assumed) all carry over
from round 4 unchanged. **Distinguished from the round 10/11 mechanism
below, not duplicating it**: this single-flight lock is an in-process,
intra-owner lock guarding against two concurrent message handlers *within
the same legitimately-owning adapter instance* both discovering "no process
yet" and double-provisioning; it says nothing about cross-instance
ownership. The workspace-level Postgres advisory lock introduced below is
the mechanism that fences ownership itself against a second, competing
instance — a different problem at a different layer, and both are needed.

**Deployment-invariant enforcement mechanism — corrected (round 5 found
round 4's "fail-fast, not a lease" framing doesn't survive scrutiny)**: a
plain check-then-start has a TOCTOU race (two adapters starting
simultaneously can each see "no owner" and both proceed), and without any
renewal signal, a durable registry can't distinguish a genuinely live owner
from one that crashed and left a stale claim behind. There is no way around
needing *some* atomic, renewal-aware primitive — round 4's attempt to avoid
this by calling it "just fail-fast" was avoiding a real requirement, not
simplifying one. **Design, kept as minimal as the requirement allows**: a
single row per workspace in the same durable registry already used for
per-user process state, with a unique constraint on `workspace_id`. Startup
does an atomic claim (`INSERT ... ON CONFLICT DO NOTHING`, or equivalent
compare-and-set) writing its own instance identity and a heartbeat
timestamp. If the row already exists: check whether the existing heartbeat
is within a defined staleness threshold — if fresh, refuse to start; if
stale (owner crashed without a clean handoff), atomically take over
(conditional `UPDATE ... WHERE heartbeat < threshold`) and proceed. A running
adapter renews its own heartbeat periodically. This is, honestly, a
lightweight lease in substance — one row, one heartbeat field, no separate
leasing service — not the renewal-free "just fail-fast" round 4 claimed was
sufficient; naming it accurately here rather than repeating that
oversimplification.

**Fencing — added (round 6 found the heartbeat/takeover design above solves
"two new adapters race," but not "the old owner comes back")**: without a
fence, an adapter that missed heartbeats due to a long GC pause or a
transient DB/network partition — then got correctly declared stale and
taken over by a replacement — could resume operating (touching containers,
the registry, Slack events) with no way to know it had already lost
ownership, since nothing invalidates its authority to act. **Fix**: every
claim or takeover writes a monotonically increasing `ownership_epoch` (or an
equivalently unique, non-reusable `lease_token`) alongside the owner id and
heartbeat. Heartbeat *renewal* is itself a conditional update —
`UPDATE ... WHERE workspace_id = ? AND owner_id = ? AND lease_token = ?` —
and a failed renewal (zero rows affected) means this instance has already
been superseded: it must stop taking any further action immediately, not
just log a warning. Every registry state transition and container
start/stop/recovery operation this design performs must carry and check the
same epoch/token; an operation presenting a stale one is rejected. Takeover
itself is the same conditional-update pattern — set owner, token/epoch, and
heartbeat together, and only treat it as successful if exactly one row was
affected. Two adapters racing to take over the same stale row resolve safely
under normal transactional semantics: whichever update commits first changes
the row such that the second one's `WHERE heartbeat < threshold` predicate no
longer matches, so it correctly fails rather than also succeeding.

**Fencing enforcement point — round 7/8/9 attempts each found insufficient by
review; round 10 introduced the right primitive (Postgres session-level
advisory locks) but keyed it at the wrong granularity, which round 11
corrects**: round 7 fenced the registry row; round 8 added a fenced DB claim
immediately before each call (rejected — same-process, non-atomic); round 9
introduced a per-host proxy (rejected — its in-process lock never touched a
takeover happening independently in the DB); round 10 introduced a Postgres
advisory lock shared by takeover and mutation (the reviewer confirmed this
primitive is sound) but keyed it per `(workspace_id, user_id)`, while this
document's own existing architecture (§5, §9) has ownership takeover happen
at the **workspace** level — one adapter process claims an entire workspace,
then routes individual users' work to their own agent-server processes. A
per-user lock and a workspace-level takeover were never actually contending
for the same key, so round 10's central claim ("takeover and mutation share
one lock") **did not hold** — the review correctly flagged this as a
Critical, not a wording gap: it's the exact H1 race from round 9, still
open, just hidden behind a lock that didn't cover the real contention point.

**Fix — workspace-level advisory lock (the reviewer's own recommended
option at this deployment's scale, over redesigning ownership itself to
per-user granularity)**: the advisory lock key is derived from
`workspace_id` alone. *Every* operation this design treats as
ownership-or-mutation-sensitive for that workspace — takeover/claim,
heartbeat-driven staleness decisions, and the proxy's handling of *any*
bound user's Docker/Slack mutation within that workspace — acquires this
same lock for its full critical section before doing anything else. The
accepted cost: two different bound users' Docker operations within the same
workspace now serialize behind one lock rather than running independently.
At this deployment's scale (a handful of users per workspace, occasional
provisioning/eviction events, not a high-throughput system) this is a
reasonable trade for a design that's actually provably correct, and it
avoids the alternative the reviewer explicitly warned against — taking a
dynamic, growing set of per-user locks at takeover time, which has no clean
atomic snapshot and risks deadlock.

Because takeover and every in-workspace mutation now contend for the
*identical* key, a takeover attempted while any mutation is in flight
genuinely **blocks** until that mutation's critical section ends — not "the
window is short," but "these operations cannot interleave, because
Postgres enforces it." If the lock holder's *connection* dies (crash),
Postgres releases the lock automatically, unblocking whoever is waiting; a
GC pause or scheduler stall that leaves the connection alive correctly makes
a waiting takeover wait rather than race ahead.

- **Re-validate after acquiring, never trust a pre-lock check — closes
  round 10's H1**: heartbeat staleness may still be *observed* before
  attempting to acquire the lock, purely as a hint about whether trying is
  worthwhile — but the actual decision is made only after the lock is held:
  re-read the authoritative row fresh (DB server clock, not a value read
  before queuing for the lock), re-confirm the expected owner/epoch/token,
  and only then perform the CAS. This applies uniformly to initial claim,
  clean voluntary handoff, and admin-triggered takeover — none of them may
  act on information gathered before the lock was acquired, including a
  takeover that had been waiting behind another lock holder.
- **Durable intent, made actually durable — closes round 10's H2**: "same
  database session" was not enough — round 10's phrasing left the intent
  write inside the same transaction as the eventual outcome, which a crash
  before commit would roll back, erasing the very breadcrumb meant to
  survive it. Corrected sequencing, all on one pinned connection holding the
  lock throughout: (1) acquire the lock; (2) **transaction A**: insert the
  intent record and **commit**; (3) issue the Docker/Slack call; (4)
  **transaction B**: write the outcome or definitive timeout classification
  and **commit**; (5) only then release the lock. "The outcome was recorded"
  means transaction B's commit succeeded — not an ORM `flush()`, not an
  in-memory flag.
- **Intent record given an identity, not just descriptive fields — closes
  round 10's H3**: the intent record's primary correlating field is a
  freshly generated `operation_id`, identifying the **logical operation**
  (see the round 14 schema split below for why this is deliberately not
  itself the row's unique key) — committed (transaction A, above) *before*
  the Docker call is issued. For `docker create` calls specifically, this
  `operation_id` is passed as a Docker label at create time, so a container
  that was successfully created but crashed before its ID could be written
  back to the intent record can still be found on restart by searching
  Docker for that label — not by guessing from workspace/user/generation
  alone. Reconciliation matches on
  this label plus the immutable container ID once known, never on a
  reusable name.
- **Crash-recovery gate protocol — closes round 11's H1, which correctly
  found that "the next mutation can't acquire the lock until the outcome
  commits" is true only while the original holder is alive; a crash releases
  the lock via session death precisely when an intent is unresolved, which
  is exactly the case this design must not let slip through**: the intent
  record carries an explicit outcome/gate state, split into two columns for
  the reasons given below — `outcome_classification`
  (`PREPARED → APPLIED | NOT_APPLIED | AMBIGUOUS`) and `gate_state`
  (`PENDING → RECONCILED`) — and a database-enforced partial unique index
  on `gate_state = 'PENDING'` guarantees at most one *unresolved* (pending)
  intent per workspace can ever exist, not merely "in practice, given the
  lock discipline." Whoever next acquires the workspace lock for *any*
  reason (takeover or a new mutation attempt) must, before doing anything
  else:
  1. Query for a `PENDING` intent for this workspace.
  2. If none exists, proceed normally.
  3. If one exists, enter **reconciliation-only mode**: refuse to create a
     second intent, refuse any new mutation, and refuse a takeover CAS until
     this specific intent reaches `RECONCILED`.
  4. **Reconciliation evidence differs by operation kind — corrected in
     round 13, which found round 12's "query Docker for objects matching
     the `operation_id` label" stated as a universal rule when the label is
     only ever written for `docker create`**:
     - **`create`**: query Docker for objects matching the `operation_id`
       label (written into the container at create time, per above).
       Exactly one match → adopt its immutable container ID, converge the
       intent based on that object's actual observed status, mark
       `RECONCILED`.
     - **`start`/`stop`**: there is no fresh label to search for — these
       target an *existing* container already identified by its immutable
       ID, which the intent record already carries. Reconciliation
       `docker inspect`s that specific ID and checks whether the operation's
       intended postcondition (running for `start`, stopped for `stop`)
       actually holds.
  5. **`NOT_APPLIED` is not a timer-based conclusion — round 13 correction,
     the actual fix round 12's review demanded**: round 12 let a mere
     elapsed retry/backoff window with no matching object stand in for proof
     that the original request would never land — round 12's own review
     correctly rejected this: "waited and didn't see it yet" is not the same
     as "it can never still arrive," since Docker gives this design no
     daemon-side idempotent operation key and no ordered acknowledgment
     channel proving a request is done or will never execute. The fix
     differs by operation kind, because the *cost* of being wrong differs:
     - **For `create`**: a query that finds no matching object may, after
       the retry/backoff barrier, transition to `NOT_APPLIED` and permit a
       retry — a **new intent attempt row**, but carrying the *same logical*
       `operation_id` as the original (see the schema fix below for how
       `operation_id` and each attempt's own unique row identity coexist).
       **The catch is durable, not merely "next reconciliation pass" — round
       14 correction, closing round 13's M1, which correctly found that once
       an intent is `RECONCILED`, nothing was left checking it again, so a
       delayed duplicate could sit undetected indefinitely**: every logical
       `operation_id` that was ever retried (i.e. has more than one attempt
       row) is durably flagged for duplicate-watch, and this flag survives
       past `RECONCILED`. While flagged: (a) the background reconciliation
       worker's periodic pass includes duplicate-watched operations, not
       only unresolved ones; (b) any `start`, registry adoption, or recovery
       action touching a container created under a duplicate-watched
       `operation_id` first re-queries that label to confirm it still
       matches exactly one live object before proceeding; (c) if a second
       match ever appears — even long after the original retry succeeded —
       *all* matching candidates are quarantined (not just flagged for
       later, and never auto-picked by generation or registry presence) and
       the workspace re-enters `AMBIGUOUS`/held pending human resolution.
       **No fixed watch duration, and not tied to ordinary tombstone GC
       either — round 16 correction, closing round 15's M1, which correctly
       found round 15's "tie it to tombstone GC" fix still had an implicit,
       unproven expiry**: round 15 removed the invented "duplicate-watch
       window" but then tied the watch's lifetime to the existing tombstone
       GC schedule — round 15's own review caught the remaining flaw: GC
       only reasons about containers that already exist; it says nothing
       about a *delayed* original `create` that hasn't landed yet and might
       still create a container *after* the watched entry has already been
       GC'd. Tombstone GC is therefore not a safe proxy for "this duplicate
       risk is over," and this document must not claim it is. **Fix**: the
       duplicate-watch metadata for a retried `operation_id` is **never
       removed by ordinary time-based tombstone GC**. It is removed only
       when the same request-finality evidence tier 2 above requires for
       `start`/`stop` is available for the original delayed attempt (proof
       it terminated, or that its origin host/daemon is positively known to
       be gone) — or, failing that, it is retained permanently, with the
       honest fallback stated plainly: past whatever point an operator
       judges further permanent retention impractical, this design does not
       pretend to guarantee detection any longer, and says so explicitly
       rather than implying tombstone GC quietly closed the risk. This
       remains acceptable at `create`'s risk level (an idle orphan, not an
       active safety violation) precisely because the cost of getting this
       wrong is bounded low, unlike `start`/`stop` below.
     - **For `start`/`stop`**: `AMBIGUOUS` never resolves off elapsed time,
       full stop — **round 15 correction, closing round 14's H1, which
       correctly found round 14's own "quiescence window" conflated two
       different things Docker does not actually equate**: round 14 treated
       Docker's `stop` grace period (`-t`/`--time` — the wait between
       sending the stop signal and force-killing the container) as if it
       bounded the *entire* end-to-end delay from "proxy sent the request"
       to "daemon finished handling it." It does not — that grace period
       only starts once the daemon's handler has already begun executing
       the stop; nothing bounds how long a request might sit unprocessed
       before that (network delay, daemon load, a blocked handler), and
       Docker gives no API to observe or bound that separately. A `start`
       has no equivalent Docker-native bound at all — round 14's "deployment
       operational bound" for it was an assumption, not a guarantee, however
       it was worded. **Round 15 stops asserting a timer can prove this and
       resolves ambiguity with two honest tiers instead**:
       1. **Transport-level "never delivered" evidence resolves immediately,
          no waiting required — narrowed in round 16, closing round 15's H1,
          which correctly found the round-15 version too permissive**: round
          15 accepted "connection reset before full send, zero response
          bytes" as proof the daemon never received the request — but a
          transport-layer acknowledgment only confirms the *network stack*
          received bytes, not that the Docker application handler didn't
          already accept, queue, or begin processing them before the
          connection dropped; an HTTP client's ordinary send error does not,
          in general, guarantee that. The bar is narrower: this tier applies
          **only** when the client can positively prove either (a) the
          connection to the daemon was never established at all before the
          attempt failed, or (b) the client/proxy can reliably demonstrate
          that *zero request bytes* were ever delivered onto an established
          socket (a guarantee an ordinary HTTP client library does not
          provide by default — this requires the proxy's transport layer to
          be built to expose it, not assumed present). Anything short of
          this — including "connection reset, no response seen," which
          round 15 wrongly treated as sufficient — goes to tier 2 below, not
          `NOT_APPLIED`. **Deployment note, added in round 17**: with an
          off-the-shelf Docker client library (e.g. `docker-py`, built on
          `requests`/`urllib3`), condition (b) is not achievable without
          custom transport-layer instrumentation — standard libraries expose
          only request/connection exceptions, not a per-request
          byte-delivery ledger, and their own internals acknowledge that a
          send failure doesn't rule out the daemon having already responded.
          So in a deployment using an off-the-shelf client without that
          added instrumentation, this tier in practice only ever covers
          condition (a) — a failed *new* connection attempt — and every
          ambiguity on an established or pooled connection routes to tier 2.
          This is not a defect in the design (the two-tier structure is
          still correct and the narrower tier still has real value for new
          connections), but it is worth stating plainly rather than implying
          a wider practical scope than most deployments will actually get.
       2. **Otherwise — the request may have reached the daemon — there is
          no formulaic completion barrier, and this document does not
          invent one it cannot back.** Resolution requires genuine
          out-of-band human investigation, and **the investigation's release
          predicate is precise, not merely "a confident answer" — round 16
          correction, closing round 15's H1's second gap**: confirming what
          state the container is or was in is necessary but not sufficient.
          The investigation must establish one of:
          - the specific old request has *itself* terminated, with its final
            effect (if any) known — not merely that the container was
            observed in some state at some point, since an old `stop`
            handler that hasn't yet sent its signal can still act after an
            operator's inspection said otherwise (exactly round 14's
            counterexample, which a bare "container looks fine now" check
            does not rule out); or
          - the daemon or host has been isolated or restarted such that all
            of that old request's handlers, queued work, and connections are
            positively known to no longer exist.
          Evidence sources are unchanged (host-level process/log inspection,
          daemon logs, any independent audit trail available) but they must
          be applied to prove one of the two predicates above, not merely to
          observe current container state. If the investigation cannot
          establish either, the intent **stays `AMBIGUOUS` and the workspace
          remains fail-closed indefinitely** — a real, named limitation of
          using Docker (never designed to expose idempotent, queryable
          operation tracking for `start`/`stop`), not a gap papered over.
          Same honest category as this document's unreachable-daemon
          `STOP_STATE_UNKNOWN` case, extended to cover a reachable daemon
          whose specific past request's fate still can't be established.
       3. **Outcome mapping is three-way, not a blanket `NOT_APPLIED` —
          round 17 correction, closing round 16's H1, which correctly found
          "request terminated with known effect" collapsed two different
          outcomes (no effect vs. successfully applied) into one wrong
          classification, and skipped cross-checking that effect against
          current reality**: tier 1's transport evidence, or tier 2's
          request-termination predicate with a *no-effect* known outcome,
          converges to `NOT_APPLIED`. Tier 2's request-termination predicate
          with an *applied* known outcome converges to `APPLIED` **only**
          after a fresh `docker inspect` of the immutable container ID,
          taken inside the same locked section, confirms the intended
          postcondition still holds — if it doesn't (the investigation and
          the current reality disagree), the intent stays `AMBIGUOUS`/held
          rather than trusting either source alone. The full state
          machine — including this three-way split, applied uniformly with
          `create`'s own rules — is given as a single normative table below;
          this paragraph and that table describe the same rules, not two
          independent ones.
  6. Multiple matching objects found (the `create` case above) → an
     invariant violation, not a branch to auto-resolve — escalate to
     maintenance/human inspection, never auto-pick one.
  7. Only after the intent reaches `RECONCILED` does the workspace leave
     reconciliation-only mode and accept new mutations or a takeover CAS.
  8. **Schema split, correcting a real conflict round 13 introduced —
     round 14, closing round 13's M2**: round 13 said `operation_id` was
     both globally `UNIQUE` *and* reusable across retry attempts of the same
     logical operation — those two claims directly contradict each other; a
     retry's `INSERT` would be rejected by its own predecessor's row. The
     fix separates *logical* identity from *physical attempt* identity:
     - `operation_id` — the value written into the Docker label — identifies
       the **logical operation** and is reused, unchanged, across every
       retry attempt of it. It is *not* globally unique at the database
       level; uniqueness at this layer isn't the invariant that matters (the
       duplicate-watch mechanism above is what actually guards it).
     - `intent_attempt_id` — a freshly generated, globally `UNIQUE` value
       per row — identifies this specific attempt for DB bookkeeping. Each
       retry is a new row with a new `intent_attempt_id` but the same
       `operation_id`.
     - Two further columns are also kept separate, not conflated into one
       `state` field: `outcome_classification` and `gate_state`
       (`PENDING | RECONCILED`, whether this attempt still blocks new
       workspace activity). **Value domain corrected — round 15, closing
       round 14's M2, which correctly found `outcome_classification`'s
       listed values (`APPLIED | NOT_APPLIED | AMBIGUOUS`) excluded
       `PREPARED`, the very value transaction A's insert requires as the
       initial row state**: `outcome_classification` is
       `PREPARED | APPLIED | NOT_APPLIED | AMBIGUOUS`, matching the state
       machine below exactly — a row is created `PREPARED`, and every
       later value is a transition from it, never a value the schema itself
       forbids on insert. The partial unique index enforcing "at most one
       unresolved intent per workspace" is scoped on `gate_state =
       'PENDING'`, keyed by `workspace_id` — a new attempt row's `gate_state`
       starts `PENDING`, so a prior *terminal* attempt (`gate_state =
       'RECONCILED'`, regardless of its `outcome_classification`) never
       blocks it.
     - **State machine — this is the single normative table; the
       transitions given earlier alongside the transport/investigation
       tiers describe the same rules, not a competing set — round 17
       correction, closing round 16's M2, which correctly found this table
       still said "create only" and "quiescence-gated" after round 16
       introduced an evidence-gated `start`/`stop` path elsewhere in the
       document without updating this table, leaving two contradictory
       normative sources**:
       `outcome_classification`: `PREPARED → {AMBIGUOUS, APPLIED,
       NOT_APPLIED}` — **round 18 correction, closing round 17's M1**: a
       direct `PREPARED → NOT_APPLIED` transition (not routed through
       `AMBIGUOUS` first) is valid specifically for tier 1's transport proof
       above, since that evidence is conclusive at request time and doesn't
       need an intermediate ambiguous state to later resolve out of.
       `AMBIGUOUS` transitions depend on operation kind and evidence, not a
       single rule:
       - **`create`**: `AMBIGUOUS → APPLIED` if reconciliation finds exactly
         one matching object; `AMBIGUOUS → NOT_APPLIED` after the
         retry/backoff barrier finds none (the *only* timer-gated path to
         `NOT_APPLIED` in this design); otherwise stays `AMBIGUOUS`.
       - **`start`/`stop`**: never timer-gated. `AMBIGUOUS → NOT_APPLIED`
         **only** when the investigation establishes the old request's known
         effect was *no effect* (it terminated without applying) — round 16
         wrongly collapsed this and the "applied successfully" case into one
         blanket `NOT_APPLIED` outcome, corrected here per round 16 review's
         H1. `AMBIGUOUS → APPLIED` when the investigation establishes the
         old request's known effect *was* applying its intended change
         **and** a fresh `docker inspect` of the immutable container ID,
         performed inside the same locked section as this transition,
         confirms that postcondition still holds. **If the investigation's
         known effect and the fresh inspect disagree** (e.g. investigation
         says the old `stop` completed, but inspect shows the container
         running) **the intent stays `AMBIGUOUS`/held — the contradiction
         itself is not resolved by picking one source over the other**; it
         requires further investigation (a `restart policy` firing, a
         separate host-level action, or a timeline error in the original
         investigation are all real possibilities this design does not
         attempt to distinguish automatically). Otherwise stays `AMBIGUOUS`.
       `gate_state` moves `PENDING → RECONCILED` only when
       `outcome_classification` reaches a terminal value under the rules
       above (`APPLIED` for either operation kind meeting its condition, or
       `NOT_APPLIED` under its kind-specific rule) — and this transition,
       together with any registry/container-lifecycle-state update the
       outcome implies, commits in the **same database transaction** as the
       `outcome_classification` write and the fresh-inspect read that
       justified it, all inside the same workspace-lock critical section —
       so there is no window where classification, registry state, and gate
       clearance disagree with each other. Both columns are DB-enforced
       (`CHECK` constraints or native enums), not documented conventions.
  This is deliberately not round 8's retired full operation-slot state
  machine — it is one narrow, DB-enforced gate applied only to the single
  possible unresolved intent a workspace can have at a time, triggered by
  lock re-acquisition. **Durable retry scheduling — closes round 12's M3,
  which correctly found "retry later" had no defined executor**: the intent
  record carries a persisted `next_retry_at`. Any subsequent lock
  acquisition for the workspace (a new mutation attempt, a takeover, or an
  admin action) checks and advances reconciliation if due — but a workspace
  with no further incoming requests must not simply stay silently stuck
  forever, so a background reconciliation worker (not a new architectural
  component — the same kind of periodic pass this design already needs for
  registry health-checking elsewhere) also drives this on a cadence, a
  tuning parameter left as a deployment detail. **The background worker is
  bound by the same rules as every other actor, made explicit per round
  13's M3, which correctly found "also drives this" left the worker's
  obligations only implied**: it acquires the identical per-workspace
  advisory lock (through the same lock-guard helper used everywhere else in
  this design, never a separate unlocked path), performs its fresh re-read
  and evidence-gathering inside that locked section, and completes its
  transaction before releasing — it is simply another legitimate
  lock-acquiring actor, with the same obligations as a takeover or mutation
  attempt, not a privileged background process that bypasses the fencing
  discipline this entire design exists to enforce. Past a defined number of
  failed reconciliation attempts, the system alerts — but never
  auto-abandons the gate for the sake of availability; fail-closed is
  preserved regardless of how long reconciliation takes.
  **Partial unique constraint, corrected syntax per round 12's M2, corrected
  column per round 14's M2**: this is
  a `CREATE UNIQUE INDEX ... ON intent (workspace_id) WHERE gate_state =
  'PENDING'`, not a `UNIQUE(...) WHERE` table-constraint clause (which
  PostgreSQL doesn't accept in that form) and not keyed on a single
  conflated `state` column (see the schema split above).
- **Fresh re-read given an explicit isolation/snapshot requirement — closes
  round 11's M1**: "re-read the authoritative row fresh" (above) means a
  `SELECT` executed in a **new transaction or statement begun only after the
  lock is acquired** — under this project's existing Read Committed
  default — not a query that happens to be written later in the code but
  executes inside a transaction opened before the caller began waiting for
  the lock. A caller that opened a Repeatable Read transaction before
  queuing for the lock and then issued a plain `SELECT` after acquiring it
  could otherwise still observe a stale snapshot from before the lock was
  granted, defeating the re-validation rule's purpose. Implementations must
  treat "begin the re-read transaction after lock acquisition" as an
  acceptance-test-verified requirement, not an incidental code-ordering
  detail.
  Resolved intents are retained as an audit trail subject to the same
  tombstone GC policy already flagged as a tuning/deployment detail
  elsewhere in this document.
- **`docker stop`/`docker start` reordering — closes round 10's confirmation
  that this only worked "when granularity matched"; wording corrected in
  round 18, closing round 17's M1, which found this sentence still
  referenced the retired quiescence-window mechanism**: because the *next*
  mutation for a workspace cannot even attempt to acquire the lock until the
  current one's outcome transaction has committed, a stale `stop` cannot
  land after a subsequent `start` *provided* that commit only happens once
  the operation's true outcome is actually known — which, for an `AMBIGUOUS`
  `start`/`stop`, means only after tier 1's transport proof or tier 2's
  evidence-gated human investigation above resolves it, not merely once a
  database transaction happens to commit. There is no dequeue-time re-check
  to bypass, because there is no speculative dequeuing at all; the
  guarantee's strength is
  exactly the strength of that confirmation step, not a claim independent of
  it.
- **Hung lock holder — fail-closed, never a blind `pg_terminate_backend()` —
  closes round 10's H4; the isolation step made verifiable per round 11's
  H2, which correctly found "SIGKILL it or revoke its socket access" were
  illustrative examples, not conditions an operator or automation could
  actually check**: round 10 left "how long before this is a fault" as a
  bare tuning parameter — killing only the *database* session of a
  stuck-but-not-actually-crashed proxy releases the lock while the proxy
  process might still be alive and eventually issue the very call the lock
  was supposed to prevent. Past a defined maximum hold duration, the system
  alerts and the workspace enters an explicit held/maintenance state (no new
  work is accepted regardless — the lock already guarantees that). The fixed
  order — first make the old proxy structurally incapable of acting, *then*
  release the lock — is unchanged, but each step now has a checkable
  condition, not an example:
  1. **Confirm process death, not signal delivery**: `kill()`/`SIGKILL`
     returning success only means the signal was delivered — it is not
     proof of death, and is vulnerable to PID reuse. The runbook requires
     confirming exit via an unambiguous process identity (PID plus start
     time, or supervisor/cgroup-reported inactive status) and an actual
     `waitpid()`-style exit confirmation or the supervisor's own
     authoritative "stopped" state — not merely that a kill signal was
     sent.
  2. **Revoking Docker socket permissions does not close existing file
     descriptors or already-established connections**: if the process
     cannot be confirmed dead (step 1 fails or is inconclusive), permission
     revocation going forward is not sufficient by itself — the runbook must
     also force-terminate the process's existing Docker socket connections
     at a layer the process itself cannot bypass (killing the established
     connection at the daemon/OS level, not just editing filesystem
     permissions for future connection attempts).
  3. **Slack egress isolation is best-effort UX hygiene, not a safety
     claim — corrected in round 13, which found round 11's wording implied
     it was part of the same completion barrier as Docker, while this
     document elsewhere states Slack outbound calls get no durable intent
     at all**: revoking/rotating the proxy's Slack bot token centrally
     reduces the chance of a duplicate late status message, consistent with
     this document's already-stated, deliberate asymmetry (a duplicate Slack
     status message is a UX blemish, not a governance-safety violation,
     since no Slack call here causes an approval/execution outcome by
     itself). It is not claimed to prove an already-accepted Slack request
     cannot still complete — no such proof is needed for this class of
     call, unlike Docker mutations.
  4. **Process death alone does not prove an already-accepted Docker request
     is fenced — round 13 correction, per round 12's review**: confirming
     the old process/cgroup is dead only proves it can't issue *new*
     requests — it says nothing about a Docker `create`/`start`/`stop`
     request the daemon had *already accepted* before death, which can
     still complete independently of the process that sent it. This design
     does not claim otherwise. The actual fencing for that case is the
     crash-recovery gate protocol above: whether the old holder is
     confirmed dead or merely isolated, the workspace stays in the held
     state and the intent's kind-specific reconciliation rule (`create`'s
     bounded-orphan-risk timer, or `start`/`stop`'s mandatory human
     confirmation reusing the `STOP_STATE_UNKNOWN` runbook) is what actually
     clears the gate — process-death confirmation and egress isolation
     reduce the chance of *new* interference during that reconciliation, they
     are not themselves the completion proof.
  5. **Sufficient condition for isolation, stated plainly**: either (a) the
     specific process/cgroup is confirmed to no longer exist, or (b) if
     death cannot be confirmed, its Docker socket connections have been
     force-isolated at a layer it cannot bypass — not merely "a permission
     was changed for future attempts." Neither condition, by itself, permits
     skipping the reconciliation step above.
  6. **Deployment topology affects what "confirmed dead" can mean, named
     explicitly rather than left implicit**: bare metal can use a systemd
     unit/cgroup, `pidfd`, or a supervising parent's own `wait()`; a
     containerized proxy should key off the container's own immutable ID
     plus the container runtime's exited/stopped status and cgroup
     disappearance — a PID observed *inside* a container is not a host
     process identity and must not be used as one; a VM-based deployment can
     use the hypervisor/provider's VM power-state as the outer authority.
     **If a given deployment can provide none of these** and also can't
     force-isolate all relevant egress at a layer the process can't bypass,
     the correct outcome is that this workspace's hung holder **cannot be
     safely resolved automatically at all** and remains fail-closed pending
     manual, out-of-band intervention — this is a real limitation of that
     deployment topology, not a gap in this design to paper over with a
     weaker check.
  7. **The maintenance/held state is a durable DB column, not implied — round
     14 correction, closing round 13's L1, which correctly found the prior
     wording only said "stays in the held state" without ever defining
     where that state actually lives**: the workspace registry row (the
     same row `workspace_id` uniquely identifies for ownership/epoch, above)
     carries a `hold_state` column (`NONE | HELD`, DB-enforced via `CHECK`).
     It is set to `HELD` in the same transaction that begins the hung-holder
     runbook (past the maximum lock-hold duration). Every claim, takeover,
     and mutation entry point, after acquiring the workspace lock and
     performing its fresh re-read, must also check this column and refuse
     to proceed while it reads `HELD` — this is the same kind of
     DB-enforced gate as the pending-intent check above, not a separate,
     weaker convention. **Two distinct clearance paths — round 15
     correction, closing round 14's M3, which correctly found the prior
     wording had only one clearance rule (tied to a pending intent
     reconciling) and no path at all for a hung holder that got stuck
     *before* ever creating one**: a hung holder isn't always mid-Docker
     mutation — it might have died while acquiring the lock and doing its
     fresh re-read, mid-ownership-claim/takeover CAS, or between acquiring
     the lock and transaction A's commit, none of which leaves a pending
     intent behind. So:
     - **Path A (pending intent exists)**: `HELD → NONE` commits in the same
       transaction that transitions that intent's `gate_state` to
       `RECONCILED`, as before.
     - **Path B (no pending intent exists)**: after completing the same
       hung-holder isolation steps already required above (confirmed
       process death, or full egress isolation), an administrative action —
       itself holding the workspace lock — performs a fresh re-read that
       positively confirms no pending intent exists for this workspace, and
       clears `HELD → NONE` in that same locked transaction. This is a
       distinct, independently valid clearance path, not a variant of Path
       A, and carries the same evidence-recording requirement (operator
       identity, timestamp, confirmation method) as the `STOP_STATE_UNKNOWN`
       runbook elsewhere in this document — an audited administrative act,
       not a bare status flip.
  A Docker call that times out from the client side always lands in a
  pending-intent or `STOP_STATE_UNKNOWN` classification, never "treated as a
  definite failure" — the call may still land at the daemon after the
  client gave up waiting.
- **Physical connection pinning and pooling — closes round 10's H5**: the
  lock, the intent commit, the Docker/Slack call, the outcome commit, and
  the unlock all execute on one pinned physical PostgreSQL connection for
  the duration — never returned to a shared application connection pool
  mid-sequence. This code path must not go through PgBouncer (or equivalent)
  in transaction- or statement-pooling mode, since those modes return the
  server connection to the pool between statements and are explicitly
  documented as incompatible with session-level features; it connects
  directly to Postgres, or through a pooler configured for session pooling
  with the client connection held for the whole operation. The singleton
  lock (below) needs its own separate dedicated long-lived connection for
  the same reason. All contending processes must connect to the same
  Postgres database, since advisory locks are database-local. If the
  connection or the database itself is lost involuntarily (failover,
  restart), the proxy treats this as having lost all its locks
  unconditionally and re-initializes from scratch — it never assumes
  continuity of anything it believed it held before the loss.
- **Exactly-one-proxy, including the connection-loss gap round 10 left open
  — closes round 9's H2 and round 10's M1**: on startup, the proxy acquires
  a second, fixed-key advisory lock (namespaced separately from any
  workspace key, see below) on its own dedicated long-lived connection,
  held for its process lifetime; a second instance's `pg_try_advisory_lock`
  fails immediately and it refuses to run. **If this dedicated connection
  itself drops while the proxy process is still alive** (round 10 didn't
  address this): the proxy must detect the loss and immediately stop
  accepting new UDS requests and cancel not-yet-started work — it may not
  silently open a new connection, reacquire the singleton lock, and keep
  running as though nothing happened, since doing so would let it resume
  under a fresh identity while still trusting in-memory state acquired
  under the old one. It must go through full re-initialization instead.
- **Lock key mapping made concrete — closes round 10's M2**: keys use
  PostgreSQL's signed-64-bit single-key advisory lock form. Each key is
  derived by hashing a canonical, versioned, fixed-format string (e.g.
  `f"ohs-workspace-lock:v1:{workspace_id}"` for a workspace lock,
  `"ohs-proxy-singleton:v1"` for the singleton lock — distinct namespace
  prefixes before hashing) through a documented, cross-language-stable
  algorithm (a standard cryptographic hash folded to 64 bits) — never a
  language runtime's built-in `hash()`, which is not guaranteed stable
  across processes or restarts. Collision between two different keys
  mapping to the same lock is accepted as the hash function's own
  astronomically small probability at this deployment's scale (it would
  cause unnecessary blocking, not a security bypass) rather than engineered
  away with a perfect scheme.
- **Reentrancy and monitoring discipline — closes round 10's M4**: Postgres
  session-level advisory locks are reentrant (a session can re-acquire the
  same key and must call unlock the same number of times) — the
  implementation must go through a single, well-tested lock-guard helper
  used everywhere in the proxy's code, never ad hoc acquire/release calls,
  to avoid an accidental nested acquire silently leaking a hold count.
  Operationally, `pg_locks` is monitored for these keys' holder backend and
  hold duration, feeding the same alerting the hung-holder runbook above
  depends on.
- **Outbound Slack calls — split from inbound dedup (unchanged from round
  9/10)**: inbound duplicate delivery is §6b's `event_id` check-and-set,
  unrelated to this lock. Outbound governance-relevant Slack calls (status
  messages) acquire the same workspace lock for ordering consistency but
  get no durable intent record in v1 — a duplicate status message on retry
  is a UX blemish, not a safety violation, since no Slack call here causes
  an approval/execution outcome by itself.
- **Epoch/generation-labeled containers (unchanged from round 9/10, M2's
  completeness request already met)**: every container is labeled with
  `workspace_id`, `user_id`, and the generation it was created under; a
  missing, malformed, or inconsistent label is treated as a superseded
  container, never promoted to `READY`; reconciliation always uses
  immutable container IDs, never reusable names.
- **UDS caller authorization — closes round 9's H5; round 10's residual
  same-UID limitation (M3) accepted explicitly, with mitigations, not left
  silent**: filesystem permissions restrict the socket to a dedicated
  adapter service account; `SO_PEERCRED` (Linux-specific, flagged as such)
  checks the connecting UID; every request also carries a per-claim owner
  token from the ownership row (not epoch alone), generated by the proxy
  itself with sufficient entropy, never placed in argv/environment
  variables/logs, and rotated on **every** takeover *and* on a clean
  voluntary handoff (round 9 left the latter case unspecified — round 11
  states it explicitly: rotation is not crash-triggered only). The proxy
  never includes one workspace's data in a response to a caller
  authenticated for a different workspace. **Accepted as a named v1
  limitation, not solved here**: all adapter processes share one OS service
  account, so this does not provide true isolation between two adapters
  compromised independently of each other — full separation would need
  distinct UIDs or an equivalent OS credential per workspace, deferred as a
  hardening item for a larger multi-tenant deployment, not needed at this
  deployment's single-operator scale.
- **Manual `STOP_STATE_UNKNOWN` resolution — same lock, no special case**:
  the admin action acquires the same workspace lock, performs a fresh
  `docker inspect` inside that locked section, and only then applies the
  CAS with the freshly observed state in its predicate. The CAS itself does
  not "reach into" Docker — the safety argument is the lock preventing
  anything else from acting on this workspace between the inspect and the
  CAS, combined with `restart_policy=no` and immutable-ID-based
  reconciliation.
- **"Only component permitted" enforced, not declared (unchanged from round
  10)**: the adapter's OS account has no Docker socket access; only the
  proxy's service account does. The adapter holds only Slack's app-level
  token (inbound); the bot token (outbound) lives only in the proxy.
- **Wording correction — closes round 10's L1**: "connection death is
  faster and more reliable than the heartbeat timeout" overstated a general
  guarantee. Corrected: on ordinary process termination, connection death is
  typically detected quickly; the actual upper bound depends on driver
  behavior, TCP keepalive configuration, and infrastructure setup, and is
  not itself a proven guarantee this document can assume without measuring
  it in the target deployment.
- **Cost, unchanged**: still a real infrastructure component and a single
  point of failure, fail-closed by design, accepted at this deployment's
  scale, flagged for re-evaluation before any multi-host deployment.

### Explicitly still open

- **Implementation acceptance criterion (round 6)**: a targeted
  crash-injection test — kill the process between writing `CLAIMED` and the
  tool call actually starting, restart, verify no double execution — must
  pass before the eviction-eligibility rule's safety claim can drop its
  qualifier. Not assumed passing; not deferred as unknowable either.
- **Heartbeat/staleness invariants (round 6's M1) — relationships specified,
  exact numbers left as deployment config**: heartbeat interval must be
  clearly smaller than the staleness threshold (e.g. no more than a third of
  it, to tolerate a couple of missed beats before false-positive takeover);
  heartbeat timestamps must be read from the database server's clock, not
  the adapter host's, to avoid clock-skew-induced false staleness; a defined
  tolerance for transient heartbeat-write failures (not every single missed
  write should trigger self-shutdown); an owner that fails to renew past
  that tolerance must self-stop rather than continue operating on a lease it
  can no longer prove it holds; and the threshold must be chosen wide enough
  to cover realistic GC pauses, DB failover windows, and scheduler delays —
  exact seconds are a tuning decision, but these relationships are not.
- ~~Rejection-reconciliation ID schema~~ — **decided in round 8**:
  `action_event_id` is the canonical correlation key, 1:1 cardinality, no
  match on missing/unparseable IDs (see the outbox-termination section
  above). No longer open.
- Full OS-enforced elimination of the drain-marker forgery risk (UID/GID or
  mount-namespace separation between agent-server and spawned tool
  subprocesses, or an external supervisor independent of in-container state)
  — v1 ships with credential-redaction/accidental-interference hygiene only,
  explicitly not a closed trust boundary (see above). **Scoped precisely
  (round 8, closes round 7's M3 — the prior wording overclaimed that
  `STOP_STATE_UNKNOWN` fully absorbs this risk)**: the `STOP_STATE_UNKNOWN`
  split protects against the *double-write* risk (two live writers on one
  volume) regardless of marker forgery — that guarantee holds even if a
  marker is fully forged, because it never depends on trusting the marker at
  all. It does **not** protect against a narrower, separate
  *data-consistency* risk: a forged marker could make an actually-unclean
  drain look clean (missing final flushed writes), causing the system to
  skip `STOPPED_UNCLEAN`'s recovery-mode reconciliation when it was actually
  needed — a correctness gap in what gets recovered, not a safety gap in
  who's allowed to write. This residual is accepted as part of the same
  "not an OS-enforced trust boundary" limitation already flagged, not a new
  unresolved item, but it is now named explicitly rather than left implied
  as fully covered.
- Tombstone GC policy and the full registry-vs-Docker-reality reconciliation
  classification table beyond the `STOPPED_UNCLEAN`/`STOP_STATE_UNKNOWN`
  triggers now specified.
- Key custody (root protection, access boundaries, rotation, backup/unbind
  policy) — unchanged from round 4, still open.
- Tuning parameters: idle-timeout duration, warm-pool size, reconciliation
  cadence, bounded-wait deadline during `DRAINING`, exact heartbeat interval
  and staleness threshold values (relationships specified above).
- ~~The proxy's own exactly-one-instance mechanism~~ — **decided in round
  10, connection-loss gap closed in round 11**: a fixed-key
  `pg_try_advisory_lock` held for the process's lifetime, plus full
  re-initialization (not silent reacquisition) if that dedicated connection
  drops. No longer open.
- ~~Owner-token rotation on clean handoff~~ — **decided in round 11**:
  rotation happens on every takeover *and* every clean voluntary handoff,
  not crash-triggered cases only. No longer open.
- **Remaining from round 10, still open**: the exact maximum lock-hold
  duration before a workspace is treated as having a hung holder (round 11
  specifies the *fail-closed runbook* for handling this, but not the
  specific number — needs a bound tied to realistic Docker call latency,
  measured rather than assumed). The `SO_PEERCRED` UDS mechanism remains
  Linux-specific; a non-Linux deployment target needs an equivalent, not
  designed here. Proxy process supervision (restart policy, health check)
  beyond the advisory-lock-based singleton guarantee is still a deployment
  detail.
- **New in round 11**: full UID-level isolation between different
  workspaces' adapter processes (all currently share one OS service
  account, per the accepted M3 limitation above) is deferred to a future,
  larger multi-tenant deployment, not built for v1. The specific
  cryptographic hash algorithm and bit-folding scheme for deriving advisory
  lock keys from their canonical string form is named as needing a concrete
  choice at implementation time (a documented, cross-language-stable
  standard hash), not fully pinned down in this document.
- ~~Crash-recovery gate for an unresolved intent~~ — **decided in round
  12**: explicit intent state machine, DB-enforced partial unique
  constraint, and mandatory reconciliation-only mode for any new lock
  holder; see above. No longer open.
- ~~Hung-holder isolation criteria~~ — **decided in round 12, corrected in
  round 13**: verifiable process-death confirmation and Docker egress
  isolation, not illustrative examples. **Round 13 correction**: this is
  isolation to reduce interference during reconciliation, not itself proof
  that an already-accepted Docker request won't complete (that's the
  crash-recovery gate's job); Slack egress isolation is restated as
  best-effort UX hygiene consistent with Slack's accepted asymmetric
  treatment, not a safety-critical completion proof. No longer open.
- **Remaining from round 12**: the specific reconciliation retry/backoff
  barrier duration for `create`'s `NOT_APPLIED` timer, and the background
  reconciliation worker's polling cadence, are tuning parameters — need to
  be measured against realistic Docker daemon responsiveness, not assumed.
  The exact mechanism for confirming "supervisor/cgroup-reported inactive
  status" (e.g. which init system, what API) is left to the deployment's
  actual process-supervision choice, not designed here.
- ~~Provable completion barrier for external-call fencing~~ — **rounds
  13-15 each attempted or over-relaxed a formulaic answer (reusing
  `STOP_STATE_UNKNOWN`'s runbook too early in round 13; a "quiescence
  window" conflating Docker's stop grace period with end-to-end completion
  in round 14; an over-permissive transport-level shortcut and an
  under-specified investigation predicate in round 15); actually decided in
  round 16**: the transport-level shortcut is narrowed to only
  connection-never-established or provably-zero-bytes-delivered cases —
  everything else requires genuine out-of-band human investigation that
  must specifically prove the old request terminated with known effect, or
  that its origin host/daemon is positively confirmed gone, not merely that
  the container currently looks correct. If that can't be established, the
  workspace stays fail-closed indefinitely — an honest, named limitation of
  what Docker's API supports, not a gap papered over. No longer open.
- ~~Reconciliation evidence per operation kind~~ — **decided in round 13**:
  `create` uses the `operation_id` Docker label; `start`/`stop` use the
  intent's recorded immutable container ID plus a direct `docker inspect`
  for the intended postcondition. No longer open.
- ~~Durable retry executor for reconciliation~~ — **decided in round 13,
  lock-acquisition duty made explicit in round 14**: a persisted
  `next_retry_at` on the intent record, advanced by any subsequent lock
  acquisition for the workspace and by a background reconciliation pass
  that itself acquires the same per-workspace advisory lock (round 14
  closes round 13's M3, which found this only implied); alerts past a
  defined failed-attempt count without ever auto-abandoning the fail-closed
  gate. No longer open.
- ~~Durable duplicate-watch for retried `create` operations~~ — **decided in
  round 14; tombstone-GC tie-in found unsound in round 15 review and
  corrected in round 16**: any logical `operation_id` that was ever retried
  is flagged for duplicate-watch surviving past `RECONCILED`, checked by the
  background worker and by any later `start`/adopt/recovery action touching
  that operation, with all candidates quarantined (never auto-picked) if a
  second match ever appears. The watch is **never removed by ordinary
  time-based tombstone GC** (round 15's attempt to tie it there was itself
  an unproven implicit expiry, since GC only reasons about containers that
  already exist, not a delayed `create` that hasn't landed yet) — it clears
  only on the same finality evidence `start`/`stop` requires, or is retained
  permanently with the limitation stated explicitly rather than implied
  closed by GC. No longer open.
- ~~`operation_id` uniqueness vs. retry reuse schema conflict~~ — **decided
  in round 14, `PREPARED` value-domain gap closed in round 15,
  `start`/`stop → NOT_APPLIED` transition added in round 16, three-way
  outcome mapping and single normative table reconciled in round 17**:
  `operation_id` (logical, reused across retries) is split from
  `intent_attempt_id` (physical, globally unique per row);
  `outcome_classification` (`PREPARED | APPLIED | NOT_APPLIED | AMBIGUOUS`)
  is split from `gate_state` so the partial unique index scopes correctly
  to "unresolved," not "any prior attempt." For `start`/`stop`,
  `AMBIGUOUS` reaches `NOT_APPLIED` only on a proven no-effect outcome, and
  `APPLIED` only when a proven applied-effect outcome is *also* confirmed by
  a fresh inspect — a disagreement between the two leaves it `AMBIGUOUS`.
  No longer open.
- ~~Held/maintenance state's persistence~~ — **decided in round 14,
  no-pending-intent clearance path added in round 15**: a named
  `hold_state` column on the workspace registry row, checked by every
  claim/takeover/mutation entry point after acquiring the lock, with two
  independently valid clearance paths (via a pending intent's own
  reconciliation, or via an audited administrative action confirming none
  exists). No longer open.
- ~~§9's availability-cost disclosure~~ — **decided in round 16, closing
  round 15's L1**: §9's cost paragraph now states, as its own sentence, that
  Track 2 v1 is not fully self-healing — an ambiguous `start`/`stop` failure
  can take an individual workspace out of service indefinitely pending
  privileged human investigation, not merely a generic
  infrastructure-component/SPOF cost. No longer open.
- **New in round 16**: how an operator actually conducts the out-of-band
  investigation required to resolve an `AMBIGUOUS` `start`/`stop` intent
  (which logs, which independent audit trail, what counts as sufficient
  proof of termination in a given deployment's tooling) is not standardized
  here, since it will necessarily vary by deployment. `remove` and any other
  Docker operation kinds beyond `create`/`start`/`stop` remain uncovered by
  this reconciliation design, flagged so a future operation kind isn't
  silently assumed to fit an existing pattern without checking.
- ~~Three-way outcome mapping for evidence-gated `start`/`stop`~~ —
  **decided in round 17, closing round 16's H1**: a proven no-effect old
  request converges to `NOT_APPLIED`; a proven applied-effect old request
  converges to `APPLIED` only if a fresh inspect (same locked section)
  confirms it; a disagreement between the two stays `AMBIGUOUS`/held for
  further investigation, never auto-resolved by trusting one source. No
  longer open.
- ~~Single normative state-machine table~~ — **decided in round 17, closing
  round 16's M2; last two sync gaps closed in round 18**: the document's
  one formal state-machine definition states the three-way `start`/`stop`
  mapping and `create`'s timer-gated path directly. Round 17 review found
  two residual sync issues (the table's first transition omitted the direct
  `PREPARED → NOT_APPLIED` path tier 1 uses, and one sentence still named
  the retired "quiescence-window-gated" mechanism) — both fixed in round 18.
  No longer open.
- **New in round 17**: an off-the-shelf Docker client library (e.g.
  `docker-py`) cannot satisfy tier 1's "zero request bytes delivered to an
  established socket" condition without custom transport instrumentation
  this document doesn't design — in practice, most deployments will only
  ever use tier 1 for new-connection failures, with everything else routing
  to tier 2's human investigation. This is disclosed as a deployment note,
  not treated as a design defect, since the two-tier structure itself
  remains correct.

**Round 18 confirmation review: 0 Critical, 0 High, 0 Medium, 0 Low —
§5a judged IMPLEMENTATION-READY.** The reviewer confirmed both sync fixes
landed correctly and re-verified the full mechanism end to end (lock
granularity, post-lock re-read, durable intent commit ordering, the
pending-intent crash-recovery gate, the three-way `start`/`stop` outcome
mapping, hung-holder isolation, permanent duplicate-watch, and `hold_state`
clearance) with no regression of any issue closed in earlier rounds.
Explicit caveat from the reviewer: "implementation-ready" means the spec is
sufficient to begin implementation — it does not mean acceptance tests have
been run or that this is production-ready. Items intentionally left as
deployment/tuning decisions, not blockers: key custody/rotation/backup
policy; the concrete tombstone GC and full registry-vs-Docker reconciliation
policy; exact heartbeat/staleness/idle-timeout/lock-hold/retry-backoff/
polling-cadence values; the crash-injection acceptance test itself (design
only, not yet run); full OS-level trust-boundary isolation for the drain
marker; cross-workspace UID isolation; a non-Linux `SO_PEERCRED` equivalent;
proxy supervision/health-check and deployment-specific process-death
verification; the specific advisory-lock key hash/bit-folding algorithm;
tier 1's narrow real-world coverage under common Docker client libraries;
tier 2's deployment-specific investigation SOP and audit format;
reconciliation rules for Docker operation kinds beyond
`create`/`start`/`stop`; the accepted risk that an inconclusive `start`/
`stop` can leave a single workspace fail-closed indefinitely; and the
proxy/PostgreSQL path remaining an accepted single point of failure. §4a's
OAuth token-binding/unbind lifecycle remains the one explicitly open,
not-yet-designed item elsewhere in this document — unaffected by this
verdict, which is scoped to §5a only.

## 6. Signature/security notes specific to Slack — DESIGNED (2026-09-23)

**Adapter topology, settled first because it shapes everything below**: a Slack
app's Socket Mode connection uses one app-level token per **workspace**
installation and receives events for the whole workspace over that single
WebSocket — Slack does not offer a per-user connection. So **the adapter is one
process per bound Slack workspace** (not per user), which then internally routes
each bound user's messages to *that user's own* dedicated agent-server process
(§5). Concurrency inside this single adapter process — many bound users'
messages arriving concurrently over one WebSocket — is exactly what §6b's
per-(user, thread) serialization has to handle; it doesn't go away just because
credential-sharing risk (Track 1's problem) is gone.

- Socket Mode has **no inbound webhook to verify** — the WebSocket connection is
  authenticated by the App-Level Token itself, so the `x-slack-signature` HMAC
  verification gap that bit OpenClaw's Slack plugin
  ([openclaw/openclaw#32599](https://github.com/openclaw/openclaw/issues/32599))
  does not apply to this design. **Confirmed correct by round 1 review** (Slack's
  own Socket Mode docs agree). The remaining items the reviewer flagged as
  necessary-but-undesigned are now designed:
  - **Bot's-own-messages/reply-loop prevention**: use Bolt Python's built-in
    `IgnoringSelfEvents` middleware (on by default) rather than hand-rolling this
    — but it does **not** catch messages sent via a `response_url`, per an open
    upstream Bolt issue, so any `response_url` usage in this adapter needs an
    explicit bot-id check as a supplement, not a replacement.
  - **`team_id`/`api_app_id` validation per event, workspace allowlist**: since
    the adapter is provisioned one-per-workspace (topology above), this
    collapses to a single equality check at the top of the event handler — the
    adapter knows which workspace it was installed for at startup (from its own
    config), and rejects/logs+drops any event whose `team_id`/`api_app_id`
    doesn't match, rather than trusting the WebSocket connection's one-time
    authentication as sufficient for every subsequent event.
  - **Independent app-level vs. bot token rotation**: no code-level design
    needed beyond *not coupling* the two — store and rotate them as
    independent secrets (standard secret-management practice, not a special
    mechanism); flagging so implementation doesn't accidentally bundle them.
  - **Reconnect handling**: Bolt's `SocketModeHandler` manages Socket Mode
    reconnection internally; the adapter's own responsibility is ensuring
    reconnect doesn't re-deliver already-ack'd envelopes as new work, which is
    exactly what §6b's `event_id`-based idempotency check (not envelope-level
    ack alone) is for — this is a documented real-world failure mode, not
    theoretical (see e.g. [a Socket Mode reconnect duplicate-delivery bug report](https://github.com/openclaw/openclaw/issues/50597)
    from an unrelated project, cited here only as evidence the failure mode is
    real, not as a pattern to copy).
- Session API key (used to call OHS agent-server) and the Slack Bot/App-Level
  tokens are three separate secrets; none of this design's code should hold real
  values — same "never hardcode a real endpoint/secret" lesson from the
  `agent-canvas-source` vLLM-domain incident (2026-09-23) applies here.

## 6b. Delivery, concurrency, and conversation-serialization design — DESIGNED
(2026-09-23)

The original v1 draft said "a plain key-value store is enough" for the
thread↔conversation-id mapping and stopped there. Round 1 review correctly called
this a storage engine, not a consistency contract. Concrete design:

**ACK and idempotency** (per [Slack's own Socket Mode docs](https://docs.slack.dev/apis/events-api/using-socket-mode/)):
- On receiving a Socket Mode envelope: extract `envelope_id` and send the
  protocol-level ack over the WebSocket **immediately**, before any business
  logic — Bolt Python's Lazy Listener pattern (§8) does exactly "ack now, run the
  real handler as a background task," so this falls out of the framework choice
  rather than needing bespoke plumbing.
- Separately, extract the inner Events API payload's **`event_id`** (not
  `envelope_id` — Slack's own docs specifically recommend `event_id` as the
  idempotency key) and do an atomic check-and-set against a durable "seen event
  ids" store *before* starting any work for that event. If already seen, drop it
  — this is what actually prevents duplicate processing, not the envelope-level
  ack alone. Failing to ack within 3 seconds triggers Slack's own retry (up to 3
  redeliveries, ~1 minute apart) — the Socket Mode request object exposes
  `retry_attempt`/`retry_reason` for events_api envelopes, useful for logging but
  not the authoritative dedup mechanism (that's the `event_id` check).
- TTL for the "seen event ids" store: comfortably longer than Slack's own retry
  window (a low double-digit number of minutes covers 3 retries at ~1-minute
  spacing with margin) — exact value is an implementation tuning detail, not a
  design decision.

**Per-(user, thread) serialization**: since one adapter process serves an entire
workspace (§6), maintain an in-process async lock (or a small task queue) keyed
by `(slack_user_id, thread_ts or channel_id)` — not globally, and not merely
per-workspace, since different bound users' conversations are already routed to
different agent-server processes (§5) and have no reason to block each other.
Within one user's own thread, serialize: don't let a second message for the same
thread start a new OHS call while one is still in flight for that thread.

**Crash recovery**: because ack happens before work starts (per Bolt's Lazy
Listener model), an adapter crash mid-processing simply means Slack redelivers
the envelope on its own retry schedule if the ack never went out, *or* — if ack
already went out but processing crashed after — the message is lost unless the
adapter also durably records "accepted event ids I haven't finished yet" and
reconciles on restart. For v1 scope (a handful of users, occasional real crashes,
not a high-throughput service), accepting at-least-once delivery with the
`event_id` dedup check (above) as the safety net — rather than building full
exactly-once crash recovery — is a reasonable, explicitly-chosen tradeoff, not an
oversight. Revisit if usage volume ever makes silent message loss on crash
unacceptable.

**Idempotent mapping commit**: after OHS returns a response and it's posted to
Slack, commit the (possibly new) thread→conversation-id mapping. If the process
dies between "posted to Slack" and "committed mapping," the next message in that
thread would start a fresh OHS conversation instead of continuing the old one —
acceptable degraded behavior (a new conversation, not silent data corruption or
crossed wires) for v1 scope; not fully solved, flagged as a known limitation
rather than silently ignored.

**Slack-facing UX for non-happy-path OHS states** — DESIGNED, grounded against
`openai/service.py` (2026-09-23):

Confirmed behavior: `/v1/chat/completions` does **not** block until a governance
pause resolves. It polls the conversation's own state every ~2 seconds
server-side and, as soon as the agent run leaves `RUNNING` for
`WAITING_FOR_CONFIRMATION` or `PAUSED`, returns immediately as an **HTTP 409**
with `detail: "Agent run ended with status: waiting_for_confirmation"` (or
`paused`) — not a synthetic OpenAI-shaped completion, not a hang. The actual
agent run keeps executing (or waiting) in a separate background `asyncio.Task`
regardless of what happens to this HTTP call — a client timeout/disconnect at
this point does not cancel the underlying conversation. If the pause resolves to
a *rejection*, the conversation returns to `IDLE`; the original call already
returned its 409 and never sees this, since it doesn't wait around for it.
`GET /conversations/{conversation_id}` independently exposes the same
`execution_status` value at any time, without triggering a new chat-completion
call.

Adapter design following from this:

1. On a 200 response: post the content to Slack normally (happy path, unchanged).
2. On a 409 with `waiting_for_confirmation`/`paused`: post a **status message**,
   not an error, to the Slack thread (e.g. "⏳ this needs approval before I can
   continue") — this is a governance pause, and must read as one to the user, not
   as a failure.
3. Start polling `GET /conversations/{conversation_id}`'s `execution_status`
   (the read endpoint confirmed in this investigation) until it leaves
   `waiting_for_confirmation`/`paused`.
4. On resolution to a terminal state: fetch and post the actual outcome. **Open
   implementation detail, not fully resolved here**: the cleanest way to retrieve
   the final assistant message text once execution finishes — via the
   conversation's event/history listing rather than a second
   `/v1/chat/completions` call, since resending into an `IDLE` conversation was
   only confirmed to "proceed normally," not confirmed to safely return the
   already-completed turn's content without triggering unrelated new work.
   Whoever implements this should verify the exact events/history endpoint shape
   before writing code, not assume.
5. On resolution via rejection (`IDLE` with no new assistant output): post a
   clear "❌ that action wasn't approved" message rather than silence or a
   generic error.
6. Polling cadence/timeout for step 3 (how long to keep checking before giving up
   and telling the user to check back manually) is an implementation tuning
   detail, not decided here.

None of this is Slack-specific trivia — it's the actual reliability contract for a
bot that people will use for real work, and it was entirely absent from the v1
draft.

## 7. Explicitly out of scope for v1

- Teams, LINE (need the public-endpoint/reverse-proxy design, not done yet).
- Real token-by-token streaming to Slack (endpoint doesn't support it; also Slack
  message-editing UX for streaming is its own design question, not attempted here).
- Multi-team container provisioning (see §5).
- **Not "out of scope" — moved to §0**: the per-request delegated governance
  identity gap is a confirmed prerequisite for multi-user attribution, not a
  deferrable extra. Listing it here in the original draft understated it; see §0
  for the actual status and the decision this document is waiting on.

## 8. Adapter implementation language — DECIDED: Python

Slack officially maintains Bolt SDKs in both Python and JavaScript, so language
support for Socket Mode is not a differentiator either way. Decision factors that
actually matter here:

- **Bolt for Python's `SocketModeHandler`** (`slack_bolt.adapter.socket_mode`)
  directly supports the architecture this design needs: listener functions receive
  an `ack()` callback plus access to the raw Socket Mode request (which carries
  `envelope_id` for the protocol-level ack and, for Events API envelopes,
  `retry_attempt`/`retry_reason`), and Bolt's **Lazy Listener** feature — a
  Python-only Bolt feature — is built exactly for "ack immediately, do the real
  work in the background," which is what §6b's ACK-then-queue design requires.
  ([Slack Bolt Python docs](https://docs.slack.dev/tools/bolt-python/reference/lazy_listener/index.html))
- **`IgnoringSelfEvents` middleware ships built into Bolt Python, enabled by
  default** — this satisfies most of §6's "ignore the bot's own messages" bullet
  out of the box, not something to hand-roll. One documented gap to carry into
  implementation: it does **not** filter messages sent via a `response_url`
  (upstream Bolt issue), so anything using that path still needs an explicit
  bot-id check.
  ([Bolt Python source](https://github.com/slackapi/bolt-python/blob/main/slack_bolt/middleware/ignoring_self_events/ignoring_self_events.py))
- This adapter's other job — orchestrating the per-bound-user agent-server
  process fleet from §5, and driving the OAuth Device Authorization Grant flow
  against Keycloak from §4 — shares far more surface with `central-governance-api`
  (Python/FastAPI, same OIDC/device patterns, same `httpx`-based HTTP client
  conventions already established in this codebase) than with any Slack-specific
  reference implementation. Being able to import shared validation/config code
  directly, rather than reimplementing it in a second language, is a real
  advantage `agent-canvas-source`'s existing Node/Electron stack doesn't offset —
  that stack is a desktop app, an unrelated component, not a server-side
  precedent this adapter needs to match.

**Decision: Python, using `slack-bolt`'s `SocketModeHandler` + Lazy Listeners.**

## 9. Resolution (2026-09-23) — unblocked via architecture, not via delegation
engineering

§0's Critical went through two decision points the same day:

1. **First choice**: design and build a Track 1 per-request delegated-identity
   extension (token exchange reaching into `central-governance-api`'s
   approval-ownership check), then return to finish this Slack design.
2. That extension's own round 1 review (`track1-delegated-identity-v1.md`) found
   the actual engineering cost — safely propagating identity through a shared,
   concurrent, crash-recoverable async pipeline — was approaching Track 1's own
   11-round SSO/OIDC/RBAC design effort. Surfaced to Roy rather than quietly
   grinding through more review rounds (matching how Phase 1's own foundation-level
   Critical, `execute_command()`, was handled — surface it, let Roy choose).
3. **Final choice, given actual deployment scale** (a handful of bound users, not
   a large multi-tenant SaaS): **one agent-server process per bound user**,
   abandoning the shared-process delegated-identity approach entirely. This
   resolves §0's Critical by construction, not by finishing the token-exchange
   engineering — see the revised §5.

**Current status — §1-2, §3, §5a, §6-8 ready to build (§5a reached this
after an 18-round review cycle — see below for the full history); §4a is
the one remaining NOT-ready section (see below — round 5 review flagged the
old heading as easy to misread as covering the whole document; round 7
found it still did, specifically for §4a, and round 8 fixed that framing)**:
- §1-2: Socket Mode + OpenAI-compatible bridge pattern (contract corrected and
  confirmed against source) — per-bound-user, talking to that user's own
  dedicated agent-server process.
- §4: the Device Authorization Grant flow's core mechanics (device-code
  request/poll against Keycloak) are settled. **§4a is explicitly excluded
  from "ready to build" (round 8, closes round 7's M4 — a leftover
  contradiction where §4a's own heading still says "not designed yet" while
  this status section implied §1-4 as a whole was ready)**: what the adapter
  does with the issued token(s), the `(workspace_id, slack_user_id)` binding
  key shape, and the rebind/unbind/deactivation lifecycle are all still open,
  exactly as §4a itself states — none of that is resolved by the per-user
  process architecture in §5, which only established *that* each bound user
  gets a dedicated process, not the binding-and-token-handling details of
  how that process gets provisioned with the right credential.
- §5: multi-tenant granularity revised to per-user processes (supersedes the
  earlier per-team-container decision — flagged explicitly to Roy as a
  consequence of today's choice, not silently overridden). §5a (per-user
  process lifecycle, including the workspace-level advisory-lock/
  crash-recovery design) reached **implementation-ready** after an
  18-round review cycle — see the full history and current known-limitations
  list below.
- §6/§6b: **now fully designed** (2026-09-23, same day) — one adapter process per
  Slack workspace, Bolt Python's `IgnoringSelfEvents` + Lazy Listeners handling
  reply-loop prevention and the ack-then-process ordering, `event_id`-based
  idempotency per Slack's own documented practice, per-(user, thread)
  serialization scoped inside the single per-workspace adapter process. The
  `WAITING_FOR_CONFIRMATION`/timeout/conflict UX is designed and grounded against
  actual `/v1/chat/completions` behavior (confirmed: returns HTTP 409 promptly,
  never blocks; conversation keeps running server-side regardless) — one small
  implementation detail (exact endpoint for fetching the final message after
  resolution) is flagged as open rather than guessed at.
- §8: **decided** — Python, `slack-bolt`'s `SocketModeHandler` + Lazy Listeners,
  chosen for code-sharing with `central-governance-api`'s existing OIDC/device
  patterns and because Bolt Python's Lazy Listener feature (Python-only) matches
  this design's ack-then-background-process requirement natively.

**§5a status**: architecture direction accepted throughout (lazy per-user
provisioning, warm pool via deferred-init, never-evict-non-quiescent
eligibility rule, `READY→DRAINING→STOPPED` lifecycle). Rounds 1-6 all
returned "DESIGN INCOMPLETE," each round narrowing the gap rather than
finding new architectural surprises. Progress by round:

- **Round 3**: fixed the original root cause (a pre-existing Track 1 gap in
  `_wait_for_decision_loop`) for the `expired`/`cancelled` path.
- **Round 4**: found the drain-success signal, outbox terminalization, and
  key-injection path each incomplete or wrong, and reclassified `executing`
  as a hard blocker — pending Roy's explicit choice (`AskUserQuestion`) to
  keep investing in a full, correct design over a simpler safety-only
  alternative the reviewer had offered.
- **Round 5**: a full trace of the actual claim/dispatch/crash-recovery code
  paths found the picture better than round 4 feared — `executing`'s local
  recovery is already safely handled by existing machinery (a classification
  fix, not new engineering), and the worker-thread drain gap was "nobody
  wired up a join()," not architectural. Reviewer's own verdict: `executing`
  recovery is essentially converged; the remaining 3 High findings were
  narrowly mechanical (a join-timeout/marker contradiction, a
  path-separation-only trust boundary claimed as more than it was, and a
  non-atomic "fail-fast" ownership check).
- **Round 6**: confirmed 0 Critical and closed the initial-claim TOCTOU race,
  but found each of round 5's three fixes had one remaining sharp edge — no
  fencing against a recovered "stale" owner, no distinction between
  "confirmed stopped" and "stop status unknown" (letting a replacement mount
  a volume the prior container might still be writing to), and an overstated
  claim about what environment sanitization actually protects. Reviewer's own
  framing: "the minimal convergence path is three targeted fixes, not a
  rewrite."
- **Round 7**: closed round 6's three sharp edges in principle — an
  `ownership_epoch`/`lease_token` fence, the `STOPPED_UNCLEAN`/
  `STOP_STATE_UNKNOWN` split, and an honest trust-boundary framing — plus
  round 6's Medium findings. Reviewer's verdict: 0 Critical, but **2 new
  High**, because the epoch/token fence guarded the *registry row*, not the
  point where an external Docker/Slack call actually happens — a stale owner
  that validated its token and then stalled before calling out could still
  resume and issue that call after being superseded — and lease loss had no
  defined abort semantics for work already in flight. Plus **4 new Medium**:
  the rejection-reconciliation key was still phrased as an open question
  rather than decided, `STOP_STATE_UNKNOWN`'s resolution path lacked concrete
  authority/evidence/transition rules, the trust-boundary fix slightly
  overclaimed that `STOP_STATE_UNKNOWN` fully absorbs marker-forgery risk,
  and §4a vs. this status section had a leftover contradiction.
- **Round 8**: attempted to close the enforcement-point gap with a
  per-operation fenced DB claim immediately adjacent to each external call,
  decided the rejection-reconciliation canonical key (`action_event_id`,
  1:1), made `STOP_STATE_UNKNOWN` resolution concrete (authority, evidence,
  CAS, restart-policy requirement, outcome-mapping table), precisely scoped
  the marker/`STOP_STATE_UNKNOWN` overlap (double-write risk fully covered;
  a narrower data-consistency risk from marker forgery honestly accepted),
  and carved §4a explicitly out of "ready to build." Reviewer's verdict on
  the last three: closed. On the enforcement-point attempt: **not closed —
  3 new High**, because a DB claim and the external call it guards are two
  actions in the same process, and that process can itself be arbitrarily
  paused between them — "immediately adjacent" narrows a window but cannot
  make two non-atomic, cross-boundary actions atomic. This also broke the
  "`docker stop` needs no compensation" claim (a stale stop can still land
  after a new owner's `start` and kill a healthy replacement) and left the
  manual `STOP_STATE_UNKNOWN` runbook with its own observation-to-CAS
  TOCTOU. Plus **2 Medium** (the operation-slot's own lifecycle/takeover
  rules were unspecified; a healthy container from a superseded epoch could
  be promoted straight back to `READY` without an epoch check). Reviewer's
  own conclusion: this needs "an external enforcement point... not tighter
  wording" — a scope decision, surfaced to Roy via `AskUserQuestion` rather
  than attempted again at the documentation level; **Roy chose to design the
  enforcement proxy** (over accepting the residual as a known limitation, or
  continuing to iterate at the wording level alone).
- **Round 9**: introduced a single per-host enforcement proxy as the only
  component permitted to call Docker or make governance-relevant Slack API
  calls. Reviewer's verdict: **worse than round 8, not better — 5 new High
  + 4 Medium + 1 Low, "not converged."** The core defect: the proxy's own
  in-process lock serialized *other proxy requests*, but did nothing to
  block an ownership takeover happening independently in the database — "the
  same race, just moved location," in the reviewer's words. Also newly
  found: the proxy itself had no enforced singleton mechanism (a second
  instance could run and reintroduce the exact cross-process race the proxy
  was supposed to remove), `docker stop`/`start` reordering wasn't actually
  closed (only queued-but-undequeued work was protected, not work already
  forwarded to the socket), a proxy crash mid-operation had no durable
  record for Docker or Slack outbound calls to reconcile from, and UDS
  requests carried no caller authorization beyond an epoch value any local
  process could observe. Reviewer's diagnosis: "ownership takeover and
  mutation must share the same keyed lock, or use a real distributed
  mutex" — surfaced to Roy again via `AskUserQuestion`; **Roy chose to
  redesign around Postgres advisory locks** (over accepting round 9's
  residual risk, or pausing here).
- **Round 10**: replaced the proxy's in-process lock with a Postgres
  session-level advisory lock, held by *both* ownership takeover and the
  proxy's mutation handling for their entire critical section — one real
  mutex instead of two independently-read epoch values, the primitive the
  round-9 reviewer had asked for. Reviewer's verdict: the primitive itself
  is sound, but **1 new Critical**: it was keyed per `(workspace_id,
  user_id)`, while ownership takeover in this document's own architecture
  happens at the *workspace* level — so takeover and mutation still never
  actually contended for the same lock, reintroducing round 9's exact race
  behind a lock that didn't cover it. Plus **5 new High** (no
  re-validation-after-acquiring-the-lock rule; the durable intent write
  shared a transaction with the very outcome it needed to survive a crash
  of, so it wasn't durable; no way to find a container whose creation
  crashed before its ID was recorded; a hung holder's only documented fix
  was killing the DB session, which doesn't stop the process from still
  acting; connection-pinning/pooling requirements for a session-level lock
  were unstated) and **4 Medium** (singleton lock's own connection-loss
  gap, lock-key derivation left abstract, same-UID caller isolation, lock
  reentrancy/monitoring) + **1 Low** (overstated connection-death-speed
  claim). Reviewer's own framing: the architecture is validated, and
  completing five concrete, well-specified points would likely converge it.
- **Round 11**: re-keyed the advisory lock to `workspace_id` alone —
  matching the existing one-adapter-per-workspace ownership model, accepting
  that different bound users' Docker operations within one workspace now
  serialize behind a single lock (a reasonable cost at this deployment's
  scale, and the reviewer's own recommended option over redesigning
  ownership to per-user granularity). Reviewer's verdict: **0 Critical — the
  core workspace-level advisory-lock mechanism is confirmed converged** —
  but **2 new High**: a crash releasing the lock via session death is
  precisely when an unresolved intent needs to gate the next holder, and
  round 11 had no explicit rule requiring that check; and the hung-holder
  runbook's isolation step gave illustrative examples (SIGKILL, revoke
  socket permissions) rather than a verifiable condition, and didn't cover
  Slack egress at all. Plus **2 Medium** (the post-lock re-read needed an
  explicit transaction-timing requirement; intent invariants were
  procedural, not database-enforced) and **1 Low** (round 11's own summary
  overclaimed "closes all six findings" against round 10's actual tally).
- **Round 12**: introduced an explicit intent state machine
  (`PREPARED → APPLIED | NOT_APPLIED | AMBIGUOUS → RECONCILED`) with a
  database-enforced partial unique constraint and a mandatory
  reconciliation-only gate any new lock holder must clear, plus a
  hung-holder runbook requiring confirmed process death or egress
  isolation. Reviewer's verdict: closed the post-lock re-read
  transaction-timing gap and the overstated round-11 summary, substantially
  improved the crash-recovery and hung-holder mechanisms, but **2 new
  High** remained — treating an elapsed retry window as proof a delayed
  Docker request would never land was unsound (Docker offers no daemon-side
  idempotency key or completion acknowledgment this design controls), which
  could reopen the exact stale-stop-after-new-start race for `start`/`stop`
  operations specifically; and confirming process death doesn't prove an
  *already-accepted* Docker/Slack request won't still complete, while the
  Slack-isolation step contradicted this document's own stated Slack
  asymmetry. Plus **3 Medium** (reconciliation evidence needed to differ by
  operation kind; the state machine's transitions and DDL needed
  completing; "retry later" needed a defined executor) and **1 Low**
  (the held state's persistence needed naming as a DB column).
- **Round 13**: made `start`/`stop` reconciliation reuse the existing
  `STOP_STATE_UNKNOWN` human-confirmation runbook instead of any timer,
  named `create`'s residual duplicate risk as an accepted, bounded tradeoff,
  split reconciliation evidence by operation kind, completed the state
  machine and DB constraints, reframed hung-holder isolation honestly, and
  added a durable retry-scheduling path. Reviewer's verdict: **0 Critical, 1
  new High** — a genuinely subtle gap: confirming a container's *current*
  state via inspection is not the same evidence as proving a *specific past
  request* the daemon already accepted will never still complete; reusing
  `STOP_STATE_UNKNOWN`'s runbook was the right direction but invoked too
  early, with nothing establishing that enough time had passed for such a
  request to have necessarily concluded. Plus **3 Medium** (a delayed
  `create` duplicate landing after the original intent reached `RECONCILED`
  had nothing left watching for it; `operation_id` was described as both
  globally unique and reusable across retries — a direct contradiction that
  would block a retry's own insert; the background worker's
  lock-acquisition obligations were only implied) and **1 Low** (the held
  state still lacked an actual database column definition).
- **Round 14**: introduced a **quiescence window** for `start`/`stop`
  reconciliation — Docker's own configured stop grace period plus margin for
  `stop`, a named operational bound for `start` — measured from the
  intent's `started_at` before the human-confirmation runbook runs; made
  `create`'s duplicate-watch durable past `RECONCILED`; split
  `operation_id` from a new `intent_attempt_id`; split
  `outcome_classification` from `gate_state`; made the background worker's
  lock-acquisition duty explicit; and introduced a named `hold_state`
  column. Reviewer's verdict: **0 Critical, 1 new High** — round 14's
  quiescence window conflated two different things: Docker's stop grace
  period bounds the wait *after* the daemon's handler already started
  executing a stop, not the unbounded delay *before* that (network delay,
  daemon load, a blocked handler) which nothing in Docker bounds or exposes;
  `start`'s "operational bound" was an assumption stated with more
  confidence than it had. Plus **3 Medium** (the duplicate-watch "window"
  would need the same unprovable completion-time bound just shown not to
  exist; `outcome_classification`'s value list excluded `PREPARED`, the
  value a fresh intent is created with; `hold_state`'s clearance rule had no
  path for a hung holder stuck before ever creating a pending intent) and
  **0 Low**.
- **Round 15**: removed the unsound timer claims — `start`/`stop` ambiguity
  would resolve immediately on transport-level evidence a request never
  reached the daemon, otherwise via genuine out-of-band human investigation
  with no formula, staying fail-closed indefinitely if inconclusive.
  `create`'s duplicate-watch dropped its invented expiry in favor of the
  container's own tombstone-GC lifecycle. `outcome_classification` gained
  `PREPARED`. `hold_state` gained a second clearance path. Reviewer's
  verdict: **0 Critical, 1 new High** — the transport-level evidence was
  itself too permissive (a transport-layer gap doesn't prove the
  application handler never accepted the request), and the human
  investigation only required "a confident answer" rather than specifically
  proving the old request had terminated or been positively isolated — an
  old `stop` handler that hasn't yet sent its signal survives a bare
  "container looks fine now" check. Plus **2 Medium** (tying duplicate-watch
  to ordinary tombstone GC was itself an unproven implicit expiry, since GC
  reasons about containers that already exist, not ones a delayed `create`
  might still produce after the watched entry is GC'd; the new
  transport-level `NOT_APPLIED` shortcut had nowhere valid to transition to,
  since the state machine still restricted `NOT_APPLIED` to `create`) and
  **1 Low** (§9 should state the indefinite-fail-closed availability cost
  directly, as a core v1 operating characteristic).
- **Round 16**: narrowed the transport-level shortcut, tightened the human
  investigation's release predicate, added an evidence-gated `NOT_APPLIED`
  transition for `start`/`stop`, freed `create`'s duplicate-watch from
  ordinary tombstone GC, and stated the availability cost of indefinite
  fail-closed directly in §9. Reviewer's verdict: **0 Critical, 1 new
  High** — "request terminated with known effect" collapsed two different
  outcomes (no effect vs. successfully applied) into one wrong
  classification, and an "applied" claim was never cross-checked against a
  fresh inspect of current reality. Plus **1 Medium** (the fix was described
  in prose but the document's single formal state-machine table was never
  updated to match, leaving two contradictory normative sources) and **0
  Low** (the reviewer confirmed the two-tier structure isn't hollow, but
  flagged its narrow practical scope with off-the-shelf Docker clients as
  worth a deployment note).
- **Round 17**: made outcome mapping for `start`/`stop` three-way and
  updated the single normative state-machine table to state these rules
  directly, plus a deployment note on the transport shortcut's narrow
  practical scope. Reviewer's verdict: **0 Critical, 0 High, 1 Medium, 0
  Low** — explicitly confirming the core architecture (advisory lock,
  crash-recovery gate, three-way outcome mapping, inspect-failure
  fail-closed behavior, `APPLIED`'s registry convergence) is sound. Only
  two textual sync points remained: the table's first transition omitted
  the direct `PREPARED → NOT_APPLIED` path tier 1's transport proof is
  conclusive enough to use immediately, and one sentence still referenced
  the retired "quiescence-window-gated" mechanism.
- **Round 18**: closed both remaining sync points — the table now reads
  `PREPARED → {AMBIGUOUS, APPLIED, NOT_APPLIED}` with the direct-path
  condition stated, and the leftover quiescence-window sentence now
  describes the current tier 1/tier 2 evidence-gated rule. **Reviewer's
  verdict: 0 Critical, 0 High, 0 Medium, 0 Low — §5a judged
  IMPLEMENTATION-READY**, with an explicit re-verification of the full
  mechanism end to end and no regression of any previously-closed issue.
  This closes the 18-round §5a review cycle. **Cost, unchanged**: still a
  real infrastructure component and single point of failure, fail-closed by
  design, accepted at this deployment's scale.

§5a: IMPLEMENTATION-READY as of round 18 (2026-09-24). No further review
rounds planned for this section; implementation may proceed against the
known-limitations list above.
