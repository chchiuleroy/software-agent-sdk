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
subsequent messages to *their* dedicated agent-server process (start one if none
exists yet for that `(team_id, user_id)` pair; some process lifecycle policy
— when to spin up, how long to keep idle processes alive — is not designed here,
flagged as an open item for whoever picks up the transport-layer implementation).

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

**Current status — ready to build**:
- §1-2: Socket Mode + OpenAI-compatible bridge pattern (contract corrected and
  confirmed against source) — per-bound-user, talking to that user's own
  dedicated agent-server process.
- §4/§4a: Device Authorization Grant binding flow — the resulting per-user token
  no longer needs to flow into a shared process's credential-selection machinery
  (§0's original concern); it's used once, at process provisioning time, for
  whichever process serves that bound user, matching today's existing
  `ROY_GOVERNANCE_IDENTITY`-per-process model exactly.
- §5: multi-tenant granularity revised to per-user processes (supersedes the
  earlier per-team-container decision — flagged explicitly to Roy as a
  consequence of today's choice, not silently overridden).
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

**Not yet designed**: per-user process lifecycle (when to provision, idle
eviction) — flagged in the revised §5, not solved here; the confirmation-state
Slack UX noted above under §6b.
