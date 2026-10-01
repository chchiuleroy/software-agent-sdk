// Approvals inbox (served by central-governance-api at GET /inbox).
//
// Logs in with Authorization Code + PKCE against the Keycloak realm, keeps the
// access token in memory only, lists the requests this approver may decide
// (GET /api/v1/approvals/pending) and sends the decision
// (POST /api/v1/approvals/{id}/decide).
//
// The content of a request (commands, paths, the agent's own summary) is
// untrusted, so this file never builds HTML from it: every value reaches the
// page through textContent / createTextNode. tests/test_inbox.py fails the
// build if an HTML-injection API appears in this file.

const REFRESH_MS = 15000;
const MAX_VALUE_CHARS = 2000;
const STORAGE_STATE = "inbox_state";
const STORAGE_VERIFIER = "inbox_verifier";

// ---------------------------------------------------------------- pure helpers
// (exported so tests/js/inbox.test.mjs can run them under Node)

export function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomString(byteLength = 32, cryptoImpl = globalThis.crypto) {
  const bytes = new Uint8Array(byteLength);
  cryptoImpl.getRandomValues(bytes);
  return base64url(bytes);
}

export async function pkceChallenge(verifier, cryptoImpl = globalThis.crypto) {
  const data = new TextEncoder().encode(verifier);
  const digest = await cryptoImpl.subtle.digest("SHA-256", data);
  return base64url(new Uint8Array(digest));
}

export function buildAuthUrl({
  authorizationEndpoint,
  clientId,
  redirectUri,
  state,
  challenge,
}) {
  const url = new URL(authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", "openid");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

// null = this is not a login callback. A callback whose state does not match
// what this tab stored is never trusted, whatever else it carries.
export function parseCallback(search, expectedState) {
  const params = new URLSearchParams(search);
  if (!params.has("code") && !params.has("error")) return null;
  if (!expectedState || params.get("state") !== expectedState) {
    return { error: "state_mismatch" };
  }
  if (params.has("error")) return { error: params.get("error") };
  return { code: params.get("code") };
}

export function decodeJwtPayload(token) {
  try {
    const part = token.split(".")[1];
    const padded = part.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

export function truncate(value, limit = MAX_VALUE_CHARS) {
  const text = String(value);
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}

export function formatRemaining(expiresAtIso, nowMs) {
  const expires = Date.parse(expiresAtIso);
  if (Number.isNaN(expires)) return "unknown";
  const seconds = Math.floor((expires - nowMs) / 1000);
  if (seconds <= 0) return "expired";
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${String(seconds % 60).padStart(2, "0")}s`;
}

const PAYLOAD_KEYS_SHOWN_SEPARATELY = new Set([
  "projection_version",
  "redaction_version",
  "tool_name",
  "kind",
  "redactions",
  "agent_claim",
]);

// What an approver sees for one request. Written against the display
// projection agent-server sends (kind, program, command_preview, path,
// diff_preview, ...) but tolerant of any shape: unknown keys are shown as
// plain text, never interpreted.
export function describeItem(item) {
  const payload =
    item.action_payload && typeof item.action_payload === "object"
      ? item.action_payload
      : {};
  const facts = [
    ["tool", item.tool_name],
    ["requested by", item.requester_sub],
    ["device", item.origin_device_id],
    ["risk", item.risk_level],
  ];
  const preview = [];
  for (const [key, value] of Object.entries(payload)) {
    if (PAYLOAD_KEYS_SHOWN_SEPARATELY.has(key)) continue;
    if (Array.isArray(value) && value.every((v) => typeof v === "string")) {
      preview.push({ label: key, lines: value.map((line) => truncate(line)) });
    } else if (value !== null && typeof value === "object") {
      facts.push([key, JSON.stringify(value)]);
    } else {
      facts.push([key, value]);
    }
  }
  const claim = payload.agent_claim;
  return {
    title: truncate(item.action_summary ?? ""),
    kind: typeof payload.kind === "string" ? payload.kind : "unknown",
    facts: facts.map(([key, value]) => [truncate(key, 80), truncate(value)]),
    preview,
    agentClaim:
      claim && typeof claim.text === "string" ? truncate(claim.text) : null,
    redactions: Array.isArray(payload.redactions)
      ? payload.redactions.map((rule) => truncate(rule, 80))
      : [],
  };
}

// ------------------------------------------------------------------- rendering
// `doc` is a Document (or a test double): no innerHTML, only text nodes.

function el(doc, tag, text, className) {
  const element = doc.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

export function renderItem(doc, item, nowMs, onDecide) {
  const described = describeItem(item);
  const li = el(doc, "li", undefined, "item");
  li.appendChild(el(doc, "h2", described.title));

  const facts = el(doc, "dl");
  for (const [label, value] of described.facts) {
    facts.appendChild(el(doc, "dt", label));
    facts.appendChild(el(doc, "dd", value));
  }
  li.appendChild(facts);

  for (const block of described.preview) {
    li.appendChild(el(doc, "h3", block.label));
    li.appendChild(el(doc, "pre", block.lines.join("\n")));
  }

  if (described.agentClaim) {
    const claim = el(doc, "p", undefined, "claim");
    claim.appendChild(el(doc, "strong", "The agent says (unverified): "));
    claim.appendChild(doc.createTextNode(described.agentClaim));
    li.appendChild(claim);
  }
  if (described.redactions.length > 0) {
    li.appendChild(
      el(doc, "p", `Redacted by rule: ${described.redactions.join(", ")}`, "note"),
    );
  }
  li.appendChild(
    el(doc, "p", `Expires in ${formatRemaining(item.expires_at, nowMs)}`, "expiry"),
  );

  const actions = el(doc, "div", undefined, "actions");
  for (const [decision, label] of [
    ["accept", "Approve"],
    ["reject", "Reject"],
  ]) {
    const button = el(doc, "button", label, decision);
    button.type = "button";
    button.addEventListener("click", () => onDecide(item, decision));
    actions.appendChild(button);
  }
  li.appendChild(actions);
  return li;
}

// --------------------------------------------------------------------- browser

async function main() {
  const statusEl = document.getElementById("status");
  const loginEl = document.getElementById("login");
  const listEl = document.getElementById("list");
  const whoEl = document.getElementById("who");
  const signoutEl = document.getElementById("signout");
  const say = (message) => {
    statusEl.textContent = message;
  };

  if (!globalThis.crypto?.subtle) {
    say(
      "This page needs a secure context (https, or http on localhost) to sign in.",
    );
    return;
  }

  let config;
  let discovery;
  try {
    config = await (await fetch("/inbox/config.json")).json();
    const issuer = String(config.issuer).replace(/\/$/, "");
    discovery = await (
      await fetch(`${issuer}/.well-known/openid-configuration`)
    ).json();
  } catch {
    say("Could not reach the identity provider.");
    return;
  }
  const redirectUri = `${location.origin}/inbox`;

  let token = null;
  let expiresAtMs = 0;
  const idempotencyKeys = new Map();

  function signOut(message) {
    token = null;
    listEl.replaceChildren();
    whoEl.textContent = "";
    signoutEl.hidden = true;
    loginEl.hidden = false;
    say(message ?? "Signed out.");
  }

  async function signIn() {
    const state = randomString();
    const verifier = randomString(48);
    sessionStorage.setItem(STORAGE_STATE, state);
    sessionStorage.setItem(STORAGE_VERIFIER, verifier);
    location.assign(
      buildAuthUrl({
        authorizationEndpoint: discovery.authorization_endpoint,
        clientId: config.client_id,
        redirectUri,
        state,
        challenge: await pkceChallenge(verifier),
      }),
    );
  }

  async function completeLogin(code) {
    const verifier = sessionStorage.getItem(STORAGE_VERIFIER);
    sessionStorage.removeItem(STORAGE_STATE);
    sessionStorage.removeItem(STORAGE_VERIFIER);
    const response = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: config.client_id,
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier ?? "",
      }),
    });
    if (!response.ok) throw new Error(`token endpoint ${response.status}`);
    const body = await response.json();
    token = body.access_token;
    expiresAtMs = Date.now() + 1000 * Number(body.expires_in ?? 60);
  }

  async function api(path, init = {}) {
    const response = await fetch(path, {
      ...init,
      headers: { ...(init.headers ?? {}), Authorization: `Bearer ${token}` },
    });
    if (response.status === 401) {
      signOut("Your session expired. Sign in again.");
      throw new Error("unauthorized");
    }
    return response;
  }

  async function refresh() {
    if (!token) return;
    if (Date.now() >= expiresAtMs) {
      signOut("Your session expired. Sign in again.");
      return;
    }
    let response;
    try {
      response = await api("/api/v1/approvals/pending");
    } catch {
      return;
    }
    if (response.status === 403) {
      say("This account is not allowed to decide approvals (needs the agent.approver role).");
      listEl.replaceChildren();
      return;
    }
    if (!response.ok) {
      say(`Could not load requests (HTTP ${response.status}).`);
      return;
    }
    const body = await response.json();
    listEl.replaceChildren(
      ...body.items.map((item) => renderItem(document, item, Date.now(), decide)),
    );
    say(
      body.items.length === 0
        ? "Nothing is waiting for you."
        : `${body.items.length} request(s) waiting${body.has_more ? " (showing the oldest)" : ""}.`,
    );
  }

  async function decide(item, decision) {
    const verb = decision === "accept" ? "APPROVE" : "REJECT";
    // Name the requester and tool too: the list is re-rendered every
    // REFRESH_MS, so the row under the pointer can change just before a click.
    const what = `${truncate(item.tool_name, 60)} requested by ${truncate(item.requester_sub, 80)}`;
    const summary = truncate(item.action_summary, 300);
    if (!window.confirm(`${verb} this request?\n\n${what}\n${summary}`)) {
      return;
    }
    const keyId = `${item.id}:${decision}`;
    // Same key for a retry of the same click, so a lost response is safe.
    if (!idempotencyKeys.has(keyId)) {
      idempotencyKeys.set(keyId, crypto.randomUUID());
    }
    let response;
    try {
      response = await api(
        `/api/v1/approvals/${encodeURIComponent(item.id)}/decide`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": idempotencyKeys.get(keyId),
          },
          body: JSON.stringify({ decision }),
        },
      );
    } catch {
      return;
    }
    if (response.ok) {
      idempotencyKeys.delete(keyId);
      say(decision === "accept" ? "Approved." : "Rejected.");
    } else if (response.status === 403) {
      say("Not allowed: you cannot decide your own request, or lack the approver role.");
    } else if (response.status === 409) {
      say("That request was already decided or has expired.");
    } else {
      say(`The decision was not accepted (HTTP ${response.status}).`);
    }
    await refresh();
  }

  document.getElementById("signin").addEventListener("click", signIn);
  signoutEl.addEventListener("click", () => signOut());

  const callback = parseCallback(
    location.search,
    sessionStorage.getItem(STORAGE_STATE),
  );
  if (callback) {
    // Drop ?code=&state= from the address bar before doing anything else.
    history.replaceState(null, "", "/inbox");
    if (callback.error) {
      sessionStorage.removeItem(STORAGE_STATE);
      sessionStorage.removeItem(STORAGE_VERIFIER);
      say(`Sign-in failed (${truncate(callback.error, 80)}).`);
    } else {
      try {
        await completeLogin(callback.code);
      } catch {
        say("Sign-in failed while exchanging the code.");
      }
    }
  }

  if (token) {
    const claims = decodeJwtPayload(token);
    whoEl.textContent = truncate(
      claims?.preferred_username ?? claims?.sub ?? "",
      120,
    );
    signoutEl.hidden = false;
    loginEl.hidden = true;
    await refresh();
    setInterval(() => {
      if (!document.hidden) refresh();
    }, REFRESH_MS);
  } else {
    loginEl.hidden = false;
    if (!statusEl.textContent) say("Sign in to see the requests waiting for you.");
  }
}

if (typeof document !== "undefined") {
  main();
}
