// Run with: node --test tests/js   (also run from tests/test_inbox_js.py)
import assert from "node:assert/strict";
import test from "node:test";

import {
  base64url,
  buildAuthUrl,
  decodeJwtPayload,
  describeItem,
  formatRemaining,
  parseCallback,
  pkceChallenge,
  randomString,
  renderItem,
  truncate,
} from "../../src/central_governance_api/inbox_static/inbox.js";

test("PKCE challenge matches the RFC 7636 appendix B vector", async () => {
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  assert.equal(
    await pkceChallenge(verifier),
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  );
});

test("base64url has no padding and no +/ characters", () => {
  assert.equal(base64url(new Uint8Array([251, 255, 254])), "-__-");
  assert.equal(base64url(new Uint8Array([1])), "AQ");
});

test("randomString is url-safe, long enough and not constant", () => {
  const a = randomString(32);
  assert.match(a, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(a, randomString(32));
});

test("auth url carries S256 PKCE, state and the exact redirect", () => {
  const url = new URL(
    buildAuthUrl({
      authorizationEndpoint: "https://idp.test/realms/r/protocol/openid-connect/auth",
      clientId: "inbox",
      redirectUri: "http://localhost:18002/inbox",
      state: "st",
      challenge: "ch",
    }),
  );
  const p = url.searchParams;
  assert.equal(p.get("response_type"), "code");
  assert.equal(p.get("client_id"), "inbox");
  assert.equal(p.get("redirect_uri"), "http://localhost:18002/inbox");
  assert.equal(p.get("code_challenge_method"), "S256");
  assert.equal(p.get("code_challenge"), "ch");
  assert.equal(p.get("state"), "st");
});

test("a callback is only trusted when the state matches what this tab stored", () => {
  assert.equal(parseCallback("", "st"), null);
  assert.deepEqual(parseCallback("?code=c&state=st", "st"), { code: "c" });
  assert.deepEqual(parseCallback("?code=c&state=other", "st"), {
    error: "state_mismatch",
  });
  // Nothing stored (e.g. a link someone sent you): never trusted.
  assert.deepEqual(parseCallback("?code=c&state=st", null), {
    error: "state_mismatch",
  });
  assert.deepEqual(parseCallback("?error=access_denied&state=st", "st"), {
    error: "access_denied",
  });
});

test("decodeJwtPayload reads claims and tolerates garbage", () => {
  const body = Buffer.from(JSON.stringify({ sub: "u1" })).toString("base64url");
  assert.deepEqual(decodeJwtPayload(`h.${body}.s`), { sub: "u1" });
  assert.equal(decodeJwtPayload("garbage"), null);
});

test("formatRemaining", () => {
  const now = Date.parse("2026-10-01T00:00:00Z");
  assert.equal(formatRemaining("2026-10-01T00:02:05Z", now), "2m 05s");
  assert.equal(formatRemaining("2026-09-30T23:59:00Z", now), "expired");
  assert.equal(formatRemaining("not a date", now), "unknown");
});

test("truncate bounds long values", () => {
  assert.equal(truncate("abc", 10), "abc");
  assert.equal(truncate("a".repeat(50), 10), `${"a".repeat(10)}…`);
});

const NOW = Date.parse("2026-10-01T00:00:00Z");

const terminalItem = {
  id: "11111111-1111-1111-1111-111111111111",
  tool_name: "terminal",
  action_summary: "terminal: run a command",
  requester_sub: "alice",
  origin_device_id: "dev-1",
  risk_level: "HIGH",
  expires_at: "2026-10-01T00:05:00Z",
  action_payload: {
    projection_version: "agent-server-display-v1",
    kind: "terminal",
    program: "rm",
    command_preview: "rm -rf build",
    redactions: ["bearer_token"],
    agent_claim: { text: "cleaning the build dir", trusted: false },
  },
};

test("describeItem separates facts, redactions and the untrusted claim", () => {
  const d = describeItem(terminalItem);
  assert.equal(d.kind, "terminal");
  assert.deepEqual(d.redactions, ["bearer_token"]);
  assert.equal(d.agentClaim, "cleaning the build dir");
  const labels = d.facts.map(([k]) => k);
  assert.ok(labels.includes("requested by"));
  assert.ok(labels.includes("program"));
  assert.ok(labels.includes("command_preview"));
  // projection bookkeeping is not shown as if it were a fact about the action
  assert.ok(!labels.includes("projection_version"));
  assert.ok(!labels.includes("redactions"));
});

test("describeItem survives a payload of an unknown shape", () => {
  const d = describeItem({ id: "x", action_payload: null });
  assert.equal(d.kind, "unknown");
  assert.equal(d.agentClaim, null);
  const d2 = describeItem({
    id: "x",
    action_payload: { agent_claim: "just a string", files: ["a", "b"], n: 3 },
  });
  assert.equal(d2.agentClaim, null);
  assert.deepEqual(d2.preview, [{ label: "files", lines: ["a", "b"] }]);
});

// A DOM double that fails the test if anything tries to inject markup.
function fakeDocument() {
  const make = (tag) => {
    const node = {
      tag,
      children: [],
      _text: "",
      listeners: {},
      className: "",
      appendChild(child) {
        this.children.push(child);
        return child;
      },
      addEventListener(name, fn) {
        this.listeners[name] = fn;
      },
      set textContent(value) {
        this._text = String(value);
      },
      get textContent() {
        return this._text;
      },
    };
    for (const banned of ["innerHTML", "outerHTML"]) {
      Object.defineProperty(node, banned, {
        set() {
          throw new Error(`${banned} must not be used`);
        },
      });
    }
    return node;
  };
  return {
    createElement: make,
    createTextNode: (text) => ({ tag: "#text", _text: text, children: [] }),
  };
}

function allText(node) {
  return [node._text, ...node.children.map(allText)].join("\n");
}

test("hostile request content is rendered as text, not markup", () => {
  const hostile = {
    ...terminalItem,
    action_summary: '<img src=x onerror="alert(1)">',
    action_payload: {
      ...terminalItem.action_payload,
      command_preview: "</pre><script>alert(1)</script>",
      agent_claim: { text: "<b>trust me</b>", trusted: false },
    },
  };
  const li = renderItem(fakeDocument(), hostile, NOW, () => {});
  const text = allText(li);
  assert.ok(text.includes('<img src=x onerror="alert(1)">'));
  assert.ok(text.includes("</pre><script>alert(1)</script>"));
  assert.ok(text.includes("(unverified)"));
});

test("the buttons report the decision for that item", () => {
  const calls = [];
  const li = renderItem(fakeDocument(), terminalItem, NOW, (item, decision) =>
    calls.push([item.id, decision]),
  );
  const actions = li.children.at(-1);
  const [approve, reject] = actions.children;
  approve.listeners.click();
  reject.listeners.click();
  assert.deepEqual(calls, [
    [terminalItem.id, "accept"],
    [terminalItem.id, "reject"],
  ]);
});
