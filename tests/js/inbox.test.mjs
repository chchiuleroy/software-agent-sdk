// Run with: node --test tests/js   (also run from tests/test_inbox_js.py)
import assert from "node:assert/strict";
import test from "node:test";

import {
  base64url,
  buildAuthUrl,
  decodeJwtPayload,
  describeIdentity,
  describeItem,
  formatRemaining,
  parseCallback,
  pkceChallenge,
  randomString,
  renderIdentity,
  renderItem,
  renderNav,
  resolveSection,
  SECTIONS,
  truncate,
  visibleSections,
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

// ------------------------------------------------------------- console shell

const ids = (sections) => sections.map((section) => section.id);
const SUPERADMIN_IDS = [
  "accounts",
  "departments",
  "tool-permissions",
  "awaiting-signin",
  "devices",
];

test("a signed-in account with no role only sees its own profile", () => {
  assert.deepEqual(ids(visibleSections([])), ["profile"]);
});

test("an approver sees the approvals inbox, nothing of the admin area", () => {
  assert.deepEqual(ids(visibleSections(["agent.approver"])), [
    "profile",
    "approvals",
  ]);
});

test("superadmin gets the admin area but NOT approvals: the roles are separate", () => {
  const sections = visibleSections(["governance.superadmin"]);
  assert.deepEqual(ids(sections), ["profile", ...SUPERADMIN_IDS]);
  assert.ok(sections.filter((s) => s.audience === "superadmin").length > 0);
  assert.ok(
    sections
      .filter((s) => s.audience === "superadmin")
      .every((s) => s.status === "planned"),
    "no admin view exists yet; they must be shown as planned, not live",
  );
});

test("governance.admin and agent.operator do not unlock the admin area", () => {
  assert.deepEqual(
    ids(visibleSections(["governance.admin", "agent.operator"])),
    ["profile"],
  );
});

test("every admin-area section needs exactly governance.superadmin", () => {
  const admin = SECTIONS.filter((section) => section.audience === "superadmin");
  assert.deepEqual(ids(admin), SUPERADMIN_IDS);
  for (const section of admin) {
    assert.deepEqual(section.requiredRoles, ["governance.superadmin"]);
  }
});

test("the section a link points at is only honoured when it is usable", () => {
  const approver = ["agent.approver"];
  const superadmin = ["governance.superadmin"];
  assert.deepEqual(resolveSection("", approver), { id: "approvals", denied: false });
  assert.deepEqual(resolveSection("", []), { id: "profile", denied: false });
  assert.deepEqual(resolveSection("#profile", approver), {
    id: "profile",
    denied: false,
  });
  // a deep link to something the account may not see must not reveal or open it
  assert.deepEqual(resolveSection("#approvals", []), { id: "profile", denied: true });
  assert.deepEqual(resolveSection("#devices", ["agent.approver"]), {
    id: "profile",
    denied: true,
  });
  // planned sections have no page yet
  assert.deepEqual(resolveSection("#devices", superadmin), {
    id: "profile",
    denied: true,
  });
  // not a section at all
  assert.deepEqual(resolveSection("#nonsense", approver), {
    id: "approvals",
    denied: false,
  });
});

const ME = {
  issuer: "http://kc/realms/x",
  sub: "u1",
  display_name: "Ada Lovelace",
  roles: ["agent.approver", "agent.operator"],
  email: "ada@example.com",
  email_verified: true,
  membership: { department_id: "d1", department_name: "Finance" },
};

test("describeIdentity says what is missing instead of leaving blanks", () => {
  const view = describeIdentity(ME);
  assert.equal(view.name, "Ada Lovelace");
  assert.equal(view.email, "ada@example.com");
  assert.equal(view.emailNote, null);
  assert.deepEqual(view.roles, ["agent.approver", "agent.operator"]);
  assert.equal(view.department, "Finance");

  const bare = describeIdentity({
    ...ME,
    roles: [],
    email: null,
    email_verified: false,
    membership: null,
  });
  assert.match(bare.department, /No department/);
  assert.match(bare.email, /no e-mail/i);
  assert.deepEqual(bare.roles, []);

  const unverified = describeIdentity({ ...ME, email_verified: false });
  assert.match(unverified.emailNote, /not verified/i);
});

test("describeIdentity bounds hostile or huge values", () => {
  const huge = "x".repeat(5000);
  const view = describeIdentity({
    ...ME,
    display_name: huge,
    email: huge,
    roles: [huge, "agent.approver"],
    membership: { department_id: "d", department_name: huge },
  });
  for (const value of [view.name, view.email, view.department, view.roles[0]]) {
    assert.ok(value.length <= 2001, `value too long: ${value.length}`);
  }
});

test("identity and navigation render hostile values as text only", () => {
  const hostile = '<img src=x onerror="alert(1)">';
  const card = renderIdentity(
    fakeDocument(),
    describeIdentity({
      ...ME,
      display_name: hostile,
      roles: [hostile],
      membership: { department_id: "d", department_name: hostile },
    }),
  );
  assert.ok(allText(card).includes(hostile));
  const nav = renderNav(
    fakeDocument(),
    [{ id: "x", title: hostile, status: "live" }],
    "x",
    () => {},
  );
  assert.ok(allText(nav).includes(hostile));
});

test("live entries navigate, planned ones are labelled and inert", () => {
  const chosen = [];
  const nav = renderNav(
    fakeDocument(),
    visibleSections(["agent.approver", "governance.superadmin"]),
    "approvals",
    (id) => chosen.push(id),
  );
  const items = nav.children;
  const byTitle = (title) =>
    items.find((item) => allText(item).includes(title)).children[0];
  const profile = byTitle("Profile");
  const approvals = byTitle("Approvals");
  const devices = byTitle("Devices");
  profile.listeners.click();
  approvals.listeners.click();
  assert.deepEqual(chosen, ["profile", "approvals"]);
  assert.match(approvals.className, /active/);
  assert.doesNotMatch(profile.className, /active/);
  assert.equal(devices.listeners.click, undefined, "a planned entry must not be clickable");
  assert.match(allText(devices), /coming soon/i);
});
