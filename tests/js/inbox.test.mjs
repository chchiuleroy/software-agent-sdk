// Run with: node --test tests/js   (also run from tests/test_inbox_js.py)
import assert from "node:assert/strict";
import test from "node:test";

import {
  AUDIT_EVENT_TYPES,
  auditPath,
  base64url,
  buildAuthUrl,
  decodeJwtPayload,
  describeAuditEvent,
  describeDevice,
  describeIdentity,
  describeItem,
  formatRemaining,
  looksLikeUuid,
  mergeDevices,
  ownerLabel,
  pageLimit,
  parseCallback,
  payloadText,
  pkceChallenge,
  randomString,
  renderAuditEvent,
  renderDevice,
  renderIdentity,
  renderItem,
  renderNav,
  resolveSection,
  revokeConfirmText,
  sanitizeHash,
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
  assert.deepEqual(ids(sections), ["profile", ...SUPERADMIN_IDS, "audit"]);
  assert.ok(sections.filter((s) => s.audience === "superadmin").length > 0);
  const live = sections
    .filter((s) => s.audience === "superadmin" && s.status === "live")
    .map((s) => s.id);
  assert.deepEqual(live, ["devices"], "only the Devices screen exists so far");
  assert.ok(
    sections
      .filter((s) => s.audience === "superadmin" && s.id !== "devices")
      .every((s) => s.status === "planned"),
    "the other admin views have no page yet; they must stay planned",
  );
});

test("governance.admin unlocks the Audit trail and nothing else of the admin area", () => {
  assert.deepEqual(
    ids(visibleSections(["governance.admin", "agent.operator"])),
    ["profile", "audit"],
  );
  assert.deepEqual(ids(visibleSections(["agent.operator"])), ["profile"]);
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
  // the Devices screen exists: a superadmin may open it
  assert.deepEqual(resolveSection("#devices", superadmin), {
    id: "devices",
    denied: false,
  });
  // planned sections have no page yet
  assert.deepEqual(resolveSection("#departments", superadmin), {
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
  const departments = byTitle("Departments");
  profile.listeners.click();
  approvals.listeners.click();
  assert.deepEqual(chosen, ["profile", "approvals"]);
  assert.match(approvals.className, /active/);
  assert.doesNotMatch(profile.className, /active/);
  devices.listeners.click();
  assert.deepEqual(chosen, ["profile", "approvals", "devices"]);
  assert.equal(
    departments.listeners.click,
    undefined,
    "a planned entry must not be clickable",
  );
  assert.match(allText(departments), /coming soon/i);
});

test("only a plain section hash is carried through the sign-in round trip", () => {
  // The hash survives sessionStorage and goes back into the address bar, so it
  // must never be able to carry anything but a section name.
  assert.equal(sanitizeHash("#approvals"), "#approvals");
  assert.equal(sanitizeHash("#tool-permissions"), "#tool-permissions");
  for (const hostile of [
    "",
    "#",
    "approvals",
    "#a b",
    "#<script>",
    "#a?code=1",
    "#../x",
    `#${"a".repeat(41)}`,
    null,
    undefined,
  ]) {
    assert.equal(sanitizeHash(hostile), "", String(hostile));
  }
});

// ------------------------------------------------------------ devices screen

const DEV_ME = { issuer: "http://kc/realms/x", sub: "root-0000-1111-2222" };
const deviceItem = (over = {}) => ({
  id: "reg-1",
  device_id: "laptop",
  owner_subject: "http://kc/realms/x#alice-aaaa-bbbb-cccc",
  registered_at: "2026-10-12T08:05:09.123456+00:00",
  revoked_at: null,
  revoked_by_subject: null,
  ...over,
});

test("ownerLabel shortens a long sub and keeps the full text", () => {
  const label = ownerLabel("http://kc/realms/x#alice-aaaa-bbbb-cccc", DEV_ME);
  assert.equal(label.short, "alice-aa…");
  assert.equal(label.full, "http://kc/realms/x#alice-aaaa-bbbb-cccc");
  assert.equal(label.mine, false);
  assert.equal(ownerLabel("http://kc/realms/x#bob", DEV_ME).short, "bob");
  assert.equal(ownerLabel("justtext", DEV_ME).short, "justtext");
});

test("a device is 'mine' only when issuer AND sub both match", () => {
  // The server matches the (issuer, sub) pair, never the sub alone; so must the
  // label, or another realm's account with the same sub would be shown as mine.
  assert.equal(ownerLabel(`${DEV_ME.issuer}#${DEV_ME.sub}`, DEV_ME).mine, true);
  assert.equal(ownerLabel(`http://other/realms/x#${DEV_ME.sub}`, DEV_ME).mine, false);
  assert.equal(ownerLabel(`${DEV_ME.issuer}#someone-else`, DEV_ME).mine, false);
  assert.equal(ownerLabel(`${DEV_ME.issuer}#${DEV_ME.sub}`, null).mine, false);
});

test("describeDevice reads an active and a revoked registration", () => {
  const active = describeDevice(deviceItem(), DEV_ME);
  assert.equal(active.id, "reg-1");
  assert.equal(active.deviceId, "laptop");
  assert.equal(active.revoked, false);
  assert.equal(active.registered, "2026-10-12 08:05 UTC");
  assert.equal(active.revokedBy, null);

  const revoked = describeDevice(
    deviceItem({
      revoked_at: "2026-10-12T09:00:00+00:00",
      revoked_by_subject: `${DEV_ME.issuer}#${DEV_ME.sub}`,
    }),
    DEV_ME,
  );
  assert.equal(revoked.revoked, true);
  assert.equal(revoked.revokedAt, "2026-10-12 09:00 UTC");
  assert.equal(revoked.revokedBy.mine, true);
});

test("describeDevice tolerates a bad date and bounds huge values", () => {
  assert.equal(describeDevice(deviceItem({ registered_at: "nope" }), DEV_ME).registered, "unknown");
  const huge = "x".repeat(5000);
  const view = describeDevice(
    deviceItem({ device_id: huge, owner_subject: `i#${huge}` }),
    DEV_ME,
  );
  assert.ok(view.deviceId.length <= 2001);
  assert.ok(view.owner.full.length <= 2001);
  assert.ok(view.owner.short.length <= 9);
});

test("mergeDevices appends only rows not already shown", () => {
  const a = deviceItem({ id: "a" });
  const b = deviceItem({ id: "b" });
  const c = deviceItem({ id: "c" });
  const existing = [a, b];
  const merged = mergeDevices(existing, [b, c]);
  assert.deepEqual(merged.map((d) => d.id), ["a", "b", "c"]);
  assert.equal(existing.length, 2, "the input list must not be modified");
  assert.deepEqual(mergeDevices([], [a, a]).map((d) => d.id), ["a"]);
});

test("the revoke prompt names the device and owner and does not overstate the effect", () => {
  const view = describeDevice(deviceItem(), DEV_ME);
  const text = revokeConfirmText(view);
  assert.ok(text.includes('"laptop"'));
  assert.ok(text.includes("http://kc/realms/x#alice-aaaa-bbbb-cccc"));
  assert.match(text, /only when device binding is enforced/);
  assert.match(text, /CGA_DEVICE_BINDING_ENFORCED/);
  assert.match(text, /already issued/);
  assert.doesNotMatch(text, /immediately/i);
});

const buttonsIn = (node) => [
  ...(node.tag === "button" ? [node] : []),
  ...node.children.flatMap(buttonsIn),
];

test("a device card renders hostile values as text and offers Revoke only while active", () => {
  const hostile = '<img src=x onerror="alert(1)">';
  const calls = [];
  const activeView = describeDevice(
    deviceItem({ device_id: hostile, owner_subject: `i#${hostile}` }),
    DEV_ME,
  );
  const card = renderDevice(fakeDocument(), activeView, (view) => calls.push(view.id));
  assert.ok(allText(card).includes(hostile));
  const buttons = buttonsIn(card);
  assert.equal(buttons.length, 1);
  buttons[0].listeners.click();
  assert.deepEqual(calls, ["reg-1"]);

  const revokedView = describeDevice(
    deviceItem({
      revoked_at: "2026-10-12T09:00:00+00:00",
      revoked_by_subject: "http://kc/realms/x#root-0000-1111-2222",
    }),
    DEV_ME,
  );
  const gone = renderDevice(fakeDocument(), revokedView, () => calls.push("never"));
  assert.equal(buttonsIn(gone).length, 0, "a revoked device cannot be revoked again");
  assert.match(gone.className, /revoked/);
  assert.match(allText(gone), /Revoked/);
});

test("my own device is marked (you)", () => {
  const mine = describeDevice(
    deviceItem({ owner_subject: `${DEV_ME.issuer}#${DEV_ME.sub}` }),
    DEV_ME,
  );
  assert.match(allText(renderDevice(fakeDocument(), mine, () => {})), /\(you\)/);
  const theirs = describeDevice(deviceItem(), DEV_ME);
  assert.doesNotMatch(allText(renderDevice(fakeDocument(), theirs, () => {})), /\(you\)/);
});

test("a reload keeps what was already loaded, within the server's page limit", () => {
  // Revoking a row on page 2 reloads the list; if it fell back to page 1 the
  // row just revoked would vanish from view.
  assert.equal(pageLimit(0), 50);
  assert.equal(pageLimit(20), 50);
  assert.equal(pageLimit(60), 60);
  assert.equal(pageLimit(150), 150);
  assert.equal(pageLimit(200), 200);
  assert.equal(pageLimit(999), 200, "the API accepts at most 200 per request");
});

// ------------------------------------------------------------------ audit trail

const AUDIT_ME = { issuer: "http://kc/realms/x", sub: "me-1111-2222-3333-4444" };

function auditItem(overrides = {}) {
  return {
    id: "evt-1",
    event_type: "device_revoked",
    actor_subject: "http://kc/realms/x#alice-1111-2222-3333-4444",
    origin_device_id: "laptop-7",
    approval_request_id: "0f8fad5b-d9cb-469f-a165-70867728950e",
    occurred_at: "2026-10-14T12:00:00.123456+00:00",
    payload: { reason: "lost", count: 2 },
    ...overrides,
  };
}

test("Audit is a live section for governance.admin and governance.superadmin only", () => {
  const audit = SECTIONS.find((section) => section.id === "audit");
  assert.equal(audit.status, "live");
  assert.deepEqual(audit.requiredRoles, ["governance.admin", "governance.superadmin"]);
  for (const roles of [["governance.admin"], ["governance.superadmin"]]) {
    assert.ok(ids(visibleSections(roles)).includes("audit"), roles.join());
  }
  for (const roles of [[], ["agent.approver"], ["agent.operator"]]) {
    assert.ok(!ids(visibleSections(roles)).includes("audit"), roles.join());
  }
  assert.deepEqual(resolveSection("#audit", ["governance.admin"]), {
    id: "audit",
    denied: false,
  });
  assert.deepEqual(resolveSection("#audit", ["agent.approver"]), {
    id: "profile",
    denied: true,
  });
});

test("auditPath carries only the filters that are set, and URL-encodes the cursor", () => {
  assert.equal(auditPath({ eventType: "", approvalId: "" }, null), "/api/v1/audit-events?limit=50");
  const url = new URL(
    auditPath(
      { eventType: "device_revoked", approvalId: "  0f8fad5b-d9cb-469f-a165-70867728950e " },
      "ab+/=c d",
      20,
    ),
    "http://x",
  );
  assert.equal(url.pathname, "/api/v1/audit-events");
  assert.equal(url.searchParams.get("limit"), "20");
  assert.equal(url.searchParams.get("event_type"), "device_revoked");
  assert.equal(url.searchParams.get("approval_request_id"), "0f8fad5b-d9cb-469f-a165-70867728950e");
  assert.equal(url.searchParams.get("cursor"), "ab+/=c d", "the cursor survives the round trip untouched");
  assert.ok(!auditPath({}, "x").includes("event_type"));
});

test("looksLikeUuid accepts a UUID and rejects look-alikes", () => {
  assert.ok(looksLikeUuid("0f8fad5b-d9cb-469f-a165-70867728950e"));
  assert.ok(looksLikeUuid(" 0F8FAD5B-D9CB-469F-A165-70867728950E "));
  for (const bad of ["", "abc", "0f8fad5b-d9cb-469f-a165-70867728950", "0f8fad5b-d9cb-469f-a165-70867728950e-1", "zf8fad5b-d9cb-469f-a165-70867728950e", null, undefined]) {
    assert.ok(!looksLikeUuid(bad), String(bad));
  }
});

test("describeAuditEvent reads a row and keeps the full values for tooltips", () => {
  const view = describeAuditEvent(auditItem(), AUDIT_ME);
  assert.equal(view.type, "device_revoked");
  assert.equal(view.when, "2026-10-14 12:00 UTC");
  assert.equal(view.actor.short, "alice-11…");
  assert.equal(view.actor.full, "http://kc/realms/x#alice-1111-2222-3333-4444");
  assert.equal(view.actor.mine, false);
  assert.equal(view.device, "laptop-7");
  assert.deepEqual(view.approval, { short: "0f8fad5b", full: "0f8fad5b-d9cb-469f-a165-70867728950e" });
  assert.match(view.payload, /"reason": "lost"/);
});

test("describeAuditEvent: a row with no device or approval, my own action, a bad date", () => {
  const view = describeAuditEvent(
    auditItem({
      origin_device_id: null,
      approval_request_id: null,
      actor_subject: `${AUDIT_ME.issuer}#${AUDIT_ME.sub}`,
      occurred_at: "not a date",
      payload: null,
    }),
    AUDIT_ME,
  );
  assert.equal(view.device, null);
  assert.equal(view.approval, null);
  assert.equal(view.actor.mine, true);
  assert.equal(view.when, "unknown");
  assert.equal(view.payload, "");
});

test("describeAuditEvent bounds huge values and survives a payload JSON cannot print", () => {
  const huge = "x".repeat(50000);
  const view = describeAuditEvent(
    auditItem({ event_type: huge, origin_device_id: huge, payload: { blob: huge } }),
    AUDIT_ME,
  );
  assert.ok(view.type.length < 200);
  assert.ok(view.device.length < 200);
  assert.ok(view.payload.length < 5000);
  assert.equal(payloadText({ n: 10n }), "(payload could not be shown)");
});

test("an audit row renders hostile values as text, and the payload sits in a details block", () => {
  const hostile = '<img src=x onerror="alert(1)">';
  const view = describeAuditEvent(
    auditItem({
      event_type: hostile,
      origin_device_id: hostile,
      actor_subject: `i#${hostile}`,
      payload: { note: hostile },
    }),
    AUDIT_ME,
  );
  const li = renderAuditEvent(fakeDocument(), view);
  const text = allText(li);
  assert.ok(text.includes(hostile));
  assert.match(li.className, /audit/);
  const details = li.children.find((child) => child.tag === "details");
  assert.ok(details, "the payload is tucked into <details>");
  assert.equal(details.children[0].tag, "summary");
  assert.equal(details.children[1].tag, "pre");
});

test("an audit row without a payload has no details block, and my own action says (you)", () => {
  const mine = describeAuditEvent(
    auditItem({ payload: null, actor_subject: `${AUDIT_ME.issuer}#${AUDIT_ME.sub}` }),
    AUDIT_ME,
  );
  const li = renderAuditEvent(fakeDocument(), mine);
  assert.ok(!li.children.some((child) => child.tag === "details"));
  assert.match(allText(li), /\(you\)/);
  const theirs = renderAuditEvent(fakeDocument(), describeAuditEvent(auditItem(), AUDIT_ME));
  assert.doesNotMatch(allText(theirs), /\(you\)/);
});

test("the event type filter list has no duplicates and is sorted", () => {
  assert.equal(new Set(AUDIT_EVENT_TYPES).size, AUDIT_EVENT_TYPES.length);
  assert.deepEqual([...AUDIT_EVENT_TYPES].sort(), AUDIT_EVENT_TYPES);
});
