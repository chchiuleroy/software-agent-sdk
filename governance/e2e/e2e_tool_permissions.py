"""End-to-end smoke for department tool permissions.

Real central process (uvicorn, real lifespan and asyncpg pool,
CGA_ENFORCE_TOOL_PERMISSIONS=true) on a throwaway Postgres, a local fake IdP
(JWKS plus a client-credentials token endpoint), and on the device side the
REAL GovernanceClient, the REAL refresher and the REAL analyzer. Run with the
SDK venv python; it launches central with the central venv.

Not covered (said plainly): EventService._create_governance_approval is only
unit-tested (mock conversation); no real conversation, no Keycloak.
It creates and drops its own database `central_e2e_tp`.
"""

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
from joserfc import jwk, jwt


os.environ.setdefault("OPENHANDS_SUPPRESS_BANNER", "1")

from ohs_env import CENTRAL, CPY, pg_tool
from openhands.agent_server import (
    governance_tool_permissions as refresher,  # noqa: E402
)
from openhands.agent_server.governance_client import (  # noqa: E402
    GovernanceClient,
    GovernancePermanentError,
    compute_display_digest,
)
from openhands.sdk.security import roy_tool_permissions as permissions  # noqa: E402
from openhands.sdk.security.risk import SecurityRisk  # noqa: E402
from openhands.sdk.security.roy_governance import (  # noqa: E402
    RoyPathPayloadSecurityAnalyzer,
)


PG = ["-h", "127.0.0.1", "-p", "54329", "-U", "cga"]
DB = "central_e2e_tp"
IDP_PORT, API_PORT = 18780, 8897
ISSUER = f"http://127.0.0.1:{IDP_PORT}/realms/e2e"
AUDIENCE = "central-governance-api"
SERVICE_CLIENT = "svc-agent-1"

key = jwk.RSAKey.generate_key(2048, parameters={"kid": "e2e-key"})
JWKS = json.dumps({"keys": [key.as_dict(private=False)]}).encode()


def token(sub, roles=()):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": sub,
        "aud": AUDIENCE,
        "exp": now + 600,
        "iat": now,
        "roles": list(roles),
    }
    return jwt.encode({"alg": "RS256", "kid": "e2e-key"}, claims, key)


class _Idp(BaseHTTPRequestHandler):
    def _send(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._send(JWKS)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        form = self.rfile.read(length).decode()
        client_id = dict(p.split("=", 1) for p in form.split("&")).get("client_id", "x")
        self._send(
            json.dumps(
                {
                    "access_token": token(client_id, ["agent.operator"]),
                    "expires_in": 600,
                }
            ).encode()
        )

    def log_message(self, *a):
        pass


results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


def psql(*args):
    return subprocess.run(
        [pg_tool("psql"), *PG, *args], capture_output=True, text=True, check=True
    )


def body(tool_name):
    base = {
        "request_id": uuid.uuid4().hex,
        "origin_device_id": "device-1",
        "conversation_id": "conv-1",
        "action_event_id": uuid.uuid4().hex,
        "tool_call_id": None,
        "action_type": "tool_call",
        "tool_name": tool_name,
        "policy_revision": "v1",
        "action_summary": "do it",
        "action_payload": {"kind": "x"},
        "digest_salt": "salt",
    }
    base["action_payload_digest"] = compute_display_digest(
        action_type=base["action_type"],
        tool_name=tool_name,
        policy_revision="v1",
        action_summary="do it",
        action_payload=base["action_payload"],
        digest_salt="salt",
    )
    return base


async def main():
    threading.Thread(
        target=HTTPServer(("127.0.0.1", IDP_PORT), _Idp).serve_forever, daemon=True
    ).start()
    subprocess.run([pg_tool("createdb"), *PG, DB], check=True)
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "CGA_DATABASE_URL": f"postgresql+asyncpg://cga@127.0.0.1:54329/{DB}",
        "CGA_OIDC_ISSUER": ISSUER,
        "CGA_OIDC_JWKS_URL": f"http://127.0.0.1:{IDP_PORT}/certs",
        "CGA_OIDC_AUDIENCE": AUDIENCE,
        "CGA_OIDC_REQUIRE_HTTPS": "false",
        "CGA_ENFORCE_TOOL_PERMISSIONS": "true",
        "CGA_PORT": str(API_PORT),
    }
    subprocess.run(
        [CPY, "-m", "alembic", "upgrade", "head"],
        cwd=CENTRAL,
        env=env,
        check=True,
        capture_output=True,
    )
    server = subprocess.Popen(
        [CPY, "-c", "from central_governance_api.main import main; main()"],
        cwd=CENTRAL,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
    )
    base = f"http://127.0.0.1:{API_PORT}"
    device = GovernanceClient(
        base_url=base,
        token_url=f"http://127.0.0.1:{IDP_PORT}/token",
        client_id=SERVICE_CLIENT,
        client_secret="unused",
    )
    try:
        async with httpx.AsyncClient(base_url=base, timeout=20) as c:
            for _ in range(60):
                try:
                    if (await c.get("/healthz")).status_code == 200:
                        break
                except httpx.HTTPError:
                    await asyncio.sleep(0.5)
            else:
                raise SystemExit("central did not start")
            sup = {
                "Authorization": "Bearer " + token("root", ["governance.superadmin"])
            }
            approver = {
                "Authorization": "Bearer " + token("carol", ["agent.approver"]),
                "Idempotency-Key": "d-1",
            }

            # --- before any department: the service account has nothing ---------
            permissions.set_enforcing(True)
            check(
                "refresh works before a department exists",
                await refresher.refresh_once(device),
            )
            snap = permissions.get_snapshot()
            check(
                "no department means no tools",
                snap is not None and snap.tools == frozenset(),
                str(snap and sorted(snap.tools)),
            )
            check(
                "only the pure built-ins are permitted",
                permissions.is_permitted("finish")
                and not permissions.is_permitted("file_editor"),
            )
            try:
                await device.create_approval(body("file_editor"), idempotency_key="k0")
                check("central refuses an unassigned account", False)
            except GovernancePermanentError as exc:
                check(
                    "central refuses an unassigned account (403 tool_not_permitted)",
                    exc.status_code == 403 and exc.error_code == "tool_not_permitted",
                    f"{exc.status_code} {exc.error_code}",
                )

            # --- superadmin sets it up --------------------------------------------
            r = await c.post(
                "/api/v1/admin/departments", json={"name": "Finance"}, headers=sup
            )
            dept = r.json()["id"]
            r = await c.put(
                f"/api/v1/admin/departments/{dept}/tools",
                json={"tools": ["file_editor", "grep"]},
                headers=sup,
            )
            check("superadmin sets the tool list", r.status_code == 200)
            r = await c.post(
                f"/api/v1/admin/departments/{dept}/principals",
                json={"sub": SERVICE_CLIENT},
                headers=sup,
            )
            check(
                "superadmin assigns the service account",
                r.status_code == 201,
                r.text[:80],
            )

            # --- device sees it ------------------------------------------------------
            check("device refresh picks it up", await refresher.refresh_once(device))
            check(
                "listed tool permitted, unlisted refused on the device",
                permissions.is_permitted("file_editor")
                and not permissions.is_permitted("terminal"),
            )
            analyzer = RoyPathPayloadSecurityAnalyzer(workspace_root="/ws")
            from tests.sdk.security.test_roy_governance_analyzer import _event

            from openhands.sdk.event import ActionEvent  # noqa: F401
            from openhands.tools.file_editor.definition import FileEditorAction
            from openhands.tools.terminal.definition import TerminalAction

            fe = _event(
                "file_editor", FileEditorAction(command="view", path="/ws/a.txt")
            )
            term = _event("terminal", TerminalAction(command="echo hi"))
            check(
                "analyzer: permitted in-workspace call stays LOW",
                analyzer.security_risk(fe) == SecurityRisk.LOW,
            )
            check(
                "analyzer: unpermitted tool is HIGH",
                analyzer.security_risk(term) == SecurityRisk.HIGH,
            )
            snap = permissions.get_snapshot()
            check(
                "a list that outlives its max age permits nothing",
                snap is not None
                and not permissions.is_permitted(
                    "file_editor", now=snap.fetched_at + snap.max_age_seconds + 1
                ),
            )

            # --- central enforcement ---------------------------------------------------
            created = await device.create_approval(
                body("file_editor"), idempotency_key="k1"
            )
            check("central accepts a permitted tool", "id" in created)
            try:
                await device.create_approval(body("terminal"), idempotency_key="k2")
                check("central refuses an unpermitted tool", False)
            except GovernancePermanentError as exc:
                check(
                    "central refuses an unpermitted tool",
                    exc.error_code == "tool_not_permitted",
                )

            # --- revocation lands at claim ------------------------------------------------
            r = await c.post(
                f"/api/v1/approvals/{created['id']}/decide",
                json={"decision": "accept"},
                headers=approver,
            )
            check("approver accepts", r.status_code == 200, r.text[:80])
            r = await c.put(
                f"/api/v1/admin/departments/{dept}/tools",
                json={"tools": ["grep"]},
                headers=sup,
            )
            check("superadmin revokes file_editor", r.status_code == 200)
            try:
                await device.claim(created["id"], idempotency_key="k3")
                check("claim is refused after revocation", False)
            except GovernancePermanentError as exc:
                check(
                    "claim is refused after revocation",
                    exc.error_code == "tool_not_permitted",
                )
            await refresher.refresh_once(device)
            check(
                "the next refresh removes it on the device too",
                not permissions.is_permitted("file_editor")
                and permissions.is_permitted("grep"),
            )

            audit = psql(
                "-d",
                DB,
                "-Atc",
                "select event_type from admin_audit_events order by occurred_at",
            ).stdout.split()
            check(
                "audit trail records the changes",
                {
                    "department_created",
                    "department_tools_set",
                    "department_principal_assigned",
                }
                <= set(audit),
                str(sorted(set(audit))),
            )
    finally:
        await device.aclose()
        permissions.reset()
        server.terminate()
        try:
            out, _ = server.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            out, _ = server.communicate()
        bad = [l for l in (out or "").splitlines() if "Traceback" in l or " 500 " in l]
        check("server log has no traceback / 5xx", not bad, str(bad[:2]))
        subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=False)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)


asyncio.run(main())
