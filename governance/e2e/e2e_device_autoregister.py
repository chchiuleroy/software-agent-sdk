"""Device auto-registration (OHS 1.8) against a REAL central with binding enforced.

A real central-governance-api process (uvicorn subprocess) on a THROWAWAY Postgres
(127.0.0.1:54329, user cga, trust auth) with a local fake IdP that mints RS256 tokens
and answers the client_credentials request. `CGA_DEVICE_BINDING_ENFORCED` is on.
The agent-server's own `GovernanceClient` and `governance_device_registration`
module talk to it; no agent-server process and no Keycloak.

Cases:
  A  before any registration, a create is refused: 403 device_not_bound
  B  register_once -> state "registered"; the same service account can now create
  C  register_once again (what every restart does) hits central's real 409
     device_already_registered and still ends "registered"
  D  after an admin revokes the registration, register_once -> state "revoked",
     the device is not usable (create 403), and a second attempt stays "revoked":
     a restart cannot bring a revoked device back
  E  a service account that has no devices of its own: the other account's
     registered id is not usable by it (403), so registering is per account

Run with the SDK venv python (cwd = the repository root); it creates and drops its own
randomly named database `central_e2e_autoreg_<hex>`. Every key that matters is set
explicitly in the subprocess environment, which wins over central's `.env`. The real
database is never touched.

Limits: the agent-server's startup path (ConversationService starting the background
task, the retry loop) is covered by unit tests with a fake client, not here; no real
Keycloak; one central process.
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
from joserfc import jwk, jwt

from ohs_env import CENTRAL, CPY, pg_tool
from openhands.agent_server import governance_device_registration as registration
from openhands.agent_server.governance_client import (
    GovernanceApiError,
    GovernanceClient,
    compute_display_digest,
)


PG = ["-h", "127.0.0.1", "-p", "54329", "-U", "cga"]
DB = f"central_e2e_autoreg_{uuid.uuid4().hex[:8]}"
IDP_PORT, API_PORT = 18796, 8896
ISSUER = f"http://127.0.0.1:{IDP_PORT}/realms/e2e"
AUDIENCE = "central-governance-api"
SERVICE_A, SERVICE_B = "svc-agent-a", "svc-agent-b"
DEVICE = "device-autoreg"

key = jwk.RSAKey.generate_key(2048, parameters={"kid": "e2e-key"})
JWKS = json.dumps({"keys": [key.as_dict(private=False)]}).encode()


def token(sub, roles=()):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": sub,
        "aud": AUDIENCE,
        "exp": now + 3600,
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
        cid = dict(p.split("=", 1) for p in form.split("&")).get("client_id", "x")
        self._send(
            json.dumps(
                {"access_token": token(cid, ["agent.operator"]), "expires_in": 3600}
            ).encode()
        )

    def log_message(self, *a):
        pass


RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print(
        ("[PASS] " if ok else "[FAIL] ") + name + (f"  -- {detail}" if detail else ""),
        flush=True,
    )


def create_body(case: str, device: str) -> dict:
    fields = dict(
        action_type="terminal_command",
        tool_name="bash",
        policy_revision="e2e-autoreg-v1",
        action_summary=f"echo {case}",
        action_payload={"command": f"echo {case}"},
        digest_salt=None,
    )
    return {
        "request_id": f"e2e-autoreg-{case}-{uuid.uuid4().hex[:8]}",
        "origin_device_id": device,
        "conversation_id": "e2e-autoreg-conv",
        "action_event_id": f"e2e-autoreg-event-{case}",
        "tool_call_id": None,
        **fields,
        "action_payload_digest": compute_display_digest(**fields),
    }


async def create_outcome(client: GovernanceClient, case: str, device: str):
    """None if the create was accepted, else (status, error_code)."""
    try:
        await client.create_approval(
            create_body(case, device), idempotency_key=f"k-{case}-{uuid.uuid4().hex}"
        )
    except GovernanceApiError as exc:
        return (exc.status_code, exc.error_code)
    return None


def make_client(client_id: str) -> GovernanceClient:
    return GovernanceClient(
        base_url=f"http://127.0.0.1:{API_PORT}",
        token_url=f"http://127.0.0.1:{IDP_PORT}/token",
        client_id=client_id,
        client_secret="unused",
    )


async def main():
    threading.Thread(
        target=ThreadingHTTPServer(("127.0.0.1", IDP_PORT), _Idp).serve_forever,
        daemon=True,
    ).start()
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "CGA_DATABASE_URL": f"postgresql+asyncpg://cga@127.0.0.1:54329/{DB}",
        "CGA_OIDC_ISSUER": ISSUER,
        "CGA_OIDC_JWKS_URL": f"http://127.0.0.1:{IDP_PORT}/certs",
        "CGA_OIDC_AUDIENCE": AUDIENCE,
        "CGA_OIDC_REQUIRE_HTTPS": "false",
        "CGA_PORT": str(API_PORT),
        "CGA_DEVICE_BINDING_ENFORCED": "true",
        "CGA_REQUIRE_EXECUTION_COMMITMENT": "false",
    }
    base = f"http://127.0.0.1:{API_PORT}"
    admin = {"Authorization": f"Bearer {token('admin-1', ['governance.admin'])}"}
    logpath = os.path.join(tempfile.mkdtemp(prefix="autoreg_logs_"), "central.log")
    logfile = server = None
    client_a = make_client(SERVICE_A)
    client_b = make_client(SERVICE_B)
    try:
        subprocess.run([pg_tool("createdb"), *PG, DB], check=True)
        subprocess.run(
            [CPY, "-m", "alembic", "upgrade", "head"],
            cwd=CENTRAL,
            env=env,
            check=True,
            capture_output=True,
        )
        logfile = open(logpath, "w", encoding="utf-8")
        server = subprocess.Popen(
            [CPY, "-c", "from central_governance_api.main import main; main()"],
            cwd=CENTRAL,
            env=env,
            stdout=logfile,
            stderr=subprocess.STDOUT,
        )
        async with httpx.AsyncClient(base_url=base, timeout=30) as c:
            for _ in range(60):
                try:
                    if (await c.get("/healthz")).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.5)
            else:
                raise SystemExit("central did not start; see " + logpath)

            # A
            got = await create_outcome(client_a, "A", DEVICE)
            check(
                "A a create before any registration is refused (403 device_not_bound)",
                got is not None and got[0] == 403 and got[1] == "device_not_bound",
                str(got),
            )

            # B
            status = registration.DeviceRegistrationStatus()
            final = await registration.register_once(client_a, DEVICE, status)
            check(
                "B register_once registers the device",
                final and status.state == "registered" and status.error_code is None,
                str(status),
            )
            got = await create_outcome(client_a, "B", DEVICE)
            check("B the same account can now create", got is None, str(got))

            # C: a restart is a new status object and the same call
            status = registration.DeviceRegistrationStatus()
            final = await registration.register_once(client_a, DEVICE, status)
            check(
                "C registering again (a restart) still ends registered",
                final and status.state == "registered",
                str(status),
            )
            # Evidence that this went through central's real 409 and not a replay:
            try:
                await client_a.register_device(DEVICE, idempotency_key="other-key")
                raw = None
            except GovernanceApiError as exc:
                raw = (exc.status_code, exc.error_code)
            check(
                "C central answers a fresh registration of the same id with 409",
                raw == (409, "device_already_registered"),
                str(raw),
            )

            # D: revoke through the device list, then a "restart"
            listing = await c.get("/api/v1/devices", headers=admin)
            rows = [i for i in listing.json()["items"] if i["device_id"] == DEVICE]
            reg_id = rows[0]["id"] if rows else None
            r = await c.post(
                f"/api/v1/devices/{reg_id}/revoke",
                headers={**admin, "Idempotency-Key": str(uuid.uuid4())},
            )
            check(
                "D an admin revokes the registration",
                r.status_code == 200,
                r.text[:100],
            )
            status = registration.DeviceRegistrationStatus()
            final = await registration.register_once(client_a, DEVICE, status)
            check(
                "D after revocation register_once ends revoked, not registered",
                final
                and status.state == "revoked"
                and status.error_code == "device_revoked",
                str(status),
            )
            got = await create_outcome(client_a, "D", DEVICE)
            check(
                "D the revoked device cannot create (403)",
                got is not None and got[0] == 403,
                str(got),
            )
            status2 = registration.DeviceRegistrationStatus()
            await registration.register_once(client_a, DEVICE, status2)
            check(
                "D a second restart stays revoked",
                status2.state == "revoked",
                str(status2),
            )

            # E
            got = await create_outcome(client_b, "E", DEVICE)
            check(
                "E another service account cannot use this device id (403)",
                got is not None and got[0] == 403,
                str(got),
            )
    finally:
        await client_a.aclose()
        await client_b.aclose()
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()
        if logfile is not None:
            logfile.close()
            log_text = open(logpath, encoding="utf-8", errors="replace").read()
            check(
                "no traceback or 5xx in the central log",
                "Traceback" not in log_text and '" 500 ' not in log_text,
            )
        subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=False)
    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    sys.exit(0 if all(RESULTS) else 1)


asyncio.run(main())
