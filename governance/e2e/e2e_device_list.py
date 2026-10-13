"""End-to-end check of GET /api/v1/devices: REAL central-governance-api (uvicorn subprocess,
this branch) on a THROWAWAY Postgres (127.0.0.1:54329) with REAL Keycloak service-account
tokens (operator, approver, admin). Central's own .env supplies issuer/JWKS/audience;
CGA_DATABASE_URL is overridden so the REAL database is never touched. Secrets come from the
environment and are never printed. Run with central's venv python.
"""

import asyncio
import base64
import json
import os
import subprocess
import sys
import tempfile
import uuid

import httpx

from ohs_env import CENTRAL, CPY, pg_tool


PG = ["-h", "127.0.0.1", "-p", "54329", "-U", "cga"]
DB = "central_e2e_devlist"
API_PORT = 8896
TOKEN_URL = "http://localhost:8080/realms/roy-governance/protocol/openid-connect/token"
CLIENTS = {
    "operator": ("cga-test-operator", "CGA_TEST_OPERATOR_SECRET"),
    "approver": ("cga-test-approver", "CGA_TEST_APPROVER_SECRET"),
    "admin": ("cga-test-admin", "CGA_TEST_ADMIN_SECRET"),
}
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print(
        ("[PASS] " if ok else "[FAIL] ") + name + (f"  -- {detail}" if detail else ""),
        flush=True,
    )


def claims(jwt_text):
    payload = jwt_text.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


async def real_token(http, who):
    client_id, env_name = CLIENTS[who]
    r = await http.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": os.environ[env_name],
        },
    )
    r.raise_for_status()
    return r.json()["access_token"]


async def main():
    for _, env_name in CLIENTS.values():
        assert os.environ.get(env_name), f"{env_name} not set"
    subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=False)
    subprocess.run([pg_tool("createdb"), *PG, DB], check=True)
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "CGA_DATABASE_URL": f"postgresql+asyncpg://cga@127.0.0.1:54329/{DB}",
        "CGA_PORT": str(API_PORT),
    }
    subprocess.run(
        [CPY, "-m", "alembic", "upgrade", "head"],
        cwd=CENTRAL,
        env=env,
        check=True,
        capture_output=True,
    )
    logpath = os.path.join(tempfile.mkdtemp(prefix="devlist_logs_"), "central.log")
    logfile = open(logpath, "w", encoding="utf-8")
    server = subprocess.Popen(
        [CPY, "-c", "from central_governance_api.main import main; main()"],
        cwd=CENTRAL,
        env=env,
        stdout=logfile,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{API_PORT}"
    try:
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
            tokens = {who: await real_token(c, who) for who in CLIENTS}
            auth = {k: {"Authorization": "Bearer " + v} for k, v in tokens.items()}
            op_sub = claims(tokens["operator"])["sub"]
            admin_sub = claims(tokens["admin"])["sub"]
            check(
                "real admin token carries governance.admin",
                "governance.admin" in (claims(tokens["admin"]).get("roles") or []),
            )

            dev = f"e2e-list-{uuid.uuid4().hex[:8]}"
            r = await c.post(
                "/api/v1/devices/register",
                json={"device_id": dev},
                headers={**auth["operator"], "Idempotency-Key": str(uuid.uuid4())},
            )
            check(
                "operator registers a device", r.status_code == 201, str(r.status_code)
            )
            reg_id = r.json()["id"]

            r = await c.get("/api/v1/devices", headers=auth["operator"])
            items = r.json()["items"]
            check(
                "operator lists its own device",
                r.status_code == 200 and [i["id"] for i in items] == [reg_id],
                str([i["device_id"] for i in items]),
            )
            check(
                "every listed owner is the operator",
                all(i["owner_subject"].endswith("#" + op_sub) for i in items),
            )

            r = await c.get("/api/v1/devices", headers=auth["approver"])
            check(
                "a different (non-admin) principal does not see it",
                r.status_code == 200
                and reg_id not in [i["id"] for i in r.json()["items"]],
                str(len(r.json()["items"])) + " items",
            )

            r = await c.get(
                "/api/v1/devices", headers=auth["admin"], params={"limit": 200}
            )
            check(
                "admin sees the operator's device",
                r.status_code == 200 and reg_id in [i["id"] for i in r.json()["items"]],
            )

            r = await c.post(
                f"/api/v1/devices/{reg_id}/revoke",
                headers={**auth["admin"], "Idempotency-Key": str(uuid.uuid4())},
            )
            check("admin revokes it", r.status_code == 200, str(r.status_code))
            items = (await c.get("/api/v1/devices", headers=auth["operator"])).json()[
                "items"
            ]
            check(
                "list shows revoked_at and who revoked it",
                items[0]["revoked_at"] is not None
                and items[0]["revoked_by_subject"].endswith("#" + admin_sub),
                str(items[0]["revoked_by_subject"] is not None),
            )
            r = await c.get(
                "/api/v1/devices",
                headers=auth["operator"],
                params={"include_revoked": "false"},
            )
            check(
                "include_revoked=false hides it",
                r.status_code == 200 and r.json()["items"] == [],
            )

            check(
                "no token -> 401", (await c.get("/api/v1/devices")).status_code == 401
            )
            spec = (await c.get("/openapi.json")).json()
            check(
                "route is published in OpenAPI",
                "get" in spec["paths"].get("/api/v1/devices", {}),
            )
    finally:
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
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
