"""central (temp Postgres, enforcement ON) validated with REAL Keycloak tokens.

Tokens come from the local Keycloak's test identities (client-credentials,
secrets read from the environment variables the project's own ops tooling
uses; never printed). central takes issuer/JWKS/audience from its own .env,
but CGA_DATABASE_URL is overridden so the REAL database is never touched.

What this proves that the fake-IdP runs could not: central accepts real
Keycloak tokens on the new endpoints, the real `roles` claim shape works with
the superadmin/admin separation, and a department assignment keyed on the real
service-account `sub` is what the real token resolves to.

Limit: no superadmin token exists yet (a human with governance.superadmin has
to be created by Roy), so the department data is seeded with SQL into the TEMP
database instead of through the superadmin API (that API is covered by tests).
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


os.environ.setdefault("OPENHANDS_SUPPRESS_BANNER", "1")

from ohs_env import CENTRAL, CPY, pg_tool
from openhands.agent_server.governance_client import (  # noqa: E402
    GovernanceClient,
    GovernancePermanentError,
    compute_display_digest,
)


PG = ["-h", "127.0.0.1", "-p", "54329", "-U", "cga"]
DB = "central_e2e_kc"
API_PORT = 8894
TOKEN_URL = "http://localhost:8080/realms/roy-governance/protocol/openid-connect/token"
CLIENTS = {
    "operator": ("cga-test-operator", "CGA_TEST_OPERATOR_SECRET"),
    "approver": ("cga-test-approver", "CGA_TEST_APPROVER_SECRET"),
    "admin": ("cga-test-admin", "CGA_TEST_ADMIN_SECRET"),
}
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


def psql(sql):
    return subprocess.run(
        [pg_tool("psql"), *PG, "-d", DB, "-Atc", sql],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


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


def body(tool_name):
    base = {
        "request_id": uuid.uuid4().hex,
        "origin_device_id": "device-kc",
        "conversation_id": "conv-kc",
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
        action_type="tool_call",
        tool_name=tool_name,
        policy_revision="v1",
        action_summary="do it",
        action_payload=base["action_payload"],
        digest_salt="salt",
    )
    return base


async def main():
    for _, env_name in CLIENTS.values():
        assert os.environ.get(env_name), f"{env_name} not set"
    subprocess.run([pg_tool("createdb"), *PG, DB], check=True)
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "CGA_DATABASE_URL": f"postgresql+asyncpg://cga@127.0.0.1:54329/{DB}",
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
    logdir = tempfile.mkdtemp(prefix="kc_logs_")
    logfile = open(os.path.join(logdir, "central.log"), "w", encoding="utf-8")
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
                    await asyncio.sleep(0.5)
            else:
                raise SystemExit("central did not start")
            tokens = {who: await real_token(c, who) for who in CLIENTS}
            op = claims(tokens["operator"])
            check(
                "real operator token carries a flat 'roles' claim",
                isinstance(op.get("roles"), list) and "agent.operator" in op["roles"],
                f"roles={op.get('roles')} azp={op.get('azp')}",
            )
            issuer, op_sub = op["iss"], op["sub"]
            auth = {k: {"Authorization": "Bearer " + v} for k, v in tokens.items()}

            r = await c.get("/api/v1/me/tool-permissions", headers=auth["operator"])
            check(
                "real token accepted on the new endpoint; unassigned account gets nothing",
                r.status_code == 200
                and r.json()["tools"] == []
                and r.json()["department_id"] is None,
                r.text[:90],
            )

            r = await c.post(
                "/api/v1/admin/departments", json={"name": "X"}, headers=auth["admin"]
            )
            check(
                "governance.admin (real token) cannot use the superadmin endpoints",
                r.status_code == 403,
                f"HTTP {r.status_code}",
            )
            r = await c.post(
                "/api/v1/admin/departments",
                json={"name": "X"},
                headers=auth["operator"],
            )
            check("agent.operator (real token) cannot either", r.status_code == 403)

            # Seed department data directly into the TEMP database.
            dept = str(uuid.uuid4())
            psql(f"insert into departments (id, name) values ('{dept}', 'Finance')")
            psql(
                f"insert into department_tool_permissions (department_id, tool_name, granted_by_issuer, granted_by_sub) values ('{dept}', 'file_editor', '{issuer}', 'seed')"
            )
            psql(
                f"insert into department_principals (id, department_id, issuer, sub, assigned_by_issuer, assigned_by_sub) values ('{uuid.uuid4()}', '{dept}', '{issuer}', '{op_sub}', '{issuer}', 'seed')"
            )

            r = await c.get("/api/v1/me/tool-permissions", headers=auth["operator"])
            got = r.json()
            check(
                "the real service-account sub resolves to the department and its tools",
                got.get("department_name") == "Finance"
                and got.get("tools") == ["file_editor"],
                f"{got.get('department_name')} {got.get('tools')}",
            )

            device = GovernanceClient(
                base_url=base,
                token_url=TOKEN_URL,
                client_id=CLIENTS["operator"][0],
                client_secret=os.environ[CLIENTS["operator"][1]],
            )
            try:
                created = await device.create_approval(
                    body("file_editor"), idempotency_key="k1"
                )
                check("real GovernanceClient: permitted tool accepted", "id" in created)
                try:
                    await device.create_approval(body("terminal"), idempotency_key="k2")
                    check("real GovernanceClient: unpermitted tool refused", False)
                except GovernancePermanentError as exc:
                    check(
                        "real GovernanceClient: unpermitted tool refused",
                        exc.status_code == 403
                        and exc.error_code == "tool_not_permitted",
                        f"{exc.status_code} {exc.error_code}",
                    )

                r = await c.post(
                    f"/api/v1/approvals/{created['id']}/decide",
                    json={"decision": "accept"},
                    headers={**auth["approver"], "Idempotency-Key": "d1"},
                )
                check(
                    "real approver token accepts",
                    r.status_code == 200,
                    f"HTTP {r.status_code}",
                )
                psql("delete from department_tool_permissions")
                try:
                    await device.claim(created["id"], idempotency_key="k3")
                    check("claim refused after revocation", False)
                except GovernancePermanentError as exc:
                    check(
                        "claim refused after revocation (real tokens)",
                        exc.error_code == "tool_not_permitted",
                    )
            finally:
                await device.aclose()
    finally:
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
        logfile.close()
        text = open(
            os.path.join(logdir, "central.log"), encoding="utf-8", errors="replace"
        ).read()
        bad = [l for l in text.splitlines() if "Traceback" in l or " 500 " in l]
        check("central log has no traceback / 5xx", not bad, str(bad[:2]))
        subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=False)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)


asyncio.run(main())
