"""The reconciliation queue and admin_verified (item 1.10 v2) end to end over HTTP.

A REAL central-governance-api process (uvicorn subprocess) on a THROWAWAY Postgres
(127.0.0.1:54329, user cga, trust auth) with a local fake IdP that mints RS256 tokens.
No agent-server and no Keycloak: it exercises the wire contract between an administrator
and central, which the in-process unit tests do not cross. Central's own background
sweep fails the attempts closed (the real transition to failed_unknown).

Cases:
  A  three requests end up failed / still pending / rejected: only the failed_unknown one is
     in GET /api/v1/reconciliation-queue
  B  who may read it: governance.admin only (operator, approver, superadmin are 403)
  C  the requester, who also holds governance.admin, cannot file admin_verified on her own
     request (409 cannot_verify_own_request, nothing stored) but can file her own
     requester_assertion
  D  another admin files admin_verified: 201, the record stays failed_unknown, stays in the
     list, and the admin_verified filter follows what is stored
  E  paging with limit=1 walks both records once
Then the database is read (psql) for what the API cannot show: the findings stored and the
unchanged status.

Run with the SDK venv python (cwd = the repository root); it creates and drops its own
randomly named database `central_e2e_recon_<hex>`. Both enforcement switches are forced off.

Limits: HTTP layer only; the console screen is not driven here.
"""

import asyncio
import importlib.util
import json
import os
import pathlib
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


PG = ["-h", "127.0.0.1", "-p", "54329", "-U", "cga"]
DB = f"central_e2e_recon_{uuid.uuid4().hex[:8]}"
IDP_PORT, API_PORT = 18797, 8899
ISSUER = f"http://127.0.0.1:{IDP_PORT}/realms/e2e"
AUDIENCE = "central-governance-api"
PREFIX = "e2e-recon-"

key = jwk.RSAKey.generate_key(2048, parameters={"kid": "e2e-key"})
JWKS = json.dumps({"keys": [key.as_dict(private=False)]}).encode()


def token(sub, roles):
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
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(JWKS)

    def log_message(self, *a):
        pass


def _load_digest():
    """central's digest module by file path (standard library only), so this
    interpreter does not need central's package."""
    path = pathlib.Path(CENTRAL) / "src/central_governance_api/approvals/digest.py"
    spec = importlib.util.spec_from_file_location("cga_digest", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.compute_display_digest


compute_display_digest = _load_digest()
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print(
        ("[PASS] " if ok else "[FAIL] ") + name + (f"  -- {detail}" if detail else ""),
        flush=True,
    )


def q(sql):
    return subprocess.run(
        [pg_tool("psql"), *PG, "-d", DB, "-Atc", sql],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def hdr(tok, idem=True):
    h = {"Authorization": f"Bearer {tok}"}
    if idem:
        h["Idempotency-Key"] = str(uuid.uuid4())
    return h


def build_create(case):
    fields = dict(
        action_type="terminal_command",
        tool_name="bash",
        policy_revision="e2e-recon-v1",
        action_summary=f"echo {case}",
        action_payload={"command": f"echo {case}"},
        digest_salt=None,
    )
    return {
        "request_id": f"{PREFIX}{case}-{uuid.uuid4().hex[:8]}",
        "origin_device_id": "e2e-recon-device",
        "conversation_id": "e2e-recon-conv",
        "action_event_id": f"e2e-recon-event-{case}",
        "tool_call_id": None,
        **fields,
        "action_payload_digest": compute_display_digest(
            **fields, execution_commitment=None
        ),
    }


def err_of(r):
    try:
        j = r.json()
    except Exception:
        return f"HTTP {r.status_code} (non-JSON body)"
    return f"HTTP {r.status_code} code={j.get('error_code')!r}"


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
        "CGA_DEVICE_BINDING_ENFORCED": "false",
        "CGA_REQUIRE_EXECUTION_COMMITMENT": "false",
        "CGA_EXPIRY_SWEEP_INTERVAL_SECONDS": "1",
    }
    base = f"http://127.0.0.1:{API_PORT}"
    op = token("operator-1", ["agent.operator"])
    ap = token("approver-1", ["agent.approver"])
    admin = token("admin-1", ["governance.admin"])
    owner_admin = token("owner-admin", ["agent.operator", "governance.admin"])
    logpath = os.path.join(tempfile.mkdtemp(prefix="recon_logs_"), "central.log")
    logfile = server = None
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

            async def create(case, requester_token):
                r = await c.post(
                    "/api/v1/approvals",
                    json=build_create(case),
                    headers=hdr(requester_token),
                )
                r.raise_for_status()
                return r.json()["id"]

            async def decide(aid, decision):
                r = await c.post(
                    f"/api/v1/approvals/{aid}/decide",
                    json={"decision": decision},
                    headers=hdr(ap),
                )
                r.raise_for_status()

            async def fail_closed(case, requester_token):
                """create -> accept -> claim -> the lease lapses -> central's sweep."""
                aid = await create(case, requester_token)
                await decide(aid, "accept")
                cl = await c.post(
                    f"/api/v1/approvals/{aid}/claim", headers=hdr(requester_token)
                )
                cl.raise_for_status()
                q(
                    "UPDATE pending_approval_records SET executing_lease_expires_at = "
                    f"now() - interval '2 seconds' WHERE id = '{aid}'"
                )
                for _ in range(40):
                    if (
                        q(
                            f"select status from pending_approval_records where id = '{aid}'"
                        )
                        == "failed_unknown"
                    ):
                        return aid
                    await asyncio.sleep(1)
                raise SystemExit(f"{case}: the sweep never failed the attempt closed")

            async def queue(token_, **params):
                return await c.get(
                    "/api/v1/reconciliation-queue",
                    params=params,
                    headers=hdr(token_, idem=False),
                )

            def ids(r):
                return [item["id"] for item in r.json()["items"]]

            async def finding(token_, aid, body):
                return await c.post(
                    f"/api/v1/approvals/{aid}/reconciliation-findings",
                    json=body,
                    headers=hdr(token_),
                )

            # A
            failed_a = await fail_closed("A", op)
            pending = await create("A-pending", op)
            rejected = await create("A-rejected", op)
            await decide(rejected, "reject")
            r = await queue(admin)
            check(
                "A only the failed_unknown record is in the queue",
                r.status_code == 200 and ids(r) == [failed_a],
                f"{err_of(r)} ids={ids(r) if r.status_code == 200 else None}",
            )
            check(
                "A the pending and the rejected record are not listed",
                pending not in ids(r) and rejected not in ids(r),
            )

            # B
            for who, roles in (
                ("operator", ["agent.operator"]),
                ("approver", ["agent.approver"]),
                ("superadmin", ["governance.superadmin"]),
            ):
                r = await queue(token(f"{who}-x", roles))
                check(
                    f"B {who} may not read the queue (403)",
                    r.status_code == 403,
                    err_of(r),
                )
            r = await c.get("/api/v1/reconciliation-queue")
            check("B no token is refused", r.status_code in (401, 403), err_of(r))

            # C
            failed_c = await fail_closed("C", owner_admin)
            r = await finding(
                owner_admin,
                failed_c,
                {
                    "finding_type": "admin_verified",
                    "conclusion": "confirmed_not_executed",
                },
            )
            check(
                "C the requester cannot verify her own request (409 cannot_verify_own_request)",
                r.status_code == 409
                and r.json().get("error_code") == "cannot_verify_own_request",
                err_of(r),
            )
            n = q(
                f"select count(*) from reconciliation_findings where approval_request_id = '{failed_c}'"
            )
            check("C nothing was stored by the refused finding", n == "0", f"count={n}")
            r = await finding(
                owner_admin,
                failed_c,
                {"finding_type": "requester_assertion", "note": "I did not run it"},
            )
            check(
                "C her own requester_assertion is accepted",
                r.status_code == 201,
                err_of(r),
            )

            # D
            r = await finding(
                admin,
                failed_c,
                {
                    "finding_type": "admin_verified",
                    "conclusion": "confirmed_not_executed",
                    "note": "checked the target system",
                },
            )
            check(
                "D another admin's admin_verified is accepted",
                r.status_code == 201,
                err_of(r),
            )
            status = q(
                f"select status from pending_approval_records where id = '{failed_c}'"
            )
            check(
                "D the record is still failed_unknown (a finding is evidence)",
                status == "failed_unknown",
                status,
            )
            r = await queue(admin)
            item = next((i for i in r.json()["items"] if i["id"] == failed_c), None)
            check(
                "D it stays in the list, now flagged verified, with both findings in order",
                item is not None
                and item["admin_verified"] is True
                and [f["finding_type"] for f in item["findings"]]
                == ["requester_assertion", "admin_verified"],
                str(item and [f["finding_type"] for f in item["findings"]]),
            )
            r_false = await queue(admin, admin_verified="false")
            r_true = await queue(admin, admin_verified="true")
            check(
                "D the admin_verified filter follows what is stored",
                ids(r_false) == [failed_a] and ids(r_true) == [failed_c],
                f"false={ids(r_false)} true={ids(r_true)}",
            )

            # E
            seen, cursor, pages = [], None, 0
            while True:
                params = {"limit": 1, **({"cursor": cursor} if cursor else {})}
                r = await queue(admin, **params)
                seen += ids(r)
                pages += 1
                cursor = r.json()["next_cursor"]
                if cursor is None or pages > 5:
                    break
            check(
                "E paging with limit=1 walks both records once",
                pages == 2 and sorted(seen) == sorted([failed_a, failed_c]),
                f"pages={pages} seen={seen}",
            )

        rows = q(
            "select finding_type from reconciliation_findings order by created_at"
        ).splitlines()
        check(
            "DB: exactly the two accepted findings exist",
            rows == ["requester_assertion", "admin_verified"],
            str(rows),
        )
    finally:
        if server is not None:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(server.pid), "/T", "/F"],
                    capture_output=True,
                    check=False,
                )
            else:
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
