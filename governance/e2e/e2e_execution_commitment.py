"""Execution commitment (central PR #9) end to end over HTTP.

A REAL central-governance-api process (uvicorn subprocess) on a THROWAWAY Postgres
(127.0.0.1:54329, user cga, trust auth) with a local fake IdP that mints RS256 tokens.
No agent-server and no Keycloak: it exercises the wire contract between a client and
central, which is what the unit tests (in-process ASGI) do not cross.

Cases, each against a fresh approval:
  A  happy path: create with a commitment, /wait woken by NOTIFY (not by its timeout),
     claim with the same commitment, report-result with a matching executed commitment
  B  claim with a WRONG commitment -> 409 execution_commitment_mismatch, and the failed
     attempt does not burn the approval
  C  claim with NO commitment when one is registered -> 409
  D  report-result attesting a DIFFERENT commitment is recorded, not rejected
  E  legacy flow (no commitment anywhere) still works, enforcement being off
  F  create whose digest does not cover its commitment is rejected
  G  malformed commitment -> 422
Then the database is read (psql) for what the API cannot show: `commitment_matched` per
case and the mismatch audit event.

Both enforcement switches (CGA_DEVICE_BINDING_ENFORCED, CGA_REQUIRE_EXECUTION_COMMITMENT)
are left at their defaults (off). Run with the SDK venv python (cwd = the repository
root); it creates and drops its own database `central_e2e_commit`. It does not read
central's .env and never touches the real database.

Limits: HTTP layer only; the agent-server's own use of the commitment (EventService,
real conversations) is not covered here.
"""

import asyncio
import importlib.util
import json
import os
import pathlib
import secrets
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
DB = "central_e2e_commit"
IDP_PORT, API_PORT = 18794, 8894
ISSUER = f"http://127.0.0.1:{IDP_PORT}/realms/e2e"
AUDIENCE = "central-governance-api"
PREFIX = "e2e-commit-"

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
    """central's digest module by file path: it needs only the standard library, so the
    SDK interpreter can use it without importing central's package (and its dependencies)."""
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


def commitment():
    return secrets.token_hex(32)  # 64 lowercase hex characters


def hdr(tok, idem=True):
    h = {"Authorization": f"Bearer {tok}"}
    if idem:
        h["Idempotency-Key"] = str(uuid.uuid4())
    return h


def build_create(case, c, digest_covers_commitment=True):
    fields = dict(
        action_type="terminal_command",
        tool_name="bash",
        policy_revision="e2e-commit-v1",
        action_summary=f"echo {case}",
        action_payload={"command": f"echo {case}"},
        digest_salt=None,
    )
    digest = compute_display_digest(
        **fields, execution_commitment=c if digest_covers_commitment else None
    )
    body = {
        "request_id": f"{PREFIX}{case}-{uuid.uuid4().hex[:8]}",
        "origin_device_id": "e2e-commit-device",
        "conversation_id": "e2e-commit-conv",
        "action_event_id": f"e2e-commit-event-{case}",
        "tool_call_id": None,
        **fields,
        "action_payload_digest": digest,
    }
    if c is not None:
        body["execution_commitment"] = c
    return body


def err_of(r):
    try:
        j = r.json()
    except Exception:
        return f"HTTP {r.status_code} (non-JSON body)"
    code = j.get("error_code") or (
        j.get("detail") if isinstance(j.get("detail"), str) else None
    )
    return f"HTTP {r.status_code} code={code!r}"


async def main():
    threading.Thread(
        target=ThreadingHTTPServer(("127.0.0.1", IDP_PORT), _Idp).serve_forever,
        daemon=True,
    ).start()
    subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=True)
    subprocess.run([pg_tool("createdb"), *PG, DB], check=True)
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "CGA_DATABASE_URL": f"postgresql+asyncpg://cga@127.0.0.1:54329/{DB}",
        "CGA_OIDC_ISSUER": ISSUER,
        "CGA_OIDC_JWKS_URL": f"http://127.0.0.1:{IDP_PORT}/certs",
        "CGA_OIDC_AUDIENCE": AUDIENCE,
        "CGA_OIDC_REQUIRE_HTTPS": "false",
        "CGA_PORT": str(API_PORT),
    }
    # The two switches must be off for this script to mean what it says.
    env.pop("CGA_DEVICE_BINDING_ENFORCED", None)
    env.pop("CGA_REQUIRE_EXECUTION_COMMITMENT", None)
    subprocess.run(
        [CPY, "-m", "alembic", "upgrade", "head"],
        cwd=CENTRAL,
        env=env,
        check=True,
        capture_output=True,
    )
    logpath = os.path.join(tempfile.mkdtemp(prefix="commit_logs_"), "central.log")
    logfile = open(logpath, "w", encoding="utf-8")
    server = subprocess.Popen(
        [CPY, "-c", "from central_governance_api.main import main; main()"],
        cwd=CENTRAL,
        env=env,
        stdout=logfile,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{API_PORT}"
    op = token("operator-1", ["agent.operator"])
    ap = token("approver-1", ["agent.approver"])
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

            async def create_and_accept(case, cm):
                r = await c.post(
                    "/api/v1/approvals", json=build_create(case, cm), headers=hdr(op)
                )
                if r.status_code not in (200, 201):
                    return None, r
                aid = r.json()["id"]
                d = await c.post(
                    f"/api/v1/approvals/{aid}/decide",
                    json={"decision": "accept"},
                    headers=hdr(ap),
                )
                d.raise_for_status()
                return aid, r

            async def claim(aid, cm=None):
                kw = {"json": {"execution_commitment": cm}} if cm else {}
                return await c.post(
                    f"/api/v1/approvals/{aid}/claim", headers=hdr(op), **kw
                )

            async def report(aid, attempt, executed=None):
                body = {"execution_attempt_id": attempt, "outcome": "success"}
                if executed:
                    body["executed_commitment"] = executed
                return await c.post(
                    f"/api/v1/approvals/{aid}/report-result",
                    json=body,
                    headers=hdr(op),
                )

            def applied(r):
                return r.status_code == 200 and r.json().get("status") == "applied"

            # A
            ca = commitment()
            r = await c.post(
                "/api/v1/approvals", json=build_create("A", ca), headers=hdr(op)
            )
            check(
                "A create with execution_commitment",
                r.status_code in (200, 201),
                err_of(r),
            )
            aid_a = r.json()["id"]

            async def wait_call():
                w = await c.get(
                    f"/api/v1/approvals/{aid_a}/wait",
                    params={"known_status": "pending", "timeout_seconds": 20},
                    headers=hdr(op, idem=False),
                )
                return w.json()

            async def decide_late():
                await asyncio.sleep(1.5)
                d = await c.post(
                    f"/api/v1/approvals/{aid_a}/decide",
                    json={"decision": "accept"},
                    headers=hdr(ap),
                )
                d.raise_for_status()

            t0 = time.monotonic()
            wres, _ = await asyncio.gather(wait_call(), decide_late())
            el = time.monotonic() - t0
            check(
                "A /wait woken by NOTIFY (not the 20s timeout)",
                wres.get("changed") is True
                and wres.get("status") == "accepted"
                and el < 10,
                f"{el:.2f}s",
            )
            cl = await claim(aid_a, ca)
            check(
                "A claim presenting the same commitment",
                cl.status_code == 200,
                err_of(cl),
            )
            rp = await report(aid_a, cl.json().get("execution_attempt_id"), ca)
            check(
                "A report-result with matching executed_commitment -> applied",
                applied(rp),
                err_of(rp),
            )

            # B
            cb, wrong = commitment(), commitment()
            aid_b, _ = await create_and_accept("B", cb)
            cl = await claim(aid_b, wrong)
            check(
                "B claim with a WRONG commitment -> 409 execution_commitment_mismatch",
                cl.status_code == 409 and "execution_commitment_mismatch" in cl.text,
                err_of(cl),
            )
            cl2 = await claim(aid_b, cb)
            check(
                "B failed attempt did not burn the approval: right commitment then succeeds",
                cl2.status_code == 200,
                err_of(cl2),
            )
            rp = (
                await report(aid_b, cl2.json()["execution_attempt_id"], cb)
                if cl2.status_code == 200
                else cl2
            )
            check("B report-result -> applied", applied(rp), err_of(rp))

            # C
            aid_c, _ = await create_and_accept("C", commitment())
            cl = await claim(aid_c)
            check(
                "C claim presenting NO commitment when one is registered -> 409",
                cl.status_code == 409 and "execution_commitment_mismatch" in cl.text,
                err_of(cl),
            )

            # D
            cd, other = commitment(), commitment()
            aid_d, _ = await create_and_accept("D", cd)
            cl = await claim(aid_d, cd)
            check("D claim ok", cl.status_code == 200, err_of(cl))
            rp = (
                await report(aid_d, cl.json()["execution_attempt_id"], other)
                if cl.status_code == 200
                else cl
            )
            check(
                "D report with a DIFFERENT executed_commitment is recorded, not rejected (-> applied)",
                applied(rp),
                err_of(rp),
            )

            # E
            aid_e, r = await create_and_accept("E", None)
            check(
                "E legacy create without commitment accepted (enforcement is off)",
                aid_e is not None,
                err_of(r),
            )
            cl = await claim(aid_e) if aid_e else r
            check("E legacy claim with no body", cl.status_code == 200, err_of(cl))
            rp = (
                await report(aid_e, cl.json()["execution_attempt_id"])
                if cl.status_code == 200
                else cl
            )
            check("E legacy report-result -> applied", applied(rp), err_of(rp))

            # F
            r = await c.post(
                "/api/v1/approvals",
                json=build_create("F", commitment(), digest_covers_commitment=False),
                headers=hdr(op),
            )
            check(
                "F create whose digest does not cover its commitment is rejected",
                r.status_code in (400, 409, 422),
                err_of(r),
            )

            # G
            body = build_create("G", None)
            body["execution_commitment"] = "NOT-A-VALID-COMMITMENT"
            r = await c.post("/api/v1/approvals", json=body, headers=hdr(op))
            check("G malformed commitment -> 422", r.status_code == 422, err_of(r))

        rows = {}
        for line in q(
            "select split_part(request_id, '-', 3), id, commitment_matched, "
            "execution_commitment is not null, executed_commitment is not null "
            f"from pending_approval_records where request_id like '{PREFIX}%'"
        ).splitlines():
            case, rid, matched, has_reg, has_att = line.split("|")
            rows[case] = (rid, matched, has_reg, has_att)
        check(
            "DB: A matched = true", rows.get("A", (0, 0))[1] == "t", str(rows.get("A"))
        )
        check(
            "DB: D matched = false (mismatch recorded)",
            rows.get("D", (0, 0))[1] == "f",
            str(rows.get("D")),
        )
        check(
            "DB: E (legacy) has no commitment columns set and matched unset",
            rows.get("E", (0, "x", "x", "x"))[1:] == ("", "f", "f"),
            str(rows.get("E")),
        )
        n = (
            q(
                "select count(*) from admin_audit_events where approval_request_id = "
                f"'{rows['D'][0]}' and event_type = 'approval_executed_commitment_mismatch'"
            )
            if "D" in rows
            else "none"
        )
        check(
            "DB: D wrote an approval_executed_commitment_mismatch audit event",
            n == "1",
            f"count={n}",
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
