"""End-to-end smoke for the account-request flow against a REAL central
process (uvicorn, real lifespan, real asyncpg pool) on a throwaway Postgres,
with a local fake IdP (JWKS over HTTP, tokens signed here) and a local SMTP
sink. Not covered by the unit tests: lifespan wiring (mailer built from
settings), router mounting, exception handlers, real SMTP wire exchange.

Run with the central venv python. Needs the throwaway Postgres on 54329.
It creates and drops its own database `central_e2e` (never the test DB).
"""

import asyncio
import json
import os
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
from joserfc import jwk, jwt

from ohs_env import CENTRAL as ROOT, CPY as PY, pg_tool


PG = ["-h", "127.0.0.1", "-p", "54329", "-U", "cga"]
DB = "central_e2e"
JWKS_PORT, SMTP_PORT, API_PORT = 18770, 18771, 8898
ISSUER = f"http://127.0.0.1:{JWKS_PORT}/realms/e2e"
AUDIENCE = "central-governance-api"

key = jwk.RSAKey.generate_key(2048, parameters={"kid": "e2e-key"})
JWKS = json.dumps({"keys": [key.as_dict(private=False)]}).encode()


class _Jwks(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(JWKS)

    def log_message(self, *a):
        pass


def token(sub, roles=(), **claims):
    now = int(time.time())
    body = {
        "iss": ISSUER,
        "sub": sub,
        "aud": AUDIENCE,
        "exp": now + 600,
        "iat": now,
        "roles": list(roles),
        **claims,
    }
    return jwt.encode({"alg": "RS256", "kid": "e2e-key"}, body, key)


mails: list[str] = []


async def _smtp(reader, writer):
    writer.write(b"220 sink\r\n")
    while True:
        line = (await reader.readline()).decode(errors="replace").strip()
        if not line:
            break
        verb = line.split(" ", 1)[0].upper()
        if verb == "DATA":
            writer.write(b"354 go\r\n")
            await writer.drain()
            mails.append(
                (await reader.readuntil(b"\r\n.\r\n")).decode(errors="replace")
            )
            writer.write(b"250 queued\r\n")
        elif verb == "QUIT":
            writer.write(b"221 bye\r\n")
            await writer.drain()
            break
        else:
            writer.write(b"250 OK\r\n")
        await writer.drain()
    writer.close()


results: list[tuple[str, bool, str]] = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


def psql(*args):
    return subprocess.run(
        [pg_tool("psql"), *PG, *args], capture_output=True, text=True, check=True
    )


async def main():
    threading.Thread(
        target=HTTPServer(("127.0.0.1", JWKS_PORT), _Jwks).serve_forever, daemon=True
    ).start()
    smtp_server = await asyncio.start_server(_smtp, "127.0.0.1", SMTP_PORT)

    subprocess.run([pg_tool("createdb"), *PG, DB], check=True)
    url = f"postgresql+asyncpg://cga@127.0.0.1:54329/{DB}"
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "CGA_DATABASE_URL": url,
        "CGA_OIDC_ISSUER": ISSUER,
        "CGA_OIDC_JWKS_URL": f"http://127.0.0.1:{JWKS_PORT}/certs",
        "CGA_OIDC_AUDIENCE": AUDIENCE,
        "CGA_OIDC_REQUIRE_HTTPS": "false",
        "CGA_ACCOUNT_REQUESTS_ENABLED": "true",
        "CGA_ACCOUNT_EMAIL_DOMAINS": '["corp.example"]',
        "CGA_ACCOUNT_REQUEST_HMAC_KEY": "e2e-" + "x" * 40,
        "CGA_SMTP_HOST": "127.0.0.1",
        "CGA_SMTP_PORT": str(SMTP_PORT),
        "CGA_SMTP_FROM": "ohs@corp.example",
        "CGA_SMTP_STARTTLS": "false",
        "CGA_PORT": str(API_PORT),
    }
    subprocess.run(
        [PY, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
    )
    server = subprocess.Popen(
        [PY, "-c", "from central_governance_api.main import main; main()"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
    )
    base = f"http://127.0.0.1:{API_PORT}"
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
            email = "applicant@corp.example"

            r = await c.post(
                "/api/v1/admin/departments", json={"name": "Finance"}, headers=sup
            )
            check("superadmin creates a department", r.status_code == 201, r.text[:80])
            dept_id = r.json()["id"]

            r = await c.post(
                "/api/v1/account-requests",
                json={
                    "email": "x@evil.example",
                    "display_name": "X",
                    "requested_department": "Finance",
                },
            )
            check(
                "foreign domain refused",
                r.status_code == 422 and not mails,
                str(r.status_code),
            )

            r = await c.post(
                "/api/v1/account-requests",
                json={
                    "email": email,
                    "display_name": "Applicant",
                    "requested_department": "Finance",
                    "reason": "e2e",
                },
            )
            check("submit accepted", r.status_code == 202, r.text)
            await asyncio.sleep(0.3)
            check("verification e-mail arrived over real SMTP", len(mails) == 1)
            code = re.search(r"：([A-Z2-9]{8})", mails[0]).group(1) if mails else ""
            check("mail addressed to applicant", email in (mails[0] if mails else ""))

            r = await c.post(
                "/api/v1/account-requests/verify",
                json={"email": email, "code": "AAAAAAAA"},
            )
            check("wrong code refused", r.status_code == 400)
            r = await c.post(
                "/api/v1/account-requests/verify", json={"email": email, "code": code}
            )
            check(
                "right code moves to review",
                r.status_code == 200 and r.json()["status"] == "pending_review",
                r.text,
            )

            r = await c.get("/api/v1/admin/account-requests", headers=sup)
            rows = r.json()
            check(
                "superadmin sees it awaiting review",
                [x["email"] for x in rows] == [email],
            )
            req_id = rows[0]["id"] if rows else ""

            plain = {
                "Authorization": "Bearer " + token("someone", ["governance.admin"])
            }
            r = await c.get("/api/v1/admin/account-requests", headers=plain)
            check("governance.admin cannot review accounts", r.status_code == 403)

            r = await c.post(
                f"/api/v1/admin/account-requests/{req_id}/approve",
                json={"department_id": dept_id},
                headers=sup,
            )
            check(
                "approve",
                r.status_code == 200 and r.json()["status"] == "approved",
                r.text[:100],
            )
            r = await c.post(
                f"/api/v1/admin/account-requests/{req_id}/approve",
                json={"department_id": dept_id},
                headers=sup,
            )
            check("replayed approve is 409", r.status_code == 409)

            r = await c.get("/api/v1/admin/memberships?unbound=true", headers=sup)
            check(
                "membership listed as unbound",
                [m["email"] for m in r.json()] == [email],
            )

            first = {
                "Authorization": "Bearer "
                + token("kc-user-1", [], email=email, email_verified=True)
            }
            r = await c.get("/api/v1/me", headers=first)
            check(
                "first login binds the department",
                r.status_code == 200
                and (r.json()["membership"] or {}).get("department_name") == "Finance",
                r.text[:120],
            )

            second = {
                "Authorization": "Bearer "
                + token("kc-user-2", [], email=email, email_verified=True)
            }
            r = await c.get("/api/v1/me", headers=second)
            check(
                "second identity with same e-mail gets nothing",
                r.json()["membership"] is None,
            )

            r = await c.get("/api/v1/admin/memberships?unbound=true", headers=sup)
            check("no longer listed as unbound", r.json() == [])

            audit = psql(
                "-d",
                DB,
                "-Atc",
                "select event_type from admin_audit_events order by occurred_at, event_type",
            ).stdout.split()
            check(
                "audit trail has create/approve/bind",
                {"department_created", "account_request_approved", "membership_bound"}
                <= set(audit),
                str(audit),
            )
    finally:
        server.terminate()
        try:
            out, _ = server.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            out, _ = server.communicate()
        smtp_server.close()
        if len(results) < 3:
            print((out or "")[-3000:])
        errors = [
            l for l in (out or "").splitlines() if "Traceback" in l or " 500 " in l
        ]
        check("server log has no traceback / 5xx", not errors, str(errors[:2]))
        subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=False)

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)


asyncio.run(main())
