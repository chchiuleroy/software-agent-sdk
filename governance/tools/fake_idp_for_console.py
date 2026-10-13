"""Throwaway test rig for the OHS console (/inbox) login shell. NOT for production.

Starts, on a throwaway Postgres (127.0.0.1:54329, user cga, trust auth):
  * a fake OIDC provider that serves discovery, JWKS, an authorization page where
    you pick which test person signs in, and a token endpoint that CHECKS PKCE
    (S256 verifier against the stored challenge) and the exact redirect_uri;
  * a real central-governance-api with the inbox enabled (client id ohs-console).
Then it prints the URL and waits until you stop it (Ctrl+C / kill).

Test people (pick one on the sign-in page):
  ada     no roles, verified e-mail, no department
  bob     agent.approver
  root    governance.superadmin
  dual    agent.approver + governance.superadmin
  adm     governance.admin + agent.operator (must unlock nothing)

Run with the central venv python:
  <central>/.venv/Scripts/python.exe governance/tools/fake_idp_for_console.py
"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
from joserfc import jwk, jwt

from ohs_env import CENTRAL, CPY, pg_tool


PG = ["-h", "127.0.0.1", "-p", "54329", "-U", "cga"]
DB = "central_console_rig"
IDP_PORT, API_PORT = 18795, 8895
ISSUER = f"http://127.0.0.1:{IDP_PORT}/realms/rig"
AUDIENCE = "central-governance-api"
CLIENT_ID = "ohs-console"
ORIGIN = f"http://127.0.0.1:{API_PORT}"

PEOPLE = {
    "ada": dict(name="Ada Lovelace", email="ada@example.com", verified=True, roles=[]),
    "bob": dict(
        name="Bob Approver",
        email="bob@example.com",
        verified=True,
        roles=["agent.approver"],
    ),
    "root": dict(
        name="Root Superadmin",
        email="root@example.com",
        verified=True,
        roles=["governance.superadmin"],
    ),
    "dual": dict(
        name="Dual Role",
        email="dual@example.com",
        verified=True,
        roles=["agent.approver", "governance.superadmin"],
    ),
    "adm": dict(
        name="Admin Only",
        email="adm@example.com",
        verified=False,
        roles=["governance.admin", "agent.operator"],
    ),
}

key = jwk.RSAKey.generate_key(2048, parameters={"kid": "rig-key"})
JWKS = json.dumps({"keys": [key.as_dict(private=False)]}).encode()
CODES: dict[str, dict] = {}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def access_token(who: str) -> str:
    p = PEOPLE[who]
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": f"rig-{who}",
        "aud": AUDIENCE,
        "azp": CLIENT_ID,
        "exp": now + 3600,
        "iat": now,
        "roles": p["roles"],
        "preferred_username": who,
        "name": p["name"],
        "email": p["email"],
        "email_verified": p["verified"],
    }
    return jwt.encode({"alg": "RS256", "kid": "rig-key"}, claims, key)


class Idp(BaseHTTPRequestHandler):
    def _send(self, body: bytes, status=200, ctype="application/json", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", ORIGIN)  # the console calls us
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        url = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(url.query))
        base = f"http://127.0.0.1:{IDP_PORT}/realms/rig"
        if url.path.endswith("/.well-known/openid-configuration"):
            self._send(
                json.dumps(
                    {
                        "issuer": ISSUER,
                        "authorization_endpoint": base
                        + "/protocol/openid-connect/auth",
                        "token_endpoint": base + "/protocol/openid-connect/token",
                        "jwks_uri": base + "/protocol/openid-connect/certs",
                    }
                ).encode()
            )
        elif url.path.endswith("/certs"):
            self._send(JWKS)
        elif url.path.endswith("/auth"):
            if (
                q.get("client_id") != CLIENT_ID
                or q.get("code_challenge_method") != "S256"
                or q.get("response_type") != "code"
                or not q.get("code_challenge")
                or q.get("redirect_uri") != f"{ORIGIN}/inbox"
            ):
                self._send(b"bad authorization request", 400, "text/plain")
                return
            if "who" in q:
                code = secrets.token_urlsafe(16)
                CODES[code] = {
                    "who": q["who"],
                    "challenge": q["code_challenge"],
                    "redirect_uri": q["redirect_uri"],
                }
                target = (
                    q["redirect_uri"]
                    + "?"
                    + urllib.parse.urlencode({"code": code, "state": q["state"]})
                )
                self._send(b"", 302, "text/plain", {"Location": target})
                return
            links = "".join(
                f'<li><a href="?{urllib.parse.urlencode({**q, "who": w})}">{w}</a> '
                f"({', '.join(p['roles']) or 'no roles'})</li>"
                for w, p in PEOPLE.items()
            )
            self._send(
                f"<h1>Fake sign-in</h1><ul>{links}</ul>".encode(), 200, "text/html"
            )
        else:
            self._send(b"{}", 404)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        form = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode()))
        entry = CODES.pop(form.get("code", ""), None)  # a code works once
        challenge = b64url(
            hashlib.sha256(form.get("code_verifier", "").encode()).digest()
        )
        if (
            form.get("grant_type") != "authorization_code"
            or entry is None
            or form.get("client_id") != CLIENT_ID
            or form.get("redirect_uri") != entry["redirect_uri"]
            or challenge != entry["challenge"]
        ):
            self._send(json.dumps({"error": "invalid_grant"}).encode(), 400)
            return
        self._send(
            json.dumps(
                {
                    "access_token": access_token(entry["who"]),
                    "expires_in": 3600,
                    "token_type": "Bearer",
                }
            ).encode()
        )

    def do_OPTIONS(self):  # noqa: N802
        self._send(b"", 204, extra={"Access-Control-Allow-Headers": "*"})

    def log_message(self, *a):
        pass


def seed_devices() -> None:
    """60 registrations (the per-account quota is 20): ada, bob and root own 20
    each, root registers last so its rows come first; root then revokes two of
    other people's devices. Lets the Devices screen show paging, '(you)' and
    revoked rows."""
    base = f"http://127.0.0.1:{API_PORT}"
    hdr = lambda who: {"Authorization": "Bearer " + access_token(who)}  # noqa: E731
    with httpx.Client(base_url=base, timeout=20) as c:
        for _ in range(60):
            try:
                if c.get("/healthz").status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.5)
        else:
            raise SystemExit("central did not start")
        ids = {}
        for who in ("ada", "bob", "root"):
            for n in range(1, 21):
                name = (
                    "root-laptop" if (who, n) == ("root", 1) else f"{who}-dev-{n:02d}"
                )
                r = c.post(
                    "/api/v1/devices/register",
                    json={"device_id": name},
                    headers={**hdr(who), "Idempotency-Key": secrets.token_hex(8)},
                )
                r.raise_for_status()
                ids[name] = r.json()["id"]
        for name in ("ada-dev-03", "bob-dev-02"):
            c.post(
                f"/api/v1/devices/{ids[name]}/revoke",
                headers={**hdr("root"), "Idempotency-Key": secrets.token_hex(8)},
            ).raise_for_status()


def psql(*args):
    return subprocess.run(
        [pg_tool("psql"), *PG, *args], capture_output=True, text=True, check=True
    )


def main():
    threading.Thread(
        target=ThreadingHTTPServer(("127.0.0.1", IDP_PORT), Idp).serve_forever,
        daemon=True,
    ).start()
    subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=True)
    subprocess.run([pg_tool("createdb"), *PG, DB], check=True)
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "CGA_DATABASE_URL": f"postgresql+asyncpg://cga@127.0.0.1:54329/{DB}",
        "CGA_OIDC_ISSUER": ISSUER,
        "CGA_OIDC_JWKS_URL": f"http://127.0.0.1:{IDP_PORT}/realms/rig/protocol/openid-connect/certs",
        "CGA_OIDC_AUDIENCE": AUDIENCE,
        "CGA_OIDC_REQUIRE_HTTPS": "false",
        "CGA_INBOX_OIDC_CLIENT_ID": CLIENT_ID,
        "CGA_HOST": "127.0.0.1",
        "CGA_PORT": str(API_PORT),
    }
    subprocess.run(
        [CPY, "-m", "alembic", "upgrade", "head"],
        cwd=CENTRAL,
        env=env,
        check=True,
        capture_output=True,
    )
    central = subprocess.Popen(
        [CPY, "-c", "from central_governance_api.main import main; main()"],
        cwd=CENTRAL,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        seed_devices()
        print(f"READY  open {ORIGIN}/inbox   (Ctrl+C to stop)", flush=True)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        central.terminate()
        try:
            central.wait(timeout=15)
        except subprocess.TimeoutExpired:
            central.kill()
        subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=False)


if __name__ == "__main__":
    sys.exit(main())
