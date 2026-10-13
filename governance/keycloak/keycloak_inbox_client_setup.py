# ruff: noqa: E501  (ops script outside any repo; long lines are URLs and messages)
"""Register the browser sign-in client ("A1") for the OHS console, run BY ROY.

Why this exists: creating a Keycloak client needs the admin password, and the
assistant must never receive that password. This script prompts for it with
hidden input, uses it only to get a token from the master realm, and never
prints it or the token.

What it does (every WRITE asks y/N first; reads are free):
  1. Looks for the client (default id "ohs-console").
  2. Creates it as a PUBLIC client for Authorization Code + PKCE (S256), with
     the exact redirect URIs and Web Origins of this service's /inbox page.
     No client secret exists; direct-access (password) grants stay OFF.
  3. Adds the two protocol mappers central needs in the access token: the
     audience (central-governance-api) and the flat realm-role "roles" claim
     (same definitions as ops/kc_mapper_audience.json and kc_mapper_roles.json).
  4. Optionally asks Keycloak for an EXAMPLE access token for one user and
     prints only the non-secret claims (iss, aud, azp, roles, email_verified)
     so you can see that the roles and audience will really be there.
  5. Prints the one line to add to central's .env (it does NOT edit .env).

Run (normal PowerShell or CMD; NO Windows administrator rights are needed —
the password is Keycloak's admin password, not a Windows one):
  <central>/.venv/Scripts/python.exe governance/keycloak/keycloak_inbox_client_setup.py

Defaults: server http://localhost:8080, realm roy-governance, client ohs-console,
central on port 8899 (opened as localhost or 127.0.0.1, both are registered).
Override with --server / --realm / --client-id / --port / --audience.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Callable

import httpx


DEFAULT_CLIENT_ID = "ohs-console"
MAPPER_NAMES = ("audience", "realm-roles-flat")


def mappers(audience: str) -> list[dict]:
    return [
        {
            "name": "audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.custom.audience": audience,
                "access.token.claim": "true",
            },
        },
        {
            "name": "realm-roles-flat",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-realm-role-mapper",
            "config": {
                "claim.name": "roles",
                "jsonType.label": "String",
                "multivalued": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
    ]


def client_representation(client_id: str, port: int) -> dict:
    hosts = [f"http://localhost:{port}", f"http://127.0.0.1:{port}"]
    return {
        "clientId": client_id,
        "name": "OHS console (browser sign-in)",
        "protocol": "openid-connect",
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "implicitFlowEnabled": False,
        "serviceAccountsEnabled": False,
        "fullScopeAllowed": True,
        "redirectUris": [f"{host}/inbox" for host in hosts],
        "webOrigins": hosts,
        "attributes": {"pkce.code.challenge.method": "S256"},
    }


class AdminApi:
    def __init__(self, client: httpx.Client, server: str, realm: str) -> None:
        self.client = client
        self.server = server.rstrip("/")
        self.realm = realm
        self._headers: dict[str, str] = {}

    def login(self, username: str, password: str) -> None:
        response = self.client.post(
            f"{self.server}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": username,
                "password": password,
            },
        )
        if response.status_code != 200:
            # Status only: the body could echo request details.
            raise SystemExit(f"admin login failed (HTTP {response.status_code})")
        self._headers = {"Authorization": "Bearer " + response.json()["access_token"]}

    def get(self, path: str, **params) -> httpx.Response:
        return self.client.get(
            f"{self.server}/admin/realms/{self.realm}{path}",
            headers=self._headers,
            params=params or None,
        )

    def post(self, path: str, json) -> httpx.Response:
        return self.client.post(
            f"{self.server}/admin/realms/{self.realm}{path}",
            headers=self._headers,
            json=json,
        )


def find_client(api: AdminApi, client_id: str) -> dict | None:
    response = api.get("/clients", clientId=client_id)
    response.raise_for_status()
    found = [c for c in response.json() if c.get("clientId") == client_id]
    return found[0] if found else None


def report_client(client: dict, out: Callable[[str], None]) -> None:
    out(
        f"  publicClient={client.get('publicClient')} standardFlow={client.get('standardFlowEnabled')}"
        f" directAccessGrants={client.get('directAccessGrantsEnabled')}"
    )
    out(
        f"  pkce.code.challenge.method={client.get('attributes', {}).get('pkce.code.challenge.method')!r}"
        f" fullScopeAllowed={client.get('fullScopeAllowed')}"
    )
    out(f"  redirectUris={client.get('redirectUris')}")
    out(f"  webOrigins={client.get('webOrigins')}")


def ensure_client(api, client_id, port, ask, out) -> dict | None:
    out(f"\n== 1. Client '{client_id}' ==")
    client = find_client(api, client_id)
    if client is not None:
        out("  already exists (not modified):")
        report_client(client, out)
        return client
    rep = client_representation(client_id, port)
    out("  does not exist. It would be created with:")
    report_client(rep, out)
    if ask("  Create it now? [y/N] ").strip().lower() != "y":
        out("  skipped")
        return None
    created = api.post("/clients", rep)
    out(f"  create -> HTTP {created.status_code}")
    if created.status_code != 201:
        return None
    return find_client(api, client_id)


def ensure_mappers(api, client, audience, ask, out) -> None:
    out("\n== 2. Mappers on the client ==")
    present = {m.get("name") for m in (client.get("protocolMappers") or [])}
    if not present:
        fresh = api.get(f"/clients/{client['id']}").json()
        present = {m.get("name") for m in (fresh.get("protocolMappers") or [])}
    for mapper in mappers(audience):
        if mapper["name"] in present:
            out(f"  {mapper['name']}: already present")
            continue
        if ask(f"  Add mapper '{mapper['name']}'? [y/N] ").strip().lower() != "y":
            out("  skipped")
            continue
        response = api.post(f"/clients/{client['id']}/protocol-mappers/models", mapper)
        out(f"  {mapper['name']}: add -> HTTP {response.status_code}")


def example_token(api, client, ask, out) -> None:
    out("\n== 3. Check what a token for one user would carry (optional) ==")
    username = ask("  Username to check (empty = skip): ").strip()
    if not username:
        out("  skipped")
        return
    users = api.get("/users", username=username, exact="true").json()
    if not users:
        out("  no such user")
        return
    response = api.get(
        f"/clients/{client['id']}/evaluate-scopes/generate-example-access-token",
        userId=users[0]["id"],
        scope="openid",
    )
    if response.status_code != 200:
        out(f"  could not generate an example token (HTTP {response.status_code})")
        return
    claims = response.json()
    for key in ("iss", "aud", "azp", "roles", "email", "email_verified"):
        out(f"  {key} = {claims.get(key)!r}")
    roles = claims.get("roles") or []
    out(
        "  -> 'governance.superadmin' present: " + str("governance.superadmin" in roles)
    )


def run(api, client_id, port, audience, ask, out=print) -> None:
    client = ensure_client(api, client_id, port, ask, out)
    if client is not None:
        ensure_mappers(api, client, audience, ask, out)
        example_token(api, client, ask, out)
        out(
            "\n== 4. Turn the page on in central ==\n"
            f"  Add this line to central-governance-api/.env and restart central:\n"
            f"    CGA_INBOX_OIDC_CLIENT_ID={client_id}\n"
            f"  Then open http://localhost:{port}/inbox"
        )
    out("\nDone. Nothing secret was printed.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--server", default="http://localhost:8080")
    parser.add_argument("--realm", default="roy-governance")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--audience", default="central-governance-api")
    args = parser.parse_args(argv)
    username = input("Keycloak admin username [admin]: ").strip() or "admin"
    password = getpass.getpass("Keycloak admin password (hidden): ")
    with httpx.Client(timeout=20) as client:
        api = AdminApi(client, args.server, args.realm)
        api.login(username, password)
        del password
        run(api, args.client_id, args.port, args.audience, input)
    return 0


if __name__ == "__main__":
    sys.exit(main())
