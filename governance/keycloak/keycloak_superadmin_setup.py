# ruff: noqa: E501  (ops script outside any repo; long lines are paths and messages)
"""Keycloak setup for OHS superadmin, run BY ROY in his own terminal.

Why this exists: creating a realm role and reading realm settings need the
Keycloak admin password, and the assistant must never receive that password.
This script prompts for it with hidden input, uses it only to get a token from
the master realm, and never prints it or the token.

What it does (every WRITE asks y/N first; reads are free):
  1. Reports what decides whether a user can edit their own e-mail and whether
     the e-mail is marked verified (realm flags + the user-profile "email"
     attribute permissions + each user's emailVerified).
  2. Shows which protocol mappers put realm roles into the "roles" claim, so
     you can see whether the new role will appear in tokens without a new
     mapper (a "User Realm Role" mapper with no role filter emits every realm
     role).
  3. Creates the realm role "governance.superadmin" if it is missing.
  4. Optionally grants it to ONE user you name (this is a privileged grant:
     only do it for the person who should approve accounts).
  5. Lists each service-account client with its Keycloak user id: that id is the
     `sub` that central sees, which is what a department assignment needs.

Run (central venv has httpx):
  <central>/.venv/Scripts/python.exe governance/keycloak/keycloak_superadmin_setup.py

Defaults: server http://localhost:8080, realm roy-governance. Override with
--server / --realm.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Callable

import httpx


ROLE_NAME = "governance.superadmin"


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


def report_email_settings(api: AdminApi, out: Callable[[str], None]) -> None:
    out("\n== 1. E-mail: who can edit it, and is it verified? ==")
    realm = api.get("").json()
    for key in (
        "editUsernameAllowed",
        "verifyEmail",
        "loginWithEmailAllowed",
        "registrationEmailAsUsername",
        "duplicateEmailsAllowed",
        "registrationAllowed",
    ):
        out(f"  realm.{key} = {realm.get(key)}")
    profile = api.get("/users/profile")
    if profile.status_code == 200:
        for attribute in profile.json().get("attributes", []):
            if attribute.get("name") == "email":
                perms = attribute.get("permissions", {})
                out(f"  user-profile email.permissions.edit = {perms.get('edit')}")
                out(f"  user-profile email.permissions.view = {perms.get('view')}")
                out(f"  user-profile email.required = {attribute.get('required')}")
                out(
                    "  -> a user can edit their own e-mail only if 'user' is in the"
                    " edit list above."
                )
    else:
        out(f"  (user profile not readable: HTTP {profile.status_code})")


def report_users(api: AdminApi, out: Callable[[str], None]) -> list[dict]:
    users = api.get("/users", max=100).json()
    out("\n== users (first 100): username / enabled / email / emailVerified ==")
    for user in users:
        out(
            f"  {user.get('username')!s:<24} enabled={user.get('enabled')!s:<5} "
            f"{user.get('email')!s:<34} emailVerified={user.get('emailVerified')}"
        )
    return users


def report_roles_mappers(api: AdminApi, out: Callable[[str], None]) -> None:
    out("\n== 2. Mappers that emit the 'roles' claim ==")
    found = 0
    sources = []
    for scope in api.get("/client-scopes").json():
        sources.append(
            ("client-scope", scope.get("name"), scope.get("protocolMappers"))
        )
    for client in api.get("/clients").json():
        sources.append(
            ("client", client.get("clientId"), client.get("protocolMappers"))
        )
    for kind, name, mappers in sources:
        for mapper in mappers or []:
            config = mapper.get("config", {})
            if config.get("claim.name") == "roles":
                found += 1
                out(
                    f"  {kind} {name!s}: mapper '{mapper.get('name')}' "
                    f"type={mapper.get('protocolMapper')} "
                    f"multivalued={config.get('multivalued')} "
                    f"access.token={config.get('access.token.claim')} "
                    f"rolePrefix={config.get('usermodel.realmRoleMapping.rolePrefix')!r}"
                )
    if not found:
        out("  none found: a mapper for the 'roles' claim must be added by hand.")
    else:
        out(
            "  -> a realm-role mapper normally emits all of a user's realm roles, so the"
            " new role may need no extra mapper, BUT a role only reaches a client's"
            " token if that client has 'Full scope allowed' ON or the role is in its"
            " scope mappings (see the per-client line below). Check a real token"
            " after granting."
        )
    out("  per-client fullScopeAllowed (the clients that call central matter):")
    for client in api.get("/clients").json():
        out(
            f"    {client.get('clientId')!s:<28} "
            f"fullScopeAllowed={client.get('fullScopeAllowed')}"
        )


def ensure_role(api: AdminApi, ask: Callable[[str], str], out: Callable[[str], None]):
    out(f"\n== 3. Realm role '{ROLE_NAME}' ==")
    response = api.get(f"/roles/{ROLE_NAME}")
    if response.status_code == 200:
        out("  already exists")
        return response.json()
    if response.status_code != 404:
        out(f"  could not check (HTTP {response.status_code})")
        return None
    if ask("  Create it now? [y/N] ").strip().lower() != "y":
        out("  skipped")
        return None
    created = api.post(
        "/roles",
        {
            "name": ROLE_NAME,
            "description": "OHS superadmin: approves accounts, edits departments "
            "and tool permissions. Not a superset of governance.admin.",
        },
    )
    out(f"  create -> HTTP {created.status_code}")
    return (
        api.get(f"/roles/{ROLE_NAME}").json()
        if created.status_code in (201, 204)
        else None
    )


def grant_role(
    api: AdminApi,
    role: dict | None,
    users: list[dict],
    ask: Callable[[str], str],
    out: Callable[[str], None],
) -> None:
    if role is None:
        return
    out("\n== 4. Grant (optional, privileged) ==")
    username = ask(f"  Username to receive '{ROLE_NAME}' (empty = nobody): ").strip()
    if not username:
        out("  nobody")
        return
    match = [u for u in users if u.get("username") == username]
    if not match:
        out("  no such user in the list above")
        return
    if ask(f"  Grant '{ROLE_NAME}' to '{username}'? [y/N] ").strip().lower() != "y":
        out("  skipped")
        return
    response = api.post(f"/users/{match[0]['id']}/role-mappings/realm", [role])
    out(f"  grant -> HTTP {response.status_code}")


def report_service_accounts(api: AdminApi, out: Callable[[str], None]) -> None:
    out("\n== 5. Service accounts: the `sub` central sees ==")
    for client in api.get("/clients").json():
        if not client.get("serviceAccountsEnabled"):
            continue
        response = api.get(f"/clients/{client['id']}/service-account-user")
        if response.status_code == 200:
            user = response.json()
            out(f"  client {client.get('clientId')!s:<28} sub = {user.get('id')}")
        else:
            out(f"  client {client.get('clientId')}: HTTP {response.status_code}")
    out(
        "  -> assign a sub to a department with POST /api/v1/admin/departments/{id}/principals"
    )


def run(
    api: AdminApi, ask: Callable[[str], str], out: Callable[[str], None] = print
) -> None:
    report_email_settings(api, out)
    users = report_users(api, out)
    report_roles_mappers(api, out)
    role = ensure_role(api, ask, out)
    grant_role(api, role, users, ask, out)
    report_service_accounts(api, out)
    out(
        "\nDone. Nothing secret was printed. Paste this output back if you want a review."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--server", default="http://localhost:8080")
    parser.add_argument("--realm", default="roy-governance")
    args = parser.parse_args(argv)
    username = input("Keycloak admin username [admin]: ").strip() or "admin"
    password = getpass.getpass("Keycloak admin password (hidden): ")
    with httpx.Client(timeout=20) as client:
        api = AdminApi(client, args.server, args.realm)
        api.login(username, password)
        del password
        run(api, input)
    return 0


if __name__ == "__main__":
    sys.exit(main())
