"""The local Keycloak setup page (governance/keycloak/keycloak_setup_server.py): the
step
that registers the console's sign-in client. Against a fake Keycloak admin API, so
nothing real is touched.

What matters: nothing is written without the confirmation box, the client is a public
PKCE client with the two mappers central needs, an existing client is not modified, and
the admin password never shows up in the log or the page.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import httpx
import pytest


_PATH = (
    Path(__file__).resolve().parents[2]
    / "governance"
    / "keycloak"
    / "keycloak_setup_server.py"
)
_spec = importlib.util.spec_from_file_location("kc_setup_server_under_test", _PATH)
assert _spec and _spec.loader
page = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(page)

PASSWORD = "S3cr3t-admin-password-for-the-test"


class FakeKeycloak:
    def __init__(self, existing_client: dict | None = None):
        self.client = existing_client
        self.created: list[dict] = []
        self.mappers: list[dict] = []
        self.calls: list[tuple[str, str]] = []
        self.users: list[dict] = []
        self.created_users: list[dict] = []
        self.role: dict | None = None
        self.admin_role = {"id": "r-2", "name": "governance.admin"}
        self.created_roles: list[str] = []
        self.granted: list[tuple[str, list]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "t"})
        base = "/admin/realms/roy-governance"
        if request.method == "GET" and path == f"{base}/users":
            return httpx.Response(200, json=self.users)
        if request.method == "POST" and path == f"{base}/users":
            self.created_users.append(json.loads(request.content))
            return httpx.Response(201)
        if request.method == "GET" and path.startswith(f"{base}/roles/"):
            name = path.rsplit("/", 1)[-1]
            if name == "governance.admin":
                return httpx.Response(200, json=self.admin_role)
            return (
                httpx.Response(200, json=self.role)
                if self.role
                else httpx.Response(404)
            )
        if request.method == "POST" and path == f"{base}/roles":
            self.created_roles.append(json.loads(request.content)["name"])
            return httpx.Response(201)
        if request.method == "POST" and path.endswith("/role-mappings/realm"):
            user_id = path.split("/")[-3]
            self.granted.append((user_id, json.loads(request.content)))
            return httpx.Response(204)
        if request.method == "GET" and path == f"{base}/clients":
            return httpx.Response(200, json=[self.client] if self.client else [])
        if request.method == "POST" and path == f"{base}/clients":
            body = json.loads(request.content)
            self.created.append(body)
            self.client = {**body, "id": "cid-1", "protocolMappers": []}
            return httpx.Response(201)
        if request.method == "GET" and path == f"{base}/clients/cid-1":
            return httpx.Response(200, json=self.client)
        if (
            request.method == "POST"
            and path == f"{base}/clients/cid-1/protocol-mappers/models"
        ):
            body = json.loads(request.content)
            self.mappers.append(body)
            self.client.setdefault("protocolMappers", []).append(body)
            return httpx.Response(201)
        return httpx.Response(404)


@pytest.fixture
def keycloak(monkeypatch):
    def install(fake: FakeKeycloak) -> FakeKeycloak:
        monkeypatch.setattr(
            page,
            "make_client",
            lambda: httpx.Client(transport=httpx.MockTransport(fake)),
        )
        return fake

    page.STATE.update(username="admin", password=PASSWORD, report="", users=[], log=[])
    yield install
    page.STATE.update(password=None, username=None, log=[])


def route(name: str, **form) -> bytes:
    return page.Handler._route(None, name, form)  # type: ignore[arg-type]


def test_nothing_is_written_without_the_confirmation_box(keycloak):
    fake = keycloak(FakeKeycloak())

    route("register-client", port="8899")

    assert fake.created == [] and fake.mappers == []
    assert any("未勾選" in line for line in page.STATE["log"])


def test_it_registers_a_public_pkce_client_with_the_two_mappers(keycloak):
    fake = keycloak(FakeKeycloak())

    route("register-client", port="8899", ok="1")

    (client,) = fake.created
    assert client["clientId"] == "ohs-console"
    assert client["publicClient"] is True
    assert client["standardFlowEnabled"] is True
    assert client["directAccessGrantsEnabled"] is False
    assert client["serviceAccountsEnabled"] is False
    assert client["attributes"] == {"pkce.code.challenge.method": "S256"}
    assert client["redirectUris"] == [
        "http://localhost:8899/inbox",
        "http://127.0.0.1:8899/inbox",
    ]
    assert client["webOrigins"] == ["http://localhost:8899", "http://127.0.0.1:8899"]
    assert sorted(m["name"] for m in fake.mappers) == ["audience", "realm-roles-flat"]
    audience = next(m for m in fake.mappers if m["name"] == "audience")
    assert audience["config"]["included.custom.audience"] == "central-governance-api"
    roles = next(m for m in fake.mappers if m["name"] == "realm-roles-flat")
    assert roles["config"]["claim.name"] == "roles"
    assert roles["config"]["multivalued"] == "true"
    log = "\n".join(page.STATE["log"])
    assert "CGA_INBOX_OIDC_CLIENT_ID=ohs-console" in log
    assert "http://localhost:8899/inbox" in log


def test_the_port_given_goes_into_the_redirect_addresses(keycloak):
    fake = keycloak(FakeKeycloak())

    route("register-client", port="18002", ok="1")

    assert fake.created[0]["redirectUris"][0] == "http://localhost:18002/inbox"


@pytest.mark.parametrize("port", ["abc", "0", "70000", "-1", "80 80"])
def test_a_bad_port_writes_nothing(keycloak, port):
    fake = keycloak(FakeKeycloak())

    route("register-client", port=port, ok="1")

    assert fake.created == [] and fake.mappers == []
    assert any("不合法" in line for line in page.STATE["log"])


def test_an_existing_client_is_not_modified_and_only_missing_mappers_are_added(
    keycloak,
):
    existing = {
        "id": "cid-1",
        "clientId": "ohs-console",
        "publicClient": True,
        "protocolMappers": [{"name": "audience"}],
    }
    fake = keycloak(FakeKeycloak(existing))

    route("register-client", port="8899", ok="1")

    assert fake.created == []
    assert [m["name"] for m in fake.mappers] == ["realm-roles-flat"]


def test_the_admin_password_never_reaches_the_log_or_the_page(keycloak):
    fake = keycloak(FakeKeycloak())

    answer = route("register-client", port="8899", ok="1")

    assert PASSWORD.encode() not in answer
    assert PASSWORD not in "\n".join(page.STATE["log"])
    assert PASSWORD not in json.dumps(fake.created + fake.mappers)


def test_the_page_offers_the_step_first(keycloak):
    keycloak(FakeKeycloak())
    html = page.main_page().decode()
    assert "register-client" in html
    assert html.index("register-client") < html.index("create-role")


# ---- the create-user form says what is wrong; the user list follows Keycloak ----


@pytest.mark.parametrize(
    ("username", "email", "pw1", "pw2", "expected"),
    [
        ("", "a@b.co", "x" * 12, "x" * 12, ["使用者名稱是空的"]),
        ("ann", "", "x" * 12, "x" * 12, ["EMAIL 沒有 @（或是空的）"]),
        ("ann", "no-at-sign", "x" * 12, "x" * 12, ["EMAIL 沒有 @（或是空的）"]),
        ("ann", "a@b.co", "", "", ["密碼是空的"]),
        ("ann", "a@b.co", "x" * 11, "x" * 11, ["密碼只有 11 個字元，至少要 12"]),
        ("ann", "a@b.co", "x" * 12, "y" * 12, ["兩次輸入的密碼不一樣"]),
        (
            "ann",
            "a@b.co",
            "x" * 12,
            "x" * 11,
            ["兩次輸入的密碼不一樣"],
        ),
        (
            "",
            "",
            "x" * 3,
            "y" * 3,
            [
                "使用者名稱是空的",
                "EMAIL 沒有 @（或是空的）",
                "密碼只有 3 個字元，至少要 12",
                "兩次輸入的密碼不一樣",
            ],
        ),
        ("ann", "a@b.co", "x" * 12, "x" * 12, []),
    ],
)
def test_the_create_user_form_says_which_rule_failed(
    username, email, pw1, pw2, expected
):
    assert page.create_user_problems(username, email, pw1, pw2) == expected


def test_the_problem_text_never_contains_the_password():
    secret = "short-secret"
    text = "；".join(page.create_user_problems("ann", "a@b.co", secret, "other"))
    assert secret not in text and "other" not in text


def test_a_refused_create_user_logs_the_reason_and_writes_nothing(keycloak):
    fake = keycloak(FakeKeycloak())

    route(
        "create-user",
        new_username="ann",
        new_email="ann@example.com",
        user_pw1="x" * 5,
        user_pw2="x" * 5,
        ok="1",
    )

    assert fake.created_users == []
    assert any("密碼只有 5 個字元" in line for line in page.STATE["log"])


def test_a_user_created_in_keycloak_after_login_can_be_granted(keycloak):
    fake = keycloak(FakeKeycloak())
    page.STATE["users"] = []  # what the page read at login: nobody
    fake.users = [{"id": "u-1", "username": "roy", "email": "r@example.com"}]
    fake.role = {"id": "r-1", "name": "governance.superadmin"}

    route("grant", username="roy", ok="1")

    assert fake.granted == [("u-1", [fake.role])]
    assert any(
        "授予 governance.superadmin 給 roy: HTTP 204" in x for x in page.STATE["log"]
    )


def test_the_refresh_button_rereads_the_user_list(keycloak):
    fake = keycloak(FakeKeycloak())
    fake.users = [{"id": "u-1", "username": "roy"}, {"id": "u-2", "username": "ann"}]
    page.STATE["users"] = []

    route("refresh")

    assert [u["username"] for u in page.STATE["users"]] == ["roy", "ann"]
    assert any("2 位" in line for line in page.STATE["log"])


def test_the_admin_role_can_be_granted_too_and_other_names_cannot(keycloak):
    fake = keycloak(FakeKeycloak())
    page.STATE["users"] = []
    fake.users = [{"id": "u-1", "username": "roy", "email": "r@example.com"}]
    fake.role = {"id": "r-1", "name": "governance.superadmin"}

    route("grant", username="roy", role="governance.admin", ok="1")
    route("grant", username="roy", role="realm-management", ok="1")

    assert fake.granted == [("u-1", [fake.admin_role])]
    assert any("授予失敗" in x for x in page.STATE["log"])


def test_create_role_makes_both_roles_the_console_needs(keycloak):
    fake = keycloak(FakeKeycloak())
    fake.role = None

    route("create-role", ok="1")

    assert fake.created_roles == ["governance.superadmin"]  # admin already exists
