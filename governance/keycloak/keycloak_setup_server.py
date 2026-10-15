# ruff: noqa: E501  (ops script outside any repo; long lines are messages and markup)
"""A local-only page where ROY types the Keycloak admin password and the setup runs.

Why: the assistant must never receive the admin password (it would sit in the
conversation). This page is served on 127.0.0.1 only, under a one-time random
path, and shown in the app's browser pane so Roy types the password into the
page himself. The password lives only in this process's memory, is never
written to disk or logged, and is dropped when you press "Finish" or after 20
minutes. The assistant sees only the non-secret report the page shows.

Steps in the page: log in -> read-only report (e-mail settings, users, role
mappers, service-account `sub`s) -> optional: create the realm role, grant it to
ONE user, set a NEW admin password (replacing one that was pasted into a chat).

Run with the central venv (it has httpx):
  <central>/.venv/Scripts/python.exe governance/keycloak/keycloak_setup_server.py
Prints one line: the URL to open.
"""

from __future__ import annotations

import html
import http.server
import importlib.util
import pathlib
import secrets
import sys
import threading
import urllib.parse

import httpx


_SPEC = importlib.util.spec_from_file_location(
    "kc_setup", pathlib.Path(__file__).with_name("keycloak_superadmin_setup.py")
)
kc = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(kc)  # type: ignore[union-attr]

_INBOX_SPEC = importlib.util.spec_from_file_location(
    "kc_inbox_client",
    pathlib.Path(__file__).with_name("keycloak_inbox_client_setup.py"),
)
ic = importlib.util.module_from_spec(_INBOX_SPEC)
_INBOX_SPEC.loader.exec_module(ic)  # type: ignore[union-attr]

TOKEN = secrets.token_urlsafe(24)
ADMIN_ROLE = "governance.admin"
SESSION_SECONDS = 20 * 60
STATE: dict = {
    "username": None,
    "password": None,
    "server": "http://localhost:8080",
    "realm": "roy-governance",
    "report": "",
    "users": [],
    "log": [],
}
_lock = threading.Lock()
# A required checkbox, not a JS confirm() dialog: embedded browsers may block dialogs,
# which silently made the buttons do nothing.
OK_BOX = (
    "<label><input type='checkbox' name='ok' value='1' required> 我確認要執行</label> "
)
WRITE_ROUTES = {
    "create-role",
    "grant",
    "rotate",
    "lock-email",
    "create-user",
    "register-client",
}
_httpd: http.server.ThreadingHTTPServer | None = None


def make_client() -> httpx.Client:
    return httpx.Client(timeout=20)


def _api() -> kc.AdminApi:
    """A freshly logged-in admin API (admin tokens are short-lived, so log in
    again for each action using the password held in memory)."""
    api = kc.AdminApi(make_client(), STATE["server"], STATE["realm"])
    api.login(STATE["username"], STATE["password"])
    return api


def create_user_problems(username: str, email: str, pw1: str, pw2: str) -> list[str]:
    """What is wrong with the create-user form, one sentence each (never the
    password itself): the first version only said that something was."""
    problems = []
    if not username:
        problems.append("使用者名稱是空的")
    if "@" not in email:
        problems.append("EMAIL 沒有 @（或是空的）")
    if not pw1:
        problems.append("密碼是空的")
    elif len(pw1) < 12:
        problems.append(f"密碼只有 {len(pw1)} 個字元，至少要 12")
    if pw1 != pw2:
        problems.append("兩次輸入的密碼不一樣")
    return problems


def _collect(fn, *args) -> str:
    lines: list[str] = []
    fn(*args, lines.append)
    return "\n".join(lines)


def build_report(api: kc.AdminApi) -> str:
    parts = [_collect(kc.report_email_settings, api)]
    lines: list[str] = []
    STATE["users"] = kc.report_users(api, lines.append)
    parts.append("\n".join(lines))
    parts.append(_collect(kc.report_roles_mappers, api))
    parts.append(_collect(kc.report_service_accounts, api))
    return "\n".join(parts)


def _page(body: str) -> bytes:
    return (
        "<!doctype html><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Keycloak 設定</title>"
        "<style>body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:24px auto;padding:0 16px}"
        "pre{background:#f4f4f4;padding:12px;overflow:auto;border-radius:6px;font-size:13px}"
        "fieldset{margin:16px 0;border:1px solid #bbb;border-radius:6px}label{display:block;margin:8px 0}"
        "input,select,button{font:inherit;padding:6px 8px}button{cursor:pointer}"
        ".warn{background:#fff3cd;padding:8px 12px;border-radius:6px}.ok{color:#0a6b2b}.bad{color:#a40000}"
        "@media (prefers-color-scheme:dark){body{background:#1b1b1b;color:#ddd}pre{background:#2a2a2a}"
        ".warn{background:#4a3f10}}</style>" + body
    ).encode()


def login_page(message: str = "") -> bytes:
    return _page(
        "<h2>Keycloak 管理員設定</h2>"
        "<p class='warn'>密碼只在這個頁面輸入，只存在這個本機服務的記憶體裡，不寫檔、不記錄；"
        "助理看不到它。按「完成」或 20 分鐘後即清除。</p>"
        + (f"<p class='bad'>{html.escape(message)}</p>" if message else "")
        + f"<form method='post' action='/{TOKEN}/login'>"
        "<label>管理員帳號 <input name='username' value='admin' autocomplete='off'></label>"
        "<label>管理員密碼 <input name='password' type='password' autocomplete='off' autofocus required></label>"
        "<button>登入並讀取設定（唯讀）</button></form>"
    )


def main_page(notice: str = "") -> bytes:
    users = "".join(
        f"<option value='{html.escape(u.get('username', ''))}'>{html.escape(u.get('username', ''))} "
        f"({html.escape(str(u.get('email')))})</option>"
        for u in STATE["users"]
    )
    log = "\n".join(STATE["log"])
    return _page(
        "<h2>Keycloak 管理員設定</h2>"
        + (f"<p class='ok'>{html.escape(notice)}</p>" if notice else "")
        + f"<h3>唯讀報告</h3><pre>{html.escape(STATE['report'])}</pre>"
        + (f"<h3>已執行的動作</h3><pre>{html.escape(log)}</pre>" if log else "")
        + f"<fieldset><legend>0. 註冊瀏覽器登入用的 client「{ic.DEFAULT_CLIENT_ID}」"
        "（OHS 主控台 /inbox 登入需要；public client、PKCE S256、不開密碼授權）</legend>"
        f"<form method='post' action='/{TOKEN}/register-client'>"
        "<label>central 的埠 <input name='port' value='8899' size='6' autocomplete='off'></label>"
        + OK_BOX
        + "<button>註冊（已存在則不動，只補缺的 mapper）</button></form></fieldset>"
        f"<fieldset><legend>1. 建立 realm role「{kc.ROLE_NAME}」與「{ADMIN_ROLE}」</legend>"
        f"<form method='post' action='/{TOKEN}/create-role'>"
        + OK_BOX
        + "<button>建立（已存在則不動）</button></form></fieldset>"
        "<fieldset><legend>2. 把 role 授予一位使用者（高權限，只給負責批准帳號的人）</legend>"
        f"<form method='post' action='/{TOKEN}/grant'>"
        f"<select name='role'><option value='{kc.ROLE_NAME}'>{kc.ROLE_NAME}</option>"
        f"<option value='{ADMIN_ROLE}'>{ADMIN_ROLE}（稽核、對帳畫面需要）</option></select> "
        f"<select name='username'><option value=''>（選擇）</option>{users}</select> "
        + OK_BOX
        + "<button>授予</button></form></fieldset>"
        "<fieldset><legend>1b. 建立一位真人使用者（Email verified 會設為 true；密碼由你在這裡輸入）</legend>"
        f"<form method='post' action='/{TOKEN}/create-user'>"
        "<label>使用者名稱 <input name='new_username' autocomplete='off' required></label>"
        "<label>EMAIL（要是公司網域） <input name='new_email' type='email' autocomplete='off' required></label>"
        "<label>名 <input name='first_name' autocomplete='off'></label>"
        "<label>姓 <input name='last_name' autocomplete='off'></label>"
        "<label>密碼（至少 12 字元） <input name='user_pw1' type='password' autocomplete='new-password' required></label>"
        "<label>再輸入一次 <input name='user_pw2' type='password' autocomplete='new-password' required></label>"
        f"<label><input type='checkbox' name='grant_super' value='1'> 同時授予「{kc.ROLE_NAME}」</label>"
        + OK_BOX
        + "<button>建立使用者</button></form></fieldset>"
        "<fieldset><legend>3. 限制 EMAIL 只有管理員能改（目前使用者可自改時才需要）</legend>"
        f"<form method='post' action='/{TOKEN}/lock-email'>"
        + OK_BOX
        + "<button>限制</button></form></fieldset>"
        "<fieldset><legend>4. 設定新的管理員密碼（取代貼在對話裡的舊密碼）</legend>"
        f"<form method='post' action='/{TOKEN}/rotate'>"
        "<label>新密碼（至少 14 字元） <input name='new1' type='password' autocomplete='new-password'></label>"
        "<label>再輸入一次 <input name='new2' type='password' autocomplete='new-password'></label>"
        "<p>改完後請用新密碼登入 Keycloak 管理介面。</p>"
        + OK_BOX
        + "<button>改密碼</button></form></fieldset>"
        f"<form method='post' action='/{TOKEN}/refresh'><button>重新讀取使用者清單</button></form>"
        f"<form method='post' action='/{TOKEN}/finish'><button>完成並清除密碼</button></form>"
    )


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # never log: request bodies hold the password
        pass

    def _send(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _guard(self) -> str | None:
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):
            self._send(b"forbidden", 403)
            return None
        prefix = f"/{TOKEN}/"
        if not self.path.startswith(prefix):
            self._send(b"not found", 404)
            return None
        return self.path[len(prefix) :]

    def do_GET(self):  # noqa: N802
        route = self._guard()
        if route is None:
            return
        with _lock:
            self._send(main_page() if STATE["password"] else login_page())

    def do_POST(self):  # noqa: N802
        route = self._guard()
        if route is None:
            return
        length = int(self.headers.get("Content-Length", 0))
        form = {
            k: v[0]
            for k, v in urllib.parse.parse_qs(self.rfile.read(length).decode()).items()
        }
        with _lock:
            self._send(self._route(route, form))

    def _route(self, route: str, form: dict) -> bytes:
        if route == "login":
            STATE["username"] = form.get("username", "admin") or "admin"
            STATE["password"] = form.get("password", "")
            try:
                api = _api()
                STATE["report"] = build_report(api)
            except (SystemExit, httpx.HTTPError) as exc:
                STATE["password"] = None
                return login_page(f"登入失敗：{exc}")
            return main_page("登入成功，以下是唯讀報告。")
        if not STATE["password"]:
            return login_page("請先登入")
        if route == "finish":
            STATE["password"] = None
            STATE["username"] = None
            threading.Thread(target=_shutdown, daemon=True).start()
            return _page("<h2>完成</h2><p>密碼已從記憶體清除，服務即將關閉。</p>")
        try:
            api = _api()
        except (SystemExit, httpx.HTTPError) as exc:
            return main_page(f"重新登入失敗：{exc}")
        # The user list was read at login: refresh it for every action, so a user
        # created in Keycloak meanwhile can be picked.
        listed = api.get("/users", max=100)
        if listed.status_code == 200:
            STATE["users"] = listed.json()
        if route in WRITE_ROUTES and form.get("ok") != "1":
            STATE["log"].append(f"{route}: 未勾選「我確認」，沒有執行")
            return main_page("未執行：請先勾選「我確認要執行」。")
        if route == "create-user":
            username = form.get("new_username", "").strip()
            email = form.get("new_email", "").strip().lower()
            pw1, pw2 = form.get("user_pw1", ""), form.get("user_pw2", "")
            problems = create_user_problems(username, email, pw1, pw2)
            if problems:
                STATE["log"].append("建立使用者未執行：" + "；".join(problems))
            else:
                created = api.post(
                    "/users",
                    {
                        "username": username,
                        "email": email,
                        "emailVerified": True,
                        "enabled": True,
                        "firstName": form.get("first_name", "").strip() or username,
                        "lastName": form.get("last_name", "").strip() or "-",
                        "credentials": [
                            {"type": "password", "value": pw1, "temporary": False}
                        ],
                    },
                )
                if created.status_code != 201:
                    detail = ""
                    try:
                        detail = str(created.json().get("errorMessage", ""))[:120]
                    except ValueError:
                        pass
                    STATE["log"].append(
                        f"建立使用者 {username}: HTTP {created.status_code} {detail}"
                    )
                else:
                    STATE["log"].append(
                        f"建立使用者 {username}（{email}，Email verified=true）: HTTP 201"
                    )
                    user_id = created.headers.get("Location", "").rsplit("/", 1)[-1]
                    if form.get("grant_super") == "1" and user_id:
                        role = api.get(f"/roles/{kc.ROLE_NAME}")
                        if role.status_code != 200:
                            STATE["log"].append("授予失敗：role 尚未建立")
                        else:
                            done = api.post(
                                f"/users/{user_id}/role-mappings/realm", [role.json()]
                            )
                            STATE["log"].append(
                                f"授予 {kc.ROLE_NAME} 給 {username}: HTTP {done.status_code}"
                            )
                    refreshed = api.get("/users", max=100)
                    if refreshed.status_code == 200:
                        STATE["users"] = refreshed.json()
        elif route == "lock-email":
            profile = api.get("/users/profile")
            if profile.status_code != 200:
                STATE["log"].append(
                    f"限制 EMAIL 編輯：讀不到 user profile（HTTP {profile.status_code}）"
                )
            else:
                config = profile.json()
                changed = False
                for attribute in config.get("attributes", []):
                    if attribute.get("name") == "email":
                        permissions = attribute.setdefault("permissions", {})
                        if permissions.get("edit") != ["admin"]:
                            permissions["edit"] = ["admin"]
                            changed = True
                if not changed:
                    STATE["log"].append("EMAIL 編輯權限已經只有管理員，未改動")
                else:
                    done = api.client.put(
                        f"{api.server}/admin/realms/{api.realm}/users/profile",
                        headers=api._headers,
                        json=config,
                    )
                    STATE["log"].append(
                        f"限制 EMAIL 編輯為只有管理員: HTTP {done.status_code}"
                    )
        elif route == "register-client":
            raw_port = form.get("port", "").strip() or "8899"
            if not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
                STATE["log"].append(f"註冊 client 未執行：埠「{raw_port[:10]}」不合法")
            else:
                lines: list[str] = []
                yes = lambda _prompt: "y"  # noqa: E731  (the checkbox was the confirmation)
                client = ic.ensure_client(
                    api, ic.DEFAULT_CLIENT_ID, int(raw_port), yes, lines.append
                )
                if client is not None:
                    ic.ensure_mappers(
                        api, client, "central-governance-api", yes, lines.append
                    )
                    lines.append(
                        f"下一步：在 central-governance-api/.env 加一行 CGA_INBOX_OIDC_CLIENT_ID={ic.DEFAULT_CLIENT_ID} ，"
                        f"重啟 central，再開 http://localhost:{raw_port}/inbox"
                    )
                STATE["log"].extend(line for line in lines if line.strip())
        elif route == "refresh":
            STATE["log"].append(f"使用者清單已重新讀取（{len(STATE['users'])} 位）")
        elif route == "create-role":
            for name, description in (
                (
                    kc.ROLE_NAME,
                    "OHS superadmin: approves accounts, edits departments and tool permissions. Not a superset of governance.admin.",
                ),
                (ADMIN_ROLE, "OHS admin: Audit and Reconciliation screens."),
            ):
                response = api.get(f"/roles/{name}")
                if response.status_code == 200:
                    STATE["log"].append(f"role {name}: 已存在，未改動")
                else:
                    created = api.post(
                        "/roles", {"name": name, "description": description}
                    )
                    STATE["log"].append(
                        f"建立 role {name}: HTTP {created.status_code}"
                    )
        elif route == "grant":
            username = form.get("username", "")
            match = [u for u in STATE["users"] if u.get("username") == username]
            role_name = form.get("role", kc.ROLE_NAME)
            if role_name not in (kc.ROLE_NAME, ADMIN_ROLE):
                role_name = ""
            role = api.get(f"/roles/{role_name}") if role_name else None
            if not match or role is None or role.status_code != 200:
                STATE["log"].append("授予失敗：找不到使用者或 role 尚未建立")
            else:
                done = api.post(
                    f"/users/{match[0]['id']}/role-mappings/realm", [role.json()]
                )
                STATE["log"].append(
                    f"授予 {role_name} 給 {username}: HTTP {done.status_code}"
                )
        elif route == "rotate":
            new1, new2 = form.get("new1", ""), form.get("new2", "")
            if new1 != new2 or len(new1) < 14 or new1 == STATE["password"]:
                STATE["log"].append(
                    "改密碼未執行：兩次不一致、少於 14 字元，或與舊密碼相同"
                )
            else:
                found = api.client.get(
                    f"{api.server}/admin/realms/master/users",
                    headers=api._headers,
                    params={"username": STATE["username"], "exact": "true"},
                )
                users = found.json() if found.status_code == 200 else []
                if len(users) != 1:
                    STATE["log"].append(
                        f"改密碼未執行：找不到管理員使用者（HTTP {found.status_code}）"
                    )
                else:
                    reset = api.client.put(
                        f"{api.server}/admin/realms/master/users/{users[0]['id']}/reset-password",
                        headers=api._headers,
                        json={"type": "password", "value": new1, "temporary": False},
                    )
                    STATE["log"].append(f"設定新管理員密碼: HTTP {reset.status_code}")
                    if reset.status_code in (200, 204):
                        STATE["password"] = (
                            new1  # keep the session usable; never printed
                        )
        return main_page("動作已執行，結果見下方。")


def _shutdown() -> None:
    if _httpd is not None:
        _httpd.shutdown()


def serve(port: int = 0) -> http.server.ThreadingHTTPServer:
    global _httpd
    _httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    timer = threading.Timer(SESSION_SECONDS, _shutdown)
    timer.daemon = True  # must not keep the process alive after Finish
    timer.start()
    return _httpd


if __name__ == "__main__":
    httpd = serve()
    print(f"OPEN http://127.0.0.1:{httpd.server_address[1]}/{TOKEN}/", flush=True)
    try:
        httpd.serve_forever()
    finally:
        STATE["password"] = None
        print("closed", flush=True)
        sys.stdout.flush()
