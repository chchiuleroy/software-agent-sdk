"""Real agent-server conversation with department tool permissions enforced.

Real central process (CGA_ENFORCE_TOOL_PERMISSIONS=true) on a throwaway
Postgres, a local fake IdP, a REAL agent-server process in team mode with
governance_enforce_tool_permissions on, and a scripted fake LLM (an
OpenAI-compatible server that asks for one tool call). Conversations are
started and run through the agent-server's own REST API, so this exercises the
parts the unit tests only mocked: ConversationService startup (the refresher),
a real conversation, the real Agent execution gate.

Run with the SDK venv python (cwd = openhands-sdk-governed). It creates and
drops its own database `central_e2e_rc`.
"""

import asyncio
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
from joserfc import jwk, jwt

from ohs_env import CENTRAL, CPY, SDK, SPY, pg_tool


PG = ["-h", "127.0.0.1", "-p", "54329", "-U", "cga"]
DB = "central_e2e_rc"
IDP_PORT, API_PORT, AGENT_PORT, LLM_PORT = 18790, 8896, 8795, 18791
ISSUER = f"http://127.0.0.1:{IDP_PORT}/realms/e2e"
AUDIENCE = "central-governance-api"
SERVICE_CLIENT = "svc-agent-rc"

key = jwk.RSAKey.generate_key(2048, parameters={"kid": "e2e-key"})
JWKS = json.dumps({"keys": [key.as_dict(private=False)]}).encode()


def token(sub, roles=()):
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
    def _send(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._send(JWKS)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        form = self.rfile.read(length).decode()
        cid = dict(p.split("=", 1) for p in form.split("&")).get("client_id", "x")
        self._send(
            json.dumps(
                {"access_token": token(cid, ["agent.operator"]), "expires_in": 3600}
            ).encode()
        )

    def log_message(self, *a):
        pass


LOGDIR = pathlib.Path(tempfile.mkdtemp(prefix="rc_logs_"))
WORKSPACE = pathlib.Path(tempfile.mkdtemp(prefix="rc_ws_"))
(WORKSPACE / "hello.txt").write_text("hello from the workspace\n")
MARKER = WORKSPACE / "terminal_ran.marker"
LLM_CALLS: list[str] = []


def _chat_response(message: dict) -> bytes:
    return json.dumps(
        {
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 0,
            "model": "fake-model",
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": "tool_calls"
                    if message.get("tool_calls")
                    else "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
    ).encode()


class _Llm(BaseHTTPRequestHandler):
    """First turn of a conversation: ask for one tool call chosen by the user
    message. After a tool result (or error) comes back: answer in plain text."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        text = json.dumps(messages, ensure_ascii=False)
        has_result = any(m.get("role") == "tool" for m in messages)
        if has_result:
            LLM_CALLS.append("final")
            reply = {"role": "assistant", "content": "done"}
        elif "USE_TERMINAL" in text:
            LLM_CALLS.append("terminal")
            reply = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_t",
                        "type": "function",
                        "function": {
                            "name": "terminal",
                            "arguments": json.dumps(
                                {"command": f"echo ran > {MARKER.as_posix()}"}
                            ),
                        },
                    }
                ],
            }
        elif "USE_EDITOR" in text:
            LLM_CALLS.append("file_editor")
            reply = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_e",
                        "type": "function",
                        "function": {
                            "name": "file_editor",
                            "arguments": json.dumps(
                                {
                                    "command": "view",
                                    "path": (WORKSPACE / "hello.txt").as_posix(),
                                }
                            ),
                        },
                    }
                ],
            }
        else:
            LLM_CALLS.append("noop")
            reply = {"role": "assistant", "content": "nothing to do"}
        out = _chat_response(reply)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


def psql(*args):
    return subprocess.run(
        [pg_tool("psql"), *PG, *args], capture_output=True, text=True, check=True
    )


def start_request(first_message: str) -> dict:
    sys.path.insert(0, SDK)
    from pydantic import SecretStr

    from openhands.agent_server.models import (
        SendMessageRequest,
        StartConversationRequest,
    )
    from openhands.sdk import LLM, Agent, TextContent, Tool
    from openhands.sdk.workspace import LocalWorkspace

    req = StartConversationRequest(
        agent=Agent(
            llm=LLM(
                usage_id="e2e",
                model="openai/fake-model",
                base_url=f"http://127.0.0.1:{LLM_PORT}/v1",
                api_key=SecretStr("x"),
            ),
            tools=[Tool(name="terminal"), Tool(name="file_editor")],
        ),
        workspace=LocalWorkspace(working_dir=str(WORKSPACE)),
        initial_message=SendMessageRequest(
            role="user", content=[TextContent(text=first_message)], run=False
        ),
    )
    return req.model_dump(mode="json", context={"expose_secrets": True})


async def wait_outcome(ac: httpx.AsyncClient, cid: str, timeout=60.0):
    """Poll until the conversation shows an outcome event (a tool result, an
    error or a rejection) or finishes; return (status, events)."""
    deadline = time.monotonic() + timeout
    status, events = "?", []
    while time.monotonic() < deadline:
        r = await ac.get(f"/api/conversations/{cid}")
        status = r.json().get("execution_status", "?")
        ev = await ac.get(
            f"/api/conversations/{cid}/events/search", params={"limit": 100}
        )
        events = ev.json().get("items", [])
        outcome = any(
            e.get("kind")
            in ("ObservationEvent", "AgentErrorEvent", "UserRejectObservation")
            for e in events
        )
        if outcome or status in ("finished", "error", "stuck"):
            await asyncio.sleep(1.0)  # let the follow-up events land
            ev = await ac.get(
                f"/api/conversations/{cid}/events/search", params={"limit": 100}
            )
            return status, ev.json().get("items", [])
        await asyncio.sleep(0.5)
    return status, events


async def main():
    threading.Thread(
        target=ThreadingHTTPServer(("127.0.0.1", IDP_PORT), _Idp).serve_forever,
        daemon=True,
    ).start()
    threading.Thread(
        target=ThreadingHTTPServer(("127.0.0.1", LLM_PORT), _Llm).serve_forever,
        daemon=True,
    ).start()
    subprocess.run([pg_tool("createdb"), *PG, DB], check=True)
    cenv = {
        **os.environ,
        "PYTHONUTF8": "1",
        "CGA_DATABASE_URL": f"postgresql+asyncpg://cga@127.0.0.1:54329/{DB}",
        "CGA_OIDC_ISSUER": ISSUER,
        "CGA_OIDC_JWKS_URL": f"http://127.0.0.1:{IDP_PORT}/certs",
        "CGA_OIDC_AUDIENCE": AUDIENCE,
        "CGA_OIDC_REQUIRE_HTTPS": "false",
        "CGA_ENFORCE_TOOL_PERMISSIONS": "true",
        "CGA_PORT": str(API_PORT),
    }
    subprocess.run(
        [CPY, "-m", "alembic", "upgrade", "head"],
        cwd=CENTRAL,
        env=cenv,
        check=True,
        capture_output=True,
    )
    central = subprocess.Popen(
        [CPY, "-c", "from central_governance_api.main import main; main()"],
        cwd=CENTRAL,
        env=cenv,
        stdout=open(LOGDIR / "central.log", "w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
    )
    agent_dir = tempfile.mkdtemp(prefix="rc_agent_")
    aenv = {
        **os.environ,
        "PYTHONUTF8": "1",
        "OPENHANDS_SUPPRESS_BANNER": "1",
        "OH_GOVERNANCE_DEPLOYMENT_MODE": "team",
        "OH_GOVERNANCE_BRIDGE_TOKEN": secrets.token_urlsafe(24),
        "OH_GOVERNANCE_CENTRAL_API_BASE_URL": f"http://127.0.0.1:{API_PORT}",
        "OH_GOVERNANCE_CENTRAL_API_TOKEN_URL": f"http://127.0.0.1:{IDP_PORT}/token",
        "OH_GOVERNANCE_CLIENT_ID": SERVICE_CLIENT,
        "OH_GOVERNANCE_CLIENT_SECRET": "unused",
        "OH_GOVERNANCE_ORIGIN_DEVICE_ID": "device-rc",
        "OH_GOVERNANCE_ENFORCE_TOOL_PERMISSIONS": "true",
        # So an in-workspace file view is LOW risk (no approval needed).
        "ROY_GOVERNANCE_WORKSPACE_ROOT": str(WORKSPACE),
    }
    agent = None
    try:
        base = f"http://127.0.0.1:{API_PORT}"
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
            r = await c.post(
                "/api/v1/admin/departments", json={"name": "Finance"}, headers=sup
            )
            dept = r.json()["id"]
            await c.put(
                f"/api/v1/admin/departments/{dept}/tools",
                json={"tools": ["file_editor"]},
                headers=sup,
            )
            r = await c.post(
                f"/api/v1/admin/departments/{dept}/principals",
                json={"sub": SERVICE_CLIENT},
                headers=sup,
            )
            check(
                "setup: department, tools, service account assigned",
                r.status_code == 201,
            )

        agent = subprocess.Popen(
            [
                SPY,
                "-m",
                "openhands.agent_server",
                "--host",
                "127.0.0.1",
                "--port",
                str(AGENT_PORT),
            ],
            cwd=agent_dir,
            env=aenv,
            stdout=open(LOGDIR / "agent.log", "w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
        )
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{AGENT_PORT}", timeout=60
        ) as ac:
            for _ in range(360):
                try:
                    if (await ac.get("/health")).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.5)
            else:
                agent.terminate()
                print("--- agent-server output (tail) ---")
                print(
                    (LOGDIR / "agent.log").read_text(
                        encoding="utf-8", errors="replace"
                    )[-2500:]
                )
                raise SystemExit("agent-server did not start")
            await asyncio.sleep(8)  # first permission refresh

            async def run_conversation(message: str):
                r = await ac.post("/api/conversations", json=start_request(message))
                if r.status_code not in (200, 201):
                    print("start failed", r.status_code, r.text[:400])
                    return None, []
                cid = r.json()["id"]
                r = await ac.post(f"/api/conversations/{cid}/run")
                return await wait_outcome(ac, cid)

            # --- permitted tool ----------------------------------------------------
            status, events = await run_conversation("USE_EDITOR please view the file")
            kinds = [(e.get("kind"), e.get("tool_name")) for e in events]
            obs = [
                e
                for e in events
                if e.get("kind") == "ObservationEvent"
                and e.get("tool_name") == "file_editor"
            ]
            check(
                "permitted tool (file_editor) ran in a real conversation",
                bool(obs),
                f"status={status} events={kinds[:8]}",
            )

            # --- unpermitted tool ----------------------------------------------------
            status, events = await run_conversation("USE_TERMINAL please run a command")
            kinds = [(e.get("kind"), e.get("tool_name")) for e in events]
            text = json.dumps(events, ensure_ascii=False)
            check(
                "unpermitted tool (terminal) did not execute",
                not MARKER.exists(),
                f"marker exists={MARKER.exists()} status={status}",
            )
            refusals = [
                (e.get("kind"), json.dumps(e, ensure_ascii=False))
                for e in events
                if "not permitted" in json.dumps(e)
                or "no current list" in json.dumps(e)
            ]
            snippet = ""
            if refusals:
                k, raw = refusals[0]
                i = raw.find("Refused by governance policy")
                snippet = f"{k}: " + raw[i : i + 170]
            check("the refusal is visible in the conversation", bool(refusals), snippet)
            check(
                "the refusal never names the tool or the department",
                bool(refusals) and all(("Finance" not in r) for _, r in refusals),
            )
        # central side: the agent-server's own refresher call arrived
        log = psql(
            "-d", DB, "-Atc", "select count(*) from department_principals"
        ).stdout.strip()
        check("central still has the assignment", log == "1")
    finally:
        for proc in (agent, central):
            if proc is not None:
                proc.terminate()
        for proc in (agent, central):
            if proc is not None:
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
        outs = {
            n: (LOGDIR / f"{n}.log").read_text(encoding="utf-8", errors="replace")
            if (LOGDIR / f"{n}.log").exists()
            else ""
            for n in ("agent", "central")
        }
        bad = [
            l
            for l in outs.get("central", "").splitlines()
            if "Traceback" in l or " 500 " in l
        ]
        check("central log has no traceback / 5xx", not bad, str(bad[:2]))
        if any(not ok for _, ok in results):
            print("--- agent-server log tail ---")
            print(outs.get("agent", "")[-3500:])
        subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=False)
        shutil.rmtree(WORKSPACE, ignore_errors=True)
        shutil.rmtree(LOGDIR, ignore_errors=True)
        shutil.rmtree(agent_dir, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f"\nLLM calls seen: {LLM_CALLS}")
    print(f"{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)


asyncio.run(main())
