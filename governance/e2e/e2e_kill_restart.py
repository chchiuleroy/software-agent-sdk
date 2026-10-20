"""Kill the REAL agent-server process, restart it, and count how often the tool ran.

1.16 says an approved action is executed at most once, also across a crash. The unit
tests (tests/agent_server/test_governance_crash_recovery.py) simulate the crash by
cancelling asyncio tasks. This one kills the operating-system process (the whole tree,
`taskkill /T /F`), starts a new one on the same directory and asks central what it saw.

  K1  kill WHILE the approved tool is executing (it wrote one marker line, then sleeps)
      -> after the restart the tool is NOT run again (still one line), the conversation
         is not left RUNNING, it holds an AgentErrorEvent, and central ends the approval
         as failed_unknown (it cannot know whether the first run finished)
  K3  kill while the approval is still PENDING at central (nobody decided yet)
      -> after the restart the approver accepts; the tool runs exactly once and central
         ends the approval as applied

Windows only (the terminal tool runs PowerShell there; the process kill is taskkill).
Run with the SDK venv python (cwd = openhands-sdk-governed). It creates and drops its own
database `central_e2e_kill`; it needs the throwaway Postgres described in
governance/needs_attention/e2e_needs_attention.py (127.0.0.1:54329, user cga, trust).
Takes a few minutes (each agent-server start takes several seconds).
"""

import asyncio
import codecs
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
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
from joserfc import jwk, jwt

from ohs_env import CENTRAL, CPY, SDK, SPY, pg_tool


PG = ["-h", "127.0.0.1", "-p", "54329", "-U", "cga"]
DB = "central_e2e_kill"
IDP_PORT, API_PORT, AGENT_PORT, LLM_PORT = 18820, 8920, 8821, 18821
ISSUER = f"http://127.0.0.1:{IDP_PORT}/realms/e2e"
AUDIENCE = "central-governance-api"
SERVICE_CLIENT = "svc-agent-kill"
AGENT_DEVICE = "device-kill"

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


LOGDIR = pathlib.Path(tempfile.mkdtemp(prefix="kr_logs_"))
WORKSPACE = pathlib.Path(tempfile.mkdtemp(prefix="kr_ws_"))
LLM_CALLS: list[str] = []


def marker_path(tag: str) -> pathlib.Path:
    return WORKSPACE / f"ran_{tag}.marker"


def tool_command(tag: str) -> str:
    """One line appended per execution. k1 then sleeps, so it can be killed mid-run."""
    line = f"Add-Content -Path '{marker_path(tag).as_posix()}' -Value ran"
    return f"{line}; Start-Sleep -Seconds 90" if tag.startswith("k1") else line


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
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        text = json.dumps(messages, ensure_ascii=False)
        found = None
        if not any(m.get("role") == "tool" for m in messages):
            import re

            found = re.search(r"USE_TERMINAL (\w+)", text)
        if found:
            tag = found.group(1)
            LLM_CALLS.append(tag)
            reply = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"call_{tag}",
                        "type": "function",
                        "function": {
                            "name": "terminal",
                            "arguments": json.dumps({"command": tool_command(tag)}),
                        },
                    }
                ],
            }
        else:
            LLM_CALLS.append("final")
            reply = {"role": "assistant", "content": "done"}
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


def q(sql):
    r = subprocess.run(
        [pg_tool("psql"), *PG, "-d", DB, "-Atc", sql],
        capture_output=True,
        text=True,
        check=True,
    )
    return r.stdout.strip()


def runs(tag: str) -> int:
    """How many times the tool ran: it appends one line per execution."""
    path = marker_path(tag)
    if not path.exists():
        return 0
    data = path.read_bytes()
    # a Windows PowerShell terminal may write UTF-16 with a byte-order mark
    is_utf16 = data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE))
    text = data.decode("utf-16" if is_utf16 else "utf-8", errors="replace")
    return len([line for line in text.splitlines() if line.strip()])


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
            tools=[Tool(name="terminal")],
        ),
        workspace=LocalWorkspace(working_dir=str(WORKSPACE)),
        initial_message=SendMessageRequest(
            role="user", content=[TextContent(text=first_message)], run=False
        ),
    )
    return req.model_dump(mode="json", context={"expose_secrets": True})


async def wait_for(pred, timeout=60.0, step=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        v = pred()
        if v:
            return v
        await asyncio.sleep(step)
    return None


def kill_tree(proc: subprocess.Popen) -> None:
    """The real kill: the whole process tree, no chance to clean up."""
    subprocess.run(
        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
        capture_output=True,
        check=False,
    )
    proc.wait(timeout=30)


async def main():
    if os.name != "nt":
        raise SystemExit("this e2e is Windows only (PowerShell terminal, taskkill)")
    threading.Thread(
        target=ThreadingHTTPServer(("127.0.0.1", IDP_PORT), _Idp).serve_forever,
        daemon=True,
    ).start()
    threading.Thread(
        target=ThreadingHTTPServer(("127.0.0.1", LLM_PORT), _Llm).serve_forever,
        daemon=True,
    ).start()
    subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=True)
    subprocess.run([pg_tool("createdb"), *PG, DB], check=True)
    cenv = {
        **os.environ,
        "PYTHONUTF8": "1",
        "CGA_DATABASE_URL": f"postgresql+asyncpg://cga@127.0.0.1:54329/{DB}",
        "CGA_OIDC_ISSUER": ISSUER,
        "CGA_OIDC_JWKS_URL": f"http://127.0.0.1:{IDP_PORT}/certs",
        "CGA_OIDC_AUDIENCE": AUDIENCE,
        "CGA_OIDC_REQUIRE_HTTPS": "false",
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
    agent_dir = pathlib.Path(tempfile.mkdtemp(prefix="kr_agent_"))
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
        "OH_GOVERNANCE_ORIGIN_DEVICE_ID": AGENT_DEVICE,
        # the machine governance lock, as in a real team deployment
        "ROY_GOVERNANCE_LOCK_SECURITY_ANALYZER": "llm",
        "ROY_GOVERNANCE_LOCK_CONFIRMATION_MODE": "true",
    }
    approver = {"Authorization": "Bearer " + token("approver-1", ["agent.approver"])}
    agents: list[subprocess.Popen] = []

    def rows(cid):
        return int(
            q(
                f"select count(*) from pending_approval_records "
                f"where conversation_id='{cid}'"
            )
            or 0
        )

    def central_status(cid):
        return q(
            f"select status from pending_approval_records "
            f"where conversation_id='{cid}' order by created_at desc limit 1"
        )

    def approval_id(cid):
        return q(
            f"select id from pending_approval_records "
            f"where conversation_id='{cid}' order by created_at desc limit 1"
        )

    def outbox_of(cid):
        want = cid.replace("-", "")
        for p in agent_dir.rglob("governance_outbox.json"):
            if p.parent.name == want:
                try:
                    return json.loads(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    return None
        return None

    def disk_state(cid):
        """What is on disk for one conversation: every JSON file's execution_status
        (or outbox state). Printed, not asserted: it shows what a restart finds."""
        want = cid.replace("-", "")
        found = {}
        for path in agent_dir.rglob("*.json"):
            if path.parent.name != want or path.stat().st_size > 400_000:
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                value = data.get("execution_status") or data.get("state")
                if value:
                    found[path.name] = value
        return found

    async def start_agent(ac: httpx.AsyncClient) -> bool:
        n = len(list(LOGDIR.glob("agent_*.log")))
        proc = subprocess.Popen(
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
            stdout=open(LOGDIR / f"agent_{n}.log", "w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
        )
        agents.append(proc)
        for _ in range(360):
            try:
                if (await ac.get("/health")).status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.5)
        return False

    try:
        base = f"http://127.0.0.1:{API_PORT}"
        async with (
            httpx.AsyncClient(base_url=base, timeout=20) as c,
            httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{AGENT_PORT}", timeout=60
            ) as ac,
        ):
            for _ in range(80):
                try:
                    if (await c.get("/healthz")).status_code == 200:
                        break
                except httpx.HTTPError:
                    await asyncio.sleep(0.5)
            else:
                raise SystemExit("central did not start")
            if not await start_agent(ac):
                raise SystemExit("agent-server did not start")

            async def start_run(tag: str) -> str:
                r = await ac.post(
                    "/api/conversations", json=start_request(f"USE_TERMINAL {tag}")
                )
                if r.status_code not in (200, 201):
                    raise RuntimeError(f"start failed {r.status_code} {r.text[:300]}")
                cid = r.json()["id"]
                await ac.post(f"/api/conversations/{cid}/run")
                return cid

            async def accept(cid):
                return await c.post(
                    f"/api/v1/approvals/{approval_id(cid)}/decide",
                    json={"decision": "accept"},
                    headers={**approver, "Idempotency-Key": uuid.uuid4().hex},
                )

            async def restart_agent(cid=None):
                kill_tree(agents[-1])
                if cid:
                    print(f"INFO on disk after the kill [{cid[:8]}]: {disk_state(cid)}")
                # the port must be free again before a new process can serve on it
                await asyncio.sleep(2)
                return await start_agent(ac)

            # ---- K1: killed while the approved tool is executing --------------------
            cid1 = await start_run("k1")
            pending = await wait_for(
                lambda: rows(cid1) == 1 and central_status(cid1) == "pending"
            )
            check("K1 SETUP: approval pending at central", bool(pending))
            r = await accept(cid1)
            check(
                "K1 SETUP: approver accepts", r.status_code == 200, str(r.status_code)
            )
            started = await wait_for(lambda: runs("k1") == 1, 60)
            check("K1 SETUP: the tool is running (one marker line)", bool(started))
            check(
                "K1 SETUP: central shows the approval as executing",
                central_status(cid1) == "executing",
                f"status={central_status(cid1)!r}",
            )
            check(
                "K1 the agent-server restarts after a real kill",
                await restart_agent(cid1),
            )
            await asyncio.sleep(35)  # more than one outbox relay cycle (30 s)
            check(
                "K1 the tool was NOT run again after the restart",
                runs("k1") == 1,
                f"runs={runs('k1')}",
            )
            done = await wait_for(lambda: central_status(cid1) == "failed_unknown", 60)
            check(
                "K1 central ends the approval as failed_unknown",
                bool(done),
                f"central={central_status(cid1)!r} "
                f"outbox={(outbox_of(cid1) or {}).get('state')!r}",
            )
            r = await ac.get(f"/api/conversations/{cid1}")
            status = r.json().get("execution_status")
            check(
                "K1 the conversation is not left RUNNING",
                status != "running",
                f"status={status!r}",
            )
            ev = await ac.get(
                f"/api/conversations/{cid1}/events/search", params={"limit": 100}
            )
            kinds = [e.get("kind") for e in ev.json().get("items", [])]
            check(
                "K1 the interrupted call got an AgentErrorEvent",
                "AgentErrorEvent" in kinds,
                str(kinds[-6:]),
            )

            # ---- K3: killed while the approval is still pending ---------------------
            cid3 = await start_run("k3")
            pending = await wait_for(
                lambda: rows(cid3) == 1 and central_status(cid3) == "pending"
            )
            check("K3 SETUP: approval pending at central", bool(pending))
            check(
                "K3 the agent-server restarts after a real kill",
                await restart_agent(cid3),
            )
            await asyncio.sleep(3)
            check(
                "K3 nothing ran while nobody had decided",
                runs("k3") == 0 and central_status(cid3) == "pending",
                f"runs={runs('k3')} central={central_status(cid3)!r}",
            )
            r = await accept(cid3)
            check("K3 the approver accepts after the restart", r.status_code == 200)
            ran = await wait_for(lambda: runs("k3") >= 1, 90)
            await asyncio.sleep(5)
            check(
                "K3 the tool ran exactly once",
                bool(ran) and runs("k3") == 1,
                f"runs={runs('k3')}",
            )
            applied = await wait_for(lambda: central_status(cid3) == "applied", 60)
            check(
                "K3 central ends the approval as applied",
                bool(applied),
                f"central={central_status(cid3)!r}",
            )
    finally:
        for proc in [*agents, central]:
            if proc.poll() is None:
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    capture_output=True,
                    check=False,
                )
        for proc in [*agents, central]:
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
        bad = []
        for f in sorted(LOGDIR.glob("*.log")):
            text = f.read_text(encoding="utf-8", errors="replace")
            if f.name.startswith("central") and (
                "Traceback" in text or " 500 " in text
            ):
                bad.append(f.name)
        check("central log has no traceback / 5xx", not bad, str(bad))
        if any(not ok for _, ok in results):
            for f in sorted(LOGDIR.glob("agent_*.log")):
                print(f"--- {f.name} tail ---")
                print(f.read_text(encoding="utf-8", errors="replace")[-2500:])
        subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=False)
        shutil.rmtree(WORKSPACE, ignore_errors=True)
        shutil.rmtree(LOGDIR, ignore_errors=True)
        shutil.rmtree(agent_dir, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f"\nLLM calls seen: {LLM_CALLS}")
    print(f"{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)


asyncio.run(main())
