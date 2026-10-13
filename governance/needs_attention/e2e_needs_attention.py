"""1.11 NEEDS_ATTENTION end to end: a stuck conversation can be listed and resolved.

Real central process on a throwaway Postgres, a local fake IdP, a REAL agent-server in
team mode (real ConversationService / EventService / FIFOLock / LocalConversation) and
a scripted fake LLM. Step 1 of the work used this to reproduce the bug (a conversation
left in NEEDS_ATTENTION never gets its next action governed); it now asserts the fixed
behaviour.

Phase 1 (device binding OFF)
  CONTROL  a healthy conversation registers a second approval (the baseline for A, D)
  A  central cancels the pending approval -> parked as approval_cancelled_or_expired
     -> listed -> abandon -> the conversation is idle again and its NEXT action is
     governed
  D  the same parking -> refused requests (wrong request_id, a retry the reason does
     not allow, dismiss without a note) change nothing -> dismiss -> the conversation
     is still waiting on the action, the operator rejects it -> the next action is
     governed

Phase 2 (central restarted with device binding ON, then OFF)
  Two conversations get an approval, the device is revoked, the approver accepts both:
  the agent's claim is refused -> both parked as claim_failed.
  B  abandon: central is told (pre-claim abort), the action is rejected, the record
     ends
  C  central restarted with binding OFF -> retry -> the relay (30 s cycle) repeats the
     claim with the original key -> the tool actually runs and the result is reported

Checks named SETUP-* mean the scenario itself did not run (inconclusive). A FAIL
anywhere else is a real finding.

Run from the repository root with the SDK's own Python (the one that can import
`openhands.agent_server`):

    python governance/needs_attention/e2e_needs_attention.py

Needs, beyond this repository:
  * the central-governance-api checkout, by default the sibling directory
    `central-governance-api` of this repository (OHS_CENTRAL_DIR), with its own venv
    (OHS_CENTRAL_PYTHON, default <central>/.venv/{Scripts/python.exe | bin/python});
  * PostgreSQL client and server programs (OHS_PG_BIN, a directory; default
    "C:/Program Files/PostgreSQL/17/bin" on Windows, else they are taken from PATH);
  * a throwaway Postgres on 127.0.0.1:54329 (user cga, trust auth). The script creates
    and drops its own database `central_e2e_attn` and never touches anything else.
Takes about five minutes (the relay cycle is 30 seconds and one scenario waits for it).
"""

import asyncio
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
from joserfc import jwk, jwt


HERE = pathlib.Path(__file__).resolve().parent  # <repo>/governance/needs_attention
SDK = HERE.parents[1].as_posix()  # the repository root
SPY = sys.executable  # must be the interpreter that can import openhands.agent_server
_VENV_PYTHON = "Scripts/python.exe" if os.name == "nt" else "bin/python"
CENTRAL = (
    os.environ.get("OHS_CENTRAL_DIR")
    or (HERE.parents[2] / "central-governance-api").as_posix()
)
CPY = os.environ.get("OHS_CENTRAL_PYTHON") or f"{CENTRAL}/.venv/{_VENV_PYTHON}"
PG_BIN = os.environ.get("OHS_PG_BIN") or (
    "C:/Program Files/PostgreSQL/17/bin" if os.name == "nt" else ""
)
CLI = (HERE / "governance_attention_cli.py").as_posix()
PG = ["-h", "127.0.0.1", "-p", "54329", "-U", "cga"]


def pg_tool(name: str) -> str:
    """Path of a PostgreSQL program: in OHS_PG_BIN if set, else found on PATH."""
    exe = name + (".exe" if os.name == "nt" else "")
    return f"{PG_BIN}/{exe}" if PG_BIN else exe


DB = "central_e2e_attn"
IDP_PORT, API_PORT, AGENT_PORT, LLM_PORT = 18794, 8898, 8797, 18795
ISSUER = f"http://127.0.0.1:{IDP_PORT}/realms/e2e"
AUDIENCE = "central-governance-api"
SERVICE_CLIENT = "svc-agent-attn"
AGENT_DEVICE = "device-attn"
RELAY_WAIT_SECONDS = (
    90  # the relay cycle is 30 s (GOVERNANCE_OUTBOX_RELAY_INTERVAL_SECONDS)
)

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

    def log_message(self, format: str, *args: Any) -> None:  # noqa: ARG002
        pass


LOGDIR = pathlib.Path(tempfile.mkdtemp(prefix="attn_logs_"))
WORKSPACE = pathlib.Path(tempfile.mkdtemp(prefix="attn_ws_"))
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
    """Decides from the LAST message only. A message "USE_TERMINAL <tag>" yields a
    terminal call that writes ran_<tag>.marker, so every action is told apart by its
    tag and a second request in the same conversation yields a second, different
    tool call."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        last = messages[-1] if messages else {}
        last_text = json.dumps(last, ensure_ascii=False)
        found = re.search(r"USE_TERMINAL (\w+)", last_text)
        if last.get("role") == "tool":
            LLM_CALLS.append("final")
            reply = {"role": "assistant", "content": "done"}
        elif found:
            tag = found.group(1)
            LLM_CALLS.append(tag)
            marker = (WORKSPACE / f"ran_{tag}.marker").as_posix()
            reply = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"call_{tag}",
                        "type": "function",
                        "function": {
                            "name": "terminal",
                            "arguments": json.dumps(
                                {"command": f"echo ran > {marker}"}
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

    def log_message(self, format: str, *args: Any) -> None:  # noqa: ARG002
        pass


results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(
        ("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""),
        flush=True,
    )


def info(name, detail):
    print("INFO " + name + f"  [{detail}]", flush=True)


def q(sql):
    r = subprocess.run(
        [pg_tool("psql"), *PG, "-d", DB, "-Atc", sql],
        capture_output=True,
        text=True,
        check=True,
    )
    return r.stdout.strip()


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


async def wait_for(pred, timeout=40.0, step=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        v = pred()
        if v:
            return v
        await asyncio.sleep(step)
    return None


async def main():
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
    cenv_base = {
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
        env=cenv_base,
        check=True,
        capture_output=True,
    )

    centrals: list = []

    async def start_central(bind: bool):
        """(Re)start central on the same database; binding on or off."""
        for proc in centrals:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
        centrals.clear()
        env = {**cenv_base, "CGA_DEVICE_BINDING_ENFORCED": "true" if bind else "false"}
        proc = subprocess.Popen(
            [CPY, "-c", "from central_governance_api.main import main; main()"],
            cwd=CENTRAL,
            env=env,
            stdout=open(
                LOGDIR / f"central_{len(list(LOGDIR.glob('central_*.log')))}.log",
                "w",
                encoding="utf-8",
            ),
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
        )
        centrals.append(proc)
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{API_PORT}", timeout=5
        ) as c:
            for _ in range(80):
                try:
                    if (await c.get("/healthz")).status_code == 200:
                        return True
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.5)
        return False

    agent_dir = pathlib.Path(tempfile.mkdtemp(prefix="attn_agent_"))
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
    }
    agent = None
    base = f"http://127.0.0.1:{API_PORT}"
    svc = {"Authorization": "Bearer " + token(SERVICE_CLIENT, ["agent.operator"])}
    approver = {"Authorization": "Bearer " + token("approver-1", ["agent.approver"])}

    def ik():
        return {"Idempotency-Key": uuid.uuid4().hex}

    def outbox_path(cid: str):
        want = cid.replace("-", "")
        for p in agent_dir.rglob("governance_outbox.json"):
            if p.parent.name == want:
                return p
        return None

    def outbox_of(cid: str):
        p = outbox_path(cid)
        if p is None:
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def request_id_of(cid: str) -> str:
        """The request_id of a record that must exist at this point."""
        record = outbox_of(cid)
        assert record is not None, f"no outbox for {cid}"
        return record["request_id"]

    def state_of(cid):
        return (outbox_of(cid) or {}).get("state")

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

    def marker(tag):
        return (WORKSPACE / f"ran_{tag}.marker").exists()

    try:
        if not await start_central(bind=False):
            raise SystemExit("central did not start")
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
        async with (
            httpx.AsyncClient(base_url=base, timeout=20) as c,
            httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{AGENT_PORT}", timeout=60
            ) as ac,
        ):
            for _ in range(360):
                try:
                    if (await ac.get("/health")).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.5)
            else:
                agent.terminate()
                print(
                    (LOGDIR / "agent.log").read_text(
                        encoding="utf-8", errors="replace"
                    )[-2500:]
                )
                raise SystemExit("agent-server did not start")

            async def start_and_run(tag: str) -> str:
                r = await ac.post(
                    "/api/conversations", json=start_request(f"USE_TERMINAL {tag}")
                )
                if r.status_code not in (200, 201):
                    raise RuntimeError(f"start failed {r.status_code} {r.text[:300]}")
                cid: str = r.json()["id"]
                await ac.post(f"/api/conversations/{cid}/run")
                return cid

            async def say(cid, tag):
                return await ac.post(
                    f"/api/conversations/{cid}/events",
                    json={
                        "role": "user",
                        "content": [{"type": "text", "text": f"USE_TERMINAL {tag}"}],
                        "run": True,
                    },
                )

            async def pending_approval(cid, expected_rows):
                return await wait_for(
                    lambda: rows(cid) == expected_rows
                    and central_status(cid) == "pending"
                )

            async def decide_accept(cid):
                return await c.post(
                    f"/api/v1/approvals/{approval_id(cid)}/decide",
                    json={"decision": "accept"},
                    headers={**approver, **ik()},
                )

            async def attention():
                r = await ac.get("/api/governance/attention")
                return r.json() if r.status_code == 200 else None

            async def resolve(cid, action, request_id, note=None):
                body = {"action": action, "expected_request_id": request_id}
                if note is not None:
                    body["note"] = note
                return await ac.post(
                    f"/api/governance/attention/{cid}/resolve", json=body
                )

            async def exec_status(cid):
                return (
                    (await ac.get(f"/api/conversations/{cid}"))
                    .json()
                    .get("execution_status")
                )

            def listed(items, cid):
                return next(
                    (i for i in (items or []) if i["conversation_id"] == cid), None
                )

            async def scenario(name, coro):
                print(f"\n=== {name}", flush=True)
                try:
                    await coro
                except (
                    Exception
                ) as exc:  # a crash in one scenario must not hide the others
                    check(f"{name}: scenario ran to completion", False, repr(exc)[:200])

            # ============================ phase 1 ============================
            async def control():
                cid = await start_and_run("ctl1")
                check("SETUP control: started", bool(cid))
                if not await pending_approval(cid, 1):
                    return check("SETUP control: approval #1 pending", False)
                r = await decide_accept(cid)
                check("CONTROL accept #1", r.status_code == 200, r.text[:80])
                check(
                    "CONTROL #1 ran and was reported",
                    bool(await wait_for(lambda: state_of(cid) == "result_reported", 60))
                    and marker("ctl1"),
                    f"state={state_of(cid)!r}",
                )
                await say(cid, "ctl2")
                check(
                    "CONTROL a healthy conversation registers a second approval",
                    bool(await wait_for(lambda: rows(cid) == 2, 40)),
                    f"rows={rows(cid)}",
                )

            async def scenario_a():
                cid = await start_and_run("a1")
                if not await pending_approval(cid, 1):
                    return check("SETUP A: approval #1 pending", False)
                first_request_id = (outbox_of(cid) or {}).get("request_id")
                r = await c.post(
                    f"/api/v1/approvals/{approval_id(cid)}/cancel",
                    headers={**svc, **ik()},
                )
                check(
                    "SETUP A: central cancel succeeds",
                    r.status_code == 200,
                    r.text[:80],
                )
                parked = await wait_for(lambda: state_of(cid) == "needs_attention", 40)
                ob = outbox_of(cid) or {}
                check(
                    "A parked in needs_attention",
                    bool(parked),
                    f"state={state_of(cid)!r}",
                )
                check(
                    "A the reason and code are recorded (was null before step 2)",
                    ob.get("needs_attention_reason") == "approval_cancelled_or_expired"
                    and ob.get("last_error_code") == "status=cancelled",
                    f"reason={ob.get('needs_attention_reason')!r} "
                    f"code={ob.get('last_error_code')!r}",
                )
                item = listed(await attention(), cid)
                check(
                    "A GET /attention lists it with the safe actions",
                    item is not None
                    and item["allowed_actions"] == ["abandon", "dismiss"]
                    and item["request_id"] == first_request_id,
                    str(item)[:160],
                )

                r = await resolve(cid, "abandon", first_request_id, "e2e: not wanted")
                body = r.json() if r.status_code == 200 else {}
                check("A abandon succeeds", r.status_code == 200, r.text[:160])
                check(
                    "A central was already past the approval (already_terminal) "
                    "and the action was rejected locally",
                    body.get("central_step") == "already_terminal"
                    and body.get("new_state") == "cancelled"
                    and body.get("conversation_still_waiting") is False,
                    str(body)[:200],
                )
                ob = outbox_of(cid) or {}
                check(
                    "A the record ends cancelled with the operator's note",
                    ob.get("state") == "cancelled"
                    and ob.get("resolution_note") == "e2e: not wanted"
                    and ob.get("resolved_at") is not None,
                    f"state={ob.get('state')!r}",
                )
                check(
                    "A the REAL conversation was rejected: it is idle again",
                    await exec_status(cid) == "idle",
                    f"status={await exec_status(cid)!r}",
                )
                check(
                    "A it no longer shows in the list",
                    listed(await attention(), cid) is None,
                )

                await say(cid, "a2")
                check(
                    "A (was BUG-REPRO-3) the NEXT, different action is governed "
                    "again: a second approval appears",
                    bool(await pending_approval(cid, 2)),
                    f"rows={rows(cid)}",
                )
                ob2 = outbox_of(cid) or {}
                path = outbox_path(cid)
                parent = path.parent if path else None
                archived = (
                    list(parent.glob(".governance_outbox.*.archived.json"))
                    if parent
                    else []
                )
                check(
                    "A (was BUG-REPRO-4) the outbox now tracks the new workflow "
                    "and the old record was kept as history",
                    ob2.get("request_id") not in (None, first_request_id)
                    and len(archived) == 1,
                    f"same_request={ob2.get('request_id') == first_request_id} "
                    f"archived={len(archived)}",
                )
                r = await decide_accept(cid)
                check(
                    "A the new approval is accepted", r.status_code == 200, r.text[:80]
                )
                check(
                    "A the new action runs; the abandoned one never did",
                    bool(await wait_for(lambda: marker("a2"), 60)) and not marker("a1"),
                    f"a1={marker('a1')} a2={marker('a2')}",
                )

            async def scenario_d():
                cid = await start_and_run("d1")
                if not await pending_approval(cid, 1):
                    return check("SETUP D: approval #1 pending", False)
                await c.post(
                    f"/api/v1/approvals/{approval_id(cid)}/cancel",
                    headers={**svc, **ik()},
                )
                if not await wait_for(lambda: state_of(cid) == "needs_attention", 40):
                    return check("SETUP D: parked", False, f"state={state_of(cid)!r}")
                request_id = request_id_of(cid)
                before = outbox_of(cid)

                r = await resolve(cid, "dismiss", "some-other-request", "x")
                check(
                    "D a request quoting another workflow is refused (409, "
                    "request_id_mismatch)",
                    r.status_code == 409
                    and r.json()["detail"]["error_code"] == "request_id_mismatch",
                    f"{r.status_code} {r.text[:100]}",
                )
                r = await resolve(cid, "retry", request_id)
                detail = r.json().get("detail", {}) if r.status_code == 409 else {}
                check(
                    "D retry is refused for this reason and says what is allowed",
                    r.status_code == 409
                    and detail.get("error_code") == "action_not_allowed"
                    and detail.get("allowed_actions") == ["abandon", "dismiss"],
                    f"{r.status_code} {r.text[:120]}",
                )
                r = await ac.post(
                    f"/api/governance/attention/{cid}/resolve",
                    json={"action": "dismiss", "expected_request_id": request_id},
                )
                check(
                    "D dismiss without a note is a 422",
                    r.status_code == 422,
                    str(r.status_code),
                )
                check(
                    "D none of the refused requests changed anything",
                    outbox_of(cid) == before,
                )

                r = await resolve(cid, "dismiss", request_id, "e2e: looked at central")
                body = r.json() if r.status_code == 200 else {}
                check("D dismiss succeeds", r.status_code == 200, r.text[:160])
                check(
                    "D it says the conversation is STILL waiting on the action",
                    body.get("new_state") == "resolved_manually"
                    and body.get("central_step") == "not_applicable"
                    and body.get("conversation_still_waiting") is True,
                    str(body)[:200],
                )
                check(
                    "D and it is: dismiss rejected nothing",
                    await exec_status(cid) == "waiting_for_confirmation",
                    f"status={await exec_status(cid)!r}",
                )
                r = await ac.post(
                    f"/api/conversations/{cid}/events/respond_to_confirmation",
                    json={"accept": False, "reason": "e2e: operator rejects"},
                )
                check("D the operator rejects the action by hand", r.status_code == 200)
                await say(cid, "d2")
                check(
                    "D the NEXT action is governed again",
                    bool(await pending_approval(cid, 2)),
                    f"rows={rows(cid)}",
                )
                check("D neither tool call ran", not marker("d1") and not marker("d2"))

            async def park_by_central_cancel(tag):
                cid = await start_and_run(tag)
                if not cid or not await pending_approval(cid, 1):
                    return None
                await c.post(
                    f"/api/v1/approvals/{approval_id(cid)}/cancel",
                    headers={**svc, **ik()},
                )
                if not await wait_for(lambda: state_of(cid) == "needs_attention", 40):
                    return None
                return cid

            def cli(*args, stdin=None):
                """The CLI as a subprocess, against the real agent-server."""
                return subprocess.run(
                    [SPY, CLI, *args, "--url", f"http://127.0.0.1:{AGENT_PORT}"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    input=stdin,
                    env={
                        k: v
                        for k, v in os.environ.items()
                        if k not in ("OH_SESSION_API_KEYS_0", "SESSION_API_KEY")
                    }
                    | {"PYTHONUTF8": "1"},
                )

            async def scenario_cli():
                cid_1 = await park_by_central_cancel("e1")
                cid_2 = await park_by_central_cancel("e2")
                if not (cid_1 and cid_2):
                    return check(
                        "SETUP CLI: two parked conversations",
                        False,
                        f"e1={cid_1} e2={cid_2}",
                    )
                r = cli("list", "--json")
                items = json.loads(r.stdout) if r.returncode == 0 else []
                check(
                    "CLI list --json shows both parked conversations",
                    r.returncode == 0
                    and {i["conversation_id"] for i in items} >= {cid_1, cid_2},
                    f"exit={r.returncode} {r.stderr[:120]}",
                )
                r = cli("list")
                check(
                    "CLI list (text) names the reason and the request id",
                    r.returncode == 0
                    and "approval_cancelled_or_expired" in r.stdout
                    and request_id_of(cid_1) in r.stdout,
                    r.stdout[:120],
                )

                # with an explicit request id, a note, no question asked
                r = cli(
                    "resolve",
                    cid_1,
                    "dismiss",
                    "--request-id",
                    request_id_of(cid_1),
                    "--note",
                    "e2e: cli dismiss",
                )
                check(
                    "CLI resolve dismiss with --request-id succeeds",
                    r.returncode == 0 and "resolved_manually" in r.stdout,
                    f"exit={r.returncode} {r.stdout[:100]} {r.stderr[:100]}",
                )
                check(
                    "CLI dismiss: it warns the conversation is still waiting",
                    "STILL waiting" in r.stdout,
                    r.stdout[-160:],
                )
                ob = outbox_of(cid_1) or {}
                check(
                    "CLI dismiss: the record ends resolved_manually with the note",
                    ob.get("state") == "resolved_manually"
                    and ob.get("resolution_note") == "e2e: cli dismiss",
                    str(ob.get("state")),
                )

                # without an id: it shows the record and asks; answer yes on stdin
                r = cli("resolve", cid_2, "abandon", stdin="y\n")
                check(
                    "CLI resolve abandon (shown, asked, answered y) succeeds",
                    r.returncode == 0
                    and "About to abandon" in r.stdout
                    and "cancelled" in r.stdout,
                    f"exit={r.returncode} {r.stdout[-160:]} {r.stderr[:100]}",
                )
                check(
                    "CLI abandon: the REAL conversation is idle again",
                    await exec_status(cid_2) == "idle",
                    f"{await exec_status(cid_2)!r}",
                )

                # answering no changes nothing
                cid_3 = await park_by_central_cancel("e3")
                if cid_3 is None:
                    return check("SETUP CLI: a third parked conversation", False)
                before = outbox_of(cid_3)
                r = cli("resolve", cid_3, "abandon", stdin="n\n")
                check(
                    "CLI answering n declines (exit 1) and changes nothing",
                    r.returncode == 1 and outbox_of(cid_3) == before,
                    f"exit={r.returncode}",
                )
                r = cli("resolve", cid_3, "retry", stdin="y\n")
                check(
                    "CLI an action the record does not allow is refused before asking",
                    r.returncode == 1
                    and "not allowed" in r.stderr
                    and outbox_of(cid_3) == before,
                    r.stderr[:140],
                )
                r = cli("list", "--json")
                left = {i["conversation_id"] for i in json.loads(r.stdout)}
                check(
                    "CLI the resolved two are gone from the list, "
                    "the declined one stays",
                    cid_1 not in left and cid_2 not in left and cid_3 in left,
                    str(left)[:120],
                )
                check("CLI no tool ran", not any(marker(t) for t in ("e1", "e2", "e3")))

            async def scenario_race():
                """resolve and DELETE of the same conversation sent at the same time.
                The interleaving is up to the event loop, so several rounds, both
                actions; whichever way each round falls, nothing may fail with a
                server error and nothing may be left behind.

                A smoke test, NOT proof of the lifecycle lock: against a real central
                the call an abandon makes takes milliseconds, so the window is too
                narrow to open, and this passed on the code without the lock too. The
                deterministic proof is in
                tests/agent_server/test_conversation_service.py (a resolve held
                inside its central call while a delete is started)."""
                rounds = []
                for i, action in enumerate(["abandon", "dismiss"] * 3):
                    cid = await park_by_central_cancel(f"r{i}")
                    if cid is None:
                        return check(f"SETUP race round {i}: parked", False)
                    body = {
                        "action": action,
                        "expected_request_id": request_id_of(cid),
                        "note": "e2e race",
                    }
                    resolved, deleted = await asyncio.gather(
                        ac.post(f"/api/governance/attention/{cid}/resolve", json=body),
                        ac.delete(f"/api/conversations/{cid}"),
                        return_exceptions=True,
                    )
                    rounds.append((cid, action, resolved, deleted))
                summary = [
                    (
                        action,
                        getattr(res, "status_code", repr(res)[:40]),
                        getattr(dele, "status_code", repr(dele)[:40]),
                    )
                    for _, action, res, dele in rounds
                ]
                info("RACE (action, resolve status, delete status) per round", summary)

                def code(x):
                    return getattr(x, "status_code", 599)

                check(
                    "RACE neither request ever ended in a server error",
                    all(
                        code(res) < 500 and code(dele) < 500
                        for _, _, res, dele in rounds
                    ),
                    str(summary),
                )
                check(
                    "RACE every delete succeeded",
                    all(code(dele) in (200, 204) for _, _, _, dele in rounds),
                )
                check(
                    "RACE a resolve either took effect (200) or found nothing (404)",
                    all(code(res) in (200, 404) for _, _, res, _ in rounds),
                    str([code(res) for _, _, res, _ in rounds]),
                )
                gone = [
                    (await ac.get(f"/api/conversations/{cid}")).status_code == 404
                    for cid, *_ in rounds
                ]
                check(
                    "RACE every conversation is gone afterwards", all(gone), str(gone)
                )
                check(
                    "RACE no outbox file is left behind",
                    all(outbox_path(cid) is None for cid, *_ in rounds),
                )

            await scenario("CONTROL (healthy baseline)", control())
            await scenario("A: central cancels -> abandon", scenario_a())
            await scenario("D: dismiss and refused requests", scenario_d())
            await scenario("CLI against the real agent-server", scenario_cli())
            await scenario("RACE: resolve and delete at the same time", scenario_race())

            # ============================ phase 2 ============================
            async def phase2():
                check(
                    "SETUP restart central with device binding ON",
                    await start_central(bind=True),
                )
                r = await c.post(
                    "/api/v1/devices/register",
                    json={"device_id": AGENT_DEVICE},
                    headers={**svc, **ik()},
                )
                check(
                    "SETUP register the agent's device",
                    r.status_code == 201,
                    r.text[:80],
                )
                cid_b = await start_and_run("b1")
                cid_c = await start_and_run("c1")
                ok_b = await pending_approval(cid_b, 1)
                ok_c = await pending_approval(cid_c, 1)
                if not (ok_b and ok_c):
                    return check(
                        "SETUP B and C: approvals pending",
                        False,
                        f"b={rows(cid_b)} c={rows(cid_c)}",
                    )
                dev_id = q(
                    f"select id from device_registrations "
                    f"where device_id='{AGENT_DEVICE}'"
                )
                r = await c.post(
                    f"/api/v1/devices/{dev_id}/revoke", headers={**svc, **ik()}
                )
                check(
                    "SETUP revoke the device (claims will now be refused)",
                    r.status_code == 200,
                    r.text[:80],
                )
                for cid in (cid_b, cid_c):
                    r = await decide_accept(cid)
                    check("SETUP approver accepts", r.status_code == 200, r.text[:80])
                parked_b = await wait_for(
                    lambda: state_of(cid_b) == "needs_attention", 60
                )
                parked_c = await wait_for(
                    lambda: state_of(cid_c) == "needs_attention", 60
                )
                ob_b, ob_c = outbox_of(cid_b) or {}, outbox_of(cid_c) or {}
                check(
                    "B and C are parked after the claim was refused",
                    bool(parked_b and parked_c),
                    f"b={state_of(cid_b)!r} c={state_of(cid_c)!r}",
                )
                check(
                    "B and C: reason claim_failed with central's error code recorded",
                    ob_b.get("needs_attention_reason") == "claim_failed"
                    and ob_c.get("needs_attention_reason") == "claim_failed",
                    f"b={ob_b.get('last_error_code')!r} "
                    f"c={ob_c.get('last_error_code')!r}",
                )
                check(
                    "B and C: neither tool ran", not marker("b1") and not marker("c1")
                )
                items = await attention()
                check(
                    "B and C are both listed with retry, abandon and dismiss",
                    all(
                        (listed(items, x) or {}).get("allowed_actions")
                        == ["retry", "abandon", "dismiss"]
                        for x in (cid_b, cid_c)
                    ),
                    str([i["allowed_actions"] for i in items or []]),
                )

                # ---- B: abandon -> central pre-claim abort
                status_before = central_status(cid_b)
                r = await resolve(
                    cid_b, "abandon", ob_b["request_id"], "e2e: abandon B"
                )
                body = r.json() if r.status_code == 200 else {}
                check("B abandon succeeds", r.status_code == 200, r.text[:200])
                info(
                    "B central status before -> after the abort",
                    f"{status_before} -> {central_status(cid_b)}",
                )
                check(
                    "B central was told with the pre-claim abort, the action was "
                    "rejected, the record ended",
                    body.get("central_step") == "aborted"
                    and body.get("new_state") == "cancelled"
                    and body.get("conversation_still_waiting") is False
                    and await exec_status(cid_b) == "idle",
                    str(body)[:200],
                )
                check("B the tool never ran", not marker("b1"))

                # ---- C: fix the cause (binding off), then retry
                check(
                    "SETUP restart central with device binding OFF",
                    await start_central(bind=False),
                )
                r = await resolve(cid_c, "retry", ob_c["request_id"])
                body = r.json() if r.status_code == 200 else {}
                check(
                    "C retry is accepted and only re-arms the claim (nothing sent yet)",
                    r.status_code == 200
                    and body.get("new_state") == "claim_inflight"
                    and body.get("central_step") == "not_applicable",
                    r.text[:200],
                )
                ob = outbox_of(cid_c) or {}
                check(
                    "C the stale reason is cleared while the claim is pending again",
                    ob.get("state")
                    in (
                        "claim_inflight",
                        "claimed",
                        "execution_started",
                        "result_pending",
                        "result_reported",
                    )
                    and ob.get("needs_attention_reason") is None,
                    f"state={ob.get('state')!r} "
                    f"reason={ob.get('needs_attention_reason')!r}",
                )
                started = time.monotonic()
                done = await wait_for(
                    lambda: state_of(cid_c) == "result_reported", RELAY_WAIT_SECONDS
                )
                waited = time.monotonic() - started
                check(
                    "C the relay repeated the claim and the result was reported",
                    bool(done),
                    f"state={state_of(cid_c)!r} after {waited:.0f}s",
                )
                info("C seconds from retry to result_reported", f"{waited:.0f}")
                check("C the tool ran exactly once (its marker exists)", marker("c1"))
                check(
                    "C central ends the approval as applied",
                    central_status(cid_c) == "applied",
                    f"status={central_status(cid_c)!r}",
                )
                items = await attention()
                check(
                    "C and B are gone from the list",
                    listed(items, cid_c) is None and listed(items, cid_b) is None,
                    str(items)[:160],
                )

            await scenario("PHASE 2: claim_failed -> B abandon, C retry", phase2())
    finally:
        for proc in [agent, *centrals]:
            if proc is not None:
                proc.terminate()
        for proc in [agent, *centrals]:
            if proc is not None:
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for f in sorted(LOGDIR.glob("*.log")):
            text = f.read_text(encoding="utf-8", errors="replace")
            info(f"{f.name} tracebacks", f"{text.count('Traceback')} (in {LOGDIR})")
    ok = sum(1 for _, v in results if v)
    print(f"\n{ok}/{len(results)} passed")
    raise SystemExit(0 if ok == len(results) else 1)


if __name__ == "__main__":
    asyncio.run(main())
