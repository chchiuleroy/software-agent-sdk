"""Device binding (CGA_DEVICE_BINDING_ENFORCED=true) end to end.

Real central process on a throwaway Postgres, a local fake IdP, a REAL
agent-server process in team mode and a scripted fake LLM. Three parts:

  P  direct HTTP/GovernanceClient: create/claim need an ACTIVE device owned by
     the calling principal (unregistered, other owner, revoked, re-register after
     revoke); what an idempotent REPLAY does after revocation is only OBSERVED
     and printed (the open 1.8 decision), not asserted.
  C  real conversations: unregistered device -> nothing is approved and the tool
     does not run; registered -> approval appears, an approver accepts, the tool
     runs; revoked -> the next attempt creates no approval and does not run.
  D  1.10 residual: DELETE /api/conversations/{id} on the real agent-server
     cancels the not-yet-claimed central approval.

Run with the SDK venv python (cwd = openhands-governance/openhands-sdk-governed).
Needs the throwaway Postgres on 127.0.0.1:54329 (user cga, trust auth). It
creates and drops its own database `central_e2e_bind`.
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
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
from joserfc import jwk, jwt

from ohs_env import CENTRAL, CPY, SDK, SPY, pg_tool


PG = ["-h", "127.0.0.1", "-p", "54329", "-U", "cga"]
DB = "central_e2e_bind"
IDP_PORT, API_PORT, AGENT_PORT, LLM_PORT = 18792, 8897, 8796, 18793
ISSUER = f"http://127.0.0.1:{IDP_PORT}/realms/e2e"
AUDIENCE = "central-governance-api"
SERVICE_CLIENT = "svc-agent-bind"
KC = os.environ.get("BIND_IDP") == "keycloak"  # real Keycloak instead of the fake IdP
KC_TOKEN_URL = (
    "http://localhost:8080/realms/roy-governance/protocol/openid-connect/token"
)
KC_CLIENTS = {
    "svc": ("cga-test-operator", "CGA_TEST_OPERATOR_SECRET"),
    "approver": ("cga-test-approver", "CGA_TEST_APPROVER_SECRET"),
    "other": ("cga-test-admin", "CGA_TEST_ADMIN_SECRET"),
}
AGENT_DEVICE = "device-bind"

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


LOGDIR = pathlib.Path(tempfile.mkdtemp(prefix="bind_logs_"))
WORKSPACE = pathlib.Path(tempfile.mkdtemp(prefix="bind_ws_"))
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
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        text = json.dumps(messages, ensure_ascii=False)
        if any(m.get("role") == "tool" for m in messages):
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


def info(name, detail):
    print("INFO " + name + f"  [{detail}]")


def psql(*args):
    return subprocess.run(
        [pg_tool("psql"), *PG, *args], capture_output=True, text=True, check=True
    )


def q(sql):
    return psql("-d", DB, "-Atc", sql).stdout.strip()


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


def create_body(case: str, device: str) -> dict:
    from openhands.agent_server.governance_client import compute_display_digest

    fields = dict(
        action_type="terminal_command",
        tool_name="bash",
        policy_revision="e2e-bind-v1",
        action_summary=f"echo {case}",
        action_payload={"command": f"echo {case}"},
        digest_salt=None,
    )
    return {
        "request_id": f"e2e-bind-{case}-{uuid.uuid4().hex[:8]}",
        "origin_device_id": device,
        "conversation_id": "e2e-bind-conv",
        "action_event_id": f"e2e-bind-event-{case}",
        "tool_call_id": None,
        **fields,
        "action_payload_digest": compute_display_digest(**fields),
    }


async def wait_for(pred, timeout=40.0, step=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        v = pred()
        if v:
            return v
        await asyncio.sleep(step)
    return None


async def main():
    sys.path.insert(0, SDK + "/openhands-agent-server")
    from openhands.agent_server.governance_client import (
        GovernanceApiError,
        GovernanceClient,
    )

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
        **(
            {}
            if KC
            else {
                "CGA_OIDC_ISSUER": ISSUER,
                "CGA_OIDC_JWKS_URL": f"http://127.0.0.1:{IDP_PORT}/certs",
                "CGA_OIDC_AUDIENCE": AUDIENCE,
                "CGA_OIDC_REQUIRE_HTTPS": "false",
            }
        ),
        # BIND_ENFORCED=false is the mutation check: the binding cases must then FAIL.
        "CGA_DEVICE_BINDING_ENFORCED": os.environ.get("BIND_ENFORCED", "true"),
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
    agent_dir = tempfile.mkdtemp(prefix="bind_agent_")
    aenv = {
        **os.environ,
        "PYTHONUTF8": "1",
        "OPENHANDS_SUPPRESS_BANNER": "1",
        "OH_GOVERNANCE_DEPLOYMENT_MODE": "team",
        "OH_GOVERNANCE_BRIDGE_TOKEN": secrets.token_urlsafe(24),
        "OH_GOVERNANCE_CENTRAL_API_BASE_URL": f"http://127.0.0.1:{API_PORT}",
        "OH_GOVERNANCE_CENTRAL_API_TOKEN_URL": KC_TOKEN_URL
        if KC
        else f"http://127.0.0.1:{IDP_PORT}/token",
        "OH_GOVERNANCE_CLIENT_ID": KC_CLIENTS["svc"][0] if KC else SERVICE_CLIENT,
        "OH_GOVERNANCE_CLIENT_SECRET": os.environ[KC_CLIENTS["svc"][1]]
        if KC
        else "unused",
        "OH_GOVERNANCE_ORIGIN_DEVICE_ID": AGENT_DEVICE,
    }
    agent = None
    base = f"http://127.0.0.1:{API_PORT}"
    svc: dict = {}
    approver: dict = {}
    other: dict = {}

    async def refresh_tokens():
        """Fill svc / approver / other bearer headers (real Keycloak or minted)."""
        if KC:
            async with httpx.AsyncClient(timeout=20) as h:
                for name, target in (
                    ("svc", svc),
                    ("approver", approver),
                    ("other", other),
                ):
                    cid, env_name = KC_CLIENTS[name]
                    r = await h.post(
                        KC_TOKEN_URL,
                        data={
                            "grant_type": "client_credentials",
                            "client_id": cid,
                            "client_secret": os.environ[env_name],
                        },
                    )
                    r.raise_for_status()
                    target["Authorization"] = "Bearer " + r.json()["access_token"]
        else:
            svc["Authorization"] = "Bearer " + token(SERVICE_CLIENT, ["agent.operator"])
            approver["Authorization"] = "Bearer " + token(
                "approver-1", ["agent.approver"]
            )
            other["Authorization"] = "Bearer " + token("other-svc", ["agent.operator"])

    def ik():
        return {"Idempotency-Key": uuid.uuid4().hex}

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
            await refresh_tokens()

            async def register(device, headers=svc):
                return await c.post(
                    "/api/v1/devices/register",
                    json={"device_id": device},
                    headers={**headers, **ik()},
                )

            async def decide(aid):
                return await c.post(
                    f"/api/v1/approvals/{aid}/decide",
                    json={"decision": "accept"},
                    headers={**approver, **ik()},
                )

            # ===================== Part P: direct HTTP =====================
            gc = GovernanceClient(
                base_url=base,
                token_url=KC_TOKEN_URL if KC else f"http://127.0.0.1:{IDP_PORT}/token",
                client_id=KC_CLIENTS["svc"][0] if KC else SERVICE_CLIENT,
                client_secret=os.environ[KC_CLIENTS["svc"][1]] if KC else "unused",
            )

            async def err_of(coro):
                try:
                    await coro
                    return None
                except GovernanceApiError as e:
                    return (e.status_code, e.error_code)

            b = create_body("unreg", "dev-direct")
            got = await err_of(gc.create_approval(b, idempotency_key="k-unreg"))
            check(
                "P1 create with an unregistered device is refused (403 device_not_bound)",
                got is not None and got[0] == 403,
                str(got),
            )

            r = await register("dev-direct")
            check(
                "P2 the device owner can register it",
                r.status_code == 201,
                r.text[:100],
            )
            reg_id = r.json().get("id")

            b1 = create_body("ok1", "dev-direct")
            created = await gc.create_approval(b1, idempotency_key="k-create-1")
            aid1 = created["id"]
            check("P3 create with the registered device is accepted", bool(aid1))
            await decide(aid1)
            claim1 = await gc.claim(aid1, idempotency_key="k-claim-1")
            check(
                "P4 claim with the registered device works",
                "execution_attempt_id" in claim1,
            )

            b2 = create_body("ok2", "dev-direct")
            aid2 = (await gc.create_approval(b2, idempotency_key="k-create-2"))["id"]
            await decide(aid2)  # accepted, deliberately NOT claimed yet

            b3 = create_body(
                "ok3", "dev-direct"
            )  # claimed BEFORE the revoke, reported after
            aid3 = (await gc.create_approval(b3, idempotency_key="k-create-3"))["id"]
            await decide(aid3)
            attempt3 = (await gc.claim(aid3, idempotency_key="k-claim-3"))[
                "execution_attempt_id"
            ]

            r = await register("dev-other", headers=other)
            check("P5 another principal registers its own device", r.status_code == 201)
            got = await err_of(
                gc.create_approval(
                    create_body("steal", "dev-other"), idempotency_key="k-steal"
                )
            )
            check(
                "P6 a device registered by someone else cannot be used (403)",
                got is not None and got[0] == 403,
                str(got),
            )

            r = await c.post(
                f"/api/v1/devices/{reg_id}/revoke", headers={**svc, **ik()}
            )
            check("P7 the owner revokes the device", r.status_code == 200, r.text[:100])

            got = await err_of(
                gc.create_approval(
                    create_body("afterrev", "dev-direct"), idempotency_key="k-afterrev"
                )
            )
            check(
                "P8 create after revoke is refused (403)",
                got is not None and got[0] == 403,
                str(got),
            )
            got = await err_of(gc.claim(aid2, idempotency_key="k-claim-2"))
            check(
                "P9 claim of an already-accepted approval after revoke is refused (403)",
                got is not None and got[0] == 403,
                str(got),
            )
            r = await register("dev-direct")
            check(
                "P10 the revoked device cannot be re-registered",
                r.status_code in (403, 409),
                f"{r.status_code} {r.text[:80]}",
            )

            # Observation only: the open 1.8 question (idempotent replay after revoke).
            try:
                again = await gc.create_approval(b1, idempotency_key="k-create-1")
                info(
                    "OBS replay of an earlier CREATE (same key and body) after revoke",
                    f"returned the stored response, id matches={again.get('id') == aid1}",
                )
            except GovernanceApiError as e:
                info(
                    "OBS replay of an earlier CREATE after revoke",
                    f"refused {e.status_code} {e.error_code}",
                )
            replay_attempt = None
            try:
                again = await gc.claim(aid1, idempotency_key="k-claim-1")
                replay_attempt = again.get("execution_attempt_id")
                info(
                    "OBS replay of an earlier CLAIM after revoke",
                    "returned the stored response, execution_attempt_id present="
                    f"{replay_attempt is not None}, same as original="
                    f"{replay_attempt == claim1['execution_attempt_id']}",
                )
            except GovernanceApiError as e:
                info(
                    "OBS replay of an earlier CLAIM after revoke",
                    f"refused {e.status_code} {e.error_code}",
                )

            # report-result after revoke (central checks the device only on create/claim)
            got = await err_of(
                gc.report_result(
                    aid1,
                    idempotency_key="k-rep-wrong",
                    outcome="success",
                    execution_attempt_id=str(uuid.uuid4()),
                )
            )
            check(
                "R0 control: report-result with a WRONG attempt id is refused",
                got is not None,
                str(got),
            )
            try:
                rep = await gc.report_result(
                    aid3,
                    idempotency_key="k-rep-3",
                    outcome="success",
                    execution_attempt_id=attempt3,
                )
                info(
                    "OBS report-result after revoke, lease claimed BEFORE the revoke",
                    f"accepted, status={rep.get('status')}",
                )
            except GovernanceApiError as e:
                info(
                    "OBS report-result after revoke, lease claimed BEFORE the revoke",
                    f"refused {e.status_code} {e.error_code}",
                )
            if replay_attempt:
                try:
                    rep = await gc.report_result(
                        aid1,
                        idempotency_key="k-rep-1",
                        outcome="success",
                        execution_attempt_id=replay_attempt,
                    )
                    info(
                        "OBS report-result after revoke, lease obtained by a REPLAYED claim",
                        f"accepted, status={rep.get('status')}",
                    )
                except GovernanceApiError as e:
                    info(
                        "OBS report-result after revoke, lease obtained by a REPLAYED claim",
                        f"refused {e.status_code} {e.error_code}",
                    )
            await gc.aclose()

        # ===================== real agent-server =====================
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
        await refresh_tokens()
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

            async def start_and_run(message):
                r = await ac.post("/api/conversations", json=start_request(message))
                if r.status_code not in (200, 201):
                    print("start failed", r.status_code, r.text[:400])
                    return None
                cid = r.json()["id"]
                await ac.post(f"/api/conversations/{cid}/run")
                return cid

            def rows(cid):
                return int(
                    q(
                        f"select count(*) from pending_approval_records "
                        f"where conversation_id='{cid}'"
                    )
                    or 0
                )

            def status_of(cid):
                return q(
                    f"select status from pending_approval_records "
                    f"where conversation_id='{cid}' order by created_at desc limit 1"
                )

            # ---- C1: unregistered device
            cid = await start_and_run("USE_TERMINAL please run a command")
            await asyncio.sleep(25)
            check("C1 unregistered device: the tool did not run", not MARKER.exists())
            check(
                "C1 unregistered device: central holds no approval for the conversation",
                rows(cid) == 0,
                f"rows={rows(cid)}",
            )
            r = await ac.get(f"/api/conversations/{cid}")
            info("C1 conversation state", r.json().get("execution_status"))

            # ---- C2: registered device -> approval -> accept -> tool runs
            r = await c_register(base, svc, AGENT_DEVICE)
            check(
                "C2 register the agent-server's device (same service account)",
                r.status_code == 201,
                r.text[:100],
            )
            cid2 = await start_and_run("USE_TERMINAL please run a command")
            pending = await wait_for(
                lambda: status_of(cid2) == "pending" and rows(cid2) == 1
            )
            check(
                "C2 a pending approval for the registered device appears in central",
                bool(pending),
                f"status={status_of(cid2)!r} rows={rows(cid2)}",
            )
            if pending:
                aid = q(
                    f"select id from pending_approval_records where conversation_id='{cid2}'"
                )
                async with httpx.AsyncClient(base_url=base, timeout=20) as c:
                    d = await c.post(
                        f"/api/v1/approvals/{aid}/decide",
                        json={"decision": "accept"},
                        headers={**approver, "Idempotency-Key": uuid.uuid4().hex},
                    )
                check("C2 an approver accepts it", d.status_code == 200, d.text[:100])
                ran = await wait_for(lambda: MARKER.exists(), timeout=60)
                check(
                    "C2 after the claim the tool runs",
                    bool(ran),
                    f"status={status_of(cid2)}",
                )

            # ---- D: delete a conversation that has a not-yet-claimed approval (real server)
            if MARKER.exists():
                MARKER.unlink()
            cidd = await start_and_run("USE_TERMINAL please run a command")
            pend = await wait_for(
                lambda: status_of(cidd) == "pending" and rows(cidd) == 1
            )
            check(
                "D  a second pending approval exists before the delete",
                bool(pend),
                f"status={status_of(cidd)!r}",
            )
            if pend:
                r = await ac.delete(f"/api/conversations/{cidd}")
                check(
                    "D  DELETE /api/conversations/{id} succeeds on the real agent-server",
                    r.status_code in (200, 204),
                    f"{r.status_code} {r.text[:80]}",
                )
                cancelled = await wait_for(
                    lambda: status_of(cidd) == "cancelled", timeout=30
                )
                check(
                    "D  the unclaimed central approval is cancelled by the delete",
                    bool(cancelled),
                    f"status={status_of(cidd)!r}",
                )
                check(
                    "D  the deleted conversation's tool never ran", not MARKER.exists()
                )

            # ---- C3: revoke -> next attempt creates nothing and does not run
            dev_id = q(
                f"select id from device_registrations where device_id='{AGENT_DEVICE}'"
            )
            async with httpx.AsyncClient(base_url=base, timeout=20) as c:
                r = await c.post(
                    f"/api/v1/devices/{dev_id}/revoke",
                    headers={**svc, "Idempotency-Key": uuid.uuid4().hex},
                )
            check(
                "C3 revoke the agent-server's device",
                r.status_code == 200,
                r.text[:100],
            )
            if MARKER.exists():
                MARKER.unlink()
            cid3 = await start_and_run("USE_TERMINAL please run a command")
            await asyncio.sleep(25)
            check("C3 after revoke the tool did not run", not MARKER.exists())
            check(
                "C3 after revoke central holds no approval for the new conversation",
                rows(cid3) == 0,
                f"rows={rows(cid3)}",
            )
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


async def c_register(base, headers, device):
    async with httpx.AsyncClient(base_url=base, timeout=20) as c:
        return await c.post(
            "/api/v1/devices/register",
            json={"device_id": device},
            headers={**headers, "Idempotency-Key": uuid.uuid4().hex},
        )


asyncio.run(main())
