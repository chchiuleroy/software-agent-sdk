"""End-to-end check of the late_report wiring: REAL central-governance-api (subprocess, the
committed late_report tightening) on a THROWAWAY Postgres (127.0.0.1:54329), REAL Keycloak
(localhost:8080, test service accounts), the real GovernanceClient and a real GovernanceOutbox.
EventService's relay methods are called unbound with a small stand-in for ``self`` (they only
touch governance_client and governance_outbox), so no conversation is needed.

Central's own .env supplies issuer/JWKS/audience; CGA_DATABASE_URL is overridden so the REAL
database is never touched. Secrets come from the environment and are never printed.
Run with the agent-server venv (needs openhands.agent_server on the path).
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from types import MethodType, SimpleNamespace

import httpx


os.environ.setdefault("OPENHANDS_SUPPRESS_BANNER", "1")

from ohs_env import CENTRAL, CPY, pg_tool
from openhands.agent_server.event_service import EventService  # noqa: E402
from openhands.agent_server.governance_client import (  # noqa: E402
    GovernanceClient,
    GovernancePermanentError,
    compute_display_digest,
)
from openhands.agent_server.governance_outbox import (  # noqa: E402
    GovernanceOutbox,
    OutboxRecord,
    OutboxState,
)


PG = ["-h", "127.0.0.1", "-p", "54329", "-U", "cga"]
DB = "central_e2e_late"
API_PORT = 8897
BASE = f"http://127.0.0.1:{API_PORT}"
TOKEN_URL = "http://localhost:8080/realms/roy-governance/protocol/openid-connect/token"
RESULTS: list[bool] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append(bool(ok))
    print(
        ("[PASS] " if ok else "[FAIL] ") + name + (f"  -- {detail}" if detail else ""),
        flush=True,
    )


def psql(sql: str) -> str:
    return subprocess.run(
        [pg_tool("psql"), *PG, "-d", DB, "-Atc", sql],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


async def approver_token(http: httpx.AsyncClient) -> str:
    r = await http.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": "cga-test-approver",
            "client_secret": os.environ["CGA_TEST_APPROVER_SECRET"],
        },
    )
    r.raise_for_status()
    return r.json()["access_token"]


def create_body(case: str) -> dict:
    fields = dict(
        action_type="terminal_command",
        tool_name="bash",
        policy_revision="e2e-late-v1",
        action_summary=f"echo {case}",
        action_payload={"command": f"echo {case}"},
        digest_salt=None,
    )
    return {
        "request_id": f"e2e-late-{case}-{uuid.uuid4().hex[:8]}",
        "origin_device_id": "e2e-late-device",
        "conversation_id": "e2e-late-conv",
        "action_event_id": f"e2e-late-event-{case}",
        "tool_call_id": None,
        **fields,
        "action_payload_digest": compute_display_digest(**fields),
    }


async def status_of(client: GovernanceClient, approval_id: str) -> str:
    # 'applied' never equals the statuses read here, so wait() answers at once
    return (await client.wait(approval_id, known_status="applied", timeout_seconds=1))[
        "status"
    ]


async def decide(http: httpx.AsyncClient, ap_tok: str, aid: str, decision: str) -> None:
    d = await http.post(
        f"{BASE}/api/v1/approvals/{aid}/decide",
        json={"decision": decision},
        headers={
            "Authorization": f"Bearer {ap_tok}",
            "Idempotency-Key": str(uuid.uuid4()),
        },
    )
    d.raise_for_status()


async def executing_approval(client, http, ap_tok, case: str) -> tuple[str, str, dict]:
    body = create_body(case)
    created = await client.create_approval(
        body, idempotency_key=f"create-{body['request_id']}"
    )
    aid = created["id"]
    await decide(http, ap_tok, aid, "accept")
    claim = await client.claim(aid, idempotency_key=f"claim-{body['request_id']}")
    return aid, claim["execution_attempt_id"], body


async def fail_closed_by_lease_expiry(client, aid: str) -> bool:
    """Lapse the execution lease in the throwaway DB, then wait for central's own
    background sweep to fail the attempt closed (the real transition)."""
    psql(
        "UPDATE pending_approval_records SET executing_lease_expires_at = "
        f"now() - interval '2 seconds' WHERE id = '{aid}'"
    )
    for _ in range(40):
        if await status_of(client, aid) == "failed_unknown":
            return True
        await asyncio.sleep(1)
    return False


async def result_pending_outbox(
    tmp: Path, case: str, body: dict, aid: str, attempt: str, outcome: str
):
    outbox = GovernanceOutbox(tmp / case)
    (tmp / case).mkdir(parents=True)
    await outbox.create_record(
        OutboxRecord(
            request_id=body["request_id"],
            conversation_id=body["conversation_id"],
            action_event_id=body["action_event_id"],
            tool_call_id=None,
            tool_name=body["tool_name"],
            action_type=body["action_type"],
            policy_revision=body["policy_revision"],
            action_summary=body["action_summary"],
            action_payload=body["action_payload"],
            digest_salt=None,
            action_payload_digest=body["action_payload_digest"],
            execution_commitment="0" * 64,
            origin_device_id=body["origin_device_id"],
            state=OutboxState.RESULT_PENDING,
            central_approval_id=aid,
            execution_attempt_id=attempt,
            pending_report_outcome=outcome,
        )
    )
    return outbox


def stand_in(client: GovernanceClient, outbox: GovernanceOutbox):
    me = SimpleNamespace(
        governance_client=client,
        governance_outbox=outbox,
        stored=SimpleNamespace(id="e2e"),
    )
    for name in ("_fall_back_to_late_report", "_send_late_report"):
        setattr(me, name, MethodType(getattr(EventService, name), me))
    return me


def finding_rows(aid: str) -> list[str]:
    out = psql(
        "SELECT finding_type || '|' || coalesce(conclusion,'') || '|' || "
        "coalesce(evidence->>'execution_attempt_id','') FROM reconciliation_findings "
        f"WHERE approval_request_id = '{aid}' ORDER BY created_at"
    )
    return [ln for ln in out.splitlines() if ln]


async def run_cases(
    client: GovernanceClient, http: httpx.AsyncClient, ap: str, tmp: Path
) -> None:
    # A: lease lapsed and swept to failed_unknown; device holds a success
    aid, attempt, body = await executing_approval(client, http, ap, "A")
    check("A fail-closed by real sweep", await fail_closed_by_lease_expiry(client, aid))
    outbox = await result_pending_outbox(tmp, "A", body, aid, attempt, "success")
    me = stand_in(client, outbox)
    await EventService._relay_outbox_once(me)
    check(
        "A outbox RECONCILIATION_REPORTED",
        outbox.load().state == OutboxState.RECONCILIATION_REPORTED,
        outbox.load().state.value,
    )
    check(
        "A one late_report row, confirmed_executed, attempt id stored",
        finding_rows(aid) == [f"late_report|confirmed_executed|{attempt}"],
        str(finding_rows(aid)),
    )
    check(
        "A central status unchanged (finding is evidence only)",
        await status_of(client, aid) == "failed_unknown",
    )
    await EventService._relay_outbox_once(me)
    check("A second relay cycle is a no-op", len(finding_rows(aid)) == 1)

    # B: device outcome failure_definite -> inconclusive (conservative mapping)
    aid_b, attempt_b, body_b = await executing_approval(client, http, ap, "B")
    await fail_closed_by_lease_expiry(client, aid_b)
    outbox_b = await result_pending_outbox(
        tmp, "B", body_b, aid_b, attempt_b, "failure_definite"
    )
    await EventService._relay_outbox_once(stand_in(client, outbox_b))
    check(
        "B failure_definite is filed as inconclusive",
        finding_rows(aid_b) == [f"late_report|inconclusive|{attempt_b}"],
        str(finding_rows(aid_b)),
    )

    # C: central refuses a late_report for the wrong attempt (real error code through real HTTP)
    try:
        await client.reconciliation_finding(
            aid_b,
            idempotency_key=f"late-wrong-{uuid.uuid4()}",
            finding_type="late_report",
            conclusion="inconclusive",
            execution_attempt_id=str(uuid.uuid4()),
        )
        check("C wrong attempt id refused", False, "no error raised")
    except GovernancePermanentError as exc:
        check(
            "C wrong attempt id refused (execution_attempt_mismatch)",
            exc.error_code == "execution_attempt_mismatch",
            str(exc.error_code),
        )
    check("C no extra finding written", len(finding_rows(aid_b)) == 1)

    # D: an applied approval cannot receive a late_report even with the right attempt id
    aid_d, attempt_d, body_d = await executing_approval(client, http, ap, "D")
    await client.report_result(
        aid_d,
        idempotency_key=f"direct-{attempt_d}",
        execution_attempt_id=attempt_d,
        outcome="success",
    )
    check(
        "D precondition: central status is applied",
        await status_of(client, aid_d) == "applied",
    )
    try:
        await client.reconciliation_finding(
            aid_d,
            idempotency_key=f"late-applied-{uuid.uuid4()}",
            finding_type="late_report",
            conclusion="confirmed_executed",
            execution_attempt_id=attempt_d,
        )
        check("D late_report on applied refused", False, "no error raised")
    except GovernancePermanentError as exc:
        check(
            "D late_report on applied refused (late_report_not_applicable)",
            exc.error_code == "late_report_not_applicable",
            str(exc.error_code),
        )
    check("D no finding written", finding_rows(aid_d) == [])

    # E: report refused as illegal_transition but central is applied (not failed_unknown)
    outbox_e = await result_pending_outbox(
        tmp, "E", body_d, aid_d, attempt_d, "success"
    )
    await EventService._relay_outbox_once(stand_in(client, outbox_e))
    check(
        "E illegal_transition on an applied record stays NEEDS_ATTENTION (no late report)",
        outbox_e.load().state == OutboxState.NEEDS_ATTENTION
        and finding_rows(aid_d) == [],
        outbox_e.load().state.value,
    )

    # F: a refusal that is not illegal_transition (cancelled record, attempt mismatch)
    body_f = create_body("F")
    created = await client.create_approval(
        body_f, idempotency_key=f"create-{body_f['request_id']}"
    )
    aid_f = created["id"]
    await client.cancel(aid_f, idempotency_key=f"cancel-{body_f['request_id']}")
    outbox_f = await result_pending_outbox(
        tmp, "F", body_f, aid_f, str(uuid.uuid4()), "success"
    )
    await EventService._relay_outbox_once(stand_in(client, outbox_f))
    check(
        "F other permanent refusal -> NEEDS_ATTENTION, no finding",
        outbox_f.load().state == OutboxState.NEEDS_ATTENTION
        and finding_rows(aid_f) == [],
        outbox_f.load().state.value,
    )


async def main() -> None:
    for name in ("CGA_TEST_OPERATOR_SECRET", "CGA_TEST_APPROVER_SECRET"):
        assert os.environ.get(name), f"{name} not set"
    subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=False)
    subprocess.run([pg_tool("createdb"), *PG, DB], check=True)
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "CGA_DATABASE_URL": f"postgresql+asyncpg://cga@127.0.0.1:54329/{DB}",
        "CGA_PORT": str(API_PORT),
        "CGA_EXPIRY_SWEEP_INTERVAL_SECONDS": "1",
    }
    subprocess.run(
        [CPY, "-m", "alembic", "upgrade", "head"],
        cwd=CENTRAL,
        env=env,
        check=True,
        capture_output=True,
    )
    logdir = tempfile.mkdtemp(prefix="late_logs_")
    logpath = os.path.join(logdir, "central.log")
    logfile = open(logpath, "w", encoding="utf-8")
    server = subprocess.Popen(
        [CPY, "-c", "from central_governance_api.main import main; main()"],
        cwd=CENTRAL,
        env=env,
        stdout=logfile,
        stderr=subprocess.STDOUT,
    )
    client = GovernanceClient(
        base_url=BASE,
        token_url=TOKEN_URL,
        client_id="cga-test-operator",
        client_secret=os.environ["CGA_TEST_OPERATOR_SECRET"],
    )
    tmp = Path(tempfile.mkdtemp(prefix="e2e_late_"))
    try:
        async with httpx.AsyncClient(timeout=30.0) as http:
            for _ in range(60):
                try:
                    if (await http.get(f"{BASE}/healthz")).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.5)
            else:
                raise SystemExit("central did not start; see " + logpath)
            check("preflight: throwaway central answers /healthz", True)
            ap = await approver_token(http)
            await run_cases(client, http, ap, tmp)
    finally:
        await client.aclose()
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
        logfile.close()
        subprocess.run([pg_tool("dropdb"), *PG, "--if-exists", DB], check=False)
    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    sys.exit(0 if all(RESULTS) else 1)


asyncio.run(main())
