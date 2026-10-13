"""End-to-end check of EventService.cancel_unclaimed_governance_approval() against a REAL
central-governance-api (127.0.0.1:8898) on a THROWAWAY Postgres (127.0.0.1:54329) and REAL
Keycloak (localhost:8080, test service accounts). Uses the real GovernanceClient and a real
GovernanceOutbox; the method is called unbound with a small stand-in for ``self`` (it only
touches governance_client, governance_outbox and stored.id), so no conversation is needed.
Secrets come from the environment and are never printed.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx

from openhands.agent_server.event_service import EventService
from openhands.agent_server.governance_client import (
    GovernanceClient,
    compute_display_digest,
)
from openhands.agent_server.governance_outbox import (
    GovernanceOutbox,
    OutboxRecord,
    OutboxState,
)


BASE = "http://127.0.0.1:8898"
TOKEN_URL = "http://localhost:8080/realms/roy-governance/protocol/openid-connect/token"
RESULTS: list[bool] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append(ok)
    print(
        ("[PASS] " if ok else "[FAIL] ") + name + (f"  -- {detail}" if detail else "")
    )


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
        policy_revision="e2e-cancel-v1",
        action_summary=f"echo {case}",
        action_payload={"command": f"echo {case}"},
        digest_salt=None,
    )
    return {
        "request_id": f"e2e-cancel-{case}-{uuid.uuid4().hex[:8]}",
        "origin_device_id": "e2e-cancel-device",
        "conversation_id": "e2e-cancel-conv",
        "action_event_id": f"e2e-cancel-event-{case}",
        "tool_call_id": None,
        **fields,
        "action_payload_digest": compute_display_digest(**fields),
    }


async def status_of(client: GovernanceClient, approval_id: str) -> str:
    # 'applied' never equals the statuses used here, so wait() returns the current status at once
    return (await client.wait(approval_id, known_status="applied", timeout_seconds=1))[
        "status"
    ]


async def make_case(client, tmp: Path, case: str):
    body = create_body(case)
    created = await client.create_approval(
        body, idempotency_key=f"create-{body['request_id']}"
    )
    aid = created["id"]
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
            state=OutboxState.CREATED,
            central_approval_id=aid,
        )
    )
    me = SimpleNamespace(
        governance_client=client,
        governance_outbox=outbox,
        stored=SimpleNamespace(id=case),
    )
    return aid, outbox, me


async def decide(http, ap_tok, aid, decision):
    d = await http.post(
        f"{BASE}/api/v1/approvals/{aid}/decide",
        json={"decision": decision},
        headers={
            "Authorization": f"Bearer {ap_tok}",
            "Idempotency-Key": str(uuid.uuid4()),
        },
    )
    d.raise_for_status()


async def main() -> None:
    client = GovernanceClient(
        base_url=BASE,
        token_url=TOKEN_URL,
        client_id="cga-test-operator",
        client_secret=os.environ["CGA_TEST_OPERATOR_SECRET"],
    )
    run = EventService.cancel_unclaimed_governance_approval
    tmp = Path(tempfile.mkdtemp(prefix="e2e_cancel_"))
    async with httpx.AsyncClient(timeout=30.0) as http:
        h = await http.get(f"{BASE}/healthz")
        check(
            "preflight: throwaway central answers /healthz",
            h.status_code == 200,
            f"HTTP {h.status_code}",
        )
        if h.status_code != 200:
            sys.exit(2)
        ap = await approver_token(http)

        # A: still pending -> cancelled
        aid, outbox, me = await make_case(client, tmp, "A")
        check(
            "A precondition: central status is pending",
            await status_of(client, aid) == "pending",
        )
        await run(me)
        check(
            "A pending -> central status cancelled",
            await status_of(client, aid) == "cancelled",
        )
        check("A outbox CANCELLED", outbox.load().state == OutboxState.CANCELLED)
        await run(me)  # second call: record is terminal, must be a no-op
        check(
            "A second call is a no-op",
            await status_of(client, aid) == "cancelled"
            and outbox.load().state == OutboxState.CANCELLED,
        )

        # B: accepted, never claimed -> pre-claim abort -> cancelled
        aid, outbox, me = await make_case(client, tmp, "B")
        await decide(http, ap, aid, "accept")
        check(
            "B precondition: central status is accepted",
            await status_of(client, aid) == "accepted",
        )
        await run(me)
        check(
            "B accepted -> central status cancelled (pre-claim abort)",
            await status_of(client, aid) == "cancelled",
        )
        check("B outbox CANCELLED", outbox.load().state == OutboxState.CANCELLED)

        # C: rejected already -> nothing to do, no exception, outbox unchanged
        aid, outbox, me = await make_case(client, tmp, "C")
        await decide(http, ap, aid, "reject")
        await run(me)
        check("C rejected stays rejected", await status_of(client, aid) == "rejected")
        check(
            "C outbox unchanged (CREATED)", outbox.load().state == OutboxState.CREATED
        )

        # D: stale outbox but central already claimed it (executing) -> must not be touched
        aid, outbox, me = await make_case(client, tmp, "D")
        await decide(http, ap, aid, "accept")
        await client.claim(aid, idempotency_key=f"claim-{uuid.uuid4()}")
        check(
            "D precondition: central status is executing",
            await status_of(client, aid) == "executing",
        )
        await run(me)
        check(
            "D executing approval is left alone",
            await status_of(client, aid) == "executing",
        )
        check(
            "D outbox unchanged (CREATED)", outbox.load().state == OutboxState.CREATED
        )

    await client.aclose()
    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    sys.exit(0 if all(RESULTS) else 1)


asyncio.run(main())
