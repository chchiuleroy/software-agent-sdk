# governance/e2e/

End-to-end scripts for the governance layer: a real `central-governance-api` process on
a throwaway Postgres (`127.0.0.1:54329`, user `cga`, trust auth), usually a fake or real
Keycloak, and the real agent-server code. They are rigs, not part of the unit-test suite.

Where central lives is set in [`ohs_env.py`](ohs_env.py) (defaults: the sibling directory
`central-governance-api`; override with `OHS_CENTRAL_DIR`, `OHS_CENTRAL_PYTHON`,
`OHS_PG_BIN`). Run each script with the SDK venv's Python from the repository root:

```bash
.venv/Scripts/python.exe governance/e2e/e2e_device_list.py
```

Secrets (`CGA_TEST_*_SECRET`) come from the environment and are never printed.

| Script | What it checks | Needs |
|---|---|---|
| `e2e_account_requests.py` | account-request flow, real lifespan, SMTP sink | throwaway Postgres |
| `e2e_cancel_on_delete.py` | cancelling an unclaimed approval when its conversation is deleted | **a central already running on 127.0.0.1:8898**, Keycloak |
| `e2e_execution_commitment.py` | execution commitment over HTTP: claim/report mismatch, legacy flow, audit event (no agent-server) | throwaway Postgres |
| `e2e_device_binding.py` | device binding enforced, with a real agent-server | throwaway Postgres |
| `e2e_device_autoregister.py` | device auto-registration (1.8) against a real central with binding enforced: register, restart (real 409), revoke stays revoked (no agent-server process) | throwaway Postgres |
| `e2e_device_list.py` | `GET /api/v1/devices` | throwaway Postgres, Keycloak |
| `e2e_late_report.py` | late-report wiring | throwaway Postgres, Keycloak |
| `e2e_mcp_refusal.py` | MCP tools in team mode against a real MCP server over local HTTP (`../tools/ohs_test_mcp.py`): every call refused before any approval, what an approver would see if refusal is off, the tool fingerprint's stability and change | throwaway Postgres (the MCP server is started by the script, 127.0.0.1 only) |
| `e2e_reconciliation_queue.py` | the reconciliation queue and `admin_verified` (1.10 v2) against a real central: only `failed_unknown` listed, role gate, no self-verification, a finding keeps the status, filter and paging (needs central with PR #49 merged) | throwaway Postgres, fake IdP |
| `e2e_real_conversation.py` | real conversation with tool permissions enforced | throwaway Postgres |
| `e2e_relaxed_tools.py` | what asks for approval after the 1.14 relaxation, in a real team-mode conversation WITH the governance lock: path-less grep/glob and task_tracker run without an approval, an absolute-pattern glob and terminal wait and register exactly one. `RELAX_E2E_NO_LOCK=1` is the control run (the relaxed cases then ask again) | throwaway Postgres |
| `e2e_kill_restart.py` | kills the REAL agent-server process tree (`taskkill /T /F`, Windows only) and restarts it: K1 killed while the approved tool executes (no second run, `AgentErrorEvent`, central `failed_unknown`), K3 killed while the approval is pending (after the restart the approval is accepted and the tool runs exactly once). Found two real defects, see `../recovery/design.md` section 4 | throwaway Postgres |
| `e2e_real_keycloak.py` | central validated with real Keycloak tokens | throwaway Postgres, Keycloak |
| `e2e_tool_permissions.py` | department tool permissions | throwaway Postgres |

Verification after the move (2026-10-13, this machine): seven of eight exit 0.
`e2e_cancel_on_delete.py` was not verified: with no central on :8898 it stops at the
first connection (`ConnectError`), so only its imports and path setup were exercised.
