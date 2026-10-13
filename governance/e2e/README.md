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
| `e2e_device_binding.py` | device binding enforced, with a real agent-server | throwaway Postgres |
| `e2e_device_list.py` | `GET /api/v1/devices` | throwaway Postgres, Keycloak |
| `e2e_late_report.py` | late-report wiring | throwaway Postgres, Keycloak |
| `e2e_real_conversation.py` | real conversation with tool permissions enforced | throwaway Postgres |
| `e2e_real_keycloak.py` | central validated with real Keycloak tokens | throwaway Postgres, Keycloak |
| `e2e_tool_permissions.py` | department tool permissions | throwaway Postgres |

Verification after the move (2026-10-13, this machine): seven of eight exit 0.
`e2e_cancel_on_delete.py` was not verified: with no central on :8898 it stops at the
first connection (`ConnectError`), so only its imports and path setup were exercised.
