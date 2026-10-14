# governance/

Documents and operator tooling for this fork's governance layer (team mode: the
agent-server asks `central-governance-api` to approve actions). Nothing here is imported
by the `openhands-*` packages; it is not part of what upstream OpenHands ships.

The code itself lives in `openhands-agent-server/openhands/agent_server/governance_*.py`
and `event_service.py`; its tests are under `tests/agent_server/`.

| Directory | What |
|---|---|
| [`needs_attention/`](needs_attention/) | Outbox records parked in `NEEDS_ATTENTION`: how to see and resolve them (operator guide + CLI), the design and its review history, and an end-to-end script against a real central. |
| [`recovery/`](recovery/) | Crash recovery: why an approved action is executed at most once after a restart, the three things that guarantee it, the crash scenes pinned by tests, and what opening a replayable action class would have to change. |
| [`e2e/`](e2e/) | End-to-end scripts: real central on a throwaway Postgres (account requests, device binding, late report, tool permissions, ...). |
| [`tools/`](tools/) | Throwaway rig for the console sign-in (fake IdP). |
| [`keycloak/`](keycloak/) | Keycloak setup scripts Roy runs himself (admin password never shared). |

These are permanent files, not temporary PR artifacts: do not move them to `.pr/`
(which is removed on approval or merge).
