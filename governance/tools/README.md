# governance/tools/

`fake_idp_for_console.py`: throwaway rig for the OHS console (`/inbox`) sign-in: a fake
OIDC provider plus a real central on a throwaway Postgres. Not for production. Paths are
resolved by [`ohs_env.py`](ohs_env.py) (see `../e2e/README.md` for the overrides).
Not re-run after the move to this directory: it is an interactive server; only
compilation and lint were checked.

`ohs_test_mcp.py`: a small MCP server for testing how the governance layer treats MCP
tools (`sum_numbers`, `word_count`, and `add_note`, which writes a line to a temp file).
Streamable HTTP, on 127.0.0.1 only (any other `--host` is refused). Start it with
`python governance/tools/ohs_test_mcp.py --port 18795`; point an agent at it with
`mcp_config={"ohs_test": {"url": "http://127.0.0.1:18795/mcp"}}`. Set
`OHS_TEST_MCP_DESC_SUFFIX` to make it describe `word_count` differently. Used by
`../e2e/e2e_mcp_refusal.py`.
