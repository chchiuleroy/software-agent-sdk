# governance/tools/

`fake_idp_for_console.py`: throwaway rig for the OHS console (`/inbox`) sign-in: a fake
OIDC provider plus a real central on a throwaway Postgres. Not for production. Paths are
resolved by [`ohs_env.py`](ohs_env.py) (see `../e2e/README.md` for the overrides).
Not re-run after the move to this directory: it is an interactive server; only
compilation and lint were checked.
