# governance/keycloak/

One-off Keycloak setup scripts that **Roy runs himself**: they need the Keycloak admin
password, which is typed with hidden input (or into a local-only page) and is never
given to the assistant. Each write asks y/N first. Not re-run after the move to this
directory (they are interactive); only compilation and lint were checked.

| Script | What |
|---|---|
| `keycloak_inbox_client_setup.py` | register the browser sign-in client for the OHS console |
| `keycloak_setup_server.py` | local-only page where the admin password is typed and the setup runs |
| `keycloak_superadmin_setup.py` | realm role and settings for the OHS superadmin |
