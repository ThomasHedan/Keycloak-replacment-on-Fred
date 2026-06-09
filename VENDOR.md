# Vendored source

This repository vendors the [Thales Group **Fred**](https://github.com/ThalesGroup/fred)
platform as the working base for replacing Keycloak with **Azure Entra ID**.

| Field | Value |
|-------|-------|
| Upstream | https://github.com/ThalesGroup/fred |
| Imported commit | `a151864d19500a5077e11fbd9b7216a02e134c20` |
| Imported on | 2026-06-09 |
| License | Apache 2.0 (see `LICENSE`) |

## Goal of this fork

Replace Keycloak with Azure Entra ID, keeping **OpenFGA + Postgres** as the
source of truth for teams and membership.

Architecture decisions:

- **Entra ID** = authentication + JWT issuance only (no admin/directory writes from Fred).
- **OpenFGA** = authorization relationships (org roles, team membership, resource permissions).
- **Postgres user store** = Fred's own minimal user table, filled by **JIT provisioning**
  on first login (no IdP admin API needed).
- The redundant Keycloak **group** layer (and `keycloak_rebac_sync.py`) is removed.

## Planned work (slices)

1. ✅ Vendor Fred upstream.
2. ⬜ OIDC: accept Entra tokens in `libs/fred-core/fred_core/security/oidc.py` (issuer/audience/claims `roles` + `oid`) + JIT provisioning.
3. ⬜ M2M: Entra client-credentials in `libs/fred-core/fred_core/security/outbound.py` (scope `.default`).
4. ⬜ Unplug Keycloak: drop group writes + remove `keycloak_rebac_sync.py`, OpenFGA-only.
5. ⬜ Frontend: MSAL in `apps/frontend/src/security/`.
6. ⬜ Config & docs: rename `KEYCLOAK_*` env vars, Entra deployment guide.
