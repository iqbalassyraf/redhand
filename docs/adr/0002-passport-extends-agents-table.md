# ADR 0002: The Agent Passport extends the existing `agents` table

- **Status:** Accepted (2026-11-01)
- **Phase:** 1

## Context
`public.agents` already held agent identity, tenant, framework, status and an `allowed_tools`
list, and was used by telemetry and the dashboard.

## Decision
Migration `20261101000000_phase1_passport.sql` extends `agents` with owner, backup owner,
`scopes` (`[{server, tool, access}]`), `expires_at`, `version`, `status_reason`,
`status_changed_at` and `last_seen_at`. Statuses become `active | frozen | revoked` (stored) plus
`expired` (derived from `expires_at`). Old statuses map: suspended/quarantined → frozen,
decommissioned → revoked (lossy; accepted pre-launch, rollback in `supabase/rollbacks/`).

Database triggers enforce that revocation is permanent and bump `version` on any status, scope or
expiry change. The control audit log is a separate append-only table.

## Alternatives
- **New `passports` table:** clean slate, but duplicates identity already referenced by traces,
  security events and HITL rows.

## Consequences
- `allowed_tools` is now superseded by `scopes`; it is kept for compatibility and can be dropped
  in a later contract migration.
- `access` (read/write) is stored but not enforced until Safe Mode (Phase 2) provides a trusted
  tool classification.
