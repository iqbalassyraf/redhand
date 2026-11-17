# ADR 0024: Organization SDK keys issued in the dashboard (and telemetry trust)

**Status:** Proposed (2026-11-17), with the pull request. Phase 4.5 C1 (plan `docs/plans/phase45-c1-sdk-keys.md`). Owner decisions K1 ("reported only" passports,
built in C1b), K2 (90-day default), K3 (admin-only management, recommended and assumed).

## Context
An agent's SDK sends traces and model use with an organization SDK key. Until now such a key could only be made with raw SQL: on staging (2026-11-16) one went to
the wrong organization and its plaintext was typed into chat. B4a and B4b were therefore unusable by a real customer. Keys also had no audit trail, `last_used_at` was
never written, ingest had no per-key rate limit, and a row-level policy let organization admins write the table directly (bypassing any audit).

## Decision (C1a)
- **Admins create and revoke keys** through `POST/DELETE /v1/organization/sdk-keys` (every member can list them, without secrets).
- **The key is generated in core** (`rh_live_` + 32 random bytes, URL-safe), **shown once** in the create response, and stored only as its SHA-256 hash with a 12-character
  display prefix. It is never logged, stored or returned again.
- **Database functions** `control_sdk_key_create` (at most 10 usable keys per organization, expiry 1 hour to 366 days, serialised per organization) and
  `control_sdk_key_revoke` (idempotent, organization-scoped) write an audit row (`sdk_key.created`, `sdk_key.revoked`, target type `sdk_key`) in the same transaction;
  the audit row never holds the hash. The old "Admins can manage SDK keys" write policy is dropped, so the table can only be written through these functions.
- **Ingest:** a per-key limit of 120 batches a minute per core instance (429 with `Retry-After: 60`), checked only after the key is valid; `last_used_at` stamped after
  the reply, at most once a minute (in core and again in the database).
- **Dashboard:** an "SDK keys" card on Passports (create with name and days, show once with Copy, list prefix, state, expiry, last used, revoke with confirmation).

## Alternatives considered
- **Keep raw SQL with a runbook.** It is what failed on staging. Rejected.
- **Dashboard-only (no API).** The dashboard calls the API anyway, and automation needs it. Rejected.
- **Store the key encrypted so it can be shown again.** A shown-again key is a key someone can steal again; a hash cannot be reversed. Rejected.

## Consequences
- A customer can start sending usage without help. Every key change is in the audit log.
- The rate limit is per instance (see `services/rate_limit.py`); with N instances the effective limit is up to N times higher. Acceptable as abuse protection, not a quota.
- The display prefix (12 characters, of which 4 random) is public within the organization; it identifies a key but cannot be used as one.
- **Not in C1a:** telemetry still renames passports and creates ordinary active ones for new agent ids. C1b fixes both (amendment below).

## Amendment (2026-11-17): C1b telemetry trust
**Context.** Ingest upserted the agent row on every batch: any holder of the organization's SDK key could rename or re-frame an existing passport whose
external id it knew (names appear in alerts, the dashboard and the audit view), and every new agent id became an ordinary active passport.

**Decision** (owner chose K1 "reported only" over mandatory pre-registration, which would break the SDK's zero-setup path):
- Ingest calls `telemetry_resolve_agent()`: an existing passport only gets its heartbeat; a new agent id becomes a passport with `agents.reported_only = true`
  (name cut to 256 characters, framework to 64). The column defaults to false, so every existing passport keeps working.
- A reported-only passport is refused at token exchange (403 "Agent passport is reported only: ..."), reported as `frozen` to the gateway by
  `/internal/v1/gateway-context` (defence in depth: it should never hold a token), and skipped by the Risk ladder's automatic actions (its numbers are whatever
  the key sent). Its telemetry is still accepted and shown.
- An admin promotes it with `POST /v1/passports/{id}/promote` (`confirm: true`, reason), through `control_passport_promote()`: audited as `passport.promoted`,
  a revoked passport cannot be promoted (409), another organization's passport is not found (404), an ordinary one is a no-op. Promotion grants nothing by itself:
  the passport still needs scopes and an agent key.
- Dashboard: label "reported by SDK" with the explanation on hover, and a **Promote** button with a confirmation.

**Alternatives.** Pre-registration only (rejected above); keep the upsert but stop updating the name (still creates usable passports from a key); a separate
"telemetry agents" table (duplicates the passport model the Black Box, Risk and spend features already key on).

**Consequences.** A leaked SDK key can no longer rename a passport or create one that reaches tools; it can still create reported-only rows (bounded by the
per-key rate limit) and send false telemetry for existing agents. Deploy order matters: the migration must be applied before core, because core now selects
`reported_only` in the gateway context (a missing column fails the lookup, so the gateway denies: closed, but an outage).
