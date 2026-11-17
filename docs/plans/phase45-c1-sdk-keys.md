# Plan: Phase 4.5 C1, SDK keys and telemetry trust

**Status:** Draft for the owner's approval (2026-11-17). The direction was approved in conversation on 2026-11-17, with two decisions:
K1, a new agent id becomes a "reported only" passport; K2, new SDK keys default to 90 days. This document needs approval before any code is written,
because it touches authentication, keys, the schema and public APIs (CLAUDE.md sections 3.2 and 3.3).

## 1. Goal
Let a customer issue and revoke their own SDK keys, and make the telemetry path unable to create or change passports in ways an admin did not choose.
The phase "done" test it serves is B4 done tests 1 to 3 being usable by a real customer without raw SQL. New done tests, proposed:
1. An admin creates an SDK key in the dashboard and sees it once. Telemetry sent with it is accepted, and its "last used" time appears.
2. A revoked or expired key is refused with 401. A key from another organization never reaches this organization's agents.
3. Telemetry naming a new agent id creates a passport marked "reported only". That passport cannot get a gateway token, and it stays so until an admin promotes it.
4. Telemetry for an existing passport never changes its name, framework or environment.

## 2. Current state (read on `main`, 2026-11-17)
- `sdk_api_keys` (`supabase/migrations/20261030000000_schema.sql`) holds a SHA-256 hash, a prefix, `is_active`, `expires_at` and `last_used_at`.
  - There is no API, dashboard or audit trail for it. Staging keys were made with raw SQL, and on 2026-11-16 one went to the wrong organization, with its plaintext typed into chat.
  - `last_used_at` is never written.
- `verify_sdk_api_key` (`services/redhand-core/src/redhand_core/routers/telemetry.py`) checks the prefix, hash, `is_active` and expiry. It is fine, but ingest has no per-key rate limit; only the body cap applies.
- **Bug: ingest renames passports.** The `agents` upsert on `(organization_id, external_agent_id, environment)` overwrites `name` and `framework` on every batch.
  - Any SDK key holder who knows a passport's external id can rename it.
  - Names appear in alerts, the dashboard and the audit view.
- **A new external id becomes an ordinary active passport** with no owner and no scopes.
  - The staging run found one: `night-spend`.
  - It cannot call tools (no scopes, no agent key), but it looks like a real passport, and the Risk ladder and alerts treat it as one.

## 3. Approach
- **Keys (C1a):**
  - Routes `POST /v1/organization/sdk-keys`, `GET /v1/organization/sdk-keys` and `DELETE /v1/organization/sdk-keys/{id}`. All are admin only and organization-scoped.
  - Create returns the plaintext **once**. The key is `rh_live_` plus 32 bytes from `secrets.token_urlsafe` (well over 128 bits). Only the SHA-256 hash and a 12-character display prefix are stored.
  - Expiry is 1 to 365 days, default 90 (K2). At most 10 active keys per organization.
  - Revoke sets `is_active = false` and is idempotent.
  - Both actions go through audited database functions (`sdk_key.created`, `sdk_key.revoked`) in one transaction, like the other control functions.
  - `last_used_at` is updated at most once a minute per key, after the reply, best effort.
  - A per-key ingest limit reuses the existing sliding-window limiter (`services/redhand-core/src/redhand_core/services/rate_limit.py`), for example 120 batches a minute per key.
  - A dashboard card "SDK keys" shows name, prefix, created, expires, last used and Revoke. Nothing ever shows a full key again.
- **Telemetry agents (C1b):**
  - Replace the upsert with a database function `telemetry_resolve_agent`:
    - insert the agent if new, marking it `reported_only = true`;
    - on conflict, update only `last_heartbeat_at`;
    - return the row.
  - **The name, framework and environment of an existing passport are never touched.**
  - A `reported_only` passport:
    - is refused by token exchange (`routers/agent_auth.py`) and by the gateway context (fail closed);
    - is skipped by the Risk ladder's automatic actions;
    - is labelled "reported by SDK, no gateway access" on Passports and in its timeline.
  - An admin can promote it: one audited action, `passport.promoted`, with a confirmation. After promotion it is an ordinary passport that still needs scopes and an agent key.
- **Alternatives rejected:**
  - Require registration before telemetry: stricter, but it breaks the SDK's zero-setup path. The owner chose "reported only".
  - Keep keys in the dashboard only, without API routes: the API is needed for automation, and the dashboard calls it anyway.
  - Use a new `status` value instead of a flag: `status` drives freeze, revoke and expiry everywhere, and a fifth value touches far more code than one boolean checked in three places.

## 4. Changes
- Migration `20261127000000_sdk_keys.sql` with its rollback:
  - `agents.reported_only` (default false; existing rows false), `sdk_api_keys.created_by` and `sdk_api_keys.revoked_at`;
  - the audit actions;
  - the functions `control_sdk_key_create`, `control_sdk_key_revoke`, `telemetry_resolve_agent` and `control_passport_promote`;
  - an index on `sdk_api_keys(organization_id)`.
- Core changes:
  - `routers/sdk_keys.py` and `passports/sdk_keys.py`;
  - `verify_sdk_api_key` (rate limit, `last_used_at`);
  - ingest (resolve function), token exchange and gateway context (reported-only refusal), the Risk ladder skip, and the local twin.
- Dashboard: an "SDK keys" card, the reported-only label and a Promote button.
- Docs: ADR 0024, a runbook, threat-model rows, OpenAPI, the changelog, and a night Part Q whose commands are validated by a test before the brief ships.

## 5. Security impact
- **New trust boundary:** keys are issued by admins in the dashboard instead of by hand in the database. Plaintext exists only in the create response. It is never logged or stored, and never shown again.
- **Less power for the SDK key:** it can no longer rename passports, and a passport it creates cannot get gateway access until a person promotes it.
- **Abuse limits:** a per-key rate limit, at most 10 active keys per organization, and expiry by default.
- **Failure modes:**
  - a failing key lookup still refuses (401 or 503, never allow);
  - a failing `last_used_at` write never fails an ingest;
  - a failing resolve function fails the ingest (it is on the identity path) and creates nothing half-made.

## 6. Data and migrations
- The migration is additive, and existing passports keep working (`reported_only = false`).
- `night-spend`-style rows already on staging stay ordinary. The owner can revoke them, which is already listed.
- The rollback drops the new column, functions and audit actions, using `NOT VALID` for audit rows already written.
- The rollback test runs on a scratch database, as before.

## 7. Tests
Tests are written first. They cover:
- **Key routes:**
  - admin can and operator or viewer cannot;
  - another organization's key cannot be read or revoked;
  - plaintext appears only in the create response;
  - the limit of 10 active keys;
  - expiry from 1 to 365 days, and revoke is idempotent.
- **Key check:** revoked, expired, wrong-prefix, tampered and other-organization keys are all refused.
- **Usage tracking:** `last_used_at` is throttled, and the rate limit refuses with 429 without reading the body.
- **The renaming bug:** a regression test that renaming is impossible fails before the fix.
- **Reported-only passports:**
  - a new id is created as reported only;
  - it is refused at token exchange and at the gateway context;
  - promote is audited, admin only and needs confirmation;
  - Risk ladder actions skip it.
- **Database:** SQL tests with rollback, and parity tests for the local twin.
- **Deliberate breakages** of the hash check, the organization filter, the no-rename rule, the reported-only refusal and the role checks.
- **Browser:** a real-browser run of the card at two widths.

## 8. Cost and performance
- **Gateway:** no change on the hot path except reading one more column, already fetched with the passport row.
- **Ingest:**
  - one function call instead of one upsert, so the same cost;
  - one throttled update a minute per key;
  - the rate-limit check is in memory.
- **Running cost:** none per agent.

## 9. Risks and open questions
- **Bypass of the rate limit:** the limiter is per core instance, so several instances allow more in total. That is acceptable for abuse limiting, but not a hard quota.
- **SDK code:** existing SDK users see their agents' names stop following the SDK's `agent_name`. A rename now happens in the dashboard.
- **K3 (decision needed):** key management is admin only. This is recommended and assumed above.
