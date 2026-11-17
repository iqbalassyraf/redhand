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
- **Not in C1a:** telemetry still renames passports and creates ordinary active ones for new agent ids. C1b fixes both (amendment to follow).
