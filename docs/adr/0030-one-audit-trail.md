# ADR 0030: One audit trail: the gateway's own ledger is retired

**Status:** Accepted by the owner (2026-11-18, "retire the gateway ledger"). Supersedes the gateway-ledger parts of ADR 0011 (Black Box recorder, which described the ledger as the existing chain), ADR 0021 (`/v1/audit/verify` wording) and the Phase 1 baseline note on the ledger. Those documents are not rewritten.

## Context
Two hash-chained records of the same gateway decisions existed:
1. **The gateway's in-process ledger** (`agentwall/src/telemetry/audit_logger.py`): one SHA-256 chain over **all tenants mixed together**, the last 10,000 records in memory, an optional append-only file (`AGENTWALL_AUDIT_LOG_FILE`), readable at `GET /v1/audit/logs` and `GET /v1/audit/verify` with the service token. Nothing in the product read it.
2. **The Black Box in core** (ADR 0011, migration `20261110000000_blackbox.sql`): per organization, in Postgres, append-only by trigger, hash-chained in SQL, retention-managed, verifiable per tenant (`GET /v1/blackbox/verify`, the dashboard's "Verify chain"). The gateway reports every decision to it through `recorder.py`.

CLAUDE.md listed the ledger as the last open Phase 1 gap ("the gateway's own in-memory ledger remaining separate from the Black Box"). Two chains that can disagree, one of them cross-tenant and unverifiable by customers, is worse than one.

## Decision
The Black Box is the one audit trail. The gateway's ledger, its two routes and `AGENTWALL_AUDIT_LOG_FILE` are removed.
- `_record` in `gateway/service.py` now builds the Black Box event directly, including the argument **names and SHA-256 digest** (never values; helper moved to `agentwall/src/gateway/digest.py`, same canonical form, so digests stay comparable).
- Every decision still reaches the recorder (tests assert this for allow, each refusal reason and error). The once-a-minute limit that protected the ledger now only limits the FULL row (digest and payload excerpt) for a repeating refusal; every refusal still produces a Black Box row.
- `GET /v1/audit/logs` and `GET /v1/audit/verify` return 404 (a test asserts it, even with the service token). A deployed `AGENTWALL_AUDIT_LOG_FILE` is ignored (settings ignore unknown variables).

## Alternatives considered
- **Keep it as a "local diagnostic"**: two chains remain, the cross-tenant read route stays. Rejected.
- **Make `/v1/audit/*` proxy to core**: adds a dependency for no gain; core already serves per-tenant verification.
- **Move the chain into the gateway's database access**: the gateway has none by design (it is lookups and rules only).

## Consequences
- **Behaviour change:** when core is unreachable for longer than the recorder's bounded buffer, decisions are dropped and counted (a `recorder.gap` marker on the next batch and a metric), not kept locally. **Enforcement is unaffected** (the gateway still denies). Previously the in-memory ledger or file could hold them, but that record was never part of a customer-visible trail and was lost on restart unless a file was configured.
- The route that returned every tenant's decisions in one response (service token) no longer exists: one less cross-tenant surface.
- Smoke checks changed: `deploy/cloudrun/smoke.sh` and `scripts/smoke_launch.py` now expect **404** at the old path, so they must be run against a gateway that already runs this version.
- The core's `worm_audit_logger.py` (S3/GCS WORM, unused in request paths per `docs/review/phase1-baseline.md`) is a separate subject and untouched.
- Per-call cost falls by one lock and one hash chain step; the argument digest remains.
