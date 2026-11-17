# ADR 0027: Tenant data lifecycle: owner export, deletion with a grace period, owner-run purge (Phase 4.5 D1)

**Status:** Proposed (2026-11-17), with the pull request.

## Context
A customer must be able to take their data out and to have it deleted. Until now neither existed as a product feature: deleting an organization failed on the append-only audit table and
was an improvised DBA task (the old runbook), and there was no export at all. Both are data-protection duties we expect to face (PDPA access and deletion requests) and both are risky
paths: an export is a built-in exfiltration route, and a deletion is irreversible.

## Decision
- **One list of tenant tables.** `tenant_data_manifest()` (database function) names every table that holds tenant data, how it is selected (by organization, through the agent, the organization row, members)
  and the columns an export leaves out (key hashes, token hashes, code hashes, token ids of expired credentials, webhook URLs that may carry tokens). Export, row counts and the purge self-check all read it.
  A SQL test fails when a table with `organization_id` (or reached only through `agent_id`) is not in it, when a secret-looking column is neither excluded nor explicitly allowed, when an excluded column no longer exists,
  and when any foreign key from a manifest table to organizations or agents does not cascade. A new table therefore cannot be added without deciding what export and deletion do with it. The in-memory twin keeps
  a copy of the list and a test compares it with the migration text.
- **Export** (`GET /v1/organization/export`, owner only): the database function builds the JSON and writes the audit row (row counts only, never the data) in the same transaction; the secret columns are removed where the data is read.
  At most one export per organization per hour (a durable check against the audit log, so it holds across instances); 100 000 rows per table, a table over the cap says `truncated`. Served `no-store` as an attachment.
- **Deletion** is two-step. `POST /v1/organization/delete-request` (owner, the address name typed back) starts a **7-day grace period**: every agent is frozen, SDK keys are switched off, pending invites are revoked, the organization is marked.
  While marked, every operator route except status, export, a repeated request and cancel answers 403: the check sits in `get_operator`, the one dependency every operator route passes through, so a new route is closed by default.
  Cancel ends the grace period; agents stay frozen (unfreezing stays a deliberate per-agent action) and SDK keys must be created again.
- **The purge is not an API route.** `control_org_purge(org)` refuses before the grace period ends, runs as the table owner only (revoked from the service role too), switches the two append-only triggers off inside the function and on again before it returns,
  deletes in one transaction, proves every manifest table is empty for the tenant (or rolls back), and records the deletion in `tenant_deletions` (opaque id, hash of the slug, row counts: no names, no content).
  `scripts/purge_tenant.sh` is the operator's wrapper: it shows what will go and makes the operator type the address name.

## Alternatives considered
- **Purge through the API after the grace period (a scheduled job).** Convenient, but puts an irreversible, audit-defeating capability behind a network-reachable credential. Rejected: a human with database-owner access runs it.
- **Soft delete only.** Cheap and reversible, but the data stays; it does not answer a deletion request. Rejected.
- **Streaming the export from core by reading every table.** More code and the secret-column list would live in two places. Rejected: the database function reads, the manifest lists once.
- **Delete immediately on request.** Too easy to do by mistake or by a hijacked owner session. Rejected: grace period, typed confirmation, owner role, all audited.

## Consequences
- New routes: `GET /v1/organization/export`, `GET /v1/organization/deletion`, `POST /v1/organization/delete-request`, `POST /v1/organization/delete-request/cancel` (all owner, in the route sweep matrix).
- `get_operator` reads the organization row once per request (a primary-key lookup) to apply the pending-deletion rule; if that row is missing it denies.
- What a purge does **not** reach, listed in the runbook: the people's Supabase Auth accounts (deleted separately on request), database backups until they age out, Cloud Run logs, Telegram message history, the gateway's in-memory ledger, any export file the owner holds.
- Dashboard: added after this ADR as `/organization` (export, request, cancel, pending banner). Not built: a scheduled purge, per-user export, a legal-hold flag.
- A deletion request is a destructive control action by a hijacked owner session: it needs the owner role and the typed address name and leaves 7 days to notice and cancel; the audit rows and the Telegram/e-mail notifications of the owner's own channels are the detection (no new notification is added here).
