# Phase 3 plan: "See things"

**Status:** Approved (2026-11-05). M1 (Black Box core) built 2026-11-05: migration, gateway recorder,
core ingest/timeline/verify, dashboard page. 294 (redhand-core) + 174 (agentwall) tests pass, plus 25
SQL tests; `tsc --noEmit` and `npm run build` clean. Staging verification of done tests 1, 2 and 6 not
yet run (tracked below). M2 to M4 not started.

**Goal:** an owner can see everything an agent did through RedHand, prove the record was not altered,
and learn within seconds when an agent touches bait it should never touch.

**Product truth:** RedHand only sees what flows through the RedHand gateway. The recorder and the
honeytokens say nothing about agents, keys or tools used outside it. This sentence goes into the UI,
docs and runbooks verbatim.

---

## 1. Done tests

1. **Every call is recorded.** Every `tools/call` through the gateway, allowed or refused, appears in
   the agent's Black Box timeline within 10 s. Each row shows time, server, tool, decision, reason,
   upstream status and gateway latency. No raw arguments or results unless the owner turned on payload
   capture.
2. **Tamper evidence.** Changing or deleting one stored event (by hand, in SQL) makes "Verify" report
   the exact event where the chain breaks. An untouched record verifies clean.
3. **Payload capture is opt-in and redacted.** With capture off, no argument values or results are
   stored. With capture on, they are stored with secrets redacted and size-capped, and are purged
   after the retention period.
4. **Honeytoken trip.** A planted honeytoken that appears in a tool call is refused, the owner gets a
   Telegram alert within 10 s, the agent is frozen (if the honeytoken says so), and the trip is in
   the Black Box and the control audit.
5. **Honey tool trip.** A call to a decoy tool is never forwarded upstream and trips the same way.
6. **The recorder never blocks enforcement.** With core's event endpoint down, the gateway still
   allows and refuses correctly; the lost span is recorded as a gap once core is back.

## 2. Current state

| What | Where | Gap for Phase 3 |
|---|---|---|
| Hash-chained ledger | `agentwall/src/telemetry/audit_logger.py` | In memory (optional file). On Cloud Run, scale to zero erases it. One chain for all tenants. Not visible to owners. |
| Recording hook | `McpGateway._record` in `agentwall/src/gateway/service.py:265` | Already called for every allowed, refused and failed `tools/call`, and for status refusals. This is where the recorder plugs in. |
| Argument privacy | `AuditRecord` stores `argument_keys` + `arguments_sha256` only | Good default; keep it. |
| Redaction | `FirewallPolicyEngine.inspect_egress` (gateway), `services/dlp_scrubber.py` (core) | Reuse the gateway's for payload capture. |
| Reporter pattern | `agentwall/src/gateway/budget.py` (`HttpUsageReporter`, single tracked flush task, backoff) | Copy the pattern for events. |
| Old tables | `execution_traces`, `security_events` in `20261030000000_schema.sql` | Designed for LLM reasoning steps and SIEM findings; unredacted JSONB payload columns; no chain. Not used by the gateway path. |
| Control audit | `control_audit` table, dashboard "Control audit log" | Stays the record of human/system actions; the timeline shows both. |
| Alerts | Telegram alerts (Phase 2 M1), best effort | Reused for trips. |

## 3. Approach

### 3.1 Black Box Recorder

**Flow.** The gateway's `_record` also pushes a small, typed `GatewayEvent` into a bounded in-memory
buffer (per instance). A recorder task flushes batches (every 2 s or at 200 events, whichever first)
to a new core endpoint `POST /internal/v1/events` with the internal service token. Core calls one SQL
function, `record_events(p_instance, p_batch_id, p_items)`, which appends them.

**Never blocks enforcement.** Pushing to the buffer is a non-blocking append. If the buffer is full
(10,000 events), the newest event is dropped, a drop counter and a Prometheus metric go up, and the
next successful batch carries a `recorder.gap` event with the count and time span. Core down → retry
with capped exponential backoff and jitter (same as usage). Shutdown (SIGTERM) does one final flush
bounded to 3 s.

**Exactly once.** Each batch has a UUID; `record_events` ignores a batch it has already stored, so a
retry after a lost response does not duplicate rows.

**Tamper evidence, per organization.** Each organization has its own chain:
`event_chain_heads(organization_id, last_seq, last_hash)`. `record_events` locks that row
(`FOR UPDATE`), and for each event computes
`hash = sha256(prev_hash || canonical_text(event))` with `pgcrypto`, sets `seq = last_seq + 1`, and
inserts. The canonical text is a fixed, documented field order so the same hash can be recomputed in
Python and in SQL. The table is append-only: no update or delete grants, a trigger that raises on
`UPDATE`/`DELETE` except from the purge function.

**Retention without breaking the chain.** The daily purge deletes events older than the
organization's retention and moves an anchor (`event_chain_heads.anchor_seq`, `anchor_prev_hash`) to
the first kept event. Verification starts from the anchor. The anchor move is itself logged in
`control_audit`.

**Verify.** `GET /v1/blackbox/verify?from_seq&to_seq` recomputes hashes over a bounded range (at most
50,000 events per call) and returns `ok`, or the first broken `seq` with expected and stored hashes.
The dashboard "Verify" button walks the range in pages.

**What each event holds (always):** organization, agent, seq, occurred_at (gateway clock, UTC),
received_at, gateway instance, server slug, method, tool name, decision (`allow`, `deny`, `error`),
reason codes (from the fixed set the gateway already uses: `passport_frozen`, `out_of_scope`,
`safe_mode`, `budget_exceeded`, `honeytoken`, `firewall:*`...), upstream status, gateway latency (ms),
argument keys, argument SHA-256, result size in bytes, redaction count, credential id (token jti),
prev_hash, hash. Strings are length-capped (tool name 128, reasons 10 × 64).

**Payload capture (opt-in, per organization, off by default).** When on, the event also carries
`arguments_redacted` and `result_excerpt`: run through `inspect_egress`, then truncated to 2 KB each
(JSON text, with a `truncated` flag). Turning it on or off is a control action: owner/admin only,
explicit confirmation, audited. Captured payloads have their own, shorter retention (default 7 days),
after which a purge sets those two columns to null. The chain hashes the *argument SHA-256*, not the
captured excerpt, so nulling payloads at retention does not break verification.

**Dashboard.** A "Black Box" page: timeline across agents (filter by agent, decision, tool, time
range), newest first, paginated by `seq`, live refresh every 5 s (polling; SSE later if needed).
Row detail shows the payload only if it was captured. Export of a filtered range as JSON Lines or
CSV, capped at 50,000 rows per export, via core (authorized and tenant-scoped like every read).

**Gateway ledger stays.** `TamperEvidentAuditLogger` is unchanged (local forensic copy and existing
`/v1/audit/*` endpoints). The Black Box is the durable, per-tenant record owners see.

### 3.2 Honeytokens

**What a honeytoken is.** A fake credential an owner plants where only a misbehaving agent would pick
it up: in a decoy database row, a document, an environment file the agent should not read, a ticket.
If that string later shows up in traffic through the gateway, something is reading or using what it
should not.

**Creating one.** Owner or admin chooses a label, a format and an action. Core generates the value
with `secrets.token_*` (at least 128 bits of randomness), shows it once (like an agent key), and
stores only its SHA-256 and the last 4 characters. Formats look like real keys so an attacker does not
skip them, but are generated so they are never valid anywhere: `generic` (`sk_live_` + 32 base62),
`aws_like` (`AKIA` + 16 upper alphanumerics, with a paired fake secret), `password` (24 printable).
No RedHand marker inside the value. Limit: 50 active honeytokens per organization.

**Detection in the gateway.** The passport context core already sends to the gateway gains
`honeytoken_digests`: the SHA-256 digests of the organization's active honeytokens (strictly typed;
missing or malformed → the call is denied, same rule as `safe_mode` and `budget`). On every
`tools/call` the gateway walks the argument values (bounded: depth 16, 64 KB of text total), finds
substrings matching the issued formats with precompiled regexes, hashes each candidate and checks set
membership. Same scan on the tool result, before it is returned. Pure lookups: no network calls, no
LLM. Context cache TTL (≤ 4 s) bounds how fast a new honeytoken becomes live.

**What a trip does.**
- **In arguments** (the agent is *using* the bait): the call is refused before it reaches upstream
  (reason `honeytoken`), and the token is redacted from anything logged.
- **In a result** (the agent *read* the bait): the result is returned with the token redacted
  (blocking would tip off an attacker that the record is special; owners can choose to block instead).
- Either way: a `honeytoken.tripped` event in the Black Box (marked high severity), a Telegram alert
  to linked owners naming the agent, tool, honeytoken label and where it appeared (never the value),
  `last_tripped_at` updated, and if the honeytoken's action is `freeze`, the agent is frozen by the
  system actor ("RedHand Honeytoken") through the existing atomic freeze function, audited.
- Default action: `freeze` for use in arguments, `alert` for appearance in results. Configurable per
  honeytoken.
- Trips are reported to core through the same event pipeline, plus an urgent flush (like the budget
  100% alert) so the alert does not wait for the 2 s batch.

**Honey tools.** An owner can add a decoy tool to one MCP server for one agent: a name and description
that look valuable (for example `export_all_customer_records`). The gateway appends it to that
agent's `tools/list` result for that server. A `tools/call` to it is never forwarded upstream; the
gateway returns a plausible JSON-RPC error and trips exactly like a honeytoken in arguments. Limit:
5 honey tools per agent. Honest agents can call a tempting tool when a user asks for exactly that, so
the dashboard warns about false alarms and the default action for honey tools is `alert`, not
`freeze`.

### 3.3 Alternatives considered

| Option | Why not (for now) |
|---|---|
| Reuse `execution_traces` for events | Built for LLM reasoning steps (thought text, model tokens), payload columns are unredacted JSONB, no chain, enum mismatch. A dedicated narrow table is cheaper and clearer; the old tables stay untouched. |
| Write each event synchronously from the gateway to the database | Adds a network round trip to every call and makes the database a hard dependency of serving; breaks the ≤ 10 ms budget and §4.7. |
| Persist the gateway's existing ledger to a file or bucket | One chain mixing all tenants; no tenant-scoped reads; Cloud Run file system is ephemeral; owners still cannot see it. |
| Hash chain computed in the gateway | Several gateway instances would fork the chain; ordering is only well defined at the store. SQL with a row lock is the single writer. |
| External queue (Pub/Sub, Kafka) between gateway and core | New infrastructure and cost for volumes a batch HTTP call handles. Revisit if events exceed ~1M/day. |
| Classic canary tokens with callback URLs or DNS (detect use outside RedHand) | Needs a public, unauthenticated endpoint and DNS infrastructure, and detects things outside the gateway (contradicts the product truth unless clearly separated). Listed as decision D5. |
| Honeytokens checked by a regex only (with a RedHand marker in the value) | A marker makes bait easy to spot and skip. Hash lookup of plausible formats avoids that. |
| LLM summary of an agent's day | Per-request LLM cost; not needed for "see things". Parked. |

## 4. Changes

**Migrations** (each with a rollback file and SQL tests in `scripts/test_migrations.sh`):
1. `20261110000000_blackbox.sql`: `agent_events` (partition-free for now, indexes on
   `(organization_id, seq)`, `(organization_id, agent_id, occurred_at DESC)`), `event_chain_heads`,
   `event_batches` (batch id, received_at; for exactly-once), organization columns
   `blackbox_retention_days` (default 30), `payload_capture_enabled` (default false),
   `payload_retention_days` (default 7); functions `record_events`, `verify_events`, `purge_events`,
   `control_payload_capture`; append-only trigger; RLS on, service_role only (same as other tables).
2. `20261111000000_honeytokens.sql`: `honeytokens` (id, org, label, kind, digest, hint, action_on_use,
   action_on_read, status `active|retired`, created_by, created_at, last_tripped_at), `honey_tools`
   (id, org, agent, server, name, description, action, status); functions `control_honeytoken`
   (create/retire, audited), `control_honey_tool`, `record_trip` (idempotent per event id).
3. Extend the purge schedule (pg_cron) with `redhand-purge-events` (same daily slot).

**Core** (`services/redhand-core/src/redhand_core/`): `blackbox/` (models, service, canonical hash),
`routers/blackbox.py` (timeline, detail, verify, export, payload-capture toggle),
`routers/events.py` (internal ingest), `honeytokens/` (models, generator, service),
`routers/honeytokens.py`; passport context gains `honeytoken_digests` and `honey_tools`; trip handling
reuses the Telegram alert and freeze paths; `local_rpc.HANDLERS` and `local_store` gain emulations.

**Gateway** (`agentwall/src/`): `gateway/recorder.py` (buffer, `HttpEventReporter`, flush task,
gap events), `gateway/honeytokens.py` (pure scanner: extract candidates, hash, match), hooks in
`gateway/service.py` (`_record` → recorder; scan before forward and on results; honey tool injection
in `_filter_tool_list` and short-circuit in `tools/call`); `gateway/context.py` strict parsing of the
new fields; metrics for events buffered, dropped, flush latency, trips.

**Dashboard** (`apps/redhand-ui/`): `/blackbox` page (timeline, filters, detail drawer, verify,
export), Honeytokens section (create with one-time reveal, list with last trip, retire), honey tool
editor per agent, payload capture toggle in organization settings; `src/lib/api.ts` types.

**Docs:** ADR 0011 (Black Box Recorder), ADR 0012 (Honeytokens), threat model, runbooks
`black-box-recorder.md` and `honeytokens.md`, API spec, changelog, briefing (Phase 3 status).

## 5. Security impact

- **New trust boundary:** gateway → core event ingest. Internal service token (same as usage), body
  size cap (1 MB), at most 500 events per batch, every field validated with Pydantic (`extra="forbid"`)
  and length caps. Core checks every event's `agent_id` belongs to the `organization_id` it claims
  (in SQL, inside `record_events`), so a bug or a compromised gateway instance cannot write into
  another tenant's chain without it being rejected.
- **Tenant isolation:** every read (timeline, verify, export) is scoped by the caller's organization in
  the service layer and filtered in SQL by `organization_id`; chains are per organization; tests for
  cross-tenant read, export and verify.
- **Data handled:** metadata by default. Payload capture is the first time RedHand stores customer
  payloads: off by default, owner opt-in with confirmation, redacted, capped, short retention,
  deletable. Exports contain only what is stored and are owner/admin only.
- **Honeytoken values:** generated server side, shown once, stored as SHA-256 only, never logged,
  never in alerts, never returned again. Detected occurrences are redacted from events and logs.
- **Fail closed:** missing or malformed `honeytoken_digests`/`honey_tools` in the context → deny. A
  scanner error on a call → deny (enforcement path). Recorder failures never deny (it is a side
  effect), but are visible as gaps, metrics and a dashboard banner.
- **Tamper evidence limits (stated honestly):** the chain proves events were not changed after they
  were stored; someone with database superuser access can rewrite the whole chain. Optional external
  anchoring (daily head hash sent to the owner or a bucket) is decision D4.
- **Abuse:** an attacker who learns a honeytoken is bait gains nothing; one who floods traffic to fill
  the buffer only causes gaps (recorded), not bypass. Budget Guard limits flooding per agent.
- **Threat model:** add "recorder ingest", "payload capture" and "honeytoken store" to the boundaries.

## 6. Data and migrations

- All new tables; no change to existing rows. Expand-only: new context fields are added by core
  first; the gateway that requires them ships after (deploy order: migration → core → gateway, as
  before).
- Rollback: each migration has a `down` file dropping only the new objects. Rolling back loses
  recorded events; documented in the runbook.
- Retention: events 30 days (configurable 7–90), payloads 7 days (1–30), gap/trip events same as
  events, honeytokens kept until retired then 90 days, batch ids 2 days.
- Tenant export and deletion: export endpoint; organization deletion cascades.

## 7. Tests

- **Unit (gateway):** buffer bounds and drop accounting; batch ids; flush single-task join (the Phase 2
  race regression pattern); backoff cap; shutdown flush bounded; scanner finds each format nested in
  dicts and lists and inside longer strings, ignores near misses, respects depth and size bounds;
  honey tool injected only for the right agent and server and never forwarded.
- **Unit (core):** canonical hash identical in Python and SQL; ingest validation (oversized,
  extra fields, wrong tenant agent, duplicate batch); payload toggle requires role and confirmation.
- **SQL tests:** chain continuity across concurrent batches (two sessions), duplicate batch ignored,
  UPDATE/DELETE refused, purge moves the anchor and verify still passes, tampering detected at the
  right seq, payload purge keeps the chain valid, `record_trip` idempotent, freeze on trip audited.
- **Security tests:** cross-tenant timeline, detail, export, verify and honeytoken list all refused;
  viewer role cannot toggle capture or create honeytokens; honeytoken value never appears in logs,
  events, alerts or API responses (asserted by searching captured output); missing/malformed context
  fields deny.
- **Failure modes:** core down → calls still served and refused correctly, gap event after recovery;
  slow core → no added latency on calls; context without digests → deny.
- **E2E:** `tests/e2e/test_phase3_done.py` covering done tests 1–6 against the local stack.
- **Performance:** benchmark the scanner on a 64 KB argument (target ≤ 1 ms) and gateway p50/p99 with
  the recorder on, before and after.
- **Mutation checks** on the hash, the scanner and the drop counter, as in Phase 2.

## 8. Cost and performance

- **Hot path:** buffer append (microseconds) + scanner (expected well under 1 ms for normal arguments,
  bounded to 64 KB). Context payload grows by up to 50 × 64 hex chars (~3 KB). Budget ≤ 10 ms p50
  stays; numbers measured and reported in M1/M3.
- **Storage:** about 0.5 KB per event with indexes. 1,000 calls per agent per day × 30 days ≈ 15 MB per
  agent. The Supabase free tier (500 MB) holds roughly 25–30 such agents; a busier Starter customer
  needs the paid tier (8 GB included). Payload capture adds up to ~4 KB per event but only for 7 days:
  ≈ 28 MB per busy agent. Metrics and the runbook show database size per organization.
- **Compute:** one batched HTTP call per gateway instance every 2 s while traffic flows; zero when idle
  (no change to scale to zero). One SQL call per batch.
- **No LLM calls.** No new third-party services.

## 9. Milestones

| | Milestone | Contents |
|---|---|---|
| M1 | Black Box core | **Built (2026-11-05), not yet staging-verified.** Migration, ingest, gateway recorder, timeline page, verify. Done tests 1, 2, 6. |
| M2 | Retention, export, payload capture | Purge with anchor, export, opt-in capture with redaction and its retention. Done test 3. |
| M3 | Honeytokens | Migration 2, generator, context digests, scanner, trips with alert and freeze, dashboard. Done test 4. |
| M4 | Honey tools, docs, staging | Honey tools, ADRs, runbooks, threat model, staging verification of all six done tests. Done test 5. |

Each milestone is its own PR with tests and a staging check, like Phase 2.

## 10. Risks and open questions

- **Cloud Run CPU throttling** can delay background flushes between requests. Mitigation: flush is
  also started from request handling when the oldest buffered event is older than 2 s, and trips
  flush urgently. Measured on staging in M1.
- **Clock skew** between instances: the timeline orders by `seq` (store order) and shows the gateway
  time; skew shows up as out-of-order timestamps, not lost events.
- **Volume per tenant:** a looping agent can produce many events; Budget Guard caps it, and a per-org
  ingest cap (default 200,000 events/day, then sampled gap markers) protects the database. To confirm.
- **False alarms from honey tools** (honest agents calling tempting tools): default action `alert`.
- **Payload capture and PDPA:** storing customer payloads, even redacted, needs the customer's own
  lawful basis; the toggle copy says so. Flag for human/legal review; no compliance claims.

## 11. Decisions for you

| | Decision | My recommendation |
|---|---|---|
| D1 | Default event retention | 30 days, configurable 7–90 |
| D2 | Ship payload capture in Phase 3 | Yes, opt-in per organization, redacted, 2 KB caps, 7-day retention |
| D3 | Honeytoken default actions | Freeze on use in arguments; alert on appearance in results; alert for honey tools |
| D4 | External anchoring of the chain head (daily hash to owner by Telegram, or to a bucket) | Later (Phase 5 "Prove it" fits better) |
| D5 | Canary URLs that detect use *outside* RedHand (public endpoint) | Not in Phase 3; revisit with customers |
| D6 | Include honey tools | Yes, small and high value |
| D7 | Per-organization ingest cap of 200,000 events/day | Yes |
