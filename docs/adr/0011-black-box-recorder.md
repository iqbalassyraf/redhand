# ADR 0011: Black Box Recorder

- **Status:** Accepted (2026-11-05)
- **Phase:** 3 (M1)
- **Plan:** `docs/plans/phase3-plan.md`

## Context
Phase 3 asks that an owner can see everything an agent did through RedHand and prove the record was not
altered. The gateway already keeps a hash-chained ledger (`agentwall/src/telemetry/audit_logger.py`), but it
is in-memory per instance, mixes every tenant into one chain, and is not reachable by owners. Phase 1/2
already has a working pattern for "report small batches from the gateway to core without blocking
enforcement": the Budget Guard reporter (ADR 0010). This ADR reuses that pattern for a durable, tenant-scoped,
tamper-evident record.

## Decision
- **What is stored (M1):** metadata only, per `tools/call` the gateway allowed, refused or failed to
  forward: time, server, tool, decision, reason codes, upstream status, latency, argument key names and a
  SHA-256 digest of the arguments (reused from the existing ledger record, never recomputed). Raw arguments
  and results are never stored in M1 (CLAUDE.md §10); payload capture is a separate, opt-in M2 feature.
- **Where it is appended:** one SQL function, `record_events()`
  (`supabase/migrations/20261110000000_blackbox.sql`), is the only writer. It locks the organization's
  `event_chain_heads` row, so several gateway instances writing concurrently are serialized and the chain
  cannot fork. Each row's `hash` covers its own fields plus the previous row's `hash`
  (`_blackbox_event_hash`), computed only in SQL, so verification never depends on a client recomputing it
  the same way.
- **One batch, one organization:** the chain is per organization, so a batch (`EventIngestRequest`) carries
  one `organization_id` and the gateway's recorder groups its buffer by organization before flushing,
  rather than mixing tenants in one HTTP call. Every item's claimed organization is still re-checked against
  the agent's real organization inside `record_events()`: a wrong or stale value only causes that item to be
  rejected, never a cross-tenant write.
- **Never blocks enforcement:** `EventRecorder.record()` (`agentwall/src/gateway/recorder.py`) is
  synchronous and does no I/O, mirroring `BudgetMeter.try_consume()`. The buffer is bounded (10,000 events
  by default); when full, the newest event is dropped (not the oldest) and counted, and the next successful
  flush for that organization carries one synthetic `recorder.gap` event naming how many were lost. Core
  being unreachable never denies or delays a call; it only means events wait longer in the buffer.
- **Exactly once:** each batch carries a `batch_id`; `record_events()` remembers batch ids it has already
  stored (`event_batches`) and returns the stored result for a resend instead of appending again.
- **Append-only:** a trigger refuses `UPDATE`/`DELETE` on `agent_events` from everyone, including
  `service_role` application code. Retention (M2's `purge_events()`) is the only intended exception, added
  later, and moves a chain anchor so verification of the remaining range still succeeds.
- **Reads are tenant-scoped:** `GET /v1/blackbox/events` and `GET /v1/blackbox/verify` both take the
  caller's `organization_id` from the authenticated operator, never from the client, and every query filters
  by it.
- **Fail closed where it matters, fail open where it doesn't:** the recorder is a side effect, so its own
  failures never deny a call (CLAUDE.md §4.7 on event-driven side effects). Reading back the record (the
  timeline, verify) still fails closed on tenant mismatch, bad input, or a database error.

## Alternatives
- Reuse `execution_traces`/`security_events` (from the original schema): built for LLM reasoning steps and
  unredacted JSONB payloads, with no chain and an enum mismatch with the gateway's own decision labels. A
  dedicated, narrow table is cheaper to reason about and leaves those tables untouched.
- Write each event synchronously to the database from the gateway: a network round trip on every call,
  breaking the ≤ 10 ms hot-path budget (CLAUDE.md §8) and making the database a hard dependency of serving.
- A hash chain computed in the gateway instead of in SQL: several instances would fork the chain; SQL with a
  row lock is the one place ordering is well defined.
- A single global chain instead of one per organization: simpler, but a tenant's "Verify" would depend on
  rows that belong to other tenants, and a purge in one tenant would move everyone's anchor.
- An external queue (Pub/Sub, Kafka) between gateway and core: new infrastructure for volumes a batched
  HTTP call already handles; revisit if daily events exceed roughly a million.

## Consequences
- **Storage:** about 0.5 KB per event with indexes; roughly 15 MB per agent per month at 1,000 calls/day.
  The Supabase free tier (500 MB) holds on the order of 25–30 such agents before the paid tier is needed.
- **Latency:** `record()` is an in-memory append (microseconds); the scanner work added in later milestones
  is bounded. Gateway overhead with the recorder enabled has **not yet been measured**; the M1 staging
  verification (`docs/plans/phase3-plan.md` section 9.1) records this as open.
- **Cloud Run CPU throttling** can delay background flushes between requests, same as Budget Guard; the
  flush is also started from inside request handling (`schedule_flush_if_due()`), not only from the
  periodic loop.
- **Losing the gateway process** between flushes loses at most the last `RECORDER_FLUSH_INTERVAL_SECONDS`
  worth of that instance's events (an undercount, visible as a gap only if the buffer later overflows before
  the next successful flush); a final flush runs on shutdown.
- **Rolling back the migration** drops every recorded event and the chain state; there is no record to lose
  yet in M1 since this is new.
- Deploy order: migration, then core, then gateway (the gateway's new config settings have safe defaults, so
  an old core without the ingest endpoint simply fails every flush attempt and buffers, rather than crashing).
- **Claims discipline:** the Black Box only ever shows traffic that went through the RedHand gateway; the
  dashboard copy, this ADR and the runbook all say so, per the product truth in CLAUDE.md §1.

## Addendum (2026-11-05): retention (Phase 3 M2a)
- **Decision:** the append-only trigger gets exactly two exceptions instead of a session flag: `DELETE` only
  for events at or behind the organization's anchor, and `UPDATE` only to set the two payload columns to NULL
  (the rest of the row compared as JSON, so a column added later is protected by default). A session flag
  (`SET LOCAL`), as the M1 comment anticipated, was rejected: any `service_role` caller could set it.
- **Anchor guard:** a trigger on `event_chain_heads` lets the anchor move only forward, only onto an existing
  event whose hash it records, and only onto an event older than the organization's retention (minimum
  7 days). Code with full table access therefore cannot erase recent events without it showing as a broken
  chain or an audited retention change.
- **Purge:** `purge_events()` runs daily (pg_cron, 19:17 UTC). Ages use `received_at` (the database clock). The
  anchor stops just before the first event still within retention, because `received_at` is not strictly
  increasing with `seq` (seq is assigned under the chain lock, `received_at` is the transaction start). At most
  50,000 events per organization per run; the next run continues. Each anchor move is audited
  (`organization.blackbox_purged`, system actor). Batch ids older than 2 days are dropped.
- **Limits:** the guard checks the age of the anchor event only, not of every event behind it; an event a
  few seconds younger than its neighbour can sit behind an old anchor, and the purge's prefix rule (tested)
  is what keeps it. One run holds each organization's chain lock while it purges that organization, so
  ingest for it waits briefly (the gateway retries; enforcement is unaffected). A superuser can still bypass
  all of this.
- **Retention settings:** `PUT /v1/blackbox/retention` (admin, `confirm: true` for any change, compare-and-set,
  audited as `organization.blackbox_retention_changed`); events 7–90 days, payloads 1–30 days.

## Addendum (2026-11-05): payload capture (Phase 3 M2b)
- **What is stored, and when:** only for organizations that turned capture on (off by default). Per recorded
  tool call: a redacted excerpt of the arguments and, for allowed calls, of the result, each as compact JSON
  text cut to 2 KB with a `truncated` flag and the original size. Refused calls keep an argument excerpt (what
  was refused is the useful part) and no result.
- **Redact first, truncate second:** the whole value is scanned, then the redacted text is cut. Cutting first
  could slice a secret in half so no pattern matched and half of it was stored (tested at every offset around
  the cut). The gateway is the only redaction point: the raw payload never leaves it. Core validates shape and
  size and does **not** re-scrub, so a compromised gateway could send unredacted text (see follow-ups).
- **Decision D2 (personal data):** redaction covers secrets (API keys, tokens, JWTs, PEM keys), email
  addresses, Malaysian NRIC (MyKad) numbers (date-checked), card numbers (Luhn-checked), phone numbers, and
  blanks the value of any field whose NAME looks sensitive (password, token, secret, authorization, cookie,
  nric, ...). It is pattern based and best effort. It does not find names, addresses, free text, or a number
  split across fields, so capture still stores customer data.
- **Never store unscanned text:** the scan budget is 16 KiB of text, 1,000 values and depth 16; anything past
  it, and any non-JSON type, is replaced by a `[NOT_CAPTURED:...]` marker. A single string over 16 KiB is
  therefore not captured at all (no prefix is kept: cutting a string we cannot scan whole risks splitting a
  secret at the window's edge). The budget is small on purpose: only 2 KB is ever stored, and capture runs on
  the request path.
- **Measured cost (capture on, local, one capture):** small call 0.02 ms, typical 2 KB result 0.35 ms p50,
  60 KB mixed payload 2.9 ms p50 / 7 ms p99, 1,000 tiny values 0.6 ms p50. A first version with a 64 KiB budget
  took 15 ms p50 on the 60 KB payload (over the 10 ms budget in CLAUDE.md section 8) and was reworked. Arguments
  and result are scanned separately, so the worst case is about twice one capture. With capture off the cost is
  one boolean check.
- **The database enforces the setting too:** `record_events()` stores the payload columns only when the
  organization's flag is on, and drops (never rejects) a payload that is not a JSON object or is over 16 KB,
  keeping the event. Anything but an explicit true counts as off, in core's context and in SQL.
- **Context field:** core sends `payload_capture` in the gateway context; the gateway requires it (no default)
  and denies the call if it is missing or not a boolean, like `safe_mode` and `budget`. **Deploy core before the
  gateway**, or every call is denied until core is deployed.
- **Control action:** turning capture ON needs the admin role and `"confirm": true` (data starts being
  collected); turning it OFF needs the security operator role and no confirmation (the same split as Safe Mode:
  stopping is easy, starting needs care). Both are compare-and-set and audited
  (`organization.payload_capture_changed`). Turning capture off does not delete what was captured; it is
  cleared at the payload retention (default 7 days, 1-30), or sooner by shortening it.
- **Alternatives rejected:** redacting in core (the raw payload would cross the network and sit in the
  gateway's buffer first); a prefix window for oversized strings (edge-of-window leaks); a thread for the
  scan (the GIL makes it no faster and adds a hand-off).
- **Limits:** payloads are not yet shown in the dashboard (M2c adds viewing and export); the timeline API never
  returns them. The recorder buffer holds payloads in memory until flushed: at most 10,000 events of up to
  about 4 KB, so roughly 40 MB worst case on a 512 MiB instance.

