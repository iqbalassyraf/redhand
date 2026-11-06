# Runbook: Black Box Recorder

A durable, tamper-evident record of every tool call the gateway allowed, refused or failed to forward.
**Only traffic through the RedHand gateway**: it says nothing about agents or credentials used outside it.
Design: `docs/adr/0011-black-box-recorder.md`.

## Use it
- **Retention:** events are deleted after the organization's retention (default 30 days, 7–90) by the daily
  purge (`purge_events()`, pg_cron at 19:17 UTC); captured payloads (M2b) are cleared after their own
  retention (default 7 days, 1–30). An admin changes both with `PUT /v1/blackbox/retention` and
  `"confirm": true`; **a shorter retention deletes events at the next purge and cannot be undone.** Every
  purge that deletes something writes an `organization.blackbox_purged` audit row (old and new anchor,
  count). After a purge, "Verify chain" starts from the anchor; events before it are gone by design.
- **Check the purge is scheduled (Supabase SQL editor):** `SELECT jobname, schedule FROM cron.job;` should list
  `redhand-purge-events`. To run it now: `SELECT public.purge_events();`.
- **Dashboard -> Black Box:** a timeline (newest first), filterable by decision (All / ALLOW / BLOCK /
  ERROR), paginated with "Load older events".
- **Verify chain:** recomputes the hash chain from seq 1 to the newest event currently shown and reports
  either "chain intact" or the exact seq where it was tampered with.
- **What is stored (M1):** time, server, tool name, decision, reason codes, upstream status, latency, and
  the names and a SHA-256 digest of the tool call's arguments. Never the raw argument values or results
  (payload capture is a separate, opt-in M2 feature, off by default).
- Events normally appear within a few seconds (`RECORDER_FLUSH_INTERVAL_SECONDS`, default 2s). A gateway
  outage on core's side never stops enforcement; events simply wait longer and a `recorder.gap` row appears
  once they catch up if the buffer ever overflowed.

## Payload capture (opt-in)
By default the Black Box stores **metadata only**: no argument values and no results. An admin can turn on
**payload capture** so each recorded call also stores a redacted excerpt of its arguments and result.
- **Turn on (admin, confirmation required):** `PUT /v1/blackbox/payload-capture` with
  `{"enabled": true, "confirm": true, "reason": "..."}`. **Turn off (security operator, no confirmation):**
  `{"enabled": false}`. Both are audited (`organization.payload_capture_changed`). The dashboard's Black Box page has the same controls. `GET /v1/blackbox/settings` shows the current state. A change reaches the gateway within a few seconds
  (the context cache is at most 4 s).
- **What is stored:** for each `tools/call`, compact JSON text of the arguments (and the result, for allowed
  calls), cut to 2 KB, after redaction. Refused calls keep the arguments only. Kept for the payload retention
  (default 7 days), then cleared; the event itself stays for the event retention.
- **What is redacted:** API keys, tokens, JWTs and private keys; email addresses; Malaysian NRIC (MyKad)
  numbers; card numbers (checksum-valid); phone numbers; and the value of any field whose name looks sensitive
  (password, token, secret, authorization, cookie, nric, ...).
- **What is NOT detected:** names, addresses, free-text descriptions, and numbers split across several fields.
  Any single string over 16 KB is not captured at all (a marker is stored instead). Capture still stores data
  your agents handled. **Before turning it on, check you have a lawful basis to store that data (for example
  under the PDPA); this note is a prompt for your own legal review, not a statement of compliance.**
- **Turning it off does not delete what was captured.** To remove it at once use **Delete captured payloads now**
  in the dashboard (`POST /v1/blackbox/payloads/clear`, admin, confirmation, audited with the count). Events
  and the chain stay, so "Verify chain" still passes. Or shorten the payload retention; the next daily purge
  clears it.
- **Where to see it:** admins and owners can read one event's payload with
  `GET /v1/blackbox/events/{seq}/payload`; the timeline API never returns payloads. Each read is audited
  (`organization.blackbox_payload_viewed`, with the actor and sequence number, never the text) in the same
  database transaction as the read, and limited to 60 per minute per operator. The dashboard shows it in the
  event detail drawer (admins only).

## Export (M2c)
`GET /v1/blackbox/export?format=jsonl|csv` downloads the timeline, oldest first, at most 50,000 rows.
- **Who:** security operators and above get metadata. `include_payloads=true` adds the redacted excerpts and
  needs the admin role. Filters: `agent_id`, `decision`, `since`, `until`. At most 10 exports per hour per
  operator.
- **Audited first:** one `organization.blackbox_exported` row (actor, format, filters, whether payloads were
  included) is written before the first row is read. If that write fails, nothing is exported.
- **JSON Lines** ends with a trailer line `{"export_complete": ..., "rows": N, "capped_at": ...}`: a file
  without it was cut short. CSV has no trailer. CSV text cells that start with `=`, `+`, `-` or `@` are prefixed
  with an apostrophe so spreadsheets show them as text.
- **Handle the file as customer data.** With payloads it holds redacted excerpts, which can still contain
  names and free text (see "What is NOT detected"). Responses are `Cache-Control: no-store`.

## Deploy order (important)
1. Apply `supabase/migrations/20261110000000_blackbox.sql`.
2. Deploy **core**, then the **gateway** (`deploy.sh core`, then `deploy.sh gateway`). The gateway's recorder
   degrades gracefully against an older core (every flush attempt fails and the buffer grows, bounded by
   `RECORDER_MAX_BUFFERED_EVENTS`); it never denies or delays an agent call.
   **M2b (payload capture) adds a required context field: deploy core before the gateway.** A gateway that
   reaches an older core denies every call until core is updated.
3. Deploy the dashboard (merge to `main`). The `/blackbox` page needs the new core endpoints; against an
   older core it will show errors reading the timeline, nothing else.

## Test it on staging (Phase 3 done tests 1, 2, 6)
1. Make a few allowed and a few refused tool calls through the gateway (e.g. `python3
   scripts/staging_agent.py watch`, or an out-of-scope tool call).
2. **Expected:** within about 10 seconds, the dashboard's Black Box page shows those calls with the right
   decision, reasons and latency. No argument values appear anywhere in the UI or in network responses.
3. Click **Verify chain**. **Expected:** "Verified: N event(s) from seq 1 to M, chain intact."
4. **Tamper check (staging only, not production):** in the SQL editor, directly try
   `UPDATE agent_events SET tool_name = 'x' WHERE seq = <some seq>` -- expect it to be refused
   (`agent_events is append-only`), proving the trigger. There is no supported way to tamper with a stored
   event through the application; this only proves the guard exists.
5. **Recorder outage (done test 6): proven by the local end-to-end suite, not on staging.** Do **not** break
   `AGENTWALL_CORE_SERVICE_TOKEN` or stop core to test this: the gateway uses the same token and the same core
   for every passport check, so either makes it deny **every** call (correct fail-closed behaviour, but it
   tests the passport path, not the recorder). There is no supported way to fail only the event endpoint,
   and a switch for it would be a debug path in the gateway (CLAUDE.md §16). The behaviour is covered by
   `agentwall/tests/test_recorder.py` (reporter failures, crashes, backoff, gaps) and `tests/e2e/`.

## Troubleshooting
| Symptom | Likely cause |
|---|---|
| The Black Box page is empty but agents are being called | Check `redhand_gateway_events_buffered` and `redhand_gateway_event_reports_total{outcome="failed"}` on the gateway's `/metrics`: the recorder cannot reach core (wrong or missing service token, core down, or core is older than this gateway and has no `/internal/v1/events`). |
| Calls appear in gateway logs but not in the Black Box, and `redhand_gateway_events_rejected_total` goes up | Core acknowledged the batches but `record_events()` refused the items. Core logs "Event batch partly rejected" with the counts. Run `SELECT public._blackbox_event_hash(...)` by hand to surface a database fault (this is how a missing `extensions` search path was found), and check that each agent belongs to the organization the batch claims. |
| Capture is on but events have no payloads | Check `GET /v1/blackbox/settings` says `payload_capture_enabled: true`; the gateway picks changes up within about 4 s. Check `redhand_gateway_payload_captures_total{outcome="failed"}` on `/metrics` (a failure records the event without a payload and never affects the call). A payload over 16 KB, or one that is not a JSON object, is dropped by the database. |
| Every call is denied right after a gateway deploy, and gateway logs say the passport lookup returned malformed data | The gateway was deployed before core (M2b needs the `payload_capture` context field). Deploy core, then retry. |
| A `recorder.gap` row appears | The gateway's buffer filled (`RECORDER_MAX_BUFFERED_EVENTS`, default 10,000) before it could flush; some events in that window were not recorded. Enforcement itself was not affected. Raise the buffer size or flush interval if this recurs. |
| "Verify chain" fails with `hash_mismatch` or `prev_hash_mismatch` | A stored event was altered or deleted outside the application (e.g. direct database access with elevated privileges). This is exactly what Verify is for: report it as a security incident. |
| Verify returns a 400 "range starts at or before the retained anchor" | The range asked for starts before what retention has purged (M2). Pick a `from_seq` after the organization's anchor. |
| Events from one organization appear to be missing while another's are fine | Check that the gateway's recorder is grouping by `organization_id` correctly (it reads this from the passport context, same as every other tenant-scoped decision) and that core's `record_events()` is not rejecting items for a tenant mismatch (check core logs for "Event batch could not be recorded"). |

## Limits worth knowing
- Metadata only in M1: no raw arguments or results. Payload capture (M2) is opt-in per organization.
- A busy agent (around 1,000 calls/day) uses roughly 15 MB/month of database storage; the free Supabase tier
  holds on the order of 25–30 such agents before the paid tier is needed.
- The chain proves events were not changed after they were stored by anything with only the access the
  application itself has. Someone with database superuser access could still rewrite the whole chain;
  external anchoring of the chain head is a tracked follow-up (Phase 3 plan, decision D4).
