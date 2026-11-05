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

## Deploy order (important)
1. Apply `supabase/migrations/20261110000000_blackbox.sql`.
2. Deploy **core**, then the **gateway** (`deploy.sh core`, then `deploy.sh gateway`). The gateway's recorder
   degrades gracefully against an older core (every flush attempt fails and the buffer grows, bounded by
   `RECORDER_MAX_BUFFERED_EVENTS`); it never denies or delays an agent call.
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
