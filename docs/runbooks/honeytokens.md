# Runbook: honeytokens and decoy tools

**Product truth (shown in the dashboard):** RedHand sees bait only when it flows through the RedHand gateway.
It says nothing about agents, keys or tools used outside it.

## Use it
1. Dashboard -> **Honeytokens** -> *Create honeytoken* (admin or owner). Pick what it looks like, and what happens if
   an agent USES it (refuse + alert + freeze, or refuse + alert) and if it shows up in a RESULT (alert, or alert +
   freeze). **Copy the value now: it is shown once.** RedHand stores only a fingerprint.
2. Plant it where only a misbehaving agent would find it: a decoy `.env` entry, a decoy database row, a document the
   agent should never open.
3. *Decoy tools:* add a tempting tool (for example `export_all_customer_records`) to one agent on one MCP server.
   It appears in that agent's tool list. A call to it is never forwarded.
4. When bait trips: the call is refused (or the result is redacted), your linked Telegram chats are alerted (the
   alert names the agent, the label and the tool, never the value), the agent is frozen if the action says so, and
   the event is in the Black Box with reason `honeytoken` or `honey_tool` and in the control audit
   (`honeytoken.tripped`). **To resume a frozen agent, unfreeze it in the dashboard.**

## Limits worth knowing
- Detection is an exact match on three formats. A value the agent encodes (base64, URL-encoded), splits across
  fields, or hides beyond the first 64 KiB of one string is not found.
- Bait in a **result** is redacted, not blocked: the agent still gets its answer.
- Decoy tools can cause false alarms: an honest agent may call a tempting tool because a user asked. The default is
  alert, not freeze.
- One alert per agent, bait and place per 5 minutes. Every trip is still counted and audited.
- A trip report that cannot reach core is retried for about 8 seconds, then dropped (the call was already refused or
  redacted). `redhand_gateway_trip_reports_total{outcome="failed"}` counts these.

## Deploy order (important)
1. Apply migration `20261115000000_honeytokens.sql`.
2. Deploy **core**.
3. Deploy the **gateway**. An older core does not send `honeytokens` / `honey_tools`, and the new gateway then denies
   every call until core is updated. The reverse order is safe only for gateways that predate this version.
Rollback: `supabase/rollbacks/20261115000000_honeytokens.down.sql` (deletes honeytokens, decoy tools and trips).

## Troubleshooting
- *Every call denied after a deploy:* core was deployed after the gateway. Deploy core.
- *No alert on a trip:* check a Telegram chat is linked (dashboard), and `redhand_trips_total` on core. A repeat within
  5 minutes is recorded but not alerted again.
- *Trip but no freeze:* the honeytoken's action for that place is `alert`; check it in the dashboard.
- *A honeytoken never trips:* it may have been retired, or the value was altered before use (encoded or split).

## Test it on staging (Phase 3 done tests 4 and 5)
Create a honeytoken (action: freeze on use) and a decoy tool for a test agent, then run
`python3 scripts/staging_agent.py run` style calls: one call carrying the value, one to the decoy. Expect: refusal,
a Telegram alert within 10 seconds, the agent frozen after the first, the decoy never reaching upstream, and two
events in the Black Box.
