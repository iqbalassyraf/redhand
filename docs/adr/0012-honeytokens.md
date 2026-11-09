# ADR 0012: Honeytokens and decoy tools

**Status:** Accepted (2026-11-06). Phase 3 M3 and M4. Plan: `docs/plans/phase3-plan.md` section 3.2.

## Context
Phase 3's second feature: tell an owner within seconds when an agent touches bait it should never touch.
RedHand only sees what flows through its gateway, so the bait must be recognised there. The gateway's hot path
must stay lean (no I/O, bounded work, CLAUDE.md section 8) and a failure must never become a default-allow.

## Decision
- **Honeytoken = a generated fake credential.** Core generates it (`secrets`, at least 128 bits for the API
  key format), returns it ONCE, and stores only its SHA-256 digest and last four characters. Formats: `api_key`
  (`sk_live_` + 32 base62), `aws_key` (`AKIA` + 16 uppercase alphanumerics), `password` (24 alphanumerics with
  mixed case and a digit). No RedHand marker inside the value, so an attacker cannot recognise and skip it.
  Limit: 50 active per organization.
- **The gateway knows digests, never values.** The gateway context carries `{id, digest}` for the
  organization's active honeytokens and `{id, name, description}` for the agent's decoy tools on the requested
  server. Both fields are required with no default: a core that omits them (an older version) makes the lookup
  fail and the call is denied. **Deploy core before the gateway.**
- **Detection is pure lookup.** `gateway/honeytokens.py` pulls out text matching the three issued formats,
  hashes each candidate and checks membership in the digest set. At most 64 KiB of text, 1,000 values and depth
  16 per scan; a string over the remaining budget is scanned up to the budget and the rest passes unscanned
  (counted in `redhand_gateway_honeytoken_scans_truncated_total`). Keys are scanned too.
- **What a trip does.**
  - *In arguments (the agent is using the bait):* the call is refused before upstream, with a generic
    "request blocked" that does not say why. The scan runs before the scope check, so bait is a trip even for
    an out-of-scope tool.
  - *In a result (the agent read the bait):* the result still returns with the bait replaced by
    `[REDACTED:HONEYTOKEN]` (refusing would tip off an attacker that this record is special).
  - *Decoy tool called:* never forwarded. The agent gets a plausible generic tool error
    (`isError: true`). The decoy is appended to that agent's `tools/list` only (never duplicating a real tool).
  - In every case the Black Box event carries the fixed reason `honeytoken` or `honey_tool`, and **no payload is
    captured for a trip** (it may hold the bait, and the redaction patterns cannot recognise the password format).
- **Reporting.** The gateway sends `POST /internal/v1/trips` (service token) with identifiers only: trip id,
  organization, agent, kind, reference id, where seen, tool and server. `TripDispatcher` is non-blocking, retries
  a 5xx or network failure up to five times in about 8 s, drops a 4xx, and caps 50 in flight. It never changes the
  decision.
- **Core decides, from what it stores.** `record_trip()` re-checks that the agent and the reference belong to the
  organization (the gateway's claims are not trusted), is idempotent per trip id, updates `last_tripped_at` and
  `trip_count`, audits as the system actor (`honeytoken.tripped` / `honey_tool.tripped`) and says whether to
  alert (one alert per agent, reference and place per 5 minutes; every trip is still recorded). Core then freezes
  the agent through the existing freeze path if the STORED action says so, and alerts via Telegram. A failed alert
  does not undo a freeze.
- **Defaults (decision D3).** Honeytoken used in arguments: refuse, alert, freeze. Appears in a result: alert.
  Decoy tool: alert (an honest agent can call a tempting tool when a user asks for it). Each is configurable.
- **Roles.** Create and retire: admin and owner. List: security operator and above. The dashboard Honeytokens page
  shows the value once; the server decides who may do anything.

## Alternatives considered
- *Regex with a RedHand marker in the value:* a marker makes bait easy to spot and skip.
- *Sliding-window hashing of every substring of every configured length:* tens of thousands of hashes per call.
- *Letting the gateway decide the action (freeze) from the context:* a compromised gateway could then be told
  to freeze or not; core uses its own stored action.
- *Reporting trips inside the Black Box batch:* a batch can wait seconds; a trip should not.
- *Shipping honey tools later:* two migrations, two context changes and two strict deploy orders for no safety gain.

## Consequences
- Detection is exact-match on three formats: a honeytoken the agent re-encodes (base64, URL-encoded), splits
  across fields, or that sits past the 64 KiB scan window is not found. Stated in the threat model and runbook.
- Worst-case added gateway latency is about 2 ms per scan at the 64 KiB budget (measured), so about 4 ms with a
  result (budget 10 ms p50). Typical calls cost microseconds, and nothing runs when an organization has none.
- A freeze takes effect on the agent's next call after core processes the trip (context cache at most 4 s).
- Honeytokens, decoy tools and trips are kept until retired, then 90 days (`purge_honey()`, daily).
- Deleting an organization removes its honeytokens, decoy tools and trips (foreign keys cascade).

## Addendum (2026-11-06): tool names and argument keys
Found in staging verification: only argument VALUES and results were scanned, so bait used as a tool name or an
argument key was not matched, and the tool name reached the event, the gateway ledger, the log and the trip report.
The scan now covers the tool name and every argument key and value. On a trip the redacted copies are what is
recorded, logged and reported. Scan order is now bait first, then decoy.


## Addendum (2026-11-09, Phase 4 M5a): a `canary` kind for the system prompt
Phase 4 done test 7 asks that a marker put in a system prompt, which later appears in a tool call or a tool answer, trips an alert. That is the
same mechanism as a honeytoken with a different purpose: the bait is planted in the agent's own prompt, so seeing it means prompt text leaked, not
that an attacker took bait. Plan: `docs/plans/phase4-m5a-canary.md`.
- **A fourth kind, `canary`.** Same value shape as `password` (24 mixed-case alphanumerics, no RedHand marker), generated and stored exactly like the others
  (shown once, SHA-256 digest and last four characters only). Because the shape already exists, **the gateway is unchanged**: core already sends every
  active honeytoken's digest whatever its kind.
- **Defaults (decision F-D3).** Used in a call: refuse and alert, **no freeze**. In a result: alert. Anyone who steals a prompt can replay the value on purpose,
  so freezing must be an explicit admin choice. The API defaults only the fields the caller did not send; the other kinds keep freeze and alert.
- **Alert wording** says the prompt text "appears to have leaked" (an agent that legitimately passes its instructions to a tool trips it too). The trip function
  `record_trip()` now also returns the honeytoken's kind (an added key) and writes it to the trip's audit row.
- **Alternatives rejected:** a `password` honeytoken with a label (alerts and counts could not tell a leak from a taken decoy); a visible prefix (an attacker can strip it);
  matching the prompt text itself (RedHand would have to hold the most sensitive text an owner has).
- **Limits (unchanged, now shown next to the value):** only the gateway's view; a prompt shown to a person in chat or sent to a model provider is not seen; re-encoded, split or glued values are not found
  (a test pins the glued case).
- **Rollback** deletes canaries and their trips (they cannot exist under the old kind check); the audit rows stay.
