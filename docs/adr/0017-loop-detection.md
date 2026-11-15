# ADR 0017: Loop detection (identical tool calls, observe first)

**Status:** Accepted (2026-11-13). Phase 4 M6, done test 9. Plan: `docs/plans/phase4-m6-loop-detection.md` (on the plans branch, PR 58). Builds on ADR 0010 (Budget Guard), ADR 0015 (the Radar is observe only) and decision F-D4 (20 identical calls in 60 seconds, observe first).

## Context
An agent that calls the same tool with the same arguments again and again is usually stuck: a retry loop, a tool that keeps failing, or a prompt-injected instruction to repeat. It burns the daily call budget, hammers the customer's system and fills the logs. RedHand sees every call through the gateway, so it can count them. The Radar's storage, review, suppression, retention and alert path already exist and handle exactly this shape of record (a coalesced finding with a count, no text).

## Decision
1. **A bounded in-memory meter in the gateway** (`agentwall/src/gateway/loops.py`), synchronous with no I/O, like Budget Guard. The key is the agent plus a 16-byte salted BLAKE2b digest of the tool name and the canonical JSON of the arguments; the salt is random per process, so a digest means nothing outside it, and the arguments themselves are never kept or sent. Each key holds three numbers (a two-bucket sliding-window counter), an agent holds at most 16 keys and the table at most 100,000 (about 20 MB), so a flood of distinct calls cannot grow it. Inside one window the count is exact (calls 1 to N-1 pass, call N is flagged); across a window edge it is an estimate that is at most one call late.
2. **Modes per organization:** off, **observe** (default), throttle. Observe records and alerts and never changes a decision. Throttle also refuses the flagged call before it can use budget, and does **not count** a refused call, so the agent recovers as the window moves on: it is a rate limit on identical calls (about N-1 per window), not a lock-out. **Any unexpected error in throttle mode denies**; in observe it is counted and changes nothing.
3. **Findings reuse the Radar** (`RAD-LOOP-001`, kind `loop`, place `call`) through the existing reporter, retry and 30 s repeat limit, and core's coalescing, 2,000-a-day cap, review and suppression. Loops get **their own 10-minute alert cooldown** so a loop alert cannot hide an injection alert. `radar_summary` now counts only the injection and output kinds, so a loop is never a false alarm of the Radar's rules.
4. **Exemption for a legitimate polling agent is a live suppression of `RAD-LOOP-001`** (existing screen, audit and 90-day limit). Core tells the gateway (`loop_exempt`), which then neither flags nor throttles that agent. It exempts the whole agent, not one tool.
5. **Fail closed on the settings.** Core sends `loop_mode`, `loop_limit`, `loop_window_seconds` and `loop_exempt` as required fields; the gateway validates them strictly (limit 3 to 1000, window 10 to 600 seconds, real integers and booleans). An older core, or any malformed value, makes the lookup fail and the call is denied. Core treats anything but an explicit `observe` or `throttle` as off, and a failed exemption lookup as "not exempt".
6. **Kill switch:** `AGENTWALL_LOOP_DETECTION_ENABLED=false` on the gateway skips the meter for everyone, whatever core says.
7. **Order on the hot path:** after scope, tool pin and guardrails, before Budget Guard. Calls refused earlier are never counted. A call that Budget Guard then refuses **is** counted (the loop check has to come first so a throttled repeat consumes no budget); an agent hammering a limit is itself a loop.

## Alternatives considered
Count in Postgres (hot-path latency and a new dependency of every call on the database). Store the last N timestamps per key (memory grows with the limit). A new findings table (duplicates review, suppression, retention and alerts). A per-tool exemption (needs a column on suppressions and a screen; deferred). A hard block after N (an agent blocked forever cannot recover without a person).

## Consequences
- Several gateway instances each keep their own table, so the effective limit is up to the limit times the number of instances (the same approximation as Budget Guard). A call that changes its arguments each time is not caught. At the global cap the oldest key is dropped and a loop may be missed (counted in `redhand_gateway_loops_total{outcome="evicted"}`): this is a detection control, not authorization, so it errs toward under-counting.
- Every existing organization starts in observe on deploy (F-D4). A tool that is meant to be called repeatedly will produce a finding and one alert until its agent is exempted.
- Deploy order: migration, core, gateway, dashboard. Rollback: the down migration (deletes loop findings and suppressions), then redeploy the previous gateway.

## Measured cost (in process, instant fakes, warm cache; staging confirms)
`loop_check` averages 22 microseconds for typical arguments and 39 microseconds for 4 KiB arguments; per-call p50 0.70 ms with detection off and 0.74 ms on. These are RedHand's own work only (no network), against the 10 ms p50 and 50 ms p99 budgets.

## Differences from the approved plan
- Turning detection **off** also needs the confirmation (the plan named only throttle), matching the Radar's switches.
- `PUT /v1/radar/loop-settings` accepts an optional `expected_mode`; a different current mode is a 409.
- Calls refused by Budget Guard are counted as repeats (point 7); the plan said only calls that would be forwarded.
- A failed exemption lookup means "not exempt" and does not fail the whole context lookup.
- `radar_readiness_inputs` is unchanged on purpose: its "most findings one agent made in a day" figure is the shared daily cap, so loop findings correctly count toward it; silences and stored findings there are already filtered by rule prefix and kind.
- `scripts/latency_baseline.py` needed no change: it already prints every stage, including `loop_check`.
- The OpenAPI file was regenerated from the app (sorted keys), since the repository has no generator script.
- The test harness gained optional `loop_*` parameters (off by default); no existing assertion changed.
