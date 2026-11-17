# Plan: refresh the passport cache after a slow call (gateway speed fix)

**Status:** APPROVED by the owner (2026-11-11). **BUILT** on branch `fix/gateway-refresh-after-call` (PR pending). **Measured on staging 2026-11-12:** 0, 0, 0 and 1 cache misses per 200 calls (was 6 to 17); see `docs/testing/results/2026-11-12-gateway-refresh-after-call.md`. Found while checking the M5a speed step (`docs/testing/results/2026-11-09-m5a-canary-rerun.md`). Not part of the canary itself: the canary adds about 0.01 ms.

## 1. Goal
After an agent's tool call that takes 2 seconds or more upstream, its next call must find a fresh passport entry instead of waiting for core, so the gateway stays inside its budget (p99 at most 50 ms added, CLAUDE.md §8). Serves Phase 4 done test 7's speed step and the F2 closeout latency check.

## 2. Current state (checked 2026-11-11)
- The gateway looks up the passport **once, at the start of a call** (`agentwall/src/gateway/service.py`, step 3, `self.contexts.get(...)`), before forwarding upstream.
- The cache (`agentwall/src/gateway/context.py`) keeps an entry for the TTL (2 s on staging, `AGENTWALL_CONTEXT_CACHE_TTL_SECONDS=2`, capped at 2.5 s (it was 4 s until D1 PR 4, which also cut the lookup timeout from 2 s to 1 s) for the 5-second revocation target). Once an entry is a quarter of the TTL old, a call that uses it also starts one background refresh (`REFRESH_AHEAD_FRACTION`). A refreshed entry is stamped with the time the refresh was **requested**, so nothing older than the TTL is ever served.
- **The gap:** a refresh can only start at the start of a call. If the upstream tool then takes 2 s or more, the entry has expired by the time the agent's next call arrives, and that call waits about 150 ms for core. This time counts as gateway time.
- **Evidence:**
  - Staging, 4 runs on 2026-11-11 with a warm core and always-on CPU: 6 to 17 misses per 200 calls, all four runs over budget (p99 bucket 250 ms). The same with and without a canary.
  - Gateway request logs for runs 1 and 2: about 9% of requests took 1.5 s or more (deepwiki, a public server), close to the 6 to 8% miss rate.
  - A local run of the real cache class with a fake 120 ms core: 18 calls of 2.5 s gave 19 misses (one per slow call plus the first). 21 calls of 1.2 s gave 3. With no slow calls, 1 miss (the first).
- **Earlier wrong theory, stated plainly:** I first blamed cold starts, then CPU throttling. A warm gateway (2026-11-09), then a warm core and always-on gateway CPU (2026-11-11) did not reduce misses. The warm core still helps on its own: a cold core start caused the one denied call on 2026-11-09 (gateway `ReadTimeout` at 13:00:41 UTC).

## 3. Approach
Also start the background refresh **when a call finishes**, not only when it starts.
- New method on `CoreContextClient`, `refresh_if_ageing(agent_id, organization_id, server)`. It is synchronous and does no I/O: if an entry exists and is at least a quarter of the TTL old (the same rule as today), or has expired, it starts the same background refresh that exists today (one per key, bounded by `MAX_BACKGROUND_REFRESHES`). Otherwise it does nothing.
- `service.py` calls it once the upstream call returns, on every path after the passport was found: success, upstream error, upstream exception and the result checks. It runs in a `finally` around the forward, so no path is missed. It never raises.
- **Nothing about freshness changes.** TTL, stamping (time requested) and fail-closed stay the same. If the refresh fails, the old entry still expires on time and the next call looks up for itself and is denied if core is down, as today.
- **What the next call sees:** usually a fresh entry (a hit). If it arrives while that refresh is still running (within about 150 ms of the previous call ending), it waits for it (`context_wait_refresh`, at most the remaining refresh time, capped at 1 s as today), which is shorter than a full lookup.

**Alternatives considered**
1. *A longer TTL.* Breaks the 5-second revocation target, and a 5-second upstream call would still expire it. Rejected.
2. *Serve an expired entry while refreshing.* A frozen or revoked agent could get through after the TTL. Breaks fail-closed and the revocation target. Rejected.
3. *A timer that refreshes every active agent every second.* More moving parts, and core load even for idle agents. Rejected for now.
4. *Core pushes changes to the gateway.* The proper long-term answer (no lookups on the hot path at all), but new infrastructure. Out of scope; noted for Phase 4.5 or later.
5. *Accept it and reword the budget.* A product decision, and real agents call slow tools often. Not recommended.

## 4. Changes
- `agentwall/src/gateway/context.py`: `refresh_if_ageing()` (about 15 lines), reusing `_start_refresh`.
- `agentwall/src/gateway/service.py`: one call in a `finally` after the forward.
- `agentwall/tests/test_context_refresh.py` and a service test (section 7).
- `scripts/latency_baseline.py`: print how many calls took 1.5 s or more end to end, so a run shows slow upstream calls next to the misses. Numbers only, no new data.
- `docs/runbooks/latency-baseline.md` (what misses mean, and that a slow upstream used to cause them), `CHANGELOG.md`, `docs/handoff.md`.
- **Staging settings:** after the fix is measured, turn always-on CPU back off for the gateway (it did not help, and it costs money), in Cloud Run and in `deploy/cloudrun/deploy.sh`. Keep the warm core and warm gateway. This needs your go-ahead at that point.
- **No change** to the TTL, core, the database, the API, or any dependency.

## 5. Security impact
- **Trust boundaries:** none new. The refresh is the same internal call to core that exists today, with the same service token.
- **Revocation target:** unchanged. No entry older than the TTL is served, and a refresh is stamped with the time it was requested. A freeze in core is still seen within the TTL plus one lookup. Tests in section 7 assert this.
- **Fail closed:** unchanged. A refresh failure is never cached and never extends an entry. A call that finds no fresh entry looks up for itself and is denied if core does not answer.
- **Abuse:** an agent cannot use this to make the gateway call core more than once per key at a time (one refresh per key) or beyond `MAX_BACKGROUND_REFRESHES` overall. A denied call before the passport lookup (bad token, malformed message) starts no refresh.
- **Data:** none new. Nothing is logged except the existing stage timings.

## 6. Data and migrations
None.

## 7. Tests
- **Unit (`test_context_refresh.py`):**
  - After a 2.5 s call, the next call is a hit (it fails today).
  - A young entry (under a quarter of the TTL) starts no refresh at the end of a call.
  - No entry (unknown agent) starts nothing.
  - TTL 0 starts nothing.
  - Only one refresh per key, even if many calls end at once. The global bound still holds.
  - A freeze in core is seen within the TTL when refreshes come from call ends.
  - A failed end-of-call refresh never extends the old entry, and the next call is denied if core is down.
  - `invalidate()` discards an end-of-call refresh that was running.
  - A call arriving while the end-of-call refresh runs waits for it, not for a second lookup.
- **Service:** the end-of-call refresh is requested after a successful forward, an upstream error, an upstream exception, and a result redacted for a honeytoken. It is not requested for calls denied before the passport lookup, or for honeytoken, decoy, out-of-scope or guardrail denials (those return before forwarding; the entry is still refreshed by the next call's start).
- **Mutation checks:** remove the `finally`, use the finish time as the stamp, drop the one-per-key check, refresh young entries. Each must be caught.
- **Full suite:** `uv run pytest`, ruff, mypy strict on the two modules.
- **Staging (owner and Antigravity, after deploy):** the same four runs. Pass line: at most 1 miss per run (the first), and p99 at most 50 ms in all four. The script's new count of calls of 1.5 s or more shows whether the upstream was slow during the run.

## 8. Cost and performance
- **Hot path:** adds a dictionary lookup and possibly a task start after the upstream returns, well under 0.1 ms. It removes about 150 ms from each call that follows a slow call.
- **Core load:** at most one extra lookup per slow call per agent. Today an active agent already refreshes about every 0.5 s of activity, so the total stays in the same range.
- **Running cost:** nothing new from the code. Turning always-on CPU back off afterwards lowers the staging bill.

## 9. Risks and open questions
- **Back-to-back calls:** an agent that sends its next call within about 150 ms of the previous one ending still waits up to that long. LLM agents usually think for longer than that between calls; a script may not.
- **Measuring with a fast upstream:** using our own `helpdesk-mcp` instead of deepwiki would separate gateway time from upstream noise. It needs that server registered on staging for the test agent; I have not checked whether it is. Open question for the owner.
- **Size:** small (about 20 lines of code, about 150 lines of tests). One PR, branch `fix/gateway-refresh-after-call`.
