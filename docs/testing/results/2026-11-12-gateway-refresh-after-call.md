# Result: gateway cache refresh after a call, staging speed runs (2026-11-12)

- **Plan:** `docs/plans/phase4-context-refresh-after-call.md`. **Run by:** the owner with Antigravity; checked by Claude Code against the four latency files in `/tmp`, the staging database and the Cloud Run settings.
- **Under test:** gateway revision `redhand-gateway-00025-dx8` (image digest `sha256:f3b04241...`, built from the fix branch working tree), then `00026-4dx` (same image, minimum 1 instance). CPU throttling on. Core `00029-6ds`, minimum 1.
- **Agent:** `latency-test-3`, daily limit 1,000 (the staging default), upstream `deepwiki` (a public server with variable speed).

## Results (200 calls each, 0.2 s pause)

| Run | Canary | Failed | p50 / p99 (upper bounds) | `context_miss` | `context_hit` | Calls of 1.5 s or more | `honeytoken_scan` mean |
|---|---|---|---|---|---|---|---|
| 1 | no | 0 | 1 ms / 2 ms | **0** | 200 | 10 | 0.010 ms |
| 2 | no | 0 | 1 ms / 2 ms | **0** | 200 | 6 | 0.020 ms |
| 3 | yes | 0 | 1 ms / 5 ms | **0** | 200 | 2 | 0.026 ms |
| 4 | yes | 1 (call 167, upstream 502) | 1 ms / **250 ms** | 1 | 198 | 1 | 0.024 ms |

Before the fix (2026-11-11, same setup but no fix): 17, 13, 16 and 6 misses, all four runs over budget.

## What this shows
- **Misses are fixed in practice.** Runs 1 to 3 had no miss at all even though 18 of their 600 calls took 1.5 s or more. Before the fix every such call was followed by a miss. The pass line (at most 1 miss per run) is met in all four runs.
- **The canary is not a speed problem.** `honeytoken_scan` is 0.010 to 0.020 ms without a canary and 0.024 to 0.026 ms with one, about 10 microseconds more.
- **Run 4 is over the p99 line, for two separate reasons, neither new:**
  1. One call waited about 1 second in the `budget_flush_now` stage. This is by design (`agentwall/src/gateway/budget.py`, `URGENT_WAIT_SECONDS`): the call that crosses 80% of an agent's daily limit waits up to 1 s to report to core so the alert is accurate. The four runs total about 800 calls on a 1,000-call limit, so run 4 crossed it. The same 1 s stage appeared in the 2026-11-09 run 4. A real agent meets it once per day at 80% and once at 100%.
  2. One cache miss (177 ms). Which call it followed is not known; one call of 1.5 s or more happened in this run (probably the 502). It is within the pass line of one miss.
  Those two calls out of 199 are 1%, which puts the p99 bucket at 250 ms.
- **The failed call was an upstream 502** (reported by the run; not checked in the gateway logs).
- **Core load:** background refreshes went from about 185 to 192 per run (before) to 200 to 215 (after), about 10% more. This matches the plan (at most one extra lookup per slow call).

## Not measured
- Revocation latency after this change (the unit tests assert the 5-second target; not re-measured on staging).
- A fast upstream: all runs used deepwiki.
- A run that avoids the 80% budget crossing (a higher daily limit or a fresh agent per pair of runs), which would show the p99 without that by-design wait.

## Staging state after the runs (checked)
- `latency-test-3` revoked; the canary retired (0 trips); no active honeytokens or test agents left.
- Gateway `redhand-gateway-00027-7sc` and core `redhand-core-00030-qtf`: minimum 0, CPU throttling on for the gateway, same fix image.
