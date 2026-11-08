# Test brief: gateway latency after the lookup changes

- **Date:** 2026-11-08. **Written by:** Claude Code. **Run by:** Antigravity with the owner. Run ONLY after the owner has deployed core, then gateway.
- **Rules (from the owner):** do NOT create sessions as the owner, do NOT read shell history, do NOT deploy anything, do NOT change agents, scopes or limits on your own. If you need an agent key or a token, ask the owner and wait; the owner pastes secrets into the terminal only. List every change you make to staging in the result.

## What changed
Core answers the gateway's passport lookup faster (parallel database reads, fewer writes) and the gateway refreshes a passport in the background before it expires. A freeze or revoke must still take effect within 5 seconds.

## Steps
| # | Do | Expected |
|---|---|---|
| 1 | Follow `docs/runbooks/latency-baseline.md` with a fresh agent key from the owner; 200 calls at the default 0.2 s gap. Warm the gateway first with 5 calls and discard them | p50 <= 5 ms. Report p99 and the number of calls that took over 100 ms. **Target:** p99 <= 50 ms. Say plainly if not met |
| 2 | Repeat with `--interval 3` (calls farther apart than the 2 s cache), 40 calls | Expect each call to wait for a lookup. Report p50 and p99; it should be better than before (about 230 ms), not necessarily under 50 ms |
| 3 | Core timing: with `gcloud logging read` (read-only) get the latency of `/internal/v1/gateway-context` requests during steps 1 and 2 | Report p50 / p90 / max. Before: p50 232 ms, p90 334 ms |
| 4 | Revocation: owner freezes the test agent in the dashboard while you call it every 0.5 s | The first denied call comes within 5 s of the freeze. Report the delay. Owner unfreezes afterwards |
| 5 | Dashboard Passports page: "last seen" for the test agent | Updates (may lag up to a minute: expected) |

## Report back
PASS / FAIL / NOT RUN per step with the numbers. Do not paste keys or tokens.
