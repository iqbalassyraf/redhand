# Measurements

Numbers produced by scripts in this repository, with the commit and machine they came from. They are **local measurements** (loopback, in-memory store), not staging or production figures, and they are not compliance evidence.

## Revocation and failure drill (`scripts/revocation_drill.py`, run 2026-11-17)
Raw output: [`2026-11-17-revocation-drill.md`](2026-11-17-revocation-drill.md). Re-run with `uv run python scripts/revocation_drill.py --out docs/security/measurements/<date>-revocation-drill.md`; a 2-trial version runs on every build (`tests/e2e/test_revocation_drill.py`).

How to read it:
- **The promise** (CLAUDE.md 4.5): a freeze or revoke takes effect within 5 s. Measured here: **about 0.4 s** for an agent calling continuously (20 trials each, max 0.46 s) and **at the first call** for an agent calling once a second. No call was allowed after the first refusal in any trial.
- **It is not literally "the next call".** The gateway reuses a passport lookup and refreshes it in the background once it is about 0.4 s old (`REFRESH_AHEAD_FRACTION` of the 2 s cache lifetime in `agentwall/src/gateway/context.py`). A freeze is therefore visible to a busy agent after at most about 0.4 s plus the refresh round trip, during which it can still make calls. The hard bound while core answers is the 2 s cache lifetime. The wording in CLAUDE.md and the briefing ("next gateway call") should say "within about half a second, never more than 5 s".
- **When core stops answering** the gateway refuses (HTTP 503), never allows, and recovers by itself when core is back. **Core killed: first refusal after 1.8 s. Core hanging (paused): 4.3 s** (the 2 s cache lifetime plus the 2 s timeout of the lookup). That is inside the 5 s promise with only about 0.7 s to spare, on a machine with no network latency. **Follow-up worth doing:** lower the lookup timeout (or cap total time at the cache lifetime plus 1 s) so the margin does not depend on the network.
- **Upstream (MCP server) killed:** every answer was 502 within 10 ms, the gateway stayed healthy.
- **Not measured:** several gateway instances (the bound is per instance), real network and Cloud Run, expired agent tokens (core's shortest lifetime is 60 s; the verifier has unit tests).

After the gateway lookup timeout change (D1 PR 4): [`2026-11-17-revocation-drill-after-lookup-timeout.md`](2026-11-17-revocation-drill-after-lookup-timeout.md).
