# ADR 0020: Behaviour baseline (watch-only, hourly roll-up by trigger, built-in back-test)

**Status:** Proposed (2026-11-14), awaiting the owner's review with the pull request. Phase 4.5 B2, decision B-D1. Plan:
`docs/plans/phase45-b2-behaviour-baseline.md`. Builds on ADR 0019 (Risk Engine), whose Risk panel shows it.

## Context
The rules RedHand runs (scopes, pinning, Radar, loops, destinations, honeytokens) catch known patterns. They do not see an agent that
suddenly behaves unlike itself: a burst of calls, or a tool it has never touched. The approved Phase 4.5 plan asks for a per-agent baseline,
and says its false-alarm rate must be measured before it is offered as more than a warning.

## Decision
- **Rules** in core, pure and versioned (`risk/behaviour.py`, `BEHAVIOUR_MODEL`):
  - judged only after 7 days of history;
  - a spike is at least 5 times the usual hour (the 7 days before it, empty hours counted as zero) and at least 30 calls;
  - a new tool is one with no call in the 14 days before it appeared in the last 24 hours.
- **Watch-only:** shown on the Risk panel with no points, no alert and no action.
- **Back-test, always shown with the verdict:** both rules are replayed for each of the last 168 hours, each using only earlier data. This
  is the noise measure on the organization's own traffic. `GET /v1/risk/behaviour/summary` sums it per organization.
- **Data:** an hourly roll-up, `agent_tool_hourly` (agent, UTC hour, tool, calls, refused).
  - It is kept current by a row trigger on `agent_events`, in the same transaction as `record_events()`, which is not changed.
  - It is backfilled once with 30 days, purged after 35 days, organization-scoped, and service-role only.
- **Reading:** the read covers 21 days (14 for the window plus 7, so the oldest replayed hour still sees a full window).

## Alternatives considered
- **Compute from raw `agent_events` on every view.** It scans weeks of events per page and grows with traffic. Rejected.
- **A periodic roll-up job.** Core has no scheduler, and it would lag. Rejected.
- **Roll up in core after each batch** (one grouped upsert per batch). Cheaper on ingest, but the upsert sits outside `record_events()`' transaction,
  so a retried batch must be de-duplicated by batch id. Kept as the fallback if the trigger's ingest cost matters (see below).
- **Statistical models** (z-scores per tool, seasonality). More to explain and tune, and still judgement. The simple rule is enough to
  measure first.

## Consequences
- **Ingest cost:** about 0.05 ms per tool-call event added to Black Box ingest (measured locally: 5,000 inserts, about 270 ms without the trigger and
  about 525 ms with it). That is up to about 25 ms on a full 500-event batch. **This misses the plan's target of 2 ms per batch** for batches larger than
  about 40 events. Ingest is off the call path (the recorder flushes in the background), so I accepted it, and the alternative above is ready
  if it matters.
- **Failure:** if the trigger ever failed, the whole Black Box batch would roll back and the gateway would retry it (nothing is silently
  lost, and enforcement never waits on recording).
- **Read cost:** 1.4 ms for one agent's 21 days, 3.4 ms for a 200-agent organization (local PostgreSQL, 50,000 events).
- **Limits (stated on the page):**
  - a baseline only catches sudden change, so an agent that changes slowly teaches the baseline as it goes;
  - an agent is not judged in its first 7 days;
  - a full recorder buffer can drop events, so the roll-up can very rarely undercount.
- **Staging back-test (2026-11-14, read-only, test traffic):** 11 agents, 3 warm, 0 flagged hours in 1,152 replayed hours. This says only
  that quiet warm agents are not flagged: staging's bursts all fell inside the agents' warm-up. Real traffic is needed to judge noise.
- **Next decision (B2b, not here):** give behaviour points in the Risk score once the back-test on real traffic is quiet enough.

## Differences from the approved plan
- A row trigger instead of a statement trigger (`record_events()` inserts one event per statement).
- A 21-day read instead of 14 (back-test correctness).
- The ingest target was missed, as measured above.
