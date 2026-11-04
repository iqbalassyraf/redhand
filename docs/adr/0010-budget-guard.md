# ADR 0010: Budget Guard (daily tool-call limits)

- **Status:** Accepted (2026-11-04)
- **Phase:** 2 (M3)
- **Plan:** `docs/plans/phase2-m3-budget-guard.md`

## Context
Phase 2 asks for a way to stop a runaway or hijacked agent from doing unbounded work. RedHand sees tool
calls that go through the gateway. It does not see LLM tokens or money, so a limit on spend would be a claim
we cannot back; a limit on calls is something the gateway can really enforce.

## Decision
- **What is limited:** the number of `tools/call` messages the gateway forwards for an agent per local day.
  `tools/list`, `initialize` and `ping` never count. Calls refused for any reason (scope, Safe Mode,
  guardrails, inactive passport, budget) do not count, so an agent being refused cannot burn its own limit.
  Upstream failures count (the work may have been done), and so do calls that the destination check then
  refuses, because a call is counted once it has passed every policy check and before it is sent.
- **Where it is counted:** an in-memory meter in the gateway. The decision is synchronous, with no I/O, and
  the check and the increment are one step, so concurrent calls cannot overshoot a limit on one instance.
- **How counts are shared:** each gateway process has a random instance id and reports CUMULATIVE totals to
  core (`POST /internal/v1/usage`) every 5 s while there are changes, at once when a call crosses 80% or
  100%, and on shutdown. Core stores `GREATEST(old, new)` per (agent, day, instance), so resends are
  harmless and a stale report cannot lower a count. Core tells the gateway the usage of the OTHER instances
  (in the gateway context, cached at most 2 s); the gateway adds its own exact local count.
- **Day boundary:** per-organization `utc_offset_minutes` (default 480, UTC+8). Core computes the day key
  and reset time; the gateway does no time-zone work.
- **At the limit:** the call is refused (JSON-RPC policy violation, reason `budget_exceeded`, with the limit,
  usage and reset time). The owner is alerted at 80% and at 100%, once per agent per day (state in the
  database). Optionally (`budget_action = 'freeze'`) the agent is also frozen through the existing atomic
  path, recorded under a fixed system actor (`00000000-0000-0000-0000-000000000000`, shown as "RedHand
  Budget Guard"). Changing the limit resets that day's alert state so the new limit alerts again.
- **Who may change limits:** setting or lowering a limit and turning auto-freeze on need a security
  operator. Raising or removing a limit, or turning auto-freeze off, needs an admin and explicit
  confirmation. The change is compare-and-set against the values the decision was made on.
- **Fail closed:** the gateway requires core to send a strictly typed `budget` object, or it denies the call.
  A malformed stored limit reads as 0 (nothing allowed). A limited agent the meter cannot track is refused.
  Core being unreachable already denies via the context lookup.

## What it does not do (stated in the dashboard, docs, alerts and code)
It counts calls, not cost: one call to an expensive tool equals one call to a cheap one. It does not see LLM
tokens or money. Agents with no limit set are counted but never refused, so the dashboard nudges ("no
limit set"). Daylight saving is not supported by the day boundary.

## Alternatives
- Count in the database on every call: a network round trip and a failure mode on every request.
- Redis or another shared counter: a new dependency and cost; unnecessary at one instance (revisit when
  scaling out, with an ADR).
- Delta batches with batch ids: needs a batch table and exactly-once logic; cumulative totals are simpler.
- A UTC day: resets at 08:00 Malaysian time.
- Dollar budgets: would need model traffic through RedHand, and would be a false claim today.

## Consequences
- **Several gateway instances:** other instances' usage lags by up to about 7 s (2 s cache plus 5 s report),
  so the cap can be exceeded by at most `(instances - 1) x per-instance call rate x 7 s`. Measured in a
  simulation: 0, 0 and 8 calls for one, two and three instances against bounds of 0, 7 and 14. Staging runs
  one instance, where the count is exact.
- **Crash or scale to zero** loses at most the last few seconds of this instance's own calls (an undercount).
  A report is also sent on shutdown.
- **Cloud Run throttles CPU between requests.** Reports are started from inside a call, sent at once at
  80% and 100%, and sent on shutdown; the periodic loop is only a safety net. Verified on staging in M3d.
- Deploy order: migration, then core, then gateway. The gateway requires `budget`, and core's context
  lookup needs the new database functions.
- Rolling back the migration drops usage history and every limit.

## Addendum (2026-11-04): organization default limit
Agents with no limit are never stopped, and the likeliest mistake is forgetting to set one on a new agent. An
organization may therefore set `default_daily_call_limit`; every agent registered afterwards starts with it
(an audited budget change, best effort so registration never fails because of it). Existing agents are not
changed and a later change of the default does not alter agents already registered. Only an admin may set it;
raising or removing it needs confirmation. A monthly cap and a per-minute limit were considered and left out:
the daily cap already stops a runaway loop within the day.
