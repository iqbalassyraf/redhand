# Plan: Phase 4.5 B2, behaviour baseline (watch-only, with a built-in noise back-test)

**Status:** Approved by the owner on 2026-11-14. Built on branch `feat/phase45-b2-behaviour-baseline` (stacked on B1, PR #67).
ADR: `docs/adr/0020-behaviour-baseline.md`. Runbook: the "Behaviour baseline" section of `docs/runbooks/risk-engine.md`.

**Differences found while building (also in ADR 0020):**
- The trigger is a ROW trigger: `record_events()` inserts one event per statement, so a statement trigger would fire per event anyway.
- The read covers 21 days, not 14, so every replayed hour of the back-test sees a full 14-day window.

## Context
B1 (the Risk Engine, PR #67) scores agents from signals RedHand already raises. B2, approved in Phase 4.5 Part 1 (B-D1), adds what no rule can see: **an agent behaving unlike itself**:
- a sudden surge of calls;
- a tool it has never used before.

The approved plan says B2 "needs a warm-up; its false alarm rate is measured before it is offered as more than a warning".

The owner can test only at night with Antigravity, so this is built and verified locally now, with a night-test part ready.

**What staging holds** (read-only query, 2026-11-14): 4,952 call events, 11 agents, 27 agent-tool pairs, 9 days. The traffic is bursty test traffic (the busiest single agent-hour had 681 calls, from the speed runs). That is enough to build and demonstrate the baseline, **not** to judge its false-alarm rate on real customer traffic.

So B2 v1 is **watch-only**: it is shown on the Risk panel with no points, no alerts and no actions. It carries its own back-test ("over the last 7 days this would have flagged N hours") so noise can be judged on real data before anyone gives it weight.

**Proposed done test 15:** an agent with at least 7 days of history that suddenly makes 5 times its usual hourly calls (and at least 30), or calls a tool it never used in 14 days, shows a "Behaviour" warning in its Risk panel, with the numbers. A new agent shows "Warming up". Nothing is alerted, scored or frozen.

## Current state (checked)
- **Every call is in the Black Box**, allowed or refused (`agentwall/src/gateway/recorder.py`, `service.py` around lines 154 and 682).
- **Default retention is 30 days.** A full recorder buffer drops the newest events and writes a `recorder.gap` event, so the baseline can very rarely undercount.
- **`agent_events`** (`20261110000000_blackbox.sql`) has `organization_id`, `agent_id`, `occurred_at`, `method`, `tool_name` and `decision`, with an index on (organization, agent, time). Rows are inserted only by `record_events()`, which is a hash-chained, sensitive function I will **not** modify.
- **Reading 14 days of raw events per page view does not scale.** A small hourly roll-up does.
- **Patterns to reuse:**
  - B1's `risk/` package: pure module, service, router, twin, Risk panel.
  - The `purge_*` and pg_cron notice pattern (`20261111000000_blackbox_retention.sql`).
  - The SQL test pattern (rolled-back transaction).

## Approach
1. **Roll-up table** `agent_tool_hourly`: organization, agent, hour, tool, calls and refused, with primary key (agent, hour, tool). RLS on, no policies, service role only, cascading on agent and organization delete.
   - It is maintained by a **statement-level AFTER INSERT trigger** on `agent_events` that uses the inserted rows (transition table). Per batch it does one grouped upsert of `tools/call` rows.
   - `record_events()` is untouched. The trigger runs in the same transaction, so a roll-up failure rolls the batch back and the gateway retries it (the recorder already handles that).
   - The tool name is capped at 128 characters (as in `agent_events`).
   - The migration backfills the last 30 days from `agent_events` once.
   - Retention: `purge_behaviour()` deletes hours older than 35 days, scheduled through pg_cron when it is present (otherwise a notice, as for the other purges).
2. **One read function**, `agent_behaviour_hours(p_org, p_agent, p_now)`: the hourly rows of one agent for the last 14 days. It is organization-scoped and service-role only, and returns counts and tool names only.
3. **Pure rules in core**, `risk/behaviour.py` (versioned `BEHAVIOUR_MODEL`, constants, no I/O):
   - **Warm-up:** the agent's first call is at least 7 days before now. Until then: "Warming up (N of 7 days)".
   - **Spike:** calls in the last hour ≥ max(30, 5 × the average hourly calls of the 7 days before it, empty hours counted as zero).
   - **New tool:** a tool whose first call in the 14-day window is within the last 24 hours, only when warm. At most 10 listed.
   - **Back-test:** replay both rules for each of the last 168 hours using only the data before that hour. The result is "would have flagged N of the last 168 hours (spikes S, new tools T)". This is the noise measure the approved plan asks for, computed on each organization's own traffic.
4. **API:**
   - `GET /v1/risk/agents/{id}` gains a `behaviour` block. Missing means not available (an older database). If the roll-up read fails, the block says "unavailable"; the score is still shown.
   - New `GET /v1/risk/behaviour/summary` (security operator): per organization, how many agents are warm, flagged now, and the back-test totals. This is what we will read on staging to judge noise.
5. **Dashboard:** a "Behaviour (watch only, not part of the score)" section in the Risk panel. It shows warm-up state, the last hour against the usual hour, new tools (as text, length-capped) and the back-test line. Helpers in `src/lib/behaviour.ts` with node tests.
6. **Docs:** ADR 0020 (roll-up by trigger, watch-only first), a runbook section in `risk-engine.md`, a threat-model row, changelog, handoff, and Part I in the night brief and master checklist (guarded text).

**Alternative considered:** computing on read from raw `agent_events`. It is rejected because it scans 14 days of events per view, and the cost grows with traffic. A periodic roll-up job was also rejected: core has no scheduler.

**Next decision, after measurement, not in this PR:** give B2 points in the Risk score (a B2b change, one line in `WEIGHTS` plus tests), once the back-test on real traffic shows it is quiet enough.

## Changes
- `supabase/migrations/20261123000000_behaviour_baseline.sql`, its rollback, and `supabase/tests/behaviour_baseline_test.sql`.
- `services/redhand-core/src/redhand_core/risk/behaviour.py` (pure), plus additions to `risk/models.py`, `risk/service.py` and `routers/risk.py`, the twin (`local_rpc.py` and `local_store.py`, including the trigger's effect when events are recorded), and the OpenAPI regeneration.
- Tests: `tests/test_risk_behaviour.py` (rules, back-test, warm-up, seeded property tests) and additions to `test_risk_engine.py` (API, roles, tenancy, failure).
- `apps/redhand-ui/src/app/passports/RiskPanel.tsx`, `src/lib/behaviour.ts`, `tests/behaviour.test.mjs`.
- Docs as listed above.

## Security impact
- **Trust boundaries:** no new boundary.
- **Data:** counts per hour and tool names, which already sit in the Black Box. No payloads, and nothing leaves RedHand.
- **Display:** tool names come from MCP servers and agents, so they are rendered as text and capped.
- **Tenancy:** organization-scoped everywhere, with wrong-organization tests in SQL, the API and the twin.
- **Failure:** the roll-up trigger shares the ingest transaction. If it fails, that Black Box batch is retried; it is never silently lost, and enforcement is unaffected because the gateway never waits on core for recording.
- **Abuse:**
  - An agent cannot change another agent's baseline.
  - An agent can try to "train" its own baseline slowly (warm-up abuse). That is stated as a limit: a baseline only catches sudden change.
- **Watch-only:** no new automatic action.

## Data and migrations
- Additive: a new table, a trigger, functions, and a backfill bounded to 30 days.
- Rollback drops the trigger, the functions and the table (stated data loss: the roll-up only; the Black Box is untouched).
- Tested by `scripts/test_migrations.sh` (apply, tests, rollback, re-apply).

## Tests
- **Rules:**
  - spike boundary at exactly 5× and the 30 floor;
  - zero-filled hours;
  - warm-up at 7 days exactly;
  - a new tool at 24 hours exactly;
  - a tool unused for 15 days counts as new (outside the window);
  - the back-test uses only past data (no look-ahead: a test seeds a future spike and checks it is not counted);
  - property tests (seeded random, as in B1).
- **SQL:**
  - the trigger aggregates a multi-row batch correctly and counts refused calls;
  - only `tools/call` rows are counted;
  - another organization never sees the rows;
  - the backfill;
  - the purge;
  - grants.
  - Each with breakage checks.
- **Core:**
  - roles (viewer 403);
  - wrong organization 404;
  - the behaviour block present and absent;
  - a read failure gives "unavailable" while the score is still shown;
  - the summary endpoint.
- **UI:** helpers tested with node, `tsc`, `next build`, and a browser run by role at 1280 and 375 px with seeded history.
- **Gates:** full suite, ruff 0.17.3, mypy 2.4.1, the SQL script.

## Cost and performance
- **Gateway:** zero (unchanged).
- **Ingest:** one grouped upsert per Black Box batch, measured locally before and after on 50,000 events. Target: under 2 ms added per batch.
- **Read:** at most 336 hours × tools for one agent (target under 10 ms). The organization summary will be measured with 200 agents.
- **Storage:** about 24 rows per agent-tool per day, kept for 35 days. That is small.

## Night test (Part I, for later)
- (a) A new agent's Risk panel shows "Warming up".
- (b) If the owner has the key of a staging agent with 7 or more days of history (for example `agent-phase-3`), a burst of 40 varied calls shows a spike warning, and calling a scoped tool it never used shows "new tool". Otherwise NOT RUN, with the reason.
- (c) I read the organization summary on staging myself (read-only) and record the back-test noise. The staging traffic is test traffic, so it is labelled as such.

## Risks and open questions (my recommendation in brackets)
1. Staging traffic is not real traffic, so the noise figure is indicative only. [Ship watch-only. Decide on weights after real usage.]
2. The thresholds (5×, 30, 7 days, 14 days, 24 hours) are judgement. [They are constants, versioned and shown on the page.]
3. If the trigger fails, a Black Box batch is retried. [Accept. The trigger is simple, tested and measured.]
4. Branch: `feat/phase45-b2-behaviour-baseline` from `feat/phase45-b1-risk-engine` (it extends B1). The PR is stacked on #67.

## Verification
- **Local:** all the tests above, mutation checks, the local Postgres timing, and the browser run.
- **On staging, at night:** the Part I steps, plus my read-only summary query.
