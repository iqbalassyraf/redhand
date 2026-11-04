# Phase 2 M3 plan: Budget Guard

**Status:** Approved 2026-11-04 (all ten decisions). M3a and M3b built; independent code review done and its
findings fixed (see the end of this file). Telegram, dashboard and staging verification still to do.
**Phase "done" test served:** Phase 2 done test 3: *an agent over its daily limit is refused and the
owner is alerted.*

## 1. Goal
An operator can give an agent a **daily cap on tool calls**. The gateway refuses calls once the cap is
reached, the owner is alerted at 80% and at 100%, and the agent can optionally be frozen automatically.
It must add no I/O to the gateway's hot path and fail closed.

**What this is and is not.** It counts **tool calls that go through the RedHand gateway**. It does not see
LLM tokens or money: an agent's model spend happens outside the gateway. Dollar budgets would require
routing model traffic through RedHand (a later phase). The dashboard, docs and alerts must say "calls",
never "spend".

## 2. Current state
- The gateway makes its decision in `agentwall/src/gateway/service.py` (`McpGateway.handle`): token →
  passport context (`context.py`, cached at most 2 s) → status → server → method → scope and Safe Mode →
  guardrails → forward. It counts nothing per agent.
- Core already feeds the gateway per-call context through `/internal/v1/gateway-context`
  (`routers/agent_auth.py`); the gateway requires `safe_mode` as a real boolean and denies otherwise
  (the pattern this plan reuses).
- Control actions are atomic database functions with an audit row (ADR 0006); the audit log requires a
  human actor (`actor_user_id NOT NULL`).
- Alerts to linked Telegram chats exist (`telegram/bot.py: notify_organization`).
- Staging runs one instance of each service (`--max-instances 1`, scale to zero).
- The gateway's own audit ledger is in memory; there are Prometheus metrics (`gateway/metrics.py`).

## 3. Approach

### 3.1 What counts as a call
Only a `tools/call` that the gateway **forwards upstream** (an ALLOW decision) consumes budget.
Calls refused for scope, Safe Mode, guardrails, status or budget do **not**: otherwise a looping agent
that is being refused would keep digging itself deeper, and refusals are not what costs money. Upstream
failures still count (the work may have been done). `tools/list`, `initialize` and `ping` never count.

**Known edge (decided, not a bug):** a call is counted once it has passed every policy check and *before*
it is sent, so a call that the destination check then refuses (an MCP server registered at a private
address) also consumes budget although nothing left the gateway. That only happens when a server is
misconfigured, the agent is refused every time anyway, and un-counting would conflict with core's
monotonic cumulative totals. We chose the simpler rule; the repeated refusals are audited once a minute.

### 3.2 Where the counter lives
A small **in-memory meter inside the gateway**, one counter per (agent, day). The check and the increment
are one synchronous function with no `await` between them, so concurrent calls on the event loop cannot
overshoot (a test fires 1,000 concurrent calls at a limit of 100 and expects exactly 100 allowed).

Cost on the hot path: one dictionary lookup, one comparison, one increment. **No I/O.**

### 3.3 How counts reach core (and survive restarts)
Each gateway process has a random `instance_id`. It reports **cumulative totals** (not deltas) per
(agent, day) to core at `POST /internal/v1/usage` every 5 s while something changed, and immediately when
a local threshold (80% or 100%) is crossed.

- **Idempotent by construction:** resending a cumulative total is harmless, so retries need no batch ids.
- **Monotonic:** core stores `GREATEST(old, new)`, so a stale or buggy report can never lower a count.
- **Restart-safe:** a new process gets a new `instance_id`; the old process's last reported total stays in
  the sum. At most the last un-flushed few seconds of calls are lost (an undercount: bounded, documented).

### 3.4 How the gateway learns the limit and the usage so far
Core's gateway-context response gains a required `budget` object:
`{daily_call_limit | null, used_by_other_instances, day_key, resets_at, action}`.
Effective usage = `used_by_other_instances` (from core, cached at most 2 s) + this process's own local
total (always exact). Own calls are never double-counted and never lag. With one instance (staging today)
the count is **exact**. With several instances, usage by the others lags by at most about 7 s (2 s cache +
5 s flush), so the cap can be overshot by at most `(instances - 1) x per-instance call rate x 7 s`.
This is documented, not hidden.

As with `safe_mode`, the field has no default in the gateway's model: an older core that does not send it
makes the lookup fail and the call is denied, so a version mismatch is loud, not silent.

### 3.5 Day boundary
Each organization gets `utc_offset_minutes` (default **480**, Malaysia/Singapore, no daylight saving).
Core computes `day_key` (a local date) and `resets_at` and tells the gateway, so the gateway needs no time
zone logic. This also avoids depending on a time zone database in the container image. Daylight saving is
not supported (stated in the docs); most of ASEAN has none.

### 3.6 Thresholds and actions
- **80%:** one alert per agent per day (Telegram to linked chats; log). 
- **100%:** the call is refused with a clear JSON-RPC policy violation, reason `budget_exceeded`, data
  `{limit, used, resets_at}`; one alert per agent per day.
- **Optional auto-freeze** (`budget_action = 'freeze'`, off by default): on reaching 100%, core freezes the
  agent through the existing atomic freeze path. The audit row's actor is a fixed **system actor**
  (`00000000-0000-0000-0000-000000000000`) with `details.system = "budget_guard"`; the dashboard shows it
  as "RedHand Budget Guard". Unfreezing stays a human action with confirmation, as today.
- Alert "once per day" state is kept in the database, so a restart cannot re-send it.

### 3.7 Who may change limits
- Setting or **lowering** a limit: security operator or higher (it only restricts).
- **Raising or removing** a limit, or turning auto-freeze off: admin or owner plus explicit confirmation
  (same pattern as scope expansion and unfreeze).
- Phone (Telegram): read-only in v1 (`/usage`). No limit changes from chat.

### 3.6b Order of checks in the gateway (unchanged except the new last step)
status -> server -> method -> scope / Safe Mode -> guardrails -> **budget** -> forward.
A call must be otherwise allowed before it can consume budget.

### Alternatives considered
| Alternative | Why not |
|---|---|
| Count in the database on every call | Adds a network round trip and a failure mode to every request; breaks the 10 ms / 50 ms budget. |
| Redis or another shared counter | New dependency, new cost, new failure mode; unnecessary at one instance. Revisit if we scale out (needs an ADR). |
| Count in core from context lookups | Context is fetched once per agent per 2 s, not per call. |
| Delta batches with batch ids | Needs a batch table and exactly-once logic; cumulative totals are simpler and self-healing. |
| Hard-stop only, no alerts | A cap that silently starts refusing is a support incident; alerts are half the value. |
| UTC day boundary | Resets at 08:00 Malaysian time, which surprises SME owners. |
| Dollar budgets | Needs model traffic through RedHand; out of scope and would be a false claim. |

## 4. Changes
| Area | Change |
|---|---|
| **Migration** `20261105000000_budget_guard` | `agents.daily_call_limit` (null = no limit; 1 to 10,000,000), `agents.budget_action` ('deny' or 'freeze'), `organizations.utc_offset_minutes`; tables `agent_usage_daily` (agent, day, instance, calls) and `agent_budget_state` (agent, day, warned_at, limit_reached_at, frozen_at); functions `control_agent_budget`, `record_usage`, `purge_usage`; audit constraint widened again (`passport.budget_changed`). Rollback and SQL tests. |
| **Core** | Context gains `budget`. `POST /internal/v1/usage` (service token). Operator endpoints: `PUT /v1/passports/{id}/budget`, `GET /v1/usage`. Alerting and the auto-freeze path (system actor). Local-store emulation. |
| **Gateway** | New `budget.py` (the meter and flush loop). `service.py` budget step and refusal. Settings for flush interval and capacity. Metrics. |
| **Telegram** | `/usage`: today's calls against limits. Alerts at 80%, 100% and on auto-freeze. |
| **Dashboard** (minimal in M3, full in M4) | Set a limit and action per agent; usage bar; "no limit set" nudge. |
| **Docs** | ADR 0010, threat model rows, runbook (budget false positives; usage not updating), API spec, changelog. |

## 5. Security impact
- **New trust boundary use:** gateway -> core `/internal/v1/usage` uses the existing service token. Core
  derives each agent's organization from the agents table, never from the gateway's claim; inputs are
  validated (ids, integer ranges, at most 1,000 items); counts are monotonic so a faulty reporter cannot
  reduce usage.
- **Fail closed:** missing or malformed `budget` in context -> deny. If the meter cannot track an agent
  (capacity reached) -> deny. Core unreachable -> existing context failure -> deny.
- **Fail-open direction, stated:** a gateway crash loses at most its last few seconds of counts (an
  undercount), and multiple instances lag by up to about 7 s. Both are bounded and documented.
- **Abuse:** a tenant cannot read or change another tenant's usage or limits (tenancy tests). A hostile
  agent cannot lower its own count; denied calls do not consume budget, so it cannot burn a limit down for
  denial-of-service purposes with out-of-scope calls.
- **Privilege:** auto-freeze uses a system actor that no human can impersonate and that cannot log in; it
  can only freeze, never unfreeze or widen anything.
- **Data minimization:** only counts per agent per day are stored. No payloads, no arguments.
- **Telegram:** alerts are plain text; agent names are the only operator-supplied text in them.

## 6. Data and migrations
- Expand-only, backward compatible: new nullable or defaulted columns and new tables. The current core
  ignores them.
- **Deploy order:** migration -> core -> gateway (the gateway requires the new field). Enable limits only
  after both are updated.
- **Rollback script:** drops the functions, tables and columns. Rolling back loses usage history and any
  limits set. The audit constraint is restored `NOT VALID` because audit rows are append-only.
- **Retention:** usage rows 90 days, deleted by `purge_usage()` (to be scheduled with the Telegram purge).
  Budget state rows follow the same retention.

## 7. Tests
**Unit (meter):** exact cutoff; check-and-increment atomic under 1,000 concurrent calls; others + local
arithmetic; day rollover starts a fresh counter; limit lowered below usage refuses at once; limit
raised takes effect within the cache window; capacity cap fails closed; restart starts a new instance id.
**Gateway:** refusal message and audit record; denied calls (scope, Safe Mode, guardrail, status) do not
consume; `tools/list` does not count; unlimited agents are counted but never refused; missing or non-integer
`budget` denies; core down during a flush retries without losing counts; shutdown flush.
**Core:** roles (lower vs raise/remove, confirmation); idempotent resend; monotonic `GREATEST`; thresholds
fire once per day; auto-freeze uses the system actor and is audited; unknown agent in a report is
rejected; cross-tenant isolation; alert failure never breaks the report; "others" excludes the caller.
**SQL:** constraints, tenancy, atomicity (failing audit rolls back the limit change), privileges, purge.
**End to end:** done test 3 over the real core and gateway (limit 5; the sixth call is refused; the 80% and
100% alerts reach a fake Telegram; with `freeze` the agent ends frozen).
**Failure modes:** flush failure, core restart, stale cache at the day boundary, context without `budget`.
**Mutation checks:** remove the cutoff, the atomicity, the monotonic rule, the tenancy filter, the
once-per-day state, the role check and the fail-closed parsing; each must make tests fail.
**Benchmark:** before and after on the warm and cold paths against p50 <= 10 ms and p99 <= 50 ms.
**Two-instance simulation:** measure the real overshoot and compare with the documented bound.

## 8. Cost and performance
- **Latency added:** one dict operation per call (expected well under 0.05 ms); the benchmark will report it.
- **Core load:** one extra summing query per gateway context fetch (once per active agent per 2 s) and one
  batched usage report per 5 s per busy instance. Negligible at SME scale.
- **Storage:** about 100 bytes per agent per day per instance, 90 days: roughly 9 KB per agent.
- **Per-agent running cost:** effectively zero beyond the existing database; no LLM calls, no new service.
- **Cloud Run CPU throttling (real risk):** with request-based billing, CPU is throttled when no request is
  in flight, so a background flush loop may not run. Mitigations: start the flush from inside a request
  (it runs while the call is in flight), flush immediately when a threshold is crossed (the rare call that
  triggers it waits briefly, bounded by a short timeout), and flush on shutdown. We will measure on staging.
  The alternative (CPU always allocated) costs more and is not planned.

## 9. Risks and open questions
**Risks**
- Throttled flush on Cloud Run delays usage reporting (see section 8): mitigated, to be measured.
- Counts are calls, not cost: one call to an expensive tool equals one call to a cheap one.
- Agents with no limit set are not protected: the dashboard nudges, but the default is unlimited.
- Multi-instance overshoot (bounded, documented; staging has one instance).
- No daylight saving support in the day boundary.

**Decisions I need from you** (recommendation first)
1. Count only calls that the gateway **forwards** (not refused ones). *Recommended: yes.*
2. **Daily cap only** in v1; monthly cap and a per-minute burst limit later. *Recommended: yes.*
3. Day boundary from a per-organization **UTC offset, default +8**. *Recommended: yes.*
4. **Auto-freeze** option with the system actor "RedHand Budget Guard". *Recommended: yes, off by default.*
5. **Role rules:** lower = security operator; raise/remove = admin + confirm. *Recommended: yes.*
6. Accept **eventual consistency across instances** (exact at one instance). *Recommended: yes.*
7. New agents default to **no limit**, with a dashboard warning. The alternative is an organization-wide
   default cap. *Recommended: no limit plus warning for v1.*
8. **Retention** of 90 days for usage. *Recommended: yes.*
9. Telegram is **read-only** for budgets in v1 (`/usage` and alerts). *Recommended: yes.*
10. The earlier open question: is a **call-count cap** what target customers want? Worth asking two or
    three before shipping.

## 10. Milestones inside M3 (each shippable)
- **M3a:** migration, core endpoints, context `budget`, alerts, auto-freeze path, tests.
- **M3b:** gateway meter and enforcement, flush loop, metrics, benchmark, independent review of the
  gateway diff before merging.
- **M3c:** Telegram `/usage`, minimal dashboard (limit editor and usage bar).
- **M3d:** staging verification of done test 3 and docs. Dashboard polish continues in M4.


## 11. Independent code review (M3a and M3b), 2026-11-04
Ten findings; nine fixed, one documented. Each fix has a regression test that fails without it.

| Finding | Outcome |
|---|---|
| Changing a limit did not reset the once-per-day alert and auto-freeze state, so the new limit never alerted | Fixed: a changed limit resets today's and yesterday's state (SQL and local emulation) |
| Backoff exponent overflowed a float after about 1,000 failures and disabled the backoff | Fixed: exponent capped |
| Raising a limit was authorised against a pre-read, then written as an absolute value (check-then-act) | Fixed: the SQL function is compare-and-set; a conflict retries once, then answers 409 |
| Calls refused by the destination check still counted | Documented as a known edge (section 3.1) |
| Two concurrent reports could both miss a threshold crossing | Fixed: agent rows are locked, in agent order, before totals are summed |
| Alerts were handled one after another, each with its own 3 s wait | Fixed: handled concurrently with a 10 s bound |
| Every refusal over the limit wrote an audit record | Fixed: one record per agent per minute; metrics still count every refusal |
| `flush_now` swallowed errors with no log (CLAUDE.md 6.2) | Fixed: logged by class |
| Redundant in-flight state and an unused `action` field | Fixed: removed `_tasks` and `BudgetState.action` (`_flushing` kept as the guard for direct `flush()` calls) |
| The overshoot test asserted a looser bound than documented | Fixed: asserts the documented bound for 1, 2 and 3 instances (measured 0, 0 and 8 against 0, 7 and 14) |

## 12. Organization default limit (added after the staging test)
**Decision (the project owner asked for the right-sized feature set for customers):** keep the daily call cap
as built and add exactly one thing, an **organization default daily limit applied to new agents**.

- **Why:** the realistic failure for a small team is forgetting to set a limit on a new agent, and an agent
  with no limit is never stopped. One admin-set default closes that gap without per-agent work.
- **Why not more:** a monthly cap and a per-minute limit add rules and edge cases for little extra protection,
  because the daily cap already stops a runaway loop within the day. They stay out of v1.
- **Behaviour:** `organizations.default_daily_call_limit` (null by default, so nothing changes until an admin
  sets it). Registering an agent applies it as an audited budget change (actor: the person who registered the
  agent; reason "Organization default daily limit"). Existing agents are never changed by it, and a later change
  of the default does not alter agents already registered. Applying it is best effort: if it fails the agent is
  still registered with no limit, a warning is logged, and the dashboard's "no limit set" nudge shows.
- **Who:** an admin sets it; lowering needs no confirmation; raising or removing it needs an explicit
  confirmation. The change is compare-and-set, audited and idempotent like the other budget actions.
- **Where:** migration `20261106000200_budget_default.sql`, `GET` and `PUT /v1/organization/budget-default`,
  and a "Default daily limit for new agents" panel in the dashboard.

## 13. Staging verification of Budget Guard (2026-11-04)
Run by the project owner on staging (Cloud Run core and gateway at the merged commit `d8e309d`, Supabase,
Telegram) with a real agent against DeepWiki. Local times are UTC+8. The database checks were made by reading
the staging database afterwards.

| Check | Result |
|---|---|
| Deploys (core, then gateway) and the smoke test | Passed, 13 of 13 |
| Limit 5: calls 1 to 5 work, the 6th is refused | Passed. Refused with "daily limit of 5 tool calls reached; it resets at 2026-11-04T16:00:00+00:00" |
| Alerts at 80% and at 100%, once each | Passed. "has used 4 of its 5 daily tool calls (80%)" and "reached its daily limit of 5", in the right minutes |
| Raising the limit to 8 (confirmed) lets the agent work again | Passed. Resumed about 4 s after the change |
| Reaching the new limit alerts again (alert state re-armed by the limit change) | Passed. Second 100% alert at the new limit |
| Auto-freeze at the limit | Passed. A `passport.frozen` row by the system actor at 23:26:00, reason "Budget Guard: daily limit reached", 3 s after the refusal; the agent shows as frozen; the alert says it was also frozen |
| Count accuracy with one instance | Passed. The database holds exactly 8 calls for the one gateway instance |
| Once-per-day alert state | Passed. warned, limit reached and frozen are all recorded |
| Does the usage report reach core when Cloud Run throttles CPU? | Yes: both alerts arrived on the calls that triggered them. Not measured to the second |

**Not verified:** `/usage` on the phone and the dashboard's usage bar were not reviewed by the maintainer in
this run; several gateway instances (staging runs one); the daily reset at midnight on staging.

Scheduled cleanup was also added and applied to staging (migration `20261106000100_schedule_purges.sql`): the
two purge functions run daily at 19:17 UTC through pg_cron.
