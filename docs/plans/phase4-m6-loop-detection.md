# Plan: Phase 4 M6, loop detection

**Status:** DRAFT, awaiting the owner's approval (2026-11-13). Part of `docs/plans/phase4-finish-plan.md` (milestone M6, done test 9). Decision F-D4 (20 identical calls in 60 seconds, observe first) is already approved. Built in the batch described in `docs/plans/phase4-batch-build.md`; M7 is stacked on this branch.

## 1. Goal
An agent stuck in a loop (the same tool called with the same arguments again and again) is noticed and recorded, and an organization that chooses **throttle** has the repeats refused before they use budget or reach the tool. Serves Phase 4 done test 9.

## 2. Current state (checked 2026-11-13)
- **Hot path order** (`agentwall/src/gateway/service.py`, step 4): honeytokens, scope, tool pin, guardrails, Budget Guard, forward. A loop check fits between guardrails and Budget Guard, so a refused repeat never consumes the daily limit (finish plan: "throttled calls are refused before they use budget").
- **A pattern to copy:** `gateway/budget.py` is a synchronous, no-I/O, bounded per-agent counter with an injected clock. The loop meter has the same shape.
- **Findings pipeline exists:** the gateway reports findings to core through `FindingsReporter` (`gateway/radar_scan.py`, with a per-key throttle of 30 s, retry and bounded backlog); core coalesces them per agent, rule, tool and 5-minute window (`record_security_findings`, `supabase/migrations/20261117000000_radar_findings.sql`), caps 2,000 new rows per agent per day, applies per-agent **suppressions** (audited, at most 90 days) and sends one Telegram alert per agent per 10 minutes.
- **The findings table cannot hold a loop today:** `rule_id` must match `RAD-(INJ|OUT)-nnn`, `kind` is `injection` or `output`, `place` is `text`, `hidden` or `decoded`. Suppressions have the same rule check.
- **Modes are per organization** (`organizations.radar_mode`, `output_check_mode`), sent to the gateway in the context payload as required fields (an older core makes the lookup fail, so the call is denied: deploy core first).
- **Ledger throttle:** `McpGateway._record_budget_refusal` already limits the gateway's in-memory ledger to one record per agent per minute for repeated refusals, while every refusal still reaches the Black Box.

## 3. Approach

### 3.1 The meter (gateway, no I/O)
New `agentwall/src/gateway/loops.py`, `LoopMeter`, synchronous like `BudgetMeter`:
- **Key:** `(agent_id, digest)` where `digest = blake2b(process_salt, tool_name, 0x00, canonical_json(arguments))` truncated to 16 bytes. The salt is `os.urandom(16)` per process, so a digest is meaningless outside the process, is never sent or stored, and the arguments themselves are never kept. Canonical JSON is `sort_keys`, compact separators; an argument tree that cannot be serialized counts as `untracked`. Anything over 64 KiB serialized is hashed on its first 64 KiB plus its length (a stated limit: a loop whose only change is past 64 KiB of one call is still seen as a loop, which is the safe direction).
- **State per key: three numbers**, not a list of timestamps: `window_start`, `current`, `previous` (a two-bucket sliding-window counter). Estimate = `previous * (1 - elapsed/T) + current + 1`; a call is a **repeat flag** when `floor(estimate) >= L`. Memory per key is fixed, so a flood of distinct calls cannot grow it beyond the caps below. Inside one bucket the count is exact (calls 1 to L-1 pass, call L flags); across a bucket edge it is an estimate, and the runbook says so.
- **Caps:** 16 distinct keys per agent (the least recently used is dropped), 100,000 keys in all (the least recently used agent's oldest key is dropped, counted in a metric). One agent cannot push out another agent's counts except at the global cap. Worst case memory is about 20 MB.
- **Throttle semantics:** in throttle mode a flagged call is refused and is **not counted**, so the agent recovers as the window moves on. Steady state: about L-1 identical calls per window T get through. It is a rate limit on identical calls, not a lock-out. In observe mode every call is counted and passes.
- **Clock:** `time.monotonic`, injected for tests.

### 3.2 Gateway wiring
- Mode, limit, window and an exemption flag arrive in the context payload (below). Mode `off` skips the whole check (no hashing).
- Observe: a flag is recorded (metric, finding), the call continues. Any error inside the meter is counted (`loop_error`) and never changes the decision.
- Throttle: a flag refuses with JSON-RPC `-32000`, reason `loop_throttled`, message "PolicyViolation: this exact call was repeated N times in T seconds and is paused for now" (counts only, no echo of arguments); recorded in the Black Box as BLOCK with reason `loop`. **Any unexpected error in throttle mode denies** (`loop_check_error`), as the finish plan requires.
- Finding report: `RadarScanner` gets a small `report_finding()` that reuses the existing reporter, retry, backlog bound and 30 s per-key throttle. Item: rule `RAD-LOOP-001`, family `loop`, kind `loop`, severity `medium`, confidence `high`, place `call`, `would_block` false. Only counts and names are sent: no arguments, no digest.
- Metrics: `loops_total{outcome=ok|flagged|throttled|untracked|error|evicted}` and stage timer `loop_check`. No agent or tool in labels.
- Ledger flooding: `_record_budget_refusal` is generalized (its behavior for budget refusals unchanged, its tests untouched) so loop refusals also reach the in-memory ledger at most once a minute per agent, and always reach the Black Box.
- **Not counted:** calls refused earlier (out of scope, unapproved tool, guardrail, honeytoken). Only calls that would be forwarded are counted.

### 3.3 Core
- **Migration** `supabase/migrations/20261120000000_loop_detection.sql` (+ rollback):
  - `organizations.loop_mode` (`off`, `observe`, `throttle`; default `observe`), `loop_limit` (3 to 1000, default 20), `loop_window_seconds` (10 to 600, default 60), `loop_mode_changed_at`.
  - Widen `security_findings` and `radar_suppressions`: rule `RAD-(INJ|OUT|LOOP)-nnn`, kind adds `loop`, place adds `call`.
  - `agents.loop_last_alert_at`: loops get their **own** 10-minute alert cooldown, so a loop alert cannot hide an injection alert (the existing `radar_last_alert_at` is shared by all Radar findings).
  - Replace `record_security_findings` so the per-kind mode check includes `loop` (mode `off` stores nothing).
  - New `control_loop_settings()` (compare and set, idempotent, audited as `organization.loop_settings_changed`), and the audit action list widened (the list is replaced in full each time, which is why M7 is stacked on this branch).
- **API (new, additive):** `GET /v1/radar/loop-settings` (security operator or higher), `PUT /v1/radar/loop-settings` (admin; moving to `throttle` also needs `confirm: true`; the body carries the mode the caller saw, so two admins cannot overwrite each other). `GET /v1/findings` accepts kind `loop`. The OpenAPI file is regenerated.
- **Context endpoint:** new required fields `loop_mode`, `loop_limit`, `loop_window_seconds`, `loop_exempt`. `loop_exempt` is true when the agent has a **live suppression of `RAD-LOOP-001`**. That reuses the existing suppression screen, audit and 90-day limit as the way to exempt a legitimate polling agent, and the gateway then neither flags nor throttles it. One extra small indexed query per cache miss on core (measured, section 8). It exempts the whole agent, not one tool (a stated coarseness).
- **Readiness and Radar summary stay per kind:** loop findings must never enter the false-alarm and detection arithmetic of the injection and output checks (tested).
- **Alert text** (`redhand_core/radar/service.py`): "agent X sent the same call to tool Y N times in T seconds" and, in throttle mode, "extra repeats were refused". Counts and names only.
- **In-memory twin** (`services/local_rpc.py`, `local_store.py`) updated; the real SQL is covered by the SQL tests, because the twin can drift.

### 3.4 Dashboard
On `/radar`: a "Repeated calls" card with mode (Off, Observe, Throttle), limit, window, a confirmation box for Throttle, and plain wording of the limits. Loop findings appear in the existing findings table with a loop label; the existing "silence this rule for this agent" button is worded "this also exempts the agent from throttling". The Coverage page gets no new claim (no measured detection rate exists).

### Alternatives considered
1. *Count in Postgres.* Hot-path latency and a new dependency of every call on the database. Rejected.
2. *Store the last N timestamps per key.* Exact, but memory grows with the limit (limit 1000 x keys x agents). The three-number counter is bounded and the estimate error only exists across a bucket edge. Rejected.
3. *A new findings table.* Duplicates review, suppression, retention and alerts. Rejected.
4. *Per-tool exemption.* Needs a column on suppressions and a UI; deferred (listed in section 9).
5. *Hard block after N.* An agent that is blocked forever cannot recover without a human. Throttle as a rate limit is the safer first behavior.

## 4. Changes
- New: `agentwall/src/gateway/loops.py`, `supabase/migrations/20261120000000_loop_detection.sql`, `supabase/rollbacks/20261120000000_loop_detection.down.sql`, `supabase/tests/loop_detection_test.sql`, `docs/adr/0017-loop-detection.md`, `docs/runbooks/loop-detection.md`.
- Modified: `gateway/service.py`, `gateway/context.py`, `gateway/radar_scan.py` (`report_finding`), `gateway/metrics.py`, gateway app wiring and settings (one switch to turn the meter off), core `routers/agent_auth.py`, `routers/radar.py`, `radar/models.py`, `radar/service.py`, `services/local_rpc.py`, `services/local_store.py`, `apps/redhand-ui/src/app/radar/page.tsx` and `src/lib/api.ts`, `scripts/latency_baseline.py` (prints the `loop_check` stage), `docs/security/threat-model.md`, `docs/api/redhand-core.openapi.json`, `CHANGELOG.md`, `docs/handoff.md`.
- **No change** to authentication, scopes, Budget Guard arithmetic, tool pinning or the Radar rules.

## 5. Security impact
- **A new way of refusing calls** (throttle). It is opt-in per organization and starts in observe. Errors: observe never changes a decision; throttle denies.
- **Who can change it:** admin, with confirmation for throttle, audited. A hijacked agent has no access to core and cannot change its own limits.
- **Evasion:** an agent that changes its arguments each time is not caught (stated in the UI and runbook). Several gateway instances each keep their own count, so the effective limit is up to the limit times the number of instances (the same approximation as Budget Guard).
- **Abuse:** a third party can only make an agent throttle by making that agent repeat calls, which is the behavior being limited. The throttle message echoes counts only. Distinct-call floods are bounded by the caps, and a test sends 1 MiB arguments and 100,000 distinct calls inside a time limit.
- **Data:** no arguments, no digest and no salt leave the process; findings hold counts and names only. Tenant isolation: the key is the agent id, which the verified token binds to its organization; a test shows two agents with identical calls are counted apart, and a finding for one organization is never visible to another.
- **Denial of service by under-counting:** at the global cap the oldest key is dropped, so a loop may be missed under extreme pressure. This is a detection control, not authorization, so it fails open in observe and throttle alike (unlike the budget meter); it is counted in `loops_total{outcome="evicted"}` and stated in the runbook.
- **Threat model:** rows for "agent stuck in a loop" and "throttle used to disrupt an agent".

## 6. Data and migrations
Additive. Expand then migrate: core first, then gateway (the gateway requires the new fields). Rollback deletes loop findings and suppressions, restores the old checks and functions, drops the new columns; tested apply, rollback and re-apply by `scripts/test_migrations.sh`. An older gateway ignores the new fields and keeps working.

## 7. Tests (all written first, failing)
- **Meter (fake clock):** L-1 identical calls pass and call L flags; different arguments or a different tool or a different agent count apart; key order in arguments does not matter; the window expires; a bucket edge estimate stays within one call of the exact count; in throttle a refused call does not count and the agent recovers; 100,000 distinct calls stay within the caps; 1 MiB arguments finish inside a time limit; unserializable arguments are `untracked`.
- **Gateway:** mode off does no hashing (a spy); observe never refuses even when the meter raises; throttle refuses at L, and **also refuses when the meter raises** (fail closed); a refused repeat does not consume Budget Guard; a suppressed (exempt) agent is never flagged; a refusal reaches the Black Box every time but the ledger once a minute; earlier refusals (scope, pin, guardrail) are not counted.
- **Core and SQL:** mode and limit checks (out of range refused), compare and set conflict, idempotent no-op, audit row, viewer and security operator get 403 on PUT, confirmation required for throttle, loop finding coalesces and respects the 2,000 cap, suppression of `RAD-LOOP-001` works and exempts, wrong-organization agent is refused, readiness and radar summary numbers for injection and output do not change when loop findings exist.
- **Context compatibility:** a context payload without the new fields makes the lookup fail and the call is denied.
- **UI tests:** the card, the confirmation, the wording; no untrusted text rendered unsafely.
- **Mutation checks:** off by one at L, counting refused calls, dropping the per-agent cap, dropping the salt, throttle error treated as allow, loop findings entering readiness. Each must be caught.
- **Full suite, ruff 0.17.3, mypy 2.4.1 strict on the new module, `tsc`, `next build`.**

## 8. Cost and performance
- **Hot path:** mode off adds nothing; otherwise one canonical JSON dump, one 16-byte hash and two dictionary operations. Expected well under 0.1 ms for typical arguments; **measured, not assumed**, with the `loop_check` stage in the local benchmark and in the staging four-run method, against the 10 ms p50 and 50 ms p99 budgets. No figure is claimed until then.
- **Core:** one extra indexed read per context cache miss (once per agent per 2 s at most); measured.
- **Running cost:** no LLM, no service, no dependency. A few rows a day per looping agent (coalesced).

## 9. Risks and open questions
1. **Legitimate polling tools look like loops** (a status check every 2 seconds is 30 per minute). Observe-first is the answer; the night test counts false flags on the staging helpdesk agents. The exemption is per agent, not per tool.
2. **Default observe on every existing organization** when the gateway is deployed (F-D4). Each organization may get its first loop finding and one alert. Approve as is, or default new and existing organizations to `off`? Recommendation: observe, as decided.
3. **Throttle as a rate limit** (about L-1 repeats per window pass) rather than a lock-out. Confirm.
4. **Per-tool exemption** is deferred.
5. Approximate with several instances, as Budget Guard is.

## 10. Decisions requested
| | Question | Recommended |
|---|---|---|
| M6-D1 | Throttle behaves as a rate limit on identical calls (not a lock-out) | Yes |
| M6-D2 | Exempt an agent through a live suppression of `RAD-LOOP-001` | Yes |
| M6-D3 | New endpoints `GET/PUT /v1/radar/loop-settings` | Yes |
| M6-D4 | Own alert cooldown column for loops | Yes |
| M6-D5 | Default mode `observe` (20 calls, 60 s) for all organizations | Yes (F-D4) |
