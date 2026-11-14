# Plan: Phase 4.5 B1, the Risk Engine (per-agent risk score and response ladder)

**Status:** Approved by the owner on 2026-11-14 ("do as you recommend"), together with the additions below. Built on branch
`feat/phase45-b1-risk-engine`. ADR: `docs/adr/0019-risk-engine.md`. Runbook: `docs/runbooks/risk-engine.md`.

## Additions approved with the plan
1. One Telegram message per event: the alerts one report raises leave as one message per organization and agent (`AlertBatch`).
2. Evidence in the Risk panel: the agent's latest findings and refused calls, next to the score.
3. The ladder preview names up to 10 agents per rung.
4. A metric for the level mix. Built as the counter `risk_evaluations_by_level_total{level}`, not a gauge: a per-process gauge would be
   overwritten by whichever organization was read last.
5. A staging test part (Part H) in the night brief, with a guard test.
6. The runbook states what the score is not.

## 1. Goal
One explainable risk score per agent, built only from signals RedHand already records, plus an owner-defined response ladder (record, alert, Safe Mode, freeze) where the automatic actions are opt-in. Serves Phase 4.5 Part 1 (B1, approved 2026-11-06 as B-D1, with B-D4: auto-freeze off by default, opt-in per organization). Staging tests are postponed by the owner; this is built and tested locally, on a branch from `test/night-1` (owner decision 2026-11-14).

**New done tests (proposed, 12 to 14):**
12. An agent with a honeytoken trip shows a high score with the trip named as the reason; an agent with only false-alarm findings shows a low score.
13. With alerting on, crossing the alert threshold sends one Telegram alert (cooldown 1 hour per agent); with Safe Mode or freeze off (the default), nothing else happens.
14. With auto-freeze opted in, crossing its threshold freezes the agent within one report (system actor, audited, reason names the signals); after an admin unfreezes it, only **new** signals can freeze it again.

## 2. Current state (explored on `test/night-1`)
- **Signals exist, aggregates do not.** `honeytrips` (trips incl. canary via `honeytokens.kind`), `security_findings` (rule, kind, confidence, `review_status` open/confirmed/false_alarm, `radar_suppressions`), `agent_events` (BLOCK decisions with reasons), `agent_budget_state` (`limit_reached_at`), `agents.safe_mode`/`status`, `control_audit_log`. Only `radar_summary` aggregates, and only per organization. Tool pins belong to a server, not an agent.
- **Automatic actions already exist** with a system actor (`SYSTEM_ACTOR_ID`, `passports/budget.py:19`): Budget Guard auto-freeze (`routers/usage.py:104-126`) and honeytoken auto-freeze (`honeytokens/service.py:164-173`), both through the normal `service.freeze`. This contradicts CLAUDE.md §4.9 ("authenticated human actor"), which is out of date.
- **Control actions to reuse:** `freeze`/`unfreeze`/`set_agent_safe_mode` in `passports/service.py` (idempotent, audited by `control_agent_change` / `control_agent_safe_mode`). There is **no per-agent throttle** (the loop throttle is organization-wide), so the ladder has no throttle rung in v1.
- **Alerts:** `notify_organization` (`telegram/bot.py:240`), with cooldowns stored per agent in SQL columns.
- **No scheduler in core** (only `pg_cron` purges). Reports arrive from the gateway at internal endpoints: findings, trips and usage.
- **Patterns to copy:** M7's `destinations/` (models, service, router, `_rpc`, `_require_confirmation`, role deps), the twin in `services/local_rpc.py` (`_radar_summary` for a read aggregate), `DestinationsPanel.tsx` with pure helpers in `src/lib/*.ts`.
- **Small existing bug that becomes visible:** the dashboard labels every system-actor audit row "RedHand Budget Guard" (`passports/page.tsx:31,898`), even honeytoken freezes.

## 3. Approach
**Scoring is a pure, versioned function in core** (`risk/scoring.py`). Its input is per-agent signal counts; its output is the score (0 to 100), a level, and the contributing signals with points. No I/O; constants, not a model.

| Signal (last 7 days; the last 24 hours count in full, days 2 to 7 count half) | Points each | Cap |
|---|---|---|
| Honeytoken, canary or honey-tool trip | 40 | 80 |
| Radar or destination finding marked **confirmed** | 25 | 50 |
| Destination finding (`RAD-DST`), open | 10 | 30 |
| Radar injection or output finding, open, medium or high confidence | 4 | 16 |
| Loop finding (`RAD-LOOP`), open | 3 | 9 |
| Out-of-scope or tool-not-approved refusals (Black Box BLOCK) | 2 | 20 |
| Budget limit reached (today) | 10 | 10 |

The following count zero: findings marked false alarm, findings under an active suppression, low-confidence findings, and signals older than the agent's last human release (see below).

Levels: 0 to 19 low, 20 to 49 elevated, 50 to 79 high, 80 to 100 critical. The weights are deliberately low for open Radar findings, because their measured false-alarm rate on documentation is still high (M4.7b: 15.8% on unseen text). Honeytoken trips dominate because they have almost no false alarms.

**Signals come from one read-only SQL function**, `agent_risk_signals(p_org, p_agent uuid default null, p_now timestamptz)`. It counts per agent, scoped to the organization, and is callable only by the service role. Two indexes are added if the plan check shows a scan (`honeytrips (agent_id, occurred_at)`, `agent_events (agent_id, decision, occurred_at)` partial on BLOCK).

**Evaluation is event-driven, never on the gateway path.** After core records a gateway report (findings, trips or usage), it re-scores only the agents in that report and applies the ladder. The response goes back to the gateway first. A failure while scoring is logged and counted in a metric, and never fails the report. The enforcement it triggers (freeze, Safe Mode) goes through the existing functions, so the gateway sees it on the next call within the 5-second revocation SLO.

**The ladder** is stored per organization:

| Rung | Default | What happens |
|---|---|---|
| record | always on | score, level and reasons shown on the dashboard |
| alert | on, threshold 50 | one Telegram alert per agent per hour, naming the signals, with no payloads |
| Safe Mode | **off** (opt-in), threshold 70 | `set_agent_safe_mode(on)`, system actor, reason "risk score N: ..." |
| freeze | **off** (opt-in), threshold 90 | `freeze`, system actor, the same reason format |

Automatic actions only tighten, are idempotent, and use the existing audited functions.

**Release rule (no freeze loop):** when a human unfreezes the agent or turns Safe Mode off, core stores `agents.risk_released_at`. Only signals after that moment count towards automatic actions; the score on the page still shows all of them, with the released part marked. Changing the ladder needs admin; turning on Safe Mode or freeze also needs confirmation.

**Alternative considered: a periodic job that scores every agent.** Rejected because core has no scheduler, it would add `pg_cron` logic or Cloud Scheduler infrastructure (an owner decision), and it would act late. Event-driven scoring acts on the report that caused the change. A daily recompute can be added later if decay without new events matters.

## 4. Changes
- **Migration** `supabase/migrations/20261122000000_risk_engine.sql` plus a rollback:
  - columns `organizations.risk_alert_threshold` (default 50, null means off), `risk_safe_mode_threshold` (null), `risk_freeze_threshold` (null), checked 1 to 100 and in order
  - columns `agents.risk_last_alert_at`, `agents.risk_released_at`
  - `agent_risk_signals()`, `control_risk_ladder()` (admin change, audited `organization.risk_ladder_changed`) and `risk_mark_alerted()`
  - the audit CHECK list widened (keeping every M6/M7 action), and the release stamp written inside the existing unfreeze and Safe-Mode-off paths
  - grants: service role only. SQL tests in a rolled-back transaction.
- **Core:** new `redhand_core/risk/` (`scoring.py` pure; `models.py`; `service.py`: load signals, score, apply ladder) and `routers/risk.py`. Endpoints:
  - `GET /v1/risk/agents` (security operator: score, level and top reasons per agent)
  - `GET /v1/risk/agents/{id}` (full explanation)
  - `GET/PUT /v1/risk/ladder` (read for operators, change for admins, confirmation to enable Safe Mode or freeze)
  - hooks after the findings, trips and usage reports
  - twin functions in `local_rpc.py`/`local_store.py`; OpenAPI regenerated (sorted keys, as for M6/M7); Prometheus counters `risk_evaluations_total{outcome}` and `risk_actions_total{action}`
- **Dashboard:**
  - a Risk badge on each Passports row and a `RiskPanel.tsx` (score, level, each signal with its points, the released part, a link to the findings and Black Box)
  - a "Risk response" card for the ladder, beside the organization controls on Passports
  - pure helpers in `src/lib/riskForm.ts` with node tests
  - the system-actor label fixed to "RedHand (automatic)", with the reason shown
- **Docs:** ADR 0019 (Risk Engine, automatic system actions), runbook `docs/runbooks/risk-engine.md`, threat-model rows, changelog, handoff.
- **Owner approval needed separately:** a proposed edit to CLAUDE.md §4.9, to say that automatic control actions by the system actor are allowed only when opt-in, audited, tighten-only and reversible by a human.

## 5. Security impact
- **New trust boundary:** none. All inputs are data RedHand already stores, and the scoring takes no external input beyond counts.
- **Abuse:** an attacker who controls an agent could try to get a **different** agent frozen; this is not possible, because signals are counted per agent. An agent could also trigger its own freeze, which is the intended outcome.
- **Risk of harm:** an over-eager ladder freezes legitimate agents. This is why Safe Mode and freeze are off by default and need admin with confirmation, the Radar weights are low, false alarms and suppressions count zero, and the release rule prevents loops.
- **Fail closed:** this does not apply to the score itself (it is advisory). A scoring failure never blocks a report and never loosens anything. Enforcement stays where it is (the gateway reads status and Safe Mode, and fails closed as today).
- **Tenancy:** every query is organization-scoped from the verified operator or the internal report's organization. There are wrong-organization tests for every endpoint.
- **Data:** counts and rule ids only. No payloads, and nothing sent to an LLM.

## 6. Data and migrations
The migration is additive (new columns with safe defaults, new functions), so it is backward-compatible with the deployed code. The rollback drops them and restores the M7 audit list and functions. It is tested by `scripts/test_migrations.sh` (apply, tests, rollback, re-apply). No data backfill.

## 7. Tests
- **`scoring.py` (pure):** a table of signal mixes to expected score, level and reasons; caps; decay boundary at 24 hours; zero for false alarm, suppressed, low-confidence and pre-release signals; property test that the score is monotonic in each signal.
- **SQL:** counts per agent are right, never another organization's, suppression and review honoured, ladder change audited and validated.
- **Core:**
  - role matrix (viewer refused, operator reads, admin changes)
  - wrong organization
  - confirmations
  - the ladder fires each rung once (idempotent)
  - a scoring failure leaves the report accepted
  - the release rule
  - the system-actor audit rows carry the reason
- **Failure modes:** DB error while scoring gives the report 2xx, a metric, and no action; a stale score never unfreezes.
- **End to end:** through the real core and the gateway harness, a honeytoken trip makes the score critical and, with freeze opted in, the gateway denies the next call.
- **UI:** helpers tested with node, `tsc`, `next build`, and a browser run by role at 1280 and 375 px.
- **Gates:** mutation checks (weights, caps, release rule, the default-off thresholds, organization scoping), then the full suite, ruff 0.17.3 and mypy 2.4.1 as CI, and the SQL script.

## 8. Cost and performance
- **Gateway hot path:** zero added time, because nothing changes in the gateway.
- **Core:** one indexed aggregate per agent per report, measured locally before and after (target under 10 ms per report, recorded). No new service, no LLM, no external call.
- **Running cost per agent:** a few small queries per report batch, which is negligible.

## 9. Risks and open questions (my recommendation in brackets)
1. **Weights and thresholds** are judgement, not measurement. [Ship as above. The dashboard shows them, and they are constants in one file, versioned (`RISK_MODEL = "2026-11-14"`).]
2. **Alert on by default at 50?** [Yes: it only notifies. Safe Mode and freeze stay off.]
3. **Who can unfreeze a risk-frozen agent?** Today a security operator can unfreeze anything. [Keep today's roles; changing them is a separate decision.]
4. **No throttle rung**, because there is no per-agent throttle. [Leave it out and say so in the runbook.]
5. **CLAUDE.md §4.9** is already out of date with Budget Guard and honeytokens. [Propose the wording; edit only with approval.]
6. **Size:** large. [One PR in slices: SQL, scoring, core, UI, docs. Branch `feat/phase45-b1-risk-engine` from `test/night-1`; the PR targets `main` and merges after #57 to #66.]

## Verification
- **Local only:** the tests above, plus a script that seeds a local organization with trips, findings and blocks, prints each agent's score and reasons, then flips the ladder and shows the actions and audit rows.
- **Not verified until the owner resumes staging:** Supabase, Cloud Run and Telegram.
