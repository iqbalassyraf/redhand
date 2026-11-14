# ADR 0019: Risk Engine (per-agent risk score and an opt-in response ladder)

**Status:** Proposed (2026-11-14), awaiting the owner's review with the pull request. Phase 4.5 B1, decisions B-D1 (build Part 1) and B-D4
(auto-freeze off by default, opt-in per organization). Plan: `docs/plans/phase45-b1-risk-engine.md`. Builds on ADR 0010 (Budget Guard's
automatic freeze), ADR 0015 (the Radar only observes) and the honeytoken trip path, which already act through a system actor.

## Context
RedHand records many separate signals per agent: honeytoken and canary trips, Radar, loop and destination findings, calls refused for being
outside the passport, and the daily call limit. Each has its own page and alert, but nothing says "this agent, overall, looks wrong". An
owner with twenty agents cannot read five pages to decide which agent to freeze. The briefing's Phase 4.5 Part 1 asks for one explainable
score per agent and a response ladder, deterministic, with no model and no network call.

## Decision
- **The score** is a pure function in core (`risk/scoring.py`, version `RISK_MODEL`): fixed points and caps per signal, last 24 hours in
  full, days 2 to 7 at half weight, 0 to 100, four levels. Honeytoken trips weigh most (almost no false alarms). Open Radar findings weigh
  little, because they are still noisy on documentation (M4.7b: 15.8% of unseen documents had a strong finding). False alarms, silenced
  rules and low-confidence findings count zero.
- **The signals** come from one read-only SQL function (`agent_risk_signals`), organization-scoped and service-role only. It counts rows,
  never payloads.
- **When it runs:** after core records a report that carries a signal (findings, a trip, a usage limit, a Black Box batch with a
  refusal, a finding a person confirms). It never runs on the gateway's call path, and it never fails the report (bounded to 5 s, every
  error counted and logged by type).
- **The ladder**, per organization:
  - alert at 50, on by default;
  - Safe Mode and freeze, off by default; an admin turns them on with a confirmation.
  - Automatic actions only tighten, take the strongest rung reached, go through the existing audited control functions with the system
    actor, and are reported in Telegram.
- **The release rule:** when a person unfreezes an agent or turns its Safe Mode off, a trigger stamps `agents.risk_released_at`. Only
  later signals count towards automatic actions, so a person's decision is not overturned by the evidence they already looked at.
- **One notification per event:** the alerts one report raises leave as one Telegram message per organization and agent.

## Alternatives considered
- **A periodic job that scores every agent.** Core has no scheduler: this would need `pg_cron` logic or Cloud Scheduler infrastructure, and
  it would act minutes late. Event-driven scoring acts on the report that caused the change. Decay without new events affects only the
  number shown, which is computed at read time.
- **An LLM that reads the signals and decides.** It is refused here: the hot path stays at zero LLM calls, the cost is unmeasured, and
  flagged content is attacker-controlled. LLM triage is Phase 4.5 piece C, gated separately.
- **Auto Safe Mode on any strong Radar finding.** It was rejected in M4.6 (`docs/plans/phase4-m4-6-block-gate.md`) because of the
  false-alarm rate. The score keeps open findings at 4 points each, capped at 16, so the Radar alone can never reach a rung.

## Consequences
- **Automatic control actions by the system actor become a documented, general mechanism.** CLAUDE.md §4.9 ("require an authenticated
  human actor") was already out of date with Budget Guard and honeytokens. A wording change is proposed to the owner and not made here:
  automatic control actions are allowed only when opt-in, audited, tighten-only and reversible by a person.
- **A wrong weight can freeze a good agent** if the organization opted in. Mitigations:
  - freeze and Safe Mode are off by default;
  - turning either on needs an admin and a confirmation;
  - the card names the agents each rung would act on now;
  - the release rule prevents a loop;
  - every action is audited and announced.
- **The score is judgement, not measurement.** The weights are versioned, shown on the page, and stated as such.
- **The refusal signal depends on the gateway's fixed reason wording.** A test fails if the gateway rewords it.
- **No gateway change.** The gateway keeps reading status and Safe Mode as before, so enforcement and its fail-closed behaviour are
  untouched, and a freeze reaches the gateway within the revocation SLO.

## Measured cost (local PostgreSQL 16)
Measured with 200 agents, 20,000 findings and 50,000 Black Box events in one organization:
- **One agent (the path run after each report):** 5 to 7 ms.
- **The whole organization (the dashboard list):** 112 to 140 ms.

Gateway hot path: unchanged (zero). **Not measured on Supabase or Cloud Run.**

## Differences from the approved plan
- **The release stamp** is a trigger on `agents`, not code inside the unfreeze and Safe-Mode-off functions. It is just as atomic, and it
  does not rewrite proven SQL.
- **Two more evaluation points:** Black Box refusals and a finding confirmed by a person, both of which change the score.
- **The level metric** is a counter (`risk_evaluations_by_level_total`), not a gauge, which would be overwritten across tenants.
- **"Capped"** means the signal already adds its maximum (two trips reach the 80-point cap exactly), not "would have exceeded it".
