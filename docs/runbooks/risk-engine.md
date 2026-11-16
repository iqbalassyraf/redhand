# Runbook: the Risk Engine (per-agent risk score and response ladder)

**Product truth (shown in the dashboard):** the risk score adds up what RedHand has already recorded about an agent that connects through
RedHand. It is not a measured probability, it does not see agents outside the gateway, and its weights are judgement (versioned, shown on
the page).

## What it does
- **Every agent gets a score from 0 to 100** and a level: low (0 to 19), elevated (20 to 49), high (50 to 79) or critical (80 to 100). The
  score counts the last 7 days; the last 24 hours count in full, older days count half.

  | Signal | Points each | At most |
  |---|---|---|
  | Honeytoken, canary or honey-tool trip | 40 | 80 |
  | Finding marked real (confirmed) | 25 | 50 |
  | Address outside the allowed list (open) | 10 | 30 |
  | Radar finding, medium or high confidence (open) | 4 | 16 |
  | Repeated identical calls (open) | 3 | 9 |
  | Call refused, outside the passport (scope or unapproved tool) | 2 | 20 |
  | Daily call limit reached (last 24 hours) | 10 | 10 |

  These count zero: findings marked false alarm, silenced rules (for open findings), low-confidence findings.
- **The ladder** (Passports page, "Risk response" card):
  - **Alert:** at 50, on by default. One Telegram message per agent per hour, joined with the report's own alert when there is one.
  - **Safe Mode:** off by default. Only read-declared tools work.
  - **Freeze:** off by default. Every call is refused.

  Only an admin changes the ladder. Turning Safe Mode or freeze on, or lowering its number, needs the confirmation tick. The ladder acts on
  the next signal, not on what is already recorded.
- **When a person unfreezes an agent or turns its Safe Mode off,** only signals after that moment can make RedHand act on it again. The
  page still shows the full score and marks what came after the release.

## Turn on automatic actions safely
1. Leave the default (alert only) for a week and read the scores on Passports.
2. Open the Risk panel of each high or critical agent and check the evidence: are the findings real, are the refusals real mistakes?
3. Mark false alarms on the Radar page: they then count zero.
4. Only then set Safe Mode (for example at 70) and freeze (for example at 90). The card names the agents each step would act on right now;
   if a name surprises you, do not save.

## If something is wrong
| Symptom | Likely cause | What to do |
|---|---|---|
| A good agent was frozen or put in Safe Mode | Its score crossed an opted-in rung | Unfreeze or turn Safe Mode off (it stamps a release); mark the findings that were false alarms; raise or turn off that rung |
| The same agent is acted on again right after you released it | New signals arrived after the release | Look at the evidence in the Risk panel: the new signals are real records |
| No scores on Passports | The role is a viewer (scores need a security operator), or core predates the Risk Engine (the API answers 404) | Expected |
| "Risk scores could not be read" | The database did not answer | It is never shown as zero; retry. Check `risk_evaluations_total{outcome="error"}` |
| Reports work but nothing is ever alerted | Every rung is off, or Telegram is not linked | Check the card; link Telegram on Passports |
| Refused calls stopped counting after a gateway update | The gateway reworded its refusal reason | `test_the_gateway_still_uses_the_refusal_wording_the_sql_matches` fails first; align `agent_risk_signals()` |

## Reading the numbers
- `risk_evaluations_total{outcome}`: `ok`, `error` or `timeout` per evaluation after a report.
- `risk_actions_total{action}`: `alert`, `safe_mode` or `freeze`, as actually carried out.
- `risk_evaluations_by_level_total{level}`: the level each evaluation found. A shift towards high or critical across tenants is worth a look.
- Audit rows:
  - `organization.risk_ladder_changed` (old and new values);
  - automatic actions are `passport.frozen` or `passport.safe_mode_enabled`, by "RedHand Risk Engine", with the reason
    "Risk Engine: score N (level): …".

## Limits
- Only agents connected through RedHand, and only what RedHand records.
- The weights are judgement, not measurement (`RISK_MODEL` in `services/redhand-core/src/redhand_core/risk/scoring.py`).
- Scores change on reports; the number shown is recomputed when the page is read.
- There is no per-agent throttle rung: none exists to reuse (the loop throttle is organization-wide).
- A honeytoken can also freeze an agent by itself (its own action); that is separate from the ladder.

## Behaviour baseline (Phase 4.5 B2, watch only)
The Risk panel also shows **Behaviour (watch only, not part of the score)**. It adds no points, sends no alert and does nothing by itself.
- **Warming up:** for the first 7 days of an agent's history nothing is judged.
- **Surge:** this hour's calls are at least 5 times the agent's usual hour (its last 7 days, quiet hours counted) and at least 30.
- **New tool:** a tool it had not used in the 14 days before it first appeared in the last 24 hours.
- **The back-test line** says how often these rules would have flagged this agent over the last 168 hours. Read it before trusting a warning:
  an agent flagged often is noisy, not dangerous. `GET /v1/risk/behaviour/summary` adds these up for the organization.
- **Limits:** a baseline only catches sudden change; an agent that changes slowly teaches it as it goes. A full recorder buffer can very
  rarely drop events.
- **Data:** hourly counts per agent and tool (`agent_tool_hourly`), kept 35 days, built from the Black Box by a database trigger. If
  "Behaviour could not be read" appears, the score is unaffected; check the database.
- **Deploy:** migration `20261123000000_behaviour_baseline.sql` (it backfills 30 days once), then core, then the dashboard. Rollback:
  `supabase/rollbacks/20261123000000_behaviour_baseline.down.sql` (the roll-up only; the Black Box is untouched).

## Deploy and rollback
- **Deploy order:** the migration `20261122000000_risk_engine.sql` first (additive), then core, then the dashboard. The gateway does not
  change.
- **Rollback:** `supabase/rollbacks/20261122000000_risk_engine.down.sql`. The ladder settings and the alert and release stamps are lost;
  audit rows stay.
- **Turn it off without a deploy:** an admin clears every rung on the card. Scores are still shown, and nothing is sent or done.

## Incident view (Phase 4.5 B3)
Passports, **Timeline** on any agent: one ordered story of what RedHand recorded for it (refused and failed calls, activity per hour,
findings, trips, actions on its passport, and freeze all or Safe Mode for all). Security operators and above; viewers see
"Your role cannot see the incident view."
- **Freeze and review** freezes the agent from the page, with the reason "Frozen from the incident view" (editable). Unfreeze it on Passports
  after the review.
- **Export JSON / CSV** downloads the same story (at most 5,000 items) for a report or ticket. Each export is recorded as
  "Timeline exported by a person"; 10 per hour per operator ("Too many exports; try again later." after that).
- **Telegram alerts** about one agent end with a "Timeline:" link when core has `DASHBOARD_URL` (deploy.sh sets it from the first dashboard
  origin). No link: check the variable on the core service.
- **"The timeline could not be read. Try again shortly."** One of its reads failed; nothing partial is shown. Check the database; a retry is safe.
- **Limits:** only what flowed through RedHand; no call contents; items are listed newest first and a page keeps items of the same moment
  together (more than 1,000 of one kind at one exact moment is logged and may split).
- **Deploy:** migration `20261124000000_incident_view.sql` (an index and one audit action), then core, then the dashboard. Rollback:
  `supabase/rollbacks/20261124000000_incident_view.down.sql`.
