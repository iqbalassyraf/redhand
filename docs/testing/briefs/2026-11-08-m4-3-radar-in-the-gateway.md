# Test brief: Radar in the gateway (M4.3, observe only)

- **Date / PR:** 2026-11-08, branch `feat/phase4-m4-3-gateway` (PR number to be added). **Written by:** Claude Code. **Run by:** Antigravity. *owner-assisted* steps need the owner.
- **Run ONLY after** migration `20261117000000_radar_findings`, then core, then gateway are deployed to staging (owner does this). Staging URLs as in `docs/antigravity-briefing.md`. No secrets in results.

## What changed
After a tool answers, the gateway scans the answer in the background and reports findings (rule id only, never the text) to core. It never changes, delays or blocks the call. Modes per organization: `observe` (default) or `off`. Runbook: `docs/runbooks/radar.md`.

## Already verified by Claude Code (local only)
Unit, integration and end-to-end tests with fakes (1298 pass); mutation checks. **Not verified:** anything on staging, real timing.

## Steps
| # | Do | Expected | Type |
|---|---|---|---|
| 1 | With a normal agent key, call a harmless tool (e.g. helpdesk `search_kb`) | Same answer as before; no finding | regression |
| 2 | Call a helpdesk tool that returns a ticket containing an injection (the attack tickets from `injection_indirect.holdout.jsonl`, ids 141 to 160, e.g. via `get_ticket`) | The answer reaches the agent **unchanged**; within about 10 seconds `GET /v1/findings` (operator) shows a finding with a RAD-INJ rule, the tool name and server, **no ticket text** | normal |
| 3 | Repeat step 2 five times quickly | Findings coalesce into one row with a rising `occurrences`; calls are not slower in a way you can see | abuse |
| 4 | Return markup in a result (a ticket containing `<img src=x onerror=...>`) | A RAD-OUT finding appears; the markup is not removed from the answer | normal |
| 5 | Set both checks off (`PUT /v1/radar/settings`, `confirm: true`), wait 5 seconds, repeat step 2 | No new finding | normal |
| 6 | Turn them back to `observe`; repeat step 2 | Findings return | normal |
| 7 | Suppress the rule seen in step 2 for that agent (admin), repeat step 2 | No new finding or count; the suppression shows in the list | normal |
| 8 | As a viewer (or another organization's operator), `GET /v1/findings` and `PUT /v1/radar/settings` | Viewer cannot read findings/settings changes (403); the other organization sees none of these findings | abuse |
| 9 | Freeze the agent, repeat step 2 | The call is denied as before and creates **no** finding | regression |
| 10 | Read the gateway `/metrics` (service token, owner-assisted) | `redhand_gateway_radar_scans_total{outcome="ok"}` rising; `radar_reports_total{outcome="ok"}` rising; `dropped`/`error`/`failed` at 0 | normal |
| 11 | Search the whole findings response and the Black Box for the attack's wording | Not present in findings | abuse |

## Out of scope
Blocking (does not exist), the dashboard pages (M4.4), production, deploying anything yourself.

## Report back
For each step: PASS, FAIL or NOT RUN, with the evidence (status codes, rule ids, counts; no secrets, no attack text). Note any call that was slower or changed.
