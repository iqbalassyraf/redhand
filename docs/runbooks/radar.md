# Runbook: Prompt Injection Radar and output checks (observe only)

What it does: after a tool answers, the gateway scans the answer in the background for injection text aimed at the agent and for
risky output (script, odd links, internal addresses, file paths). It records a finding for the owner. It never blocks or edits a
call. It only sees what passes through the gateway.

## Turn it on or off
Dashboard settings are not built yet (M4.4). Until then an admin uses the API: `PUT /v1/radar/settings` with
`{"radar_mode": "observe"|"off", "output_check_mode": "observe"|"off", "confirm": true}` (`confirm` is required for off). Takes effect
on the next call after the gateway's context cache expires (2 to 4 seconds). New organizations start on `observe`.

## Look at what it found
`GET /v1/findings` (security operator or above). A finding has a rule id (RAD-INJ-xxx, RAD-OUT-xxx), the tool and server, and never
the text. Mark one `confirmed` or `false_alarm` with `POST /v1/findings/{id}/review`. A noisy rule on one agent can be silenced for
1 to 90 days with `POST /v1/radar/suppressions` (admin, needs confirmation, audited).

## Problems
| Symptom | Likely cause | What to do |
|---|---|---|
| No findings at all, though you expect some | Both checks are off, the answer was not scanned (denied call, not a `tools/call`), or findings are suppressed | Check `GET /v1/radar/settings`; check `redhand_gateway_radar_scans_total{outcome="ok"}` is rising |
| `radar_scans_total{outcome="dropped"}` rising | The scan queue (16) is full: results arrive faster than they are scanned | Expected under heavy bursts; findings are lost, calls are fine. If constant, consider the model off and tell engineering |
| `radar_scans_total{outcome="error"}` rising | The scanner failed on some result | Calls are fine. Report it with the time; do not paste the result |
| `radar_reports_total{outcome="failed"}` rising | Core is unreachable or erroring | Calls are fine. Fix core (see `gateway-denies-all-traffic.md` if calls also fail) |
| `radar_reports_total{outcome="refused"}` rising | Core rejected the reports (bad token or invalid fields) | Check the gateway and core service token match; check versions |
| Every call is denied after a deploy | Gateway deployed before core, so the context lacks the new fields | Deploy core first (it is backward compatible), then the gateway |
| Too many false alarms on one tool | Documentation-like text trips a rule | Review them as `false_alarm`; suppress that rule for that agent with a reason |

## Honest limits
Measured on unseen samples (blind round 2): injection 41% found with 8% false alarms on hard benign documents; markup about 92%;
addresses about 62%; file paths about 64%. It misses rephrased and long buried attacks. It is a smoke detector, not a wall, and
block mode will not exist until a measured gate is passed.
