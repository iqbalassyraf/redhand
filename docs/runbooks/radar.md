# Runbook: Prompt Injection Radar and output checks (observe only)

What it does: after a tool answers, the gateway scans the answer in the background for injection text aimed at the agent and for
risky output (script, odd links, internal addresses, file paths). It records a finding for the owner. It never blocks or edits a
call. It only sees what passes through the gateway.

## Turn it on or off
In the dashboard open **Radar** (an admin changes the two switches; turning one off needs the tick). The same through the API: `PUT /v1/radar/settings` with
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

## The Radar page
**Radar** in the header. *Checks*: the two switches and a 7-day summary. *Findings*: newest first, filter by review or kind, **Real** / **False alarm** (optional note), **Silence this rule for this agent** (reason of 3 to 300 characters, 1 to 90 days, tick the box; admin only). *Active silences*: **Remove** (admin). A security operator reviews but cannot change switches or silences; a viewer is told the role cannot see the page. A finding never shows the scanned text; "No findings" means the Radar recognised nothing, not that nothing is wrong. If the page stays empty while you expect findings, check the two switches first, then `docs/runbooks/radar.md` "Problems".

## The self-test
**Radar** page, **Run self-test** (security operator or above, once a minute per organization). The gateway runs its Radar over about 180 of our own held-out texts (hidden instructions, script, internal addresses, file paths) and the page shows how many it found with a 95% range. What it proves: the Radar code deployed in the gateway behaves as measured. What it does not prove: that your agents' traffic goes through the gateway, or anything about attacks the samples do not contain. The texts were written by the team that wrote the rules, so the numbers flatter the Radar: the independent figure for hidden instructions is about 4 in 10 (Coverage page).
| Symptom | Likely cause and fix |
|---|---|
| "A self-test ran a moment ago" | Wait about a minute. |
| "The gateway could not run the self-test. Nothing was measured." | The gateway is down, restarting, or cannot be reached from core. Check `GATEWAY_URL` on core and the gateway's health (`gateway-denies-all-traffic.md`). No result is ever shown for a failed run. |
| Same message with the gateway healthy | Core and gateway disagree on the internal service token (core logs "Gateway refused core's service token for the self-test"), or the gateway image is older than core (deploy the gateway). |
| A switch shows off in the result | The code works but the gateway is not scanning for you. Turn the check back on. |
