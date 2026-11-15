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
| Readiness panel says "figures not available" | Core could not read the counts (database error) or answered an unexpected shape | Refresh; check core logs for "readiness inputs"; the rest of the page is unaffected |
| Readiness shows 0 results scanned though findings exist | The gateway is not sending counts: older gateway, wrong service token, or core refusing | Check `redhand_gateway_radar_count_reports_total{outcome}` (ok should rise about once a minute); `refused` means token or version mismatch, `failed` means core unreachable |
| Readiness condition "Counts are complete" fails | Some results were lost (queue full, scan errors), an agent produced 1,000+ findings in a day, or findings are stored that the gateway never counted | Read the detail line; if it names rules, counts were lost on the way: check count report metrics for the days in the window |
| Readiness "Same rules the whole time" fails | The rules changed, the helper model was on, or the gateway cannot tell its rules | Expected after a gateway deploy that changed the Radar; evidence starts again on the new rules |

## Honest limits
**Update 2026-11-13 (M4.7b):** documentation headings, links, diagram labels and a few path forms no longer raise strong findings. Measured on real documents: 29% to 5% on the documents the change was tuned on, but still 15.8% (9 of 57) on documents it was not tuned on, against a goal of under 5%. Because the rules changed, the block gate says every round needs a new one. Details: `docs/security/m4-7b-results.md`.

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

## Could blocking ever be switched on? (the readiness panel, M4.6)
Blocking does not exist: SQL, core and the gateway all refuse it, and nothing on this page can change that. The panel on the **Radar** page shows, per check, the two things that would both have to look
good before anyone could even consider it: **our independent tests** (summarised from the Coverage page, which has the full gate) and **your own traffic** over the last 7 UTC days: results scanned,
strong findings, the false alarm figure counted the hard way (one false alarm marks every strong flag of that rule, and the figure never exceeds the results that had a strong finding), and seven conditions (R1 to R7, ADR 0016). "Candidate" never means "safe to block".
- To move a check toward "candidate": keep it on Watch without changing it, let traffic build up (at least 200 results), review every strong finding as Real or False alarm, and do not silence rules.
  Silencing a rule to reduce noise also resets the evidence on purpose: a silence hides findings.
- The panel's numbers come from the gateway's counts, which are taken before the 30-second repeat limit, so they are higher than the number of stored findings. That is correct.
- Real-life proof of the counting on staging: `scripts/radar_real_life_proof.py` and `docs/testing/briefs/2026-11-09-m4-6-block-gate-and-real-life-proof.md`. The proof agent must have a daily call limit above the number of calls: Budget Guard refuses calls past the limit (in the 2026-11-09 run, 20 of 120), and the script now prints the gateway's reason for each call without a result, and a hint when the cause is the daily limit. Local check on real long documents:
  `scripts/radar_real_documents.py`, recorded in `docs/security/real-document-replay.md`.
- Deploy order for M4.6b: **migration `20261118000000_radar_scan_counts`, then core, then gateway.** An older gateway sends no counts (the panel shows 0 scanned); a gateway newer than core gets
  404 on the counts route and its reports are "refused" (calls are never affected).
