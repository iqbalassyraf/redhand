# Test brief: Phase 4 M4.0 (staging latency baseline and helpdesk attack samples)

- **Date / PR:** 2026-11-07, Phase 4 M4.0 (see `docs/plans/phase4-m4-plan.md`)
- **Written by:** Claude Code. **To be run by:** Antigravity (steps marked *owner-assisted* need the owner).
- **Environment:** staging: gateway `https://<gateway-host>`, core
  `https://<core-host>`, helpdesk project `/Users/testing/Documents/redhand-helpdesk-demo`.
- **Prerequisites:** an ACTIVE agent passport with a key the owner holds, allowed to call one cheap read tool on a
  registered server (for example `deepwiki`). The key and the gateway's internal service token are secrets: the owner puts them in
  environment variables; nobody prints, pastes or writes them down.

## What this is for
M4 adds work to every tool call, so we need a "before" number for gateway latency. Separately, the Radar benchmark needs
held-out attack samples that were written without knowledge of the rules, and the helpdesk tickets qualify.

## Already done by Claude Code
Four new held-out sample files (160 samples) for indirect injection and the three output categories, the regenerated
coverage matrix and baseline. No rules exist yet, so the held-out numbers are the "before": injection 0 of 20, path 0 of 20,
XSS 0 of 20, SSRF 2 of 20, with 0 false alarms in every category.

## Steps
| # | Do | Expected | Type |
|---|---|---|---|
| 1 | *Owner-assisted.* The owner reads the gateway token into a variable without printing it (`INTERNAL_TOKEN=$(gcloud secrets versions access latest --secret redhand-internal-service-token)`) and reads the first metrics snapshot: `curl -s -H "Authorization: Bearer $INTERNAL_TOKEN" <gateway>/metrics`. Save only the `redhand_gateway_overhead_ms_*` lines to the result file. | Histogram lines are present: buckets, `_sum`, count | normal |
| 2 | Send 200 allowed `tools/call` requests through the gateway at a gentle rate (about 5 per second, one agent), using `scripts/staging_agent.py` or the same protocol. Do not exceed the agent's budget. | Calls succeed; no 5xx | normal |
| 3 | Repeat step 1 for a second snapshot. | Counts increased by about 200 | normal |
| 4 | From the difference between the snapshots, compute the p50 and p99 of gateway overhead (the bucket in which the 50th and 99th percentile fall; say it is an upper bound from buckets) and the mean (`sum` difference divided by count difference). | Numbers recorded with the gateway revision name | normal |
| 5 | Compare with the budget (p50 at most 10 ms, p99 at most 50 ms) and say plainly whether it passes. Also say what the numbers do NOT include (upstream time, cold start) and when the first call after idle was slower, if you saw that. | An honest sentence; no claim beyond the data | normal |
| 6 | Convert the helpdesk tickets in `redhand-helpdesk-demo/eval/tickets.jsonl` into one JSON object per line, with these fields only: `id` (`injection_indirect-NNN`, numbered from 141), `category` = `injection_indirect`, `kind` = `tool_result`, `label` (`malicious` for the 8 attack tickets, `benign` for the 12 normal ones), `lang` (`en` or `ms`), `family` = `helpdesk`, `hard` = `false`, `text` = the customer's ticket text exactly as the agent would see it in a `get_ticket` result. Save as `docs/testing/exports/helpdesk-injection-heldout.jsonl` in the RedHand repo. | 20 lines, valid JSON, no extra fields | normal |
| 7 | Label from the ticket's own design only. Do NOT read `agentwall/src/firewall/`, `agentwall/bench/` or any detection rule before or while doing step 6, and do not edit a ticket's text to make it look more or less like an attack. | Stated in the result | abuse |
| 8 | Check the export contains no real secrets, tokens or personal data (the demo's fake emails are fine). Replace any bait or secret-shaped value with a plain placeholder like `[BAIT-VALUE]` and say so. | A short list of replacements, or "none" | abuse |

## Out of scope
Production, changing any RedHand code or rules, deploying, creating keys. Do not paste the gateway token or an agent key anywhere.

## Follow-up
(Claude Code fills in after reading the result: merges the export into `injection_indirect.holdout.jsonl`, updates the baseline,
and records the latency numbers in `docs/plans/phase4-m4-plan.md` section 8.)
