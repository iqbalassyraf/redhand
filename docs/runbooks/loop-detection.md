# Runbook: loop detection (repeated identical tool calls)

**Product truth (shown in the dashboard):** RedHand counts only calls that flow through the RedHand gateway. It cannot see an agent that calls a tool directly. A call that changes its arguments each time is not caught.

## What it does
Counts calls with the same agent, tool and arguments. The limit-th call inside the window (default **20 in 60 seconds**) is a *repeat*.
- **Watch (default):** the repeat is recorded as a finding (rule `RAD-LOOP-001`, "Repeated calls" on the Radar page) and you get one Telegram alert per agent per 10 minutes. Nothing is refused.
- **Throttle:** the repeat is also refused ("this exact call was repeated too often ... paused for now") before it can use the agent's daily budget. The agent recovers by itself as the window moves on; about *limit minus one* identical calls per window get through.
- **Off:** nothing is counted or recorded.
Findings contain the agent, the tool, the server and a count. No arguments, no results.

## Turn it up safely
1. Leave it on **Watch** for a few days. Open Radar, **Repeated calls**, and look at which agents repeat and why.
2. For a tool that is *meant* to be called again and again (a status check every few seconds), open its finding and press **Exempt this agent from repeat checks** (admin, reason, up to 90 days). That agent is then neither flagged nor throttled. It exempts the whole agent, not one tool.
3. Choose a limit and window that fit (3 to 1000 calls, 10 to 600 seconds), then switch to **Throttle** (admin, tick the confirmation). The audit log records who and when (`organization.loop_settings_changed`).
4. To go back: set Watch (no confirmation needed) or Off (confirmation needed).

## If something is wrong
- **Gateway-wide switch, no deploy:** set `AGENTWALL_LOOP_DETECTION_ENABLED=false` on the gateway service (Cloud Run: update the environment variable, new revision). The meter is skipped for everyone whatever the organization's mode. `deploy/cloudrun/deploy.sh` replaces environment values, so say so in `docs/handoff.md` the same day.
- **All calls fail with "Passport service unavailable" right after a gateway deploy:** the gateway was deployed before core. The new gateway requires `loop_mode`, `loop_limit`, `loop_window_seconds` and `loop_exempt` from core and denies when they are missing. Deploy core first (or roll the gateway back).
- **A legitimate agent is being throttled:** exempt it (step 2), or set the organization to Watch.
- **No alert arrived:** one alert per agent per 10 minutes; later repeats are still counted. Check the Telegram link and `redhand_gateway_loops_total`.

## Reading the numbers
Gateway `/metrics`: `redhand_gateway_loops_total{outcome=ok|flagged|throttled|untracked|error|evicted|report_throttled}` and the stage `redhand_gateway_stage_ms{stage="loop_check"}`. `flagged` counts every repeat; the finding's own count is lower, because the gateway sends at most one report per agent, tool and server every 30 seconds (`report_throttled` counts the rest). `evicted` means the table was full and a count was forgotten. `error` means the meter failed (in Watch the call carried on; in Throttle it was refused). `untracked` means the arguments could not be hashed.

## Limits
- With several gateway instances each counts for itself, so the real limit can be up to the limit times the instances.
- Arguments longer than 64 KiB are compared on their first 64 KiB and their length.
- A window edge makes the count an estimate that is at most one call late.
- A call refused by Budget Guard still counts as a repeat (the loop check comes first, so a throttled repeat uses no budget).
- Every existing organization starts on Watch when this ships.

## Deploy and rollback
Order: apply `20261120000000_loop_detection.sql`, deploy core, deploy the gateway, then the dashboard. Rollback: run `supabase/rollbacks/20261120000000_loop_detection.down.sql` (it deletes loop findings and `RAD-LOOP` suppressions), and redeploy the previous gateway first if the new one is running (the old core cannot satisfy it).
