# Runbook: Budget Guard (daily tool-call limits)

Gives an agent a cap on the **tool calls it makes through the RedHand gateway** per day. Over the cap the
gateway refuses further calls, and you are alerted. It counts calls, **not money and not LLM tokens**.
Design: `docs/adr/0010-budget-guard.md`.

## Use it
- **Set a limit:** dashboard -> Passports -> the agent's **Limit** button: calls per day (blank = none) and what
  happens at the limit (refuse and alert, or refuse, alert and freeze the agent).
- **See usage:** the **Calls today** column (a bar that turns amber at 80% and red at 100%), or `/usage` on
  Telegram. Agents with no limit show "no limit set": they are counted but never stopped.
- **Alerts** go to linked Telegram chats at 80% and at 100%, once per agent per day.
- **Roles:** setting or lowering a limit, or turning auto-freeze on, needs a security operator. Raising or
  removing a limit, or turning auto-freeze off, needs an admin and a confirmation.
- **A raised limit takes effect within about 2 seconds.** Changing the limit makes the new limit alert again.
- The day starts at midnight in the organization's time zone (UTC+8 by default).

## Deploy order (important)
1. Apply `supabase/migrations/20261105000000_budget_guard.sql`.
2. Deploy **core**, then the **gateway** (`deploy.sh core`, then `deploy.sh gateway`, with `DASHBOARD_ORIGIN`
   set). The gateway requires the new `budget` field from core and denies every call without it.
3. Deploy the dashboard (merge to `main`). It tolerates an older core.
4. Cleanup runs by itself: migration `20261106000100_schedule_purges.sql` schedules `purge_usage()` and `purge_telegram_updates()` daily at 19:17 UTC with pg_cron (usage rows older than 90 days are removed). On a database without pg_cron, schedule them with any scheduler.
5. Optional: apply `20261106000200_budget_default.sql` (default limit for new agents) before deploying core of the same version.

## Default limit for new agents
Dashboard -> Passports -> **Default daily limit for new agents** -> **Change (admin)**. Every agent registered
afterwards starts with that limit (you can still change it per agent). It never changes existing agents, and
changing it later does not alter agents already registered. Blank means no default. Raising or removing it
asks for confirmation. If applying it ever fails the agent is still registered, with no limit (the dashboard
shows "no limit set").

## Test it on staging (Phase 2 done test 3)
1. In the dashboard set a limit of **5** on your DeepWiki read agent, action "refuse and alert".
2. Run the watcher with the read tool and a 1-second interval: `python3 scripts/staging_agent.py watch`.
3. **Expected:**
   - Calls 1 to 5 work. Your phone gets "has used 4 of its 5 daily tool calls (80%)" and then
     "reached its daily limit of 5 tool calls".
   - From the 6th call the watcher prints `STOPPED ... daily limit of 5 tool calls reached; it resets at ...`.
   - The dashboard shows `5 / 5` with a red bar, and `/usage` on your phone shows "5 of 5 calls (100%)".
4. Raise the limit to 8 (confirm). Within about 2 seconds the watcher prints `RESUMED`.
5. Set the action to "freeze", lower the limit to 3 and keep the watcher running: the agent is refused, then
   shows as **frozen** in the dashboard with "RedHand Budget Guard" in the audit log. Unfreeze it yourself.

## Troubleshooting
| Symptom | Likely cause |
|---|---|
| Every agent call is denied with "Passport service unavailable" right after a deploy | The gateway is newer than core (no `budget` in the context), or core runs but the migration was not applied (the usage lookup fails). Apply the migration and deploy core first. |
| The dashboard shows `0 calls` while the agent is working | Reports are not reaching core: check the gateway's `redhand_gateway_budget_reports_total{outcome="failed"}` metric and that the gateway's service token matches core's. Counts are kept and retried, nothing is lost while the gateway runs. |
| An agent was refused although it had "plenty of room" | Another gateway instance used part of the day (they are summed), or the day started earlier than you think (check the organization's UTC offset). |
| No alert arrived at the limit | Telegram is not linked or not configured (`docs/runbooks/telegram-panic-command.md`), or the limit was changed after the alert (changing it re-arms alerts). Alerts are best effort and never block enforcement. |
| An agent has no limit and ran away | Agents without a limit are never stopped. Set one; Telegram `/usage` shows heavy users. |
| Usage looks too low after a gateway restart | By design: calls not yet reported (the last few seconds) are lost when a process dies. A report is sent on a normal shutdown. |

## Limits worth knowing
- Counts calls, not cost: one expensive call counts the same as one cheap call.
- With several gateway instances the cap can be exceeded briefly (up to about 7 seconds of other instances'
  traffic). Staging runs one instance, where the count is exact.
- The day boundary has no daylight-saving support.
