# Runbook: Safe Mode

Safe Mode lets agents use only tools their scopes declare as **read**. Write-declared tools are refused
with "Safe Mode is on". Design: `docs/adr/0009-safe-mode.md`.

## Use it
- **One agent:** dashboard → Passports → the agent's **Safe Mode** button (turn off with **End Safe Mode**,
  which asks for a reason).
- **Everyone:** the **Safe Mode (all agents)** switch at the top of the Passports page.
- **From your phone:** `/safemode on` (all agents) or `/safemode on <agent name>`. Turning it off is
  dashboard-only.
- Roles: turning it on needs a security operator or higher; turning it off needs an admin or owner.
- It takes effect on the agent's next call, at most about 2 seconds later.

## The thing to understand
RedHand cannot see whether a tool really is read-only. **You declare it** on each scope. So:
- Declare `read` only for tools that cannot change anything.
- Be careful with `*` scopes declared read: every tool on that server counts as read-only.
- New scopes created in the dashboard default to `write`, so an undeclared tool is suspended in Safe Mode.

## Deploy order (important)
1. Apply the migration `supabase/migrations/20261104000000_safe_mode.sql` to the database.
2. Deploy **core**, then the **gateway** (`deploy.sh core`, then `deploy.sh gateway`, with `DASHBOARD_ORIGIN` set).
3. Do not turn Safe Mode on until both are updated. A new gateway with an old core denies every call
   ("Passport service unavailable"); an old gateway ignores the flag.

## Troubleshooting
| Symptom | Likely cause |
|---|---|
| Every agent call is denied with "Passport service unavailable" right after a deploy | The gateway is newer than core (core does not send `safe_mode`). Deploy core. |
| An agent that should be blocked can still write | The scope for that tool is declared `read`, or a `*` read scope covers it. Check Scopes. |
| An agent is blocked and nobody turned Safe Mode on | The organization switch is on (the agent row shows "safe mode (all)"), or the stored flag is malformed (core treats that as ON). |
| "requires explicit confirmation" turning it off | Turning off needs `confirm`; the dashboard sends it. API callers must too. |
