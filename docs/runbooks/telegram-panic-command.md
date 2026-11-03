# Runbook: Telegram panic command

Lets linked admins and owners freeze agents from a phone. Design: `docs/adr/0008-telegram-panic-command.md`.
Commands: `/status`, `/freeze_all [reason]`, `/freeze <agent name>`, `/help`. Unfreeze and revoke are
dashboard-only.

## One-time setup (about 15 minutes)

### 1. Create the bot (on your phone or Telegram Desktop)
1. Open Telegram, search for **@BotFather** (blue tick), press Start.
2. Send `/newbot`. Give it a display name (e.g. "RedHand Panic") and a username ending in `bot`
   (e.g. `redhand_yourname_bot`).
3. BotFather replies with a **token** like `123456789:AA...`. Treat it like a password: do not paste
   it into chats, issues or commits. Note the username too.
4. Optional but recommended: send `/setprivacy` to BotFather, pick your bot, choose **Enable**. Send
   `/setjoingroups`, pick your bot, choose **Disable** (the bot only works in private chats).

### 2. Apply the database migration (Supabase)
`supabase/migrations/20261103000000_telegram_panic.sql` (rollback in `supabase/rollbacks/`). Apply it
to staging before deploying the new core, because core now calls the new functions.

### 3. Store the secrets and give them to core (your Mac terminal, repo root)
```bash
SUPABASE_URL=https://qxxiksevqfmkqstrdkxi.supabase.co TELEGRAM_BOT_USERNAME=<bot username without @> deploy/cloudrun/deploy.sh core
```
This redeploys core with the Telegram code. Then:
```bash
TELEGRAM_BOT_USERNAME=<bot username without @> deploy/cloudrun/deploy.sh telegram
```
Paste the token when asked (hidden). The script stores it and a generated webhook secret in Secret Manager.
Later `deploy.sh core` runs keep both settings as long as `TELEGRAM_BOT_USERNAME` is set.

### 4. Point Telegram at core
```bash
python3 scripts/telegram_webhook.py set --project <gcp-project-id> --core-url <core url>
```
It prints `webhook set`, the URL, and the number of pending updates. Check anytime with `info`.

### 5. Link your phone
1. Dashboard → Passports → **Telegram panic command** → **Link Telegram** (admin or owner only).
2. On your phone open the link shown (or send `/link CODE` to the bot). The bot answers "Linked."
3. Send `/status` to confirm. Try `/freeze_all` only when you are ready for agents to stop.

## Everyday use
- **Lost phone / someone left:** dashboard → Telegram panic command → **Unlink**.
- **See what happened:** the control audit log shows `via Telegram` in the reason, plus
  `telegram.linked` and `telegram.unlinked` entries.
- **Rotate the webhook secret:** `ROTATE=1 TELEGRAM_BOT_USERNAME=... deploy/cloudrun/deploy.sh telegram`
  (it creates a new secret version and updates core), then run `scripts/telegram_webhook.py set` again so
  Telegram sends the new secret.
- **Rotate the bot token:** `/revoke` it with BotFather, create a new token, add a new version of the
  `redhand-telegram-bot-token` secret in Secret Manager, redeploy core (`deploy.sh core`), run
  `scripts/telegram_webhook.py set` again.

## Troubleshooting
| Symptom | Likely cause |
|---|---|
| The bot never answers | `python3 scripts/telegram_webhook.py info`: no URL means step 4 was skipped; a `last error` line names the problem (often 401 = secret mismatch, 503 = core lacks the settings, timeout = cold start). |
| "This chat is not linked" | Link code expired or already used; generate a new one. Or the phone was unlinked. |
| "Your role no longer allows panic commands" | The operator is no longer admin or owner. |
| "Not carried out" / "NOT carried out" | The freeze failed; nothing changed. Use the dashboard and check `docs/runbooks/control-action-failed.md`. |
| Dashboard says "Telegram is not set up" | Core has no `TELEGRAM_BOT_TOKEN` / `TELEGRAM_WEBHOOK_SECRET` (step 3). |
| First command after a quiet period is slow | Cloud Run cold start (min instances 0); expect a few seconds. |

## Maintenance
Schedule `select public.purge_telegram_updates();` daily (Supabase → Database → Cron, or any scheduler
with the service role): it removes update ids older than 7 days and used or expired link codes. Without it
the tables only grow slowly (one small row per command).
