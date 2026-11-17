# Runbook: organization SDK keys

**Product truth:** an SDK key lets an agent's RedHand SDK send traces and model use for one organization. Anyone holding it can report for any agent of that
organization, so it is a secret. RedHand stores only a hash and shows a key once.

## Everyday use (dashboard, Passports, "SDK keys")
- **Create (admin):** type a name (what it is for) and the days until it expires (1 to 365, default 90), press **Create SDK key**, copy the key from the yellow box and
  store it in a secrets manager. Press **I have stored it**. The key cannot be shown again; if it is lost, create a new one and revoke the old one.
- **Revoke (admin):** press **Revoke** on the row and confirm. Anything using the key is refused (401) from its next batch.
- **Rotate:** create the new key, deploy it, check its "Last used" moves, then revoke the old one.
- At most **10 active keys** per organization. Revoked and expired keys do not count.

## Troubleshooting
| Symptom | Check | Fix |
|---|---|---|
| Ingest answers 401 "Invalid or revoked RedHand API Key." | The key's row: revoked, expired, or a typo (keys start `rh_live_`) | Create a new key |
| Ingest answers 401 "RedHand API Key has expired." | The row's expiry | Create a new key (rotation as above) |
| Ingest answers 429 "Too many telemetry batches for this SDK key." | More than 120 batches a minute from one key, per core instance; metric `sdk_ingest_rate_limited_total` | Batch more spans per request (up to 250), or use one key per service |
| "Last used" says never though data arrives | It updates at most once a minute, after the reply; a failure is logged as `SDK key last-use could not be recorded` | Wait a minute; check the core log |
| "An organization can have at most 10 active SDK keys." | The card's count | Revoke unused keys |
| A key leaked | | Revoke it at once (audited), then create a new one |

## "Reported by SDK" passports (C1b)
- An agent id first seen in telemetry appears on Passports with the label **reported by SDK**. It has no gateway access: its token exchange answers 403
  "Agent passport is reported only: an admin must promote it on the Passports page before it can use the gateway."
- If it is yours, an admin presses **Promote** (confirm, give a reason; audited as `passport.promoted`), then sets scopes and issues an agent key as for any passport.
  If it is not, revoke it, and revoke the SDK key that created it if you do not recognise the agent.
- Telemetry never renames a passport: the name and framework are what the person who registered it typed. To rename, use the dashboard, not the SDK.
- The Risk response ladder never freezes or alerts on a reported-only passport by itself.

## Facts
- Audit actions `sdk_key.created`, `sdk_key.revoked` (target type `sdk_key`; never the hash). Metrics `sdk_keys_total{event}`, `sdk_ingest_rate_limited_total`.
- Database functions only: `control_sdk_key_create`, `control_sdk_key_revoke`, `sdk_key_touch`. Nobody can write `sdk_api_keys` directly any more.
- Rollback: `supabase/rollbacks/20261127000000_sdk_keys.down.sql` (loses who created and revoked each key; restores the old direct-write policy).
