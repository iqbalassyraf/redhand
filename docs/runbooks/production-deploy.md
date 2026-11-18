# Production deploy (ADR 0028, option A)

For the owner. Claude Code wrote this and the script; it never runs them. Nothing here has been run against production yet.

## Before the first deploy (owner checklist section C)
- A **separate** Google Cloud project for production, a Supabase production project (paid plan with backups) in the nearest region, SMTP for Supabase Auth, domains.
- Every migration in `supabase/migrations/` applied in order to the production database (the newest is named in `docs/launch/owner-checklist.md`), then row-level security checked on every table.
- The model proxy stays off: production never sets `AGENTWALL_MODEL_PROXY_ENABLED` (no-go for launch, ADR 0025; the gateway refuses to start with it in production anyway).

## Deploy (from a clean, up-to-date `main`)
```bash
export DEPLOY_ENV=production PROJECT_ID=<production project id> CONFIRM_PROJECT=<the same id>
export SUPABASE_URL=https://<production ref>.supabase.co DASHBOARD_ORIGIN=https://<production dashboard>
deploy/cloudrun/deploy.sh secrets    # once: generates the service token and signing key, asks for the Supabase secret key at a hidden prompt
deploy/cloudrun/deploy.sh core       # redhand-core-prod, ENVIRONMENT=production, minimum 1 instance
deploy/cloudrun/deploy.sh gateway    # redhand-gateway-prod, AGENTWALL_ENVIRONMENT=production, minimum 1 instance
```
Then deploy the dashboard's production environment on Vercel with the production core URL and Supabase keys, and run `deploy/cloudrun/deploy.sh cors` if the dashboard origin changed.

What the script does differently for production: service, secret and identity names end in `-prod` (a mistaken project can never overwrite staging's), `--min-instances 1` (a cold core is slower than the gateway's 1 s lookup, so the first call after idle would be refused), `ENVIRONMENT=production` (no API pages, production-only checks). It refuses to start without `PROJECT_ID` set explicitly and `CONFIRM_PROJECT` equal to it.

## Check
```bash
deploy/cloudrun/smoke.sh https://<core> https://<gateway>
uv run python scripts/smoke_launch.py --core https://<core> --gateway https://<gateway> --dashboard-origin https://<dashboard>
```
Both must pass with no FAIL. Send Claude Code the output (it contains no secrets) for the release-readiness close-out.

## Roll back
Cloud Run keeps every revision: `gcloud run services update-traffic redhand-core-prod --to-revisions <previous>=100 --region <region> --project <id>` (and the same for `redhand-gateway-prod`). Roll back the gateway before core only if the gateway needs a field core no longer sends; otherwise core first. A migration is rolled back only with its tested rollback file in `supabase/rollbacks/`, after a backup.
