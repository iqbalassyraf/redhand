# Owner checklist before announcing

One page, in order. Each line is something only the owner (or a person with the owner's accounts) can do. Tick it in a copy, not here. Claude Code cannot do these: no access to your accounts, DNS, billing or the live projects.

## A. Today (they cost nothing and reduce risk)
1. **Revoke the old look-alike keys.** The battleground used values shaped like a live Stripe key and an OpenAI key; they are readable in the public git history (commits f82af25, c83151d, 388e278, 29777ae). If either was ever real, it is leaked. Revoke both in the Stripe and OpenAI dashboards.
2. **Choose a licence** (or deliberately none = all rights reserved) and add `LICENSE`. The repository is public today with no licence.
3. **GitHub settings** (Settings, Code security): turn on private vulnerability reporting, secret scanning with push protection and Dependabot alerts; protect `main` (require the CI checks, no force pushes).
4. **Decide the open Dependabot pull requests** (#73 actions pinning, #74 dashboard dependencies, and the older ones): Claude Code does not merge them without you.

## B. Decisions
5. **Production hosting**: read `docs/adr/0028-production-hosting.md`, change what you disagree with, set Status to Accepted.
6. **Domain and DNS**: one name for the dashboard, one for core, one for the gateway (or paths behind one). Needed for CORS (`CORS_ALLOWED_ORIGINS` is exact), Telegram links and the Supabase redirect allow-list.
7. **Terms and privacy**: send `docs/launch/terms-draft.md` and `privacy-draft.md` to a lawyer. Do not publish the drafts. The product must not claim PDPA or ISO compliance until someone qualified says it may.
8. **Support contact and status page**: fill in `docs/launch/support-and-status.md`.

## C. Build the production environment (after B5)
9. **Supabase production project** in the chosen region. Apply every migration in `supabase/migrations/` in order (the current newest is `20261130000000_tenant_lifecycle`). Check row-level security is on for every table (the Supabase advisor, "Security", must show no table without it).
10. **Supabase Auth**: SMTP provider for sign-up confirmation and password reset (the built-in mailer is rate-limited and not for production), e-mail templates with your name, the redirect allow-list including the dashboard `/login` URL, password rules, e-mail confirmation on.
11. **Secrets** into the platform's secrets manager (never `.env`, never chat): `SUPABASE_SERVICE_ROLE_KEY`, `INTERNAL_SERVICE_TOKEN` (long random, the same value for core and the gateway), `AGENT_TOKEN_SIGNING_KEY`, Telegram bot token and webhook secret if you offer the panic command. List and meanings: `docs/launch/environment-variables.md`.
12. **Deploy core, then the gateway, then the dashboard** (`deploy/cloudrun/deploy.sh`, `docs/runbooks/cloud-run-staging.md` is the staging version). Set minimum instances so the first call after an idle period is not refused (see ADR 0028: the gateway refuses when core takes longer than 1 s).
13. **Run the smoke check** against the production URLs and read every WARN:
    ```bash
    uv run python scripts/smoke_launch.py --core https://<core> --gateway https://<gateway> --dashboard-origin https://<dashboard>
    ```
14. **Backups with a tested restore**: turn on the Supabase backups for the plan you chose, restore one into a scratch project and check a known organization is there. An untested backup is not a backup.
15. **Alerting**: someone is told when core or the gateway is down or returning errors (Cloud Run uptime check on `/health`, a notification channel that reaches a phone).

## D. First customer
16. **Issue a sign-up code** for the first design partner, over a private channel:
    ```bash
    export RH_CORE_URL=https://<core>   # the service token is read from RH_SERVICE_TOKEN; set it from your secrets manager, never type it into chat
    python3 scripts/issue_signup_code.py --note "<who>" --days 14
    ```
17. **Walk the first-customer path with them** (`docs/launch/first-customer-path.md`), on a call, once. Write down every place they hesitated.
18. **Run the staging night parts you still owe** (Parts N to Q), blind round 4 for Radar, and the pre-release pass in `docs/release-readiness.md` section 3, before anything beyond a design partner.

## What stays true after launch
RedHand only controls what flows through RedHand: an agent that does not go through the gateway, or a credential that is not issued by RedHand, is not protected. Say so in every sales conversation (`docs/launch/what-redhand-controls.md`).
