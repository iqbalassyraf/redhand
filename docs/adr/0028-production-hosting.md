# ADR 0028: Production hosting (Phase 4.5 D1, decision for the owner)

**Status:** Proposed (2026-11-17). Written by Claude Code so the owner can accept it, change it or reject it; nothing is deployed and no account was touched. **Every price and region claim below is unverified**: fill the cost
table from each vendor's price page, with the date, before accepting. CLAUDE.md lists production hosting as undecided ("to confirm in review").

## Context
Staging runs on Supabase (Postgres and Auth), Google Cloud Run (core and gateway, region `asia-southeast1`, Singapore, 1 instance, minimum 0) and Vercel (dashboard). Production needs the same pieces made dependable.
Constraints from CLAUDE.md: cost to serve per agent a small fraction of the price (initial market Malaysia and Southeast Asia); revocation within 5 s; gateway availability target 99.9% monthly; region configurable, not hardcoded;
boring technology; no microservices beyond what exists.

One coupling decides the min-instances question: **the gateway refuses a call when core takes longer than 1 s to answer a passport lookup** (D1 PR 4; it was 2 s). With `min-instances 0`, the first call after an idle
period waits for a cold start of core (seconds) and is refused. That is correct (fail closed) but is a bad first experience and counts against availability.

## Options
**A. Keep the stack, production-grade (recommended).** A separate production Supabase project, separate production Cloud Run services (core, gateway) and a production Vercel environment, all with one region choice for data
(`asia-southeast1`, with the Supabase project in the nearest region; confirm the exact region names when creating them).
- For: no migration, everything already deployed once and documented (`docs/runbooks/cloud-run-staging.md`, `deploy/cloudrun/`); Supabase handles auth, backups and row-level security that the code relies on; Cloud Run scales to the first dozens of customers without work.
- Against: three vendors' bills and consoles; Cloud Run minimum instances cost money even idle; Supabase backup tiers depend on the plan.
- Settings that must change from staging: `ENVIRONMENT=production`, `--min-instances 1` for core and the gateway, `--max-instances` above 1 only after the in-memory rate limiters and ledger are understood (see Consequences), custom domains, Supabase paid plan with backups, SMTP for Auth.

**B. One provider for everything (for example all on Google Cloud with Cloud SQL, or a single VM with containers).** One bill and console, no cross-vendor latency.
- For: simpler network story; possibly cheaper at larger scale.
- Against: replaces Supabase Auth and row-level security with something we run ourselves (a large change to a security product's identity layer: needs its own ADR and a new review); more operations work for a one-person team; delays launch by weeks.
- Rejected for launch; reconsider when the bill or the operations load justifies it.

**C. Self-hosted for customers** (the sidecar and Helm chart exist for enterprise). Out of scope for the hosted starter tier; unchanged.

## Cost per agent (to fill in; formula, not figures)
Monthly cost = Supabase plan + Cloud Run (core: `1` instance always on `x` price, gateway: same) + Vercel plan + e-mail provider + domain + monitoring.
Per agent = monthly cost divided by the number of paying agents at the break-even you choose. Fill:
| Item | Plan | Monthly (currency, date read) | Source URL |
|---|---|---|---|
| Supabase (Postgres, Auth, backups) | | | |
| Cloud Run core (min 1) | | | |
| Cloud Run gateway (min 1) | | | |
| Vercel dashboard | | | |
| SMTP / e-mail | | | |
| Domain, DNS, monitoring | | | |
| **Total** | | | |
Gateway work per call is a lookup and rules, no model calls (CLAUDE.md section 8); the per-agent variable cost is database writes (Black Box events, traces) and is bounded by the retention jobs. Measure it from staging before pricing.

## Decision (proposed)
Option A. Two environments only (staging, production), same code, different projects and secrets. Region for data: Singapore for Cloud Run (`asia-southeast1`, already used) and the nearest Supabase region; no hardcoded region in code.

## Consequences and open points
- **Single instance behaviour:** rate limiters, sign-up attempt limits, the export-throttle cache aside (that one is in the database), the gateway's audit ledger and budget counters are per process. Running more than one instance of core or the gateway changes their effect (limits multiply, the ledger splits).
  Keep `--max-instances 1` until each is reviewed, and say so in the runbook. The 5 s revocation bound is per instance and holds with several.
- **Availability 99.9%** is a target, not measured. A single instance per service cannot honestly promise it; state a lower number to customers until measured.
- **Backups:** Point-in-time restore depends on the Supabase plan; test a restore (owner checklist item 14).
- **Cold starts** of the dashboard (Vercel) do not affect enforcement; cold starts of core and the gateway do (see Context). Minimum 1 instance each.
- **Domains:** the dashboard, core and the gateway need stable https names; CORS and Telegram links depend on them.
- **Not decided here:** billing, a status page vendor, a WAF/CDN in front of core, a second region.
