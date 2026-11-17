# Release readiness: what must be true before RedHand is published

**Status:** living checklist, created 2026-11-16 on the owner's decision to run the heavy checks per milestone and once, comprehensively, before release.
Nothing here is done unless it says so and names the evidence.

## 1. Testing policy (owner decision, 2026-11-16)
- **Every change:** the automated CI checks (Python: ruff, mypy, pytest, pip-audit; SQL migrations: apply, tests, rollback, re-apply; Dashboard: tsc, build, npm audit) must be green. Not deferred.
- **Per milestone** (about every 2 to 3 features): Antigravity's staging run of the new night parts and Claude Code's deliberate-breakage checks, then the staging database cross-check.
- **Before release:** everything in section 3, once, comprehensively. A clean milestone run is not a substitute.
- Cost of deferring, accepted: a bug found late is harder to trace to its change, so keep milestones small and keep the per-PR evidence in the PR text.

## 2. Open items that block release (owner action unless noted)
| Item | Why it blocks | Evidence needed |
|---|---|---|
| Decoy "secret" values in `battleground/database/db.py` looked like a live Stripe key and an OpenAI key (replaced with obvious fakes on `chore/release-readiness-secret-scan`, but they stay in git history) | If either was ever real it is leaked | Owner compares the last four characters of the old values with the Stripe and OpenAI dashboards, or just revokes both; then a full-history scan (3.1) is clean |
| Production hosting and launch checks are undecided | Staging is not production | A decision recorded in `docs/briefing.md` and an ADR |
| Blind round 4 not run; Radar stays Watch only (no block mode) | The false-alarm goal is not met on unseen text | `docs/security/m4-7b-results.md` updated after one scored round |
| Examples and tests contain fake keys that the repo's own `redhand scan` flags (about a dozen test fixtures, `examples/`, `sts_downscoper.py`) | A CI secret gate would be noisy until they are built from pieces or allow-listed | A decision: allow-list file for the scan, or rebuild the fixtures |
| GitHub Actions are not pinned to commit SHAs | Supply-chain risk | Pin when Dependabot's actions PR is merged (needs the action repositories' SHAs) |
| The first model price table (Anthropic only) was approved on 2026-11-16 | Prices change; the 90-day test will fail on purpose | Re-read the provider page when the age test fails |

## 3. The pre-release pass (do all of it, in this order)
### 3.1 Secrets
- Full git history scan with a maintained scanner (gitleaks or trufflehog; adding either is a **dependency decision for the owner**, run locally, never `curl | sh`).
  Expected: no real credentials. Every finding is rotated, not just deleted.
- `redhand scan .` (the repo's own scanner) and a manual look at `.env*`, deploy scripts and `deploy/` for secrets; `.env.example` has placeholders only.
- Check the staging and production configuration (Cloud Run, Vercel, Supabase) holds secrets in a secrets manager, not in plain environment variables.

### 3.2 Code and dependencies
- Static analysis on all of `agentwall/`, `services/redhand-core/`, `packages/`, `apps/redhand-ui/` (for example Bandit and Semgrep, new tools: owner approval).
- `pip-audit` and `npm audit` (already in CI) clean at high and above; review the lockfiles for unexpected packages; confirm licences are compatible with closed-source distribution.
- Review `docs/security/threat-model.md` against the code: every trust boundary still has its mitigation row; update the rows for anything added since.
- A manual review of every endpoint list in `docs/api/redhand-core.openapi.json` and `docs/api/agentwall.openapi.json`: authenticated unless declared public, role checked, tenant scoped.
  **Automated since 2026-11-17 (run on every CI build):** `services/redhand-core/tests/test_route_sweep.py` and `agentwall/tests/test_gateway_route_sweep.py` are generated from the live
  route tables: every route has a known kind of authentication or a reasoned public entry; bad or missing credentials are refused with nothing executed; every operator route has the
  role in a reviewed matrix (a change to a required role is a visible diff); another organization's ids and list rows are unreachable. Still manual: whether each role's *meaning* is right
  (see the open questions in `docs/handoff.md`, 2026-11-17 sweep entry).

### 3.3 Dynamic and abuse testing on staging
- Run an authenticated and an unauthenticated scan of the public surface (core, gateway, dashboard): headers, TLS, CORS, rate limits, error leakage.
- Tenant isolation: two organizations, try every read and write route with the other organization's ids (the F1 sweep of 2026-11-12 is the template).
- Token abuse: stolen, expired, tampered, replayed and stale-version agent tokens; revoked and frozen agents; SSRF attempts through every URL field.
- Hostile MCP server and hostile agent input: oversized, malformed, injected tool descriptions and results.

### 3.4 Full Antigravity run
- Every part of the night brief (`docs/testing/briefs/2026-11-13-night-1.md`, order in the master brief) on a freshly deployed staging, including Parts N and O, with the result file checked against the database by Claude Code. Waived checks (M2 to M7, L3, L6, L7) are re-run here.

### 3.5 Performance and failure
- Gateway latency with everything on: p50 at most 10 ms and p99 at most 50 ms (`scripts/latency_baseline.py`, runbook `docs/runbooks/latency-baseline.md`); compare ingest overhead of the roll-up triggers (B2, B4a) under realistic load.
- Failure modes: database down, policy store unreachable, Telegram down, slow upstream: the gateway denies and alerts; core's detective features never fail an ingest.
- Revocation and freeze take effect within 5 seconds, measured.

### 3.6 Data and operations
- Backup and restore tested from a real backup; tenant data export and deletion exercised (`docs/runbooks/tenant-data-deletion.md`).
- Retention jobs scheduled in production (pg_cron or an equivalent): Black Box, honeytrips, findings, behaviour roll-up, model-spend roll-up.
- Every migration applied in order on a copy of production data shape, and every rollback script exercised.
- Runbooks exist for each failure mode (`docs/runbooks/`), alerts route to a person, and a rollback of each deploy is rehearsed.

### 3.7 Claims and copy
- Every performance, compliance or "integrates with" statement in the product, docs and site is backed by a test, a benchmark or a real integration, or says it is simulated (CLAUDE.md section 1). Legal review of any compliance wording (PDPA, ISO/IEC 42001).
- The dashboard and docs say RedHand only controls what flows through RedHand, and that spend numbers are self-reported estimates until a proxy exists.

## 4. Gated, not planned for release
- B5/B6 (model proxy): only after a measured prototype; it would make spend authoritative.
- Block mode for Radar: only after independent evidence passes the gate (`agentwall/src/bench/gate.py`).
- Phase 5 features (compliance reports, Trust Score): not before the owner asks.
