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
| ~~GitHub Actions are not pinned to commit SHAs~~ **Done 2026-11-17** (`chore/pin-actions-sha`): every action is pinned to the commit of its release tag, with the version as a comment | Supply-chain risk | Dependabot keeps SHA and comment in step |
| The first model price table (Anthropic only) was approved on 2026-11-16 | Prices change; the 90-day test will fail on purpose | Re-read the provider page when the age test fails |

## 3. The pre-release pass (do all of it, in this order)
### 3.1 Secrets
- Full git history scan with a maintained scanner (gitleaks or trufflehog; adding either is a **dependency decision for the owner**, run locally, never `curl | sh`).
  Expected: no real credentials. Every finding is rotated, not just deleted.
- `redhand scan .` (the repo's own scanner) and a manual look at `.env*`, deploy scripts and `deploy/` for secrets; `.env.example` has placeholders only.
- Check the staging and production configuration (Cloud Run, Vercel, Supabase) holds secrets in a secrets manager, not in plain environment variables.

### 3.2 Code and dependencies
- Static analysis on all of `agentwall/`, `services/redhand-core/`, `packages/`, `apps/redhand-ui/` (for example Bandit and Semgrep, new tools: owner approval).
  **First one-off run 2026-11-17** (owner approved, not added to the project): `uvx --from bandit==1.8.6 bandit -q -r agentwall services/redhand-core/src packages -x '*/tests/*'` and
  `uvx --from semgrep==1.101.0 --with 'setuptools<81' semgrep scan --config p/python --metrics=off agentwall/src services/redhand-core/src packages` (23,268 lines).
  Bandit 35 findings: **3 real** (literal bidirectional-control and zero-width characters in the source of Radar, the description rules and the MCP scanner: "Trojan Source", now written as `\uXXXX` escapes
  and guarded by `tests/deploy/test_no_hidden_characters.py`); 32 reviewed false positives or accepted (14 `hardcoded_password_string` and 7 `..._funcarg` on constants such as `"Bearer"`, issuer names and enum values; 7 `assert` in
  benchmark and twin code; `0.0.0.0` as the container bind default; `random` for retry jitter; a deliberate `except: pass` in best-effort memory zeroing). Semgrep `p/python`: 7 `logger-credential-disclosure` warnings, all reviewed:
  they log agent ids, token ids or fixed error text, never a credential. Not run: Semgrep on `apps/redhand-ui` (TypeScript rules), `p/secrets` (needs the registry login for line text).
  Re-run before release; a Pro/Team scan or CodeQL (free on public repositories) would add taint analysis.
  **Second run 2026-11-18** (after D1, C1 and B5a to c; same pinned tools, nothing added to the project; commit of `main` at 097b6b6 plus the open docs PRs):
  - **Bandit 1.8.6:** 32 findings, **0 new**: exactly the 32 reviewed false positives or accepted items of the first run (B105 x14, B106 x7, B101 x7, B104 x2, B311 x1, B110 x1). The three Trojan Source items stay fixed.
  - **Semgrep 1.101.0, `p/python` + `p/typescript`** over `agentwall/src`, `services/redhand-core/src`, `packages` and `apps/redhand-ui/src` (225 rules, 227 files, no scan errors): 7 findings, all the reviewed `logger-credential-disclosure` warnings (same two core files, plus `sts_downscoper.py`; none logs a credential). **TypeScript rules: 0 findings.** Still not run: `p/secrets`, CodeQL.
  - **`pip-audit`** on the locked Python set (`uv export --frozen`, 228 lines): **no known vulnerabilities** (the four workspace packages are skipped because they are not on PyPI).
  - **`npm audit`:** **0 vulnerabilities in production dependencies** (`--omit=dev`). Including dev dependencies: 10 **high**, all one advisory chain, `picomatch` ReDoS (GHSA-fc5q-39xc-vjpf) reached through `tailwindcss` 3.x's build tooling (chokidar, fast-glob, micromatch, anymatch). It runs only at build time on our own source, never in the shipped app. The only fix npm offers is Tailwind 4, which the owner chose to hold back (2026-11-16). **Accepted for now; decision for the owner:** migrate to Tailwind 4 (own plan) or approve an `overrides` entry for `picomatch` (a dependency change).
  - **Licences:** Python: no GPL, AGPL, SSPL or BUSL package; every third-party licence resolves to MIT, BSD, Apache-2.0, ISC, PSF or MPL-2.0 (the four workspace packages declare none: no licence has been chosen, see 3.8). npm production tree: MIT 37, ISC 11, Apache-2.0 5, BSD-3-Clause 2, 0BSD 1, **LGPL-3.0-or-later 2** (`@img/sharp-libvips-*`, prebuilt native libraries that Next.js's image optimizer loads dynamically: not modified, not bundled into our source), **CC-BY-4.0 1** (`caniuse-lite`, browser-support data: needs attribution, which the package carries), and our own `redhand-ui` as UNLICENSED. **For the owner or a lawyer:** whether LGPL libraries used as unmodified dynamic dependencies are acceptable for closed-source distribution (the usual reading is yes, with the notice kept); not legal advice.
  - **OpenAPI:** `docs/api/redhand-core.openapi.json` regenerated from code is identical to the committed file (93 paths); the gateway file lists its 8 routes (the model proxy route is absent because it is off by default). Authentication and role of every route are checked on each CI run by the two route sweeps (below), not by reading the list.
  - **Threat model:** rows exist for onboarding, invites, export and deletion, SDK keys, reported-only agents, measured usage and the proxy's spend refusals (12 matches for those terms); the open residuals (one provider key, bypass, refusals not in the Black Box) are written in the rows.
  - **Not run:** full-history secret scan (needs gitleaks or trufflehog: owner's dependency decision), Semgrep `p/secrets`, CodeQL, any dynamic scan of staging (3.3).
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
- Revocation and freeze take effect within 5 seconds, measured. **Local numbers exist since 2026-11-17** (`docs/security/measurements/`: about 0.4 s for freeze, revoke and freeze-all on real processes; core stopped: refused after 1.8 s; core hanging: refused after 4.3 s, only about 0.7 s inside the promise). **Still needed:** the same drill against staging (`scripts/revocation_drill.py` runs local processes only; a staging variant needs the real URLs and keys and the owner's go-ahead) and with two gateway instances.

### 3.6 Data and operations
- Backup and restore tested from a real backup; tenant data export and deletion exercised (`docs/runbooks/tenant-data-deletion.md`).
- Retention jobs scheduled in production (pg_cron or an equivalent): Black Box, honeytrips, findings, behaviour roll-up, model-spend roll-up.
- Every migration applied in order on a copy of production data shape, and every rollback script exercised.
- Runbooks exist for each failure mode (`docs/runbooks/`), alerts route to a person, and a rollback of each deploy is rehearsed.

### 3.7 Claims and copy
- Every performance, compliance or "integrates with" statement in the product, docs and site is backed by a test, a benchmark or a real integration, or says it is simulated (CLAUDE.md section 1). Legal review of any compliance wording (PDPA, ISO/IEC 42001).
- The dashboard and docs say RedHand only controls what flows through RedHand, and that spend numbers are self-reported estimates until a proxy exists.

## 3.8 Public repository (the repository is public since 2026-11-17)
- **History is public and permanent.** Decoy values that look like a live Stripe key and an OpenAI key (`battleground/database/db.py`, commits f82af25, c83151d, 388e278, 29777ae) are readable by anyone. Revoke or rotate both in the provider dashboards (owner); do not paste them anywhere. A history rewrite would not reach forks or caches.
  A full-history pattern scan on 2026-11-17 found no other real-looking credential (the other hits are test fixtures such as AWS's documented example key).
- Done 2026-11-17: `SECURITY.md` (private reporting, scope, no testing of hosted environments); personal test e-mail addresses, Cloud Run host names and the GCP project number replaced by placeholders in current files (history keeps them); `scripts/staging_agent.py` defaults to localhost; hidden-character guard.
  Staging host names are now given to testers by the owner (see `docs/antigravity-briefing.md`).
- Still the owner's: a **licence** (no `LICENSE` file: legally all rights reserved, which is not what an open repository usually wants), enabling GitHub's private vulnerability reporting and secret scanning with push protection in the repository settings, branch protection on `main` (require the CI checks), and whether Dependabot alerts email the right person.
- CI on pull requests from forks: the workflow uses `pull_request` with `contents: read` and no secrets, so a fork cannot read secrets; keep it that way (never switch it to `pull_request_target`).

## 4. Gated, not planned for release
- B5/B6 (model proxy): only after a measured prototype; it would make spend authoritative.
- Block mode for Radar: only after independent evidence passes the gate (`agentwall/src/bench/gate.py`).
- Phase 5 features (compliance reports, Trust Score): not before the owner asks.
