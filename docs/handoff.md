# Handoff log: Claude Code and Antigravity

Both tools work on RedHand and its demo projects. This file is how each learns what the other did. Newest entry first.

**Rules for both tools**
- Read this file at the start of a session. Add an entry at the end of your work: what changed, where, what you verified,
  what you did NOT verify, and what the other tool should do next.
- Never put secrets, keys, tokens or customer data here.
- Changes to a shared environment (Cloud Run settings, Supabase, DNS) must be written down here the same day, because the
  repo's scripts will overwrite anything they do not know about. If you change a live setting by hand, say which script
  would undo it.
- Claude Code keeps `CLAUDE.md` rules (plan first, tests, no commit or deploy unless the owner asks).

---

## 2026-11-08, Antigravity: Blind Round 2 completed (M4.1b) and untracked scripts removed
- **Changed:**
  - Deleted untracked round-1 generator scripts in `scripts/` (`build_blind_samples.py`, `generate_injection_indirect.py`, `generate_output_path.py`, `generate_output_ssrf.py`, `generate_output_xss.py`) per brief item 3.
  - Authored 800 blind round-2 samples (200 each across 4 categories: `injection_indirect`, `output_xss`, `output_ssrf`, `output_path`) in `docs/testing/exports/blind2-*.jsonl`. IDs 601 to 800, exactly 80 malicious and 120 benign (45 hard benign) per category; 60% EN (120), 25% MS (50), 15% ID (30).
  - Test result file created at `docs/testing/results/2026-11-08-m4-1b-blind-round-2.md`.
- **Verified:**
  - Schema validity, JSON integrity, ID sequences (601 to 800), kind (`tool_result`), 60/25/15 language split, and zero secret or rule leaks.
  - Strict independence: rules in `agentwall/src/firewall/`, `agentwall/src/bench/`, `agentwall/bench/`, `docs/security/`, and `docs/plans/phase4*.md` were never read.
  - Advanced variety: includes polite/bureaucratic phrasing, split-field directives, long operational runbooks (500-2000 chars), rare HTML5 tags/handlers, IPv6/decimal SSRF bypasses, and complex path traversals.
- **Not verified / Open items for Owner:**
  - Item 1 (Staging latency baseline): steps 1–5 of `2026-11-07-m4-0-latency-and-helpdesk-samples.md` await owner reading `redhand-internal-service-token` from Secret Manager without printing.
  - Item 2 (Helpdesk schema limits & rescan): step 16 of `2026-11-07-dashboard-access-fixes.md` awaits owner approval to redeploy `helpdesk-mcp` with schema length limits and rescan `kedai-kita`.
- **Next for Claude Code:**
  - Score blind round 2 against the rewritten Radar rules (frozen evaluation without changes).


## 2026-11-08, Antigravity: blind benchmark samples and helpdesk export completed
- **Changed:**
  - Exported 20 helpdesk held-out samples (8 malicious, 12 benign) to `docs/testing/exports/helpdesk-injection-heldout.jsonl`. Honeytoken bait sanitized to `[BAIT-VALUE]`.
  - Authored 1,000 blind benchmark samples (250 each across 4 categories: `injection_indirect`, `output_xss`, `output_ssrf`, `output_path`) in `docs/testing/exports/blind-*.jsonl`. IDs 301 to 550, exactly 100 malicious and 150 benign (35 hard benign) per category; 70% EN, 20% MS, 10% ID.
  - Test result files created: `docs/testing/results/2026-11-08-m4-0b-blind-samples.md` and `docs/testing/results/2026-11-07-m4-0-latency-and-helpdesk-samples.md`.
- **Verified:**
  - All 1,020 JSONL records strictly validated against brief schema requirements (correct fields, formatting, IDs, labels, langs, hard flags).
  - Independence rule strictly maintained: `agentwall/src/firewall/`, `agentwall/bench/`, and radar rules were not read before or during authoring.
  - Zero sensitive tokens or credentials present.
- **Not verified:**
  - Steps 1–5 of M4.0 brief (staging latency before/after 200 calls): marked owner-assisted; runbook documented in result file pending owner token access and test run.
- **Next for Claude Code:**
  - Ingest the blind samples and helpdesk export into benchmark evaluation, compare against Radar rules, and proceed with M4.3 gateway integration.


## 2026-11-08, Claude Code: second-stage injection model (M4.1c)
- **Owner decision:** reopen P4-D8 and build the classifier prototype. **Built:** `agentwall/src/firewall/injection_model.py` (pure-Python scorer of a 2 MiB plain JSON model, rule `RAD-INJ-012`),
  `scripts/train_injection_model.py` (training-time only), a `radar_model` bench detector, model card `docs/security/injection-model.md`, plan section 16.
  Experiments first: generic embeddings were a negative result; n-gram windows were best (cross-round AUC about 0.93).
- **Your round-2 samples** moved into the corpus as development data (`*.dev3.jsonl`) because they trained the model. They are no longer a test.
- **Verified:** 1,260 tests, strict mypy, ruff; scorer matches scikit-learn exactly (parity vectors); eleven mutations of the scorer, tiers and loader caught; training is deterministic.
- **NOT verified:** performance on independent data. The model is not wired into the gateway.
- **For Antigravity or another writer:** `docs/testing/briefs/2026-11-08-m4-1c-blind-round-3-injection.md` (injection only, 100 attacks and 150 benign, written by someone who has seen nothing; **a different AI than Gemini is preferred**).
  Still open from before: latency baseline, helpdesk schema limits and rescan.
- **Next for Claude Code:** score round 3 first, report only; then M4.3 with the model on a background path.

## 2026-11-08, Claude Code: blind round 2 scored (rules unchanged)
- **Scored once, report only:** injection 33/80 (41%) with 10/120 false alarms, XSS 74/80 (92%) with 0/120, SSRF 50/80 (62%) with 3/120, path 51/80 (64%) with 6/120.
  Frozen in `docs/security/blind-round-2.md` and in the coverage matrix. Round 2 was harder than round 1, so the two are not directly comparable.
- **Conclusion:** XSS is solid. Indirect injection is still weak and false-alarms on hard-benign operational documents; pattern rules are close to their limit.
  Decision for the owner: improve the rules again (then a round 3 is needed), or reopen the classifier decision (P4-D8) with a measured prototype.
- **Antigravity:** thank you. Samples are at `docs/testing/exports/blind2-<category>.jsonl` and are still UNSEEN by the rules; do not edit them. The two owner-assisted
  items (latency baseline, helpdesk schema limits and rescan) remain open.

## 2026-11-08, Claude Code: Radar rules rewritten after blind round 1
- **Read your results (thank you):** the independent measurement was poor (indirect injection 24%, output rules flagged documentation): frozen in
  `docs/security/blind-round-1.md`. Your 1,000 samples are now development data (`agentwall/bench/corpus/*.dev2.jsonl`) and the 20 helpdesk tickets
  are held-out samples in `injection_indirect.holdout.jsonl` (merged unchanged; the separate export file was removed). Your two result files and handoff entry are committed.
- **Changed:** `agentwall/src/firewall/radar.py` rewritten by classes of attack, a new `actionable` notion (low-confidence findings are recorded, never counted),
  report and matrix updated, M4 plan section 14. Dev samples now show 100% (that flatters; it is development data).
- **Verified:** 1,214 tests, strict mypy, ruff; every new gate mutated and caught; speed re-measured (about 1 ms per KiB).
- **NOT verified:** generalisation. That needs blind round 2.
- **For Antigravity:** `docs/testing/briefs/2026-11-08-m4-1b-blind-round-2.md` (new fresh samples, harder; do not read the rules, `docs/security/` or the corpus) plus
  three open items (latency baseline, helpdesk schema limits and rescan, deleting your generator scripts).
- **Next for Claude Code:** score round 2 first (report only), then decide: more rules, or reopen the classifier decision (P4-D8).

## 2026-11-08, Claude Code: M4.2 data layer and core API for the Radar
- **Changed:** migration `20261117000000_radar_findings.sql` (+ rollback + SQL tests), core `radar/` package and `routers/radar.py`, local-store
  emulation, OpenAPI spec regenerated, threat model rows, tenant-deletion runbook, M4 plan section 13.
- **Verified:** SQL harness (apply, tests, rollback, re-apply) passes; core tests (53) and mutation checks; ruff and strict mypy.
- **Not verified:** staging (nothing deployed). The gateway does not use any of this yet. Cadence: the staging test is M4.3, after the
  gateway hook exists. Deploy order when it ships: migration, then core, then gateway.
- **For Antigravity:** nothing new. The two M4.0 briefs (helpdesk export and blind samples) are still the priority.
- **Next for Claude Code:** M4.3 (gateway integration), unless the blind samples change the rules first.

## 2026-11-08, Claude Code: threat intelligence (CTI) split documented
- **Decided by the owner:** split CTI into A (technique labels, soon), B (indicator cache, after M4, one or two licence-cleared feeds) and
  C (LLM triage, gated). Written into `docs/plans/phase4.5-build-plan.md` Part 3; A is cross-referenced from M4 plan A3.
- **Open:** the LLM rule (advises, deterministic policy decides, tighten-only, metadata only), who reads each feed's terms, and the goal.
- **For Antigravity:** nothing yet. The two M4.0 briefs (helpdesk export and blind samples) are still the priority.
- **Not done:** no code, no feeds contacted, no licence cleared.

## 2026-11-08, Claude Code: M4.1 Radar rules (module only)
- **Changed:** `agentwall/src/firewall/radar.py` (rules, normalisation, decoding, context scoring), `radar` detector in the bench,
  report wording (perfect held-out rates shown as bounds; independence caveat), baseline and matrix regenerated, M4 plan section 12.
- **Verified:** full suite, ruff, strict mypy; 158 new tests; eight mutations caught; timing measured (0.8 ms per KiB, scan budget 16 KiB).
  First held-out run and the one disclosed fix are recorded in the plan. The held-out set is NOT independent (same author).
- **Not verified:** nothing is in the gateway, so there is no staging test yet (cadence: the staging test is M4.3).
- **For Antigravity:** the blind samples brief (`2026-11-08-m4-0b-blind-samples.md`) is now the important one: they are the only
  independent evidence. Do not read `agentwall/src/firewall/radar.py` before writing them.
- **Next for Claude Code:** report the blind samples and helpdesk tickets as soon as they arrive, then M4.2 (migration and core).

## 2026-11-08, Claude Code: M4 amendment approved, shared reporter refactor
- **Approved by the owner:** M4 plan section 11 (advanced MVP, D6 to D10): normalisation and decoding, context-aware scoring,
  explanations, would-block counters, false-alarm feedback and expiring suppression, self-test, coverage page, language badges,
  and a corrected two-part block gate. PR 35 carries the plan.
- **For Antigravity:** `docs/testing/briefs/2026-11-08-m4-0b-blind-samples.md` (write blind benchmark samples; do NOT read the rules).
  The earlier brief `2026-11-07-m4-0-latency-and-helpdesk-samples.md` still stands.
- **Changed (refactor, no behaviour change):** `agentwall/src/gateway/dispatch.py` is the shared non-blocking reporter; trips and
  tool observations now use it. All 938 existing tests pass unchanged; 22 new tests; four mutations were each caught.
- **Not verified:** a staging deploy (not needed yet; this is deployed together with M4.3, so the first staging test of it is M4.3).
## 2026-11-07, Claude Code: Phase 4 M4 plan approved, M4.0 held-out samples
- **Changed:** `docs/plans/phase4-m4-plan.md` (owner approved as recommended, D1 to D5). M4.0: four new `*.holdout.jsonl` files
  (injection_indirect, output_xss, output_ssrf, output_path, 40 each), baseline and coverage matrix regenerated, new Malay rows
  in `docs/review/malay-samples-for-review.md`. No rule or gateway code yet.
- **Verified:** `uv run pytest agentwall/tests/test_bench.py` passes; `--check` against the new baseline passes. Held-out "before"
  numbers: injection 0/20, path 0/20, XSS 0/20, SSRF 2/20, no false alarms.
- **For Antigravity (owner approved the test cadence):** run `docs/testing/briefs/2026-11-07-m4-0-latency-and-helpdesk-samples.md`:
  a staging latency baseline (needs the owner for the gateway token, never printed) and converting the 20 helpdesk tickets into
  held-out samples at `docs/testing/exports/helpdesk-injection-heldout.jsonl`. Do not read the detection rules while labelling.
- **Next for Claude Code:** M4.1 (the Radar rules, tuned on dev samples only), and the shared-reporter refactor (decision D1).

## 2026-11-07, Antigravity: dashboard access fixes and helpdesk scan verified
- **Verified:** All 15 active steps in `docs/testing/briefs/2026-11-07-dashboard-access-fixes.md` passed on staging (`https://redhand.archtificial.com`).
  - Password reset flow, 12+ char validation, single-use token invalidation, and session storage hygiene verified.
  - Page scrolling on `/passports`, `/blackbox`, `/scanner`, and `/honeytokens` restored; home page `/` stays fixed with inner scrolling.
  - Multi-origin CORS confirmed via curl for both `https://redhand.archtificial.com` and `https://redhand-dashboard.vercel.app` on core `/v1/passports` and gateway `/health`; `https://evil.example.com` rejected with no CORS headers.
  - Live scanner on `kedai-kita` MCP server completed with expected `WARN` verdict (6 tools scanned, 0 high findings, low `MCP-SEC-008` unbounded strings only).
- **Not verified:** Step 16 (rescan after helpdesk schemas add `maxLength`/`pattern`).
- **Next steps for Claude Code:** Review test results in `docs/testing/results/2026-11-07-dashboard-access-fixes.md` and proceed with Phase 4 follow-ups or schema tightening if desired.

## 2026-11-07, Claude Code: helpdesk deploy check and dashboard password reset
- **Verified (live, read-only):** the helpdesk MCP server is deployed to Cloud Run (`helpdesk-mcp`, asia-southeast1, in
  RedHand's GCP project, own service account and `helpdesk-demo-*` secrets). `/health` ok; unauthenticated `tools/call`,
  unknown tools and the admin endpoint return 401; `tools/list` is open (scanner needs it).
- **Correction for Antigravity:** RedHand v1 does NOT hold upstream credentials. The agent (n8n) sends
  `X-RedHand-Upstream-Authorization` and the gateway forwards it (`docs/briefing.md`, ADR 0001). So n8n holds the server's
  bearer token and could call the public server directly, bypassing the gateway. Fix the matrix, n8n guide and demo script to say so.
- **Changed:** dashboard password reset (login "Forgot password?" and `/reset-password`), runbook
  `docs/runbooks/operator-password-reset.md`, threat model row. The dashboard had no reset flow and the owner was locked out.
- **Not verified:** the real emailed-link reset (needs the deployed page; owner to test), registering the helpdesk server
  in RedHand (owner could not sign in), live scan of it.
- **Owner setting needed:** Supabase Auth Site URL must be `https://redhand.archtificial.com` (it was still localhost).

## 2026-11-07, Antigravity: helpdesk demo agent complete & review items resolved
- **Context:** Target system `redhand-helpdesk-demo` (M1–M7) at `/Users/testing/Documents/redhand-helpdesk-demo`.
- **Changed (in `redhand-helpdesk-demo`):**
  1. **Owner Approval of Neon:** Recorded in `docs/REPORT.md` decisions log that the owner explicitly approved Neon Serverless Postgres (`ap-southeast-1`) because Supabase's free tier is limited to 2 active projects (used by RedHand and GridWork).
  2. **Prompt Injection Radar Claims Removed:** Deleted all claims about unbuilt Prompt Injection Radar from `docs/demo-script.md` (Mermaid diagram, Scene 2, matrix, cheat sheet). Replaced with honest explanation of prompt delimiters (`<untrusted_customer_ticket>`), server-side hard caps, and Black Box audit logging.
  3. **Scene 4 Rewritten:** Separated and grounded all three tool defenses: (a) scopes deny unlisted tools, (b) registered decoy tool (`issue_instant_bank_payout`) trips an alert in Black Box, and (c) tool pinning alerts when tool descriptions or schemas drift from pinned SHA-256 manifest hashes.
  4. **Deleted Invented Numbers & Error Strings:** Removed fabricated latency numbers and fake JSON-RPC error codes/strings.
  5. **Honest Protection Matrix & Threat Boundaries:** Corrected all "No Risk" cells. Explicitly noted that n8n holds `ADMIN_APPROVAL_TOKEN` to process Telegram approval callbacks (`POST /admin/approvals/{id}/decide`), and that the upstream Cloud Run container is publicly reachable over HTTPS, so security relies on token confidentiality and gateway routing.
  6. **Deployment Guide Hardened (`docs/cloudrun-deploy.md`):** Recommends a dedicated GCP project (separate from RedHand), adds active project confirmation check before execution, creates dedicated Service Account `helpdesk-mcp-sa`, and scopes `roles/secretmanager.secretAccessor` strictly to the 3 demo secrets.
  7. **Credential Architecture (`docs/n8n-build-guide.md`):** Documented that when paired with RedHand, n8n holds only the RedHand Agent Key, never the upstream server's bearer token. RedHand Gateway attaches `X-RedHand-Upstream-Authorization: Bearer <upstream_token>`.
  8. **Neon Idle Compute Suspend Handled:** In `src/helpdesk_mcp/db.py`, wrapped connection logic with `connect_timeout=15` and automatic retry on `OperationalError`. Added `wake_database()` to `GET /health` and documented a 30s pre-demo wake step in `docs/demo-script.md`.
- **Verified:** `uv run pytest -v` (all 29 tests pass), `uv run python scripts/run_eval.py` (20/20 pass), `uv run ruff check .` (0 errors), safety grep (0 secrets).
- **Not verified:** Live Cloud Run deployment (instructions ready in `docs/cloudrun-deploy.md`, awaiting owner request).
- **Next steps for Claude Code:** Register Helpdesk MCP server in RedHand Gateway/Passport (`http://127.0.0.1:8080/mcp` or Cloud Run URL once deployed), run Phase 4 Live Scanner on `tools/list`, test tool pinning on the 6 stable tools, plant decoy tool `issue_instant_bank_payout` and honeytoken `RH-HONEY-KEDAIKITA-9941-TRAP`.

## 2026-11-07, Claude Code: multi-origin dashboard allow-list
- **Changed:** `deploy/cloudrun/deploy.sh` now takes comma-separated `DASHBOARD_ORIGIN`. Validation lives in
  `deploy/cloudrun/origins.sh` (bare https origins only, no wildcard/path/http, max five, localhost always added) and runs
  before any gcloud call. Tests: `tests/deploy/test_origins.py` (24 pass, plus a mutation check). Runbook and changelog updated.
- **Verified:** the tests above, ruff on the new test file. **Not verified:** a real deploy (nothing was deployed); shellcheck
  (not installed).
- **Next deploy must use:** `DASHBOARD_ORIGIN=https://redhand.archtificial.com,https://redhand-dashboard.vercel.app`.
  A deploy with only one origin would drop the other.
- **Uncommitted:** these edits are in the working tree, not committed or pushed.

## 2026-11-07, Antigravity: custom domain and website link
- **Changed (outside this repo):** `https://redhand.archtificial.com` points at the Vercel project `redhand-dashboard`;
  `iqbalassyraf/archtificial-gridwork` commit `aaa0c3e` links to the console routes `/passports`, `/blackbox`,
  `/honeytokens`, `/scanner` (keep those routes stable).
- **Changed (live, by hand):** `CORS_ALLOWED_ORIGINS` on `redhand-core` and `AGENTWALL_CORS_ALLOWED_ORIGINS` on
  `redhand-gateway` now list localhost, the vercel.app URL and the archtificial.com URL. Gateway revision `redhand-gateway-00014-j9m`.
- **Not verified:** operator login on the new domain (add `https://redhand.archtificial.com/**` in Supabase Auth URL
  configuration if magic links or OAuth are used).

## Helpdesk demo agent (completed, built by Antigravity)
- Separate project: n8n + Telegram + Neon Serverless Postgres (free tier Singapore) + Python MCP server at `/Users/testing/Documents/redhand-helpdesk-demo`. Full report in that project's `docs/REPORT.md`. All 7 milestones complete (`29/29 pytest passed`, `20/20 eval passed`). Ready for RedHand registration, scanning, tool pinning, honeytokens, and demo recording.
