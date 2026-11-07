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
