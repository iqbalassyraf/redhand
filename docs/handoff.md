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

## Helpdesk demo agent (in progress, built by Antigravity)
- Separate project: n8n + Telegram + Supabase (its own project) + a Python MCP server. Progress is in that project's
  `docs/REPORT.md`; paste it to Claude Code when a milestone finishes. Plan: register its MCP server in RedHand, then
  scan, pin, plant honeytokens and decoy tools, and record the demo.
