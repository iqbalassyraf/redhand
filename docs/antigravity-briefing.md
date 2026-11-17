# Briefing for Antigravity: RedHand and the Helpdesk demo agent

Written 2026-11-07 by Claude Code. Read this first, then `docs/handoff.md`, `CLAUDE.md` and `docs/briefing.md` in the
RedHand repo (`iqbalassyraf/redhand`, local path `/Users/testing/Documents/project-redhand`). It contains no secrets and
you must never add any.

## 1. What RedHand is
A security and control layer for AI agents, aimed at small teams and SMEs in Malaysia and Southeast Asia. Agents reach
their tools (MCP servers) through the RedHand **gateway**, which checks the agent's **passport** on every call.
RedHand only controls what flows through the gateway (or what an owner submits to the scanner). Never write copy or
code that implies protection beyond that.

## 2. What is built (all merged to `main`, running on staging)
| Phase | Built |
|---|---|
| 1 Identity & control | Agent passports, scopes, revoke, freeze, freeze-all, multi-tenant isolation, gateway enforcement |
| 2 Stop things | Budget Guard, Safe Mode, Telegram panic command |
| 3 See things | Black Box Recorder (hash-chained timeline, optional redacted payload capture), honeytokens, decoy tools |
| 4 (M0 to M3) | Honest benchmark (`redhand bench`), MCP Scanner (description rules, live scan), tool pinning |
Not built yet: Prompt Injection Radar and output checks (M4), canaries/secret scanning (M5), loop detection (M6), the
"brain" (risk engine, model proxy), and Phase 5 compliance reports. Do not claim these exist.

## 3. Staging environment
- Dashboard: `https://redhand.archtificial.com` (also `https://redhand-dashboard.vercel.app`), Next.js on Vercel.
- Core (control plane): `https://<core-host>`; Gateway: `https://<gateway-host>`
  (The repository is public, so the real staging host names are not written in it. Ask the owner, or run `gcloud run services describe redhand-core --region <region> --format 'value(status.url)'`, and put them in `RH_CORE_URL` / `RH_GATEWAY_URL`.)
  (Cloud Run, `asia-southeast1`). Database: Supabase Postgres (RedHand's own project).
- Deploy order is strict: **migration, then core, then gateway**. Deploy with `deploy/cloudrun/deploy.sh`; it REPLACES all
  environment variables, so always pass them. The dashboard allow-list takes several origins and must list every one:
  `DASHBOARD_ORIGIN=https://redhand.archtificial.com,https://redhand-dashboard.vercel.app`.
- If you change a live setting by hand, write it in `docs/handoff.md` the same day and name the script that would undo it.

## 4. Rules that apply to you too
1. Plan before non-trivial changes; wait for the owner's "approved".
2. Fail closed. Tenant isolation is absolute.
3. Never print, log, commit or ask for secrets. Keys live in Secret Manager or a git-ignored `.env`.
4. Prove it: run tests and show real output. Say "not run" when you did not.
5. No commit, push, merge or deploy unless the owner asks. No production changes.
6. Stay in scope; note other problems instead of fixing them.
7. Claims must be backed by tests or real integrations. Mocked things are labelled as mocked.

## 5. The Helpdesk demo agent (your next job, separate repo or folder)
Goal: a real, minimal agent that doubles as a live demo for RedHand. Stack: **n8n** (AI Agent node) + **Telegram** +
**Supabase** (a NEW project, never RedHand's) + a Python **MCP server**. The owner has the full build prompt; the
essentials are:
- The agent touches data only through MCP tools: `search_kb`, `list_open_tickets`, `get_ticket`, `draft_reply` (draft
  only), `request_refund` (idempotency key, cap RM 500, approval above RM 100), `escalate`.
- Keep tool names and descriptions **stable**: RedHand pins them and alerts on change.
- In n8n, risky actions go only through the MCP Client node. Direct Supabase/HTTP/Gmail nodes as agent tools would
  bypass the gateway.
- 20 synthetic tickets, 8 of them attacks, saved as JSONL (RedHand will reuse them as benchmark samples).
- Synthetic data only. Keep `docs/REPORT.md` current and self-contained so the owner can share it with Claude Code.

## 6. How the two of you connect later (Claude Code does this part)
Once the MCP server is deployed and its URL is in `docs/REPORT.md`: register it as an MCP server in the RedHand
dashboard, run the scanner, approve the tool pins, register the n8n agent with scopes (read tools `read`,
`request_refund` `write`), plant a decoy tool and a honeytoken in a decoy ticket, then run the demo script.
`scripts/staging_agent.py` in the RedHand repo is a tested example of an agent calling a tool through the gateway.

## 7. Open items you should know about
- Supabase Auth redirect URLs may need `https://redhand.archtificial.com/**` if magic links or OAuth are used (untested).
- Native Bahasa Malaysia review of the Malay detection rules is still pending.
- Previously pasted agent keys were deactivated; never reuse keys found in old notes or chats.
