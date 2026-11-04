# Phase 2 M2 plan: Safe Mode

**Status:** Approved 2026-11-03 (all three open decisions approved as recommended).
Design and rationale: `docs/adr/0009-safe-mode.md`.

**Goal:** an operator can put one agent, or the whole organization, into Safe Mode; the gateway then
allows only tools declared read. Phase 2 done test 2.

**Decisions taken:** new scopes default to write in the dashboard form (the API default is unchanged);
Safe Mode also filters `tools/list`; turning it off needs an admin and confirmation.

**Delivered:** migration `20261104000000_safe_mode` with rollback and SQL tests; core endpoints
(`POST /v1/passports/{id}/safe-mode`, `GET` and `POST /v1/organization/safe-mode`); the gateway check;
`/safemode on` in Telegram; dashboard controls; end-to-end test; benchmark.

**Evidence (local, 2026-11-03):** full suite and end-to-end tests pass; every protection was broken in
turn and made tests fail; benchmark warm p50 0.82 ms / p99 1.80 ms, cold p50 1.15 ms / p99 2.77 ms
(budget 10 ms / 50 ms), revocation 2.03 s.

## Staging verification (2026-11-04)
Run by the project owner on staging (Cloud Run, Supabase, Vercel dashboard, Telegram) with two agents
against the real DeepWiki MCP server: a write agent (`ask_question` declared write) and a read agent
(`read_wiki_structure` declared read), each watched by `scripts/staging_agent.py`. Times are local
(UTC+8); the audit log has whole-second resolution.

| Check | Result |
|---|---|
| Organization Safe Mode on: write agent refused with "Safe Mode is on and tool 'ask_question' is not read-only", read agent unaffected | Passed (2026-11-04 07:06 and again 17:21) |
| Organization Safe Mode off: write agent works again | Passed (off at 17:17:53, resumed 17:18:05) |
| One agent on: only that agent stops, the other keeps working | Passed (on at 17:19:36, stopped 17:19:39) |
| One agent off: it works again | Passed (off at 17:20:50, resumed 17:21:01) |
| Read agent kept working through every organization-wide Safe Mode period, including the one started by phone | Passed (no refusal logged in its window) |
| Telegram `/safemode on`: replies "Safe Mode is on for all agents…" and the write agent stops | Passed (17:21:29, stopped 17:21:34) |
| Telegram `/status` shows "Safe Mode for all agents: on" | Passed |
| Telegram `/safemode` with no argument shows usage; `/safemode off` is refused ("only available in the dashboard") | Passed |
| Every change is audited with actor and reason, and linked phones are alerted to dashboard changes | Passed |

**About the delays.** The watcher polls every 5 s and `ask_question` takes 5 to 10 s to answer, so the
refusal and resume times above are dominated by the watcher, not the gateway. In every case the first
call that started after the change was refused or allowed correctly, which is consistent with the
gateway's 2 s cache window. The measured gateway-side bound is the local benchmark (revocation-style
propagation 2.03 s). A tighter on-staging measurement would need a fast tool declared write; it was
not done.

**Not verified:** the Safe Mode button's behaviour for an agent that is revoked or expired; Safe Mode
across several gateway instances (staging runs one).
