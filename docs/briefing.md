# RedHand Starter Suite: product briefing

Source of truth for product scope and phase plan (CLAUDE.md §2). Changes need human approval.

## What RedHand is
A security and control layer for AI agents, packaged as a **Starter Suite** for small teams and
SMEs, initially in Malaysia and Southeast Asia, priced per agent at the low end of the market
(pricing to be decided once the suite is scoped). Owners live in WhatsApp, so chat-based control
(WhatsApp/Telegram) is a selling point.

## Core constraint
Cost to serve must stay a small fraction of the per-agent price. Prefer rules, lookups, static
analysis and templates. Any per-event LLM use needs an explicit cost estimate and approval.

## Phases (each sellable on its own)
| Phase | Theme | Features | Status |
|---|---|---|---|
| 1 | Identity & control | Agent Passport, one-click revoke, dashboard kill switch, MCP gateway | **Built** (see below) |
| 2 | Stop things | Budget Guard, Safe Mode, WhatsApp/Telegram panic command | **Complete** (2026-11-04) |
| 3 | See things | Black Box Recorder, Honeytokens | In progress: Black Box M1 done + M2a/M2b; M2c, M3, M4 next (`docs/plans/phase3-plan.md`) |
| 4 | Check inputs | MCP Scanner (servers/skills/packages), Prompt Injection Radar, output-handling checks, system-prompt canaries, secret-in-prompt scanning, RAG protection, loop/rate limits, OWASP coverage matrix | Plan drafted (`docs/plans/phase4-plan.md`); seeds exist (`/v1/mcp/vet`, egress guardrail, `redhand scan`). All deterministic — no external LLM on the hot path |
| 4.5 | Model proxy (evaluation) | Dollar/token budgets, user-input injection checks, output-stream inspection, approved-model enforcement | Evaluation only, separate go/no-go (`docs/plans/phase4.5-model-proxy.md`); changes RedHand's latency/cost/uptime profile |
| 5 | Prove it | Compliance reports, Trust Score | Not started |
| Parked | Higher tiers | Red Team service, Shadow Agent Finder, Cross-agent firewall, Policy marketplace | Fuzzer exists in `redhand-sdk` |

## Product truth
RedHand only controls what flows through RedHand. Agents holding raw credentials or direct access
outside the gateway are not covered. Copy must say "RedHand covers agents connected via RedHand."

## Phase 1 decisions (2026-11-01)
| Question | Decision | Record |
|---|---|---|
| Control point | MCP gateway (AgentWall), fail closed | ADR 0001 |
| MCP only for v1? | Yes. Remote (HTTP) MCP servers; local stdio servers later | ADR 0001 |
| Passport storage | Extend `public.agents` | ADR 0002 |
| Agent credentials | Agent key → 10-minute Ed25519 access token | ADR 0003 |
| Revocation | Per-call status lookup, ≤ 2 s cache, ≤ 5 s SLO | ADR 0004 |
| Operator login and tenancy | Supabase Auth; tenant from membership | ADR 0005 |
| Who holds upstream credentials (v1) | The customer/agent (`X-RedHand-Upstream-Authorization`); RedHand brokering is Phase 1.5 | ADR 0001 |
| Hosting | Hosted first; staging on Google Cloud Run in `asia-southeast1` (free tier), Supabase in Singapore; self-host via existing sidecar/Helm later | Staging: `docs/runbooks/cloud-run-staging.md` |
| Where customers' agents run | To be validated with 5–10 Malaysian SMEs | Open |
| Starter-tier gating of enterprise features (SCIM, multi-cloud STS, Helm, OCSF) | Gate by tier, don't delete | Open |

## Phase 1 "done" tests
1. Register an agent → passport visible with owner, scopes, expiry.
2. Agent connected via gateway → in-scope MCP call succeeds; out-of-scope call denied and logged.
3. Revoke one agent → its next call fails within the revocation SLO (5 s).
4. Freeze all → every agent in the tenant is denied; the audit log records it.

All four pass end to end in `tests/e2e/test_phase1_done.py`.
