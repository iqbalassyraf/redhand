# Phase 2 plan: "Stop things"

**Status:** Complete (2026-11-04). All milestones shipped and verified on staging.

**Goal:** an owner can stop agents from their phone, put them into read-only mode, and cap what they
can do.

## Done tests
**All three passed on staging (2026-11-04).** Notes per test are in the milestone files.

1. An owner sends `/freeze_all` in Telegram and every agent is denied within 5 s; the audit log shows
   who and that it came via Telegram.
2. With Safe Mode on, a read call succeeds and a write call is refused.
3. An agent over its daily limit is refused and the owner is alerted.

## Milestones
| | Milestone | Status |
|---|---|---|
| M0 | Restrict core `/metrics`; dashboard polish (scope editor, zero-scope warning, server names in the audit log) | Done |
| M1 | Telegram panic command and alerts | Done: verified on staging with a real bot and phone |
| M2 | Safe Mode | Done: verified on staging 2026-11-04 (`docs/plans/phase2-m2-safe-mode.md`) |
| M3 | Budget Guard (tool-call caps, not LLM spend) | Done: verified on staging 2026-11-04; organization default limit added (`docs/plans/phase2-m3-budget-guard.md` sections 12 and 13) |
| M4 | Dashboard, docs, staging verification | Done: usage view and limit editor shipped with M3; docs and staging results recorded |

## Decisions taken (defaults, since no answer was given)
- Telegram first; WhatsApp later only if customers ask.
- Budgets count tool calls. Dollar budgets would need model traffic routed through RedHand.
- A limit denies and alerts by default; auto-freeze is an opt-in per agent (M3).
- No always-on instance yet. Cold start of the first command after idle is measured in M1 staging
  verification and the warm-instance cost decision is made then.

## M1 design
See `docs/adr/0008-telegram-panic-command.md`, `docs/security/threat-model.md` and
`docs/runbooks/telegram-panic-command.md`.

## Still open from earlier
Rename an agent; actor email in the audit log (core returns only the user id).
