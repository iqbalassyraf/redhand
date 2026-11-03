# Phase 2 plan: "Stop things"

**Status:** Approved 2026-11-03. Milestones are shippable one at a time.

**Goal:** an owner can stop agents from their phone, put them into read-only mode, and cap what they
can do.

## Done tests
1. An owner sends `/freeze_all` in Telegram and every agent is denied within 5 s; the audit log shows
   who and that it came via Telegram.
2. With Safe Mode on, a read call succeeds and a write call is refused.
3. An agent over its daily limit is refused and the owner is alerted.

## Milestones
| | Milestone | Status |
|---|---|---|
| M0 | Restrict core `/metrics`; dashboard polish (scope editor, zero-scope warning, server names in the audit log) | Done |
| M1 | Telegram panic command and alerts | Built and tested locally; not yet run against a real bot or staging |
| M2 | Safe Mode | Built and tested locally; not yet on staging |
| M3 | Budget Guard (tool-call caps, not LLM spend) | Not started |
| M4 | Dashboard, docs, staging verification | Not started |

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
