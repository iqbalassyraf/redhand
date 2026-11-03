# ADR 0008: Telegram panic command

- **Status:** Accepted (2026-11-03)
- **Phase:** 2 (M1)
- **Plan:** `docs/plans/phase2-plan.md`

## Context
Phase 2 is "stop things". The most valuable stop is the one an owner can trigger from a phone when
they are away from the dashboard. Small customers already use Telegram and WhatsApp.

## Decision
A Telegram bot receives commands on a webhook in redhand-core.

- **Who may act:** a chat acts only when it is linked to an operator. An admin or owner creates a
  one-time code in the dashboard (10 minutes, single use, stored hashed, rate-limited) and sends it
  to the bot. Linking, the single-use consumption and the audit row happen in one database function.
- **Authorization on every command:** the operator's role is re-read from `organization_members`
  each time. Demoting or removing someone stops their phone immediately. Admin or owner is required,
  the same as freeze-all in the dashboard.
- **Stop only:** `/freeze_all`, `/freeze <name>` and `/status`. Unfreeze, revoke and scope changes
  stay in the dashboard because they need explicit confirmation (CLAUDE.md §5.3). A stolen phone can
  therefore stop agents but not start them.
- **Webhook trust:** `X-Telegram-Bot-Api-Secret-Token` compared in constant time, 64 KB body limit,
  private chats only, update ids de-duplicated, per-chat rate limits. Telegram's request is parsed
  only after the secret is verified.
- **Audit:** the freeze is the existing atomic `control_freeze_all` / `control_agent_change`, with the
  reason prefixed `via Telegram:`. Link and unlink events are new audit actions.
- **Alerts:** other linked chats are told about freezes, and dashboard freezes, unfreezes, revokes
  and freeze-all are sent to linked chats. Alerts are sent after the action, are best effort, give up
  after 3 seconds and can never fail the action.
- **Failure behaviour:** every command is answered. If something fails the reply says the command was
  NOT carried out and to use the dashboard. The webhook still answers 200 so Telegram does not
  redeliver old commands.
- **Secrets:** the bot token never reaches a log (Telegram puts it in the URL, so httpx's request
  logging is disabled in this module and errors are logged by class only). Both secrets live in Secret
  Manager.

## Alternatives
- **WhatsApp first:** needs Meta business verification and costs per conversation. Telegram is free.
  The command layer is channel-independent, so WhatsApp can be added later.
- **Allow `/unfreeze` over chat:** convenient, but lets a stolen phone restart agents.
- **Trust the Telegram user id without linking:** anyone could message the bot; rejected.
- **Queue and retry commands:** a delayed freeze is worse than a clear failure message.

## Consequences
- Core must be reachable by Telegram over https. With Cloud Run scaled to zero the first command after
  idle takes a few seconds; keeping one instance warm is a cost decision for later.
- Anyone holding an unlocked linked phone can freeze all agents. That is the intended trade: stopping
  is cheap and reversible, and unfreezing needs the dashboard.
- Telegram sees the agent names in alert text. Messages are plain text, never formatted, so a name
  cannot inject markup. Do not put sensitive data in agent names.
- New tables hold chat ids (personal data). Chat ids are never returned by the API; update ids are
  purged after 7 days.
