# ADR 0006: Control actions are single database transactions

- **Status:** Accepted (2026-11-02)
- **Phase:** 1 (hardening)
- **Plan:** `docs/plans/atomic-control-actions.md`

## Context
Each control action wrote its state change and its audit row as separate statements. If the second
failed, the agent was already frozen or revoked but unrecorded, which breaks "auditable control
actions" (CLAUDE.md §4.9).

## Decision
Four Postgres functions apply the change and write the audit row in one transaction
(`control_agent_change`, `control_freeze_all`, `control_create_passport`, `control_mcp_server`).
redhand-core keeps the decisions and calls them through `rpc`. A compare-and-set on the status
read by core guards against concurrent changes: the action is re-decided once from fresh state,
then fails with 409. Execute rights are limited to `service_role`.

## Alternatives
- **Compensate in Python:** still leaves a gap on a crash, and undoing a freeze could re-enable
  an agent.
- **Audit by trigger:** also catches out-of-band edits, but the actor and reason still need an RPC
  inside the same transaction. A possible later addition.
- **All logic in SQL:** duplicates the state machine in two languages.

## Consequences
- A failed audit write now fails the action (nothing applied) instead of leaving an unrecorded
  change. For a freeze this means it can fail while the audit table is unwritable; the gateway is
  denying everything in that situation anyway.
- The local development store emulates the functions all-or-nothing, and a test replays real
  recorded calls against PostgreSQL to keep the two in step.
- `AuditWriteError` and its runbook are gone.
