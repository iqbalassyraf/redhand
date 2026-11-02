# Plan: atomic control actions (action and audit entry in one transaction)

**Status:** Draft, awaiting approval. No migration or code has been written.
**Follows up:** `docs/plans/phase1-plan.md` §9, item 1.

## 1. Goal
Every control action (register, freeze, unfreeze, revoke, freeze-all, scope change, renew, key
rotation, MCP server register/deactivate) and its `control_audit_log` row commit together or not
at all. This serves "done" tests 3 and 4: a freeze or revoke can never exist without its audit
record, and an audit record can never describe an action that did not happen (CLAUDE.md §4.9).

## 2. Current state
- `redhand_core/passports/service.py` applies the state change with one PostgREST call, then
  inserts the audit row with a second call (`write_audit`). If the second fails, core logs an
  error and returns HTTP 500 although the agent is already frozen or revoked
  (runbook: `docs/runbooks/control-action-audit-failure.md`).
- `routers/passports.py` has the same two-step pattern for MCP server register/deactivate.
- Passport creation and key rotation make three writes (agent, key, audit); revoke makes three
  (agent, key deactivation, audit).
- The local dev store (`services/local_store.py`) mirrors table operations, not transactions.

## 3. Approach
Add Postgres functions called with `supabase.rpc(...)`, so one call is one transaction. Python
keeps the decision logic (state machine, confirmation rules, scope-expansion check); the functions
only **apply changes and write the audit row**, with a compare-and-set guard.

| Function | Does |
|---|---|
| `control_agent_change(p_org, p_agent, p_actor, p_action, p_expected_status, p_changes, p_deactivate_keys, p_new_key, p_reason, p_details)` | Locks the agent row (`FOR UPDATE`), checks it belongs to `p_org` and (when given) still has `p_expected_status`, applies only whitelisted columns (`status`, `status_reason`, `scopes`, `expires_at`), optionally deactivates keys and inserts one new key hash, inserts the audit row. Returns the updated row. Used by freeze, unfreeze, revoke, scopes, renew, rotate-key. |
| `control_freeze_all(p_org, p_actor, p_reason)` | One `UPDATE ... WHERE organization_id = p_org AND status = 'active' RETURNING id`, then the audit row listing the ids. |
| `control_create_passport(p_org, p_actor, p_agent, p_key, p_details)` | Inserts agent, key hash and audit row. |
| `control_mcp_server(p_org, p_actor, p_op, p_server, p_server_id)` | Registers or deactivates a server and writes the audit row. |

- **Conflicts:** if the expected status no longer matches (another operator acted in between),
  the function returns `conflict: true` and core re-reads once and re-decides, else returns 409.
- **Keys:** only the SHA-256 hash is passed to the database; the plaintext key never leaves core.
- **Local dev store:** gains an `rpc()` that applies the same steps on a copy of its tables and
  swaps the copy in only on success, so tests exercise the all-or-nothing behaviour.

**Alternatives considered**
1. *Compensate in Python* (undo the state change if the audit insert fails): rejected. A crash
   between the two steps still leaves the gap, and undoing a revoke or freeze could re-enable an
   agent.
2. *Audit by database trigger on `agents`*: attractive because it also catches out-of-band edits,
   but the actor and reason still have to reach the database inside the same transaction, which
   again needs an RPC. Kept as a possible later hardening, not part of this change.
3. *All logic in SQL functions*: rejected. It duplicates the state machine in two languages and
   makes tests harder.

## 4. Changes
- New migration `supabase/migrations/20261102000000_atomic_control_actions.sql` and rollback
  `supabase/rollbacks/20261102000000_atomic_control_actions.down.sql`.
- `redhand_core/passports/service.py` and `routers/passports.py`: replace `write_audit` plus
  separate updates with the RPC calls; delete `AuditWriteError` and its 500 handling.
- `services/local_store.py`: `rpc()` emulation.
- Tests: new SQL-level tests (psql against a throwaway PostgreSQL 16, as for the Phase 1
  migration) and updated Python tests.
- Docs: replace `control-action-audit-failure.md` with a short note that failures now roll back;
  update `docs/security/threat-model.md` and the OpenAPI export if responses change.

## 5. Security impact
- No new trust boundary. The functions are callable only by `service_role` (execute revoked from
  `PUBLIC`, `anon`, `authenticated`), use `SET search_path = public, pg_temp`, and use only
  parameters (no dynamic SQL), so operators cannot reach them directly.
- Tenant isolation is enforced inside every function (`organization_id = p_org`), in addition to
  core's own scoping. A foreign agent id behaves as not found.
- Fail closed: any error rolls back the whole action, so a failed audit write means the action
  did not happen and the API returns an error. For a *freeze* this is a safe-side trade-off to
  note: if the audit table is unwritable, freezes fail too. Mitigation: freeze-all and freeze
  stay available through the same path, and database health is a prerequisite of enforcement
  anyway (the gateway already denies when core cannot read passports).

## 6. Data and migrations
Additive only (new functions); no table or column changes, so it is backward compatible with the
deployed code. Rollback drops the four functions. Tested on PostgreSQL 16 up, rollback and
re-apply, then applied to the staging Supabase project.

## 7. Tests
- Atomicity: force the audit insert to fail (invalid action value, then revoked privileges) and
  assert the agent row, keys and version are unchanged.
- Each function: allowed case; wrong tenant; unknown agent; revoked agent cannot be reactivated;
  expected-status mismatch returns conflict; unknown column in `p_changes` is rejected;
  freeze-all touches only the caller's active agents.
- Python: every existing passport and e2e test must keep passing unchanged except where they
  asserted the old 500 behaviour; add a test that an injected audit failure leaves the agent state
  untouched.
- Run the same functions against the staging Supabase project and check the results.

## 8. Cost and performance
No new infrastructure. Control actions go from 2–3 round trips to 1, so slightly faster. No effect
on the gateway hot path.

## 9. Risks and open questions
- The Supabase Python client's `rpc` support must be confirmed in the locked version before
  implementation (check the source in `uv.lock`'s version, not memory).
- A freeze can now fail when the database is unhealthy (see §5). Accepted, because the gateway
  would be denying everything in that situation anyway.
- Question for you: any objection to dropping the "action applied but audit failed" runbook
  entirely, rather than keeping it for historical reference?
