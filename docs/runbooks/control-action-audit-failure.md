# Runbook: "The action was applied, but its audit record could not be written"

**Meaning:** a freeze, revoke or other control action changed the passport, but the insert into
`control_audit_log` failed. Safety took priority, so the agent's state did change.

1. Find the error in core logs: `Control action applied but audit write failed: action=... target=...`.
2. Check database health and permissions on `control_audit_log`.
3. Record the missed entry manually through the normal insert path (never by editing existing
   rows; the table is append-only by trigger), with a reason that references this incident.
4. Follow-up: moving each control action into a single SQL transaction removes this window.
