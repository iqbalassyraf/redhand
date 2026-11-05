# Runbook: deleting a tenant

`control_audit_log` rejects UPDATE and DELETE by trigger, so deleting an organization (which
cascades) fails while the tenant has audit rows. This is intentional: audit deletion must be a
deliberate, reviewed maintenance action.

1. Confirm the deletion request and the retention policy that applies (PDPA and contract terms).
2. Export the tenant's data if required.
3. In a reviewed maintenance window, as a database owner: disable the
   `control_audit_log_no_update` trigger **and the `trg_agent_events_append_only` trigger on
   `agent_events`** (Black Box events are append-only too, except behind the retention anchor), delete the
   organization, re-enable both triggers, and record the action in the operations log.
