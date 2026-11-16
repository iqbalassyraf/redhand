-- =============================================================================
-- Phase 4.5 B3: incident view (ADR 0022). Rollback: supabase/rollbacks/20261124000000_timeline_audit_index.down.sql
--
-- The incident view reads the control actions whose target is one agent. control_audit_log had only (organization_id, created_at), so
-- that read scanned every audit row of the organization. This index serves it directly. Additive: no data changes, no function changes,
-- safe with the code already deployed. The other timeline reads already have indexes (agent_events, security_findings, honeytrips,
-- agent_tool_hourly).
-- =============================================================================

BEGIN;

CREATE INDEX IF NOT EXISTS idx_control_audit_org_target_time
    ON public.control_audit_log (organization_id, target_id, created_at DESC);

COMMIT;
