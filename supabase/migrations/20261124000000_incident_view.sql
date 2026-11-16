-- =============================================================================
-- Phase 4.5 B3: incident view (ADR 0022). Rollback: supabase/rollbacks/20261124000000_incident_view.down.sql
--
-- 1. An index for the timeline's "actions on this agent" read. control_audit_log had only (organization_id, created_at), so that read
--    scanned every audit row of the organization. The other timeline reads already have indexes.
-- 2. A new audit action, passport.timeline_exported, written by core before an incident summary export reads anything (as the Black
--    Box export is audited). Core inserts it with the service role; no new function.
-- Additive: no data changes, safe with the code already deployed.
-- =============================================================================

BEGIN;

CREATE INDEX IF NOT EXISTS idx_control_audit_org_target_time
    ON public.control_audit_log (organization_id, target_id, created_at DESC);

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked',
    'passport.safe_mode_enabled', 'passport.safe_mode_disabled',
    'organization.safe_mode_enabled', 'organization.safe_mode_disabled',
    'passport.budget_changed', 'organization.budget_default_changed',
    'organization.blackbox_retention_changed', 'organization.blackbox_purged',
    'organization.payload_capture_changed',
    'organization.blackbox_payload_viewed', 'organization.blackbox_exported',
    'organization.blackbox_payloads_cleared',
    'honeytoken.created', 'honeytoken.retired', 'honeytoken.tripped',
    'honey_tool.created', 'honey_tool.retired', 'honey_tool.tripped',
    'tool_pin.pending', 'tool_pin.approved', 'tool_pin.rejected', 'tool_pin.approved_all',
    'mcp_server.pin_mode_changed',
    'organization.radar_settings_changed', 'radar_finding.reviewed',
    'radar_suppression.created', 'radar_suppression.revoked',
    'organization.loop_settings_changed',
    'passport.destination_added', 'passport.destination_removed', 'passport.destination_mode_changed',
    'organization.risk_ladder_changed',
    'passport.timeline_exported'
));

COMMIT;
