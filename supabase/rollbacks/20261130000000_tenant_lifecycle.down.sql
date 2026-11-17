-- Rollback for 20261130000000_tenant_lifecycle.sql: drops the export, deletion and purge functions, the deletion columns and tenant_deletions (the record of past purges is lost).
-- Organizations with a pending deletion simply stop being pending. Deploy the previous core first: the current core calls these functions.
-- The audit action lists are restored as NOT VALID (existing organization.exported / deletion_* rows stay, as audit rows cannot be rewritten).

BEGIN;

DROP FUNCTION IF EXISTS public.control_org_purge(uuid);
DROP FUNCTION IF EXISTS public.control_org_cancel_deletion(uuid, uuid);
DROP FUNCTION IF EXISTS public.control_org_request_deletion(uuid, uuid, text, interval);
DROP FUNCTION IF EXISTS public.control_org_export(uuid, uuid, integer);
DROP FUNCTION IF EXISTS public.tenant_row_counts(uuid);
DROP FUNCTION IF EXISTS public.tenant_table_rows(jsonb, uuid, integer);
DROP FUNCTION IF EXISTS public.tenant_data_manifest();
DROP TABLE IF EXISTS public.tenant_deletions;
ALTER TABLE public.organizations DROP CONSTRAINT IF EXISTS organizations_deletion_consistent;
ALTER TABLE public.organizations DROP COLUMN IF EXISTS deletion_purge_after, DROP COLUMN IF EXISTS deletion_requested_by, DROP COLUMN IF EXISTS deletion_requested_at;

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
    'passport.timeline_exported',
    'passport.spend_limit_changed',
    'organization.approved_models_changed',
    'sdk_key.created', 'sdk_key.revoked',
    'passport.promoted',
    'organization.created', 'member.invited', 'member.invite_revoked', 'member.joined', 'member.removed', 'member.role_changed'
)) NOT VALID;

COMMIT;
