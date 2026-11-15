-- Rollback for 20261122000000_risk_engine.sql: drops the trigger, the three functions, the index and the new columns (the ladder settings
-- and the per-agent alert and release stamps are lost: stated data loss), and restores M7's audit CHECK list without the new action
-- (NOT VALID: control_audit_log is append-only, so existing organization.risk_ladder_changed rows stay).

BEGIN;

DROP TRIGGER IF EXISTS trg_agents_risk_release ON public.agents;
DROP FUNCTION IF EXISTS public.risk_stamp_release();
DROP FUNCTION IF EXISTS public.risk_mark_alerted(uuid, uuid, integer);
DROP FUNCTION IF EXISTS public.control_risk_ladder(uuid, uuid, integer, integer, integer, text);
DROP FUNCTION IF EXISTS public.agent_risk_signals(uuid, uuid, timestamptz);
DROP INDEX IF EXISTS public.idx_honeytrips_agent_time;

ALTER TABLE public.agents DROP COLUMN IF EXISTS risk_released_at, DROP COLUMN IF EXISTS risk_last_alert_at;
ALTER TABLE public.organizations DROP CONSTRAINT IF EXISTS organizations_risk_ladder_order;
ALTER TABLE public.organizations
    DROP COLUMN IF EXISTS risk_freeze_threshold,
    DROP COLUMN IF EXISTS risk_safe_mode_threshold,
    DROP COLUMN IF EXISTS risk_alert_threshold;

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
    'passport.destination_added', 'passport.destination_removed', 'passport.destination_mode_changed'
)) NOT VALID;

COMMIT;
