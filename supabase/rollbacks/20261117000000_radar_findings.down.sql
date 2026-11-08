-- Rollback for 20261117000000_radar_findings.sql: removes the findings and suppression tables (and their data), the
-- functions, the organization and agent columns, the purge job, and restores the audit CHECK list without the four new
-- actions (NOT VALID: control_audit_log is append-only, so existing radar_* rows stay).

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.unschedule(jobid) FROM cron.job WHERE jobname = 'redhand-purge-findings';
    END IF;
END;
$$;

DROP FUNCTION IF EXISTS public.purge_findings();
DROP FUNCTION IF EXISTS public.radar_summary(uuid);
DROP FUNCTION IF EXISTS public.control_radar_suppression_revoke(uuid, uuid, uuid, text);
DROP FUNCTION IF EXISTS public.control_radar_suppression_create(uuid, uuid, uuid, text, integer, text);
DROP FUNCTION IF EXISTS public.control_finding_review(uuid, uuid, uuid, text, text, text);
DROP FUNCTION IF EXISTS public.control_radar_settings(uuid, uuid, text, text, text, text, text);
DROP FUNCTION IF EXISTS public.record_security_findings(uuid, uuid, jsonb);
DROP TABLE IF EXISTS public.radar_suppressions;
DROP TABLE IF EXISTS public.security_findings;
ALTER TABLE public.agents DROP COLUMN IF EXISTS radar_last_alert_at;
ALTER TABLE public.organizations
    DROP COLUMN IF EXISTS output_check_mode_changed_at, DROP COLUMN IF EXISTS radar_mode_changed_at,
    DROP COLUMN IF EXISTS output_check_mode, DROP COLUMN IF EXISTS radar_mode;

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
    'mcp_server.pin_mode_changed'
)) NOT VALID;

COMMIT;

NOTIFY pgrst, 'reload schema';
