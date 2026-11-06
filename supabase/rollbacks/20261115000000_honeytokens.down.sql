-- Rollback for 20261115000000_honeytokens.sql: removes the honeytoken tables and functions (and the data in
-- them: honeytokens, honey tools and trips) and restores the audit CHECK list without the six new actions.
-- NOT VALID because control_audit_log is append-only, so existing honeytoken.* / honey_tool.* rows stay.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.unschedule(jobid) FROM cron.job WHERE jobname = 'redhand-purge-honey';
    END IF;
END;
$$;

DROP FUNCTION IF EXISTS public.purge_honey();
DROP FUNCTION IF EXISTS public.record_trip(uuid, uuid, uuid, text, uuid, text, text, text);
DROP FUNCTION IF EXISTS public.control_honey_tool_retire(uuid, uuid, uuid);
DROP FUNCTION IF EXISTS public.control_honey_tool_create(uuid, uuid, uuid, text, text, text, text);
DROP FUNCTION IF EXISTS public.control_honeytoken_retire(uuid, uuid, uuid);
DROP FUNCTION IF EXISTS public.control_honeytoken_create(uuid, uuid, text, text, text, text, text, text);
DROP TABLE IF EXISTS public.honeytrips;
DROP TABLE IF EXISTS public.honey_tools;
DROP TABLE IF EXISTS public.honeytokens;

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
    'organization.blackbox_payloads_cleared'
)) NOT VALID;

COMMIT;

NOTIFY pgrst, 'reload schema';
