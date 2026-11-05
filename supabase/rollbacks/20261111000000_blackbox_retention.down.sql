-- Rollback for 20261111000000_blackbox_retention.sql: unschedules the daily purge, drops the purge, the
-- retention control function and the anchor guard, and restores the M1 append-only trigger body (no
-- exceptions at all). Events already purged cannot be restored; anchors already moved stay where they
-- are, and verify_events() keeps starting from them. The restored audit CHECK list is NOT VALID because
-- control_audit_log is append-only and existing blackbox_* audit rows cannot be removed.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.unschedule(jobid) FROM cron.job WHERE jobname = 'redhand-purge-events';
    END IF;
END;
$$;

BEGIN;

DROP FUNCTION IF EXISTS public.purge_events(integer);
DROP FUNCTION IF EXISTS public.control_blackbox_retention(uuid, uuid, integer, integer, text, integer, integer);
DROP TRIGGER IF EXISTS trg_event_chain_heads_anchor_guard ON public.event_chain_heads;
DROP FUNCTION IF EXISTS public._guard_event_anchor();

CREATE OR REPLACE FUNCTION public._forbid_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'agent_events is append-only' USING ERRCODE = 'insufficient_privilege';
END;
$$;

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked',
    'passport.safe_mode_enabled', 'passport.safe_mode_disabled',
    'organization.safe_mode_enabled', 'organization.safe_mode_disabled',
    'passport.budget_changed', 'organization.budget_default_changed'
)) NOT VALID;

COMMIT;

NOTIFY pgrst, 'reload schema';
