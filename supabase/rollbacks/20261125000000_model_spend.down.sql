-- Rollback for 20261125000000_model_spend.sql (the audit list it restores includes passport.timeline_exported from 20261124): unschedules the purge (when pg_cron is present), drops the trigger, the functions, the
-- roll-up table and the two agent columns (the daily model-use roll-up and every agent's dollar limit and alert day are lost: stated data
-- loss; the spans it was built from are untouched), and restores the previous audit CHECK list without the new action (NOT VALID:
-- control_audit_log is append-only, so existing passport.spend_limit_changed rows stay).

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.unschedule('redhand-purge-model-spend');
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'redhand-purge-model-spend was not scheduled';
END;
$$;

DROP TRIGGER IF EXISTS trg_execution_traces_model_spend ON public.execution_traces;
DROP FUNCTION IF EXISTS public.model_spend_rollup();
DROP FUNCTION IF EXISTS public.model_spend_backfill(integer);
DROP FUNCTION IF EXISTS public.agent_model_usage(uuid, uuid, date, date);
DROP FUNCTION IF EXISTS public.purge_model_spend();
DROP FUNCTION IF EXISTS public.control_agent_spend_limit(uuid, uuid, uuid, bigint, text, bigint);
DROP FUNCTION IF EXISTS public.spend_mark_alerted(uuid, uuid, date);
DROP TABLE IF EXISTS public.agent_model_daily;
ALTER TABLE public.agents DROP COLUMN IF EXISTS spend_alerted_day, DROP COLUMN IF EXISTS spend_limit_micro_usd;

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
)) NOT VALID;

COMMIT;
