-- Rollback for 20261105000000_budget_guard.sql
-- Drops the Budget Guard functions, tables and columns and restores the earlier audit-log CHECK list.
-- Usage history, alert state and every limit that was set are lost: agents return to "no limit".
-- The restored constraint is NOT VALID because control_audit_log is append-only and existing
-- passport.budget_changed rows cannot be removed; they stay in place, unchecked.

BEGIN;

DROP FUNCTION IF EXISTS public.purge_usage();
DROP FUNCTION IF EXISTS public.org_usage(uuid, date);
DROP FUNCTION IF EXISTS public.usage_by_others(uuid, uuid, date, text);
DROP FUNCTION IF EXISTS public.mark_budget_frozen(uuid, date);
DROP FUNCTION IF EXISTS public.record_usage(text, jsonb);
DROP FUNCTION IF EXISTS public.control_agent_budget(uuid, uuid, uuid, integer, text, text, integer, text);

DROP TABLE IF EXISTS public.agent_budget_state;
DROP TABLE IF EXISTS public.agent_usage_daily;

ALTER TABLE public.organizations DROP COLUMN utc_offset_minutes;
ALTER TABLE public.agents DROP COLUMN budget_action, DROP COLUMN daily_call_limit;

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked',
    'passport.safe_mode_enabled', 'passport.safe_mode_disabled',
    'organization.safe_mode_enabled', 'organization.safe_mode_disabled'
)) NOT VALID;

COMMIT;

NOTIFY pgrst, 'reload schema';
