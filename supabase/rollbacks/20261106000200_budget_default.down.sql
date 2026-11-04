-- Rollback for 20261106000200_budget_default.sql
-- Drops the default-limit function and column and restores the earlier audit-log CHECK list. Agents that
-- already received a limit from the default keep it (it is an ordinary per-agent limit). The restored
-- constraint is NOT VALID because control_audit_log is append-only and existing
-- organization.budget_default_changed rows cannot be removed; they stay in place, unchecked.

BEGIN;

DROP FUNCTION IF EXISTS public.control_org_budget_default(uuid, uuid, integer, text, integer);
ALTER TABLE public.organizations DROP COLUMN default_daily_call_limit;

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked',
    'passport.safe_mode_enabled', 'passport.safe_mode_disabled',
    'organization.safe_mode_enabled', 'organization.safe_mode_disabled',
    'passport.budget_changed'
)) NOT VALID;

COMMIT;

NOTIFY pgrst, 'reload schema';
