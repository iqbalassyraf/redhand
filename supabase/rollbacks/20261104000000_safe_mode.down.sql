-- Rollback for 20261104000000_safe_mode.sql
-- Drops the Safe Mode functions and columns and restores the earlier audit-log CHECK list.
-- Any Safe Mode flags currently set are lost, so agents and organizations return to normal
-- (read and write) enforcement: turn Safe Mode off deliberately before rolling back if that
-- matters. The restored constraint is NOT VALID because control_audit_log is append-only and
-- existing safe_mode_* audit rows cannot be removed; they stay in place, unchecked.

BEGIN;

DROP FUNCTION IF EXISTS public.control_org_safe_mode(uuid, uuid, boolean, text);
DROP FUNCTION IF EXISTS public.control_agent_safe_mode(uuid, uuid, uuid, boolean, text);

ALTER TABLE public.organizations DROP COLUMN safe_mode;
ALTER TABLE public.agents DROP COLUMN safe_mode;

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked'
)) NOT VALID;

COMMIT;

NOTIFY pgrst, 'reload schema';
