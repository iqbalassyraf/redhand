-- Rollback for 20261103000000_telegram_panic.sql
-- Drops the Telegram tables and functions and restores the earlier audit-log CHECK lists.
-- The restored constraints are added NOT VALID: control_audit_log is append-only, so any
-- telegram.* rows already written cannot be removed and stay in place, unchecked.
-- Destroys all Telegram links; operators must re-link after a re-apply.

BEGIN;

DROP FUNCTION IF EXISTS public.purge_telegram_updates();
DROP FUNCTION IF EXISTS public.telegram_claim_update(bigint);
DROP FUNCTION IF EXISTS public.telegram_unlink(uuid, uuid, uuid);
DROP FUNCTION IF EXISTS public.telegram_link_chat(text, bigint);

DROP TABLE IF EXISTS public.telegram_updates;
DROP TABLE IF EXISTS public.telegram_links;
DROP TABLE IF EXISTS public.telegram_link_codes;

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated'
)) NOT VALID;
ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_target_type_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_target_type_check
    CHECK (target_type IN ('agent', 'organization', 'mcp_server')) NOT VALID;

COMMIT;

NOTIFY pgrst, 'reload schema';
