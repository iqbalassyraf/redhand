-- Rollback for 20261113000000_blackbox_access.sql: drops the two access functions and restores the audit CHECK
-- list without the two M2c actions. It is NOT VALID because control_audit_log is append-only, so existing
-- organization.blackbox_payload_viewed / organization.blackbox_exported rows cannot be removed.

BEGIN;

DROP FUNCTION IF EXISTS public.read_event_payload(uuid, uuid, bigint);
DROP FUNCTION IF EXISTS public.audit_blackbox_export(uuid, uuid, jsonb);

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
    'organization.payload_capture_changed'
)) NOT VALID;

COMMIT;

NOTIFY pgrst, 'reload schema';
