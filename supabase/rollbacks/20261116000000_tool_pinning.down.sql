-- Rollback for 20261116000000_tool_pinning.sql: removes the pin table (and its data), the functions and the two mcp_servers
-- columns, and restores the audit CHECK list without the five new actions (NOT VALID: control_audit_log is append-only, so
-- existing tool_pin.* rows stay).

BEGIN;

DROP FUNCTION IF EXISTS public.control_server_pin_mode(uuid, uuid, uuid, text, text, text);
DROP FUNCTION IF EXISTS public.control_tool_pins_approve_all(uuid, uuid, uuid, text);
DROP FUNCTION IF EXISTS public.control_tool_pin(uuid, uuid, uuid, text, text);
DROP FUNCTION IF EXISTS public.record_tool_observation(uuid, uuid, jsonb);
DROP TABLE IF EXISTS public.mcp_tool_pins;
ALTER TABLE public.mcp_servers DROP COLUMN IF EXISTS pin_last_alert_at, DROP COLUMN IF EXISTS pin_mode;

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
    'honey_tool.created', 'honey_tool.retired', 'honey_tool.tripped'
)) NOT VALID;

COMMIT;

NOTIFY pgrst, 'reload schema';
