-- Rollback for 20261127000000_sdk_keys.sql: drops the three functions, the index and the three new columns (who created and revoked each key is lost:
-- stated data loss; the keys themselves and their active flags stay), restores the old "Admins can manage SDK keys" policy, and restores the previous audit list
-- (NOT VALID: control_audit_log is append-only, so existing sdk_key.* rows stay).

BEGIN;

DROP FUNCTION IF EXISTS public.sdk_key_touch(uuid);
DROP FUNCTION IF EXISTS public.control_sdk_key_revoke(uuid, uuid, uuid, text);
DROP FUNCTION IF EXISTS public.control_sdk_key_create(uuid, uuid, text, text, text, timestamptz);
DROP INDEX IF EXISTS public.idx_sdk_api_keys_org;
ALTER TABLE public.sdk_api_keys DROP COLUMN IF EXISTS revoked_by, DROP COLUMN IF EXISTS revoked_at, DROP COLUMN IF EXISTS created_by;

DROP POLICY IF EXISTS "Admins can manage SDK keys" ON public.sdk_api_keys;
CREATE POLICY "Admins can manage SDK keys"
    ON public.sdk_api_keys FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM public.organization_members
            WHERE organization_id = public.sdk_api_keys.organization_id
              AND user_id = auth.uid()
              AND role IN ('owner', 'admin')
        )
    );

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_target_type_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_target_type_check
    CHECK (target_type IN ('agent', 'organization', 'mcp_server', 'telegram_link')) NOT VALID;
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
    'passport.timeline_exported',
    'passport.spend_limit_changed',
    'organization.approved_models_changed'
)) NOT VALID;

COMMIT;
