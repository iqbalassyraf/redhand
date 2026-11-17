-- Rollback for 20261129000000_onboarding.sql: drops the onboarding functions and tables (pending sign-up codes and member invites are lost; organizations and members
-- created through them stay) and restores the previous audit lists as NOT VALID (existing organization.created / member.* audit rows stay, as they cannot be rewritten).
-- Deploy the previous core first: the current core calls these functions.

BEGIN;

DROP FUNCTION IF EXISTS public.list_organization_members(uuid);
DROP FUNCTION IF EXISTS public.control_member_set_role(uuid, uuid, uuid, text);
DROP FUNCTION IF EXISTS public.control_member_remove(uuid, uuid, uuid);
DROP FUNCTION IF EXISTS public.control_member_invite_accept(uuid, text);
DROP FUNCTION IF EXISTS public.control_member_invite_revoke(uuid, uuid, uuid);
DROP FUNCTION IF EXISTS public.control_member_invite_create(uuid, uuid, text, text, timestamptz);
DROP FUNCTION IF EXISTS public.control_org_create(uuid, text, text, text);
DROP FUNCTION IF EXISTS public.role_rank(text);
DROP TABLE IF EXISTS public.member_invites;
DROP TABLE IF EXISTS public.signup_codes;

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
    'organization.approved_models_changed',
    'sdk_key.created', 'sdk_key.revoked',
    'passport.promoted'
)) NOT VALID;
ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_target_type_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_target_type_check
    CHECK (target_type IN ('agent', 'organization', 'mcp_server', 'telegram_link', 'sdk_key')) NOT VALID;

COMMIT;
