-- =============================================================================
-- Phase 4.5 D1: onboarding (docs/plans, ADR 0026). Rollback: supabase/rollbacks/20261129000000_onboarding.down.sql
--
-- Until now every organization and member was added by hand in SQL. This adds:
--   - signup_codes: single-use, expiring codes (stored as SHA-256 only) that let a signed-in user with no organization create one;
--   - member_invites: single-use, expiring invite tokens (SHA-256 only) an admin issues for a teammate;
--   - control_org_create / control_member_invite_create / _revoke / _accept / control_member_remove / control_member_set_role: the only way to write
--     those rows, each audited in the same transaction, never holding a code or token in the audit details;
--   - list_organization_members(): members with their e-mail (read from auth.users), for admins.
-- Rules enforced here (core checks them too): a user belongs to at most one organization through these functions; an invite can never grant owner or a
-- role above the inviter's; the last owner can never be removed or demoted; only an owner can touch an owner.
-- =============================================================================

BEGIN;

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
    'passport.promoted',
    'organization.created', 'member.invited', 'member.invite_revoked', 'member.joined', 'member.removed', 'member.role_changed'
));
ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_target_type_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_target_type_check
    CHECK (target_type IN ('agent', 'organization', 'mcp_server', 'telegram_link', 'sdk_key', 'member', 'invite'));

CREATE TABLE public.signup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash TEXT NOT NULL UNIQUE CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    note TEXT CHECK (note IS NULL OR char_length(note) <= 200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    used_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    used_org UUID REFERENCES public.organizations(id) ON DELETE SET NULL
);

CREATE TABLE public.member_invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'security_operator', 'viewer')),
    token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    used_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX idx_member_invites_org ON public.member_invites(organization_id);

-- Closed to every client role: only the service role (core) reaches these tables, and only through the functions below.
ALTER TABLE public.signup_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.member_invites ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.role_rank(p_role text) RETURNS integer
LANGUAGE sql IMMUTABLE
AS $$ SELECT CASE p_role WHEN 'viewer' THEN 1 WHEN 'security_operator' THEN 2 WHEN 'admin' THEN 3 WHEN 'owner' THEN 4 ELSE 0 END $$;

-- -----------------------------------------------------------------------------
-- control_org_create(): a signed-in user with no organization creates one with a single-use code and becomes its owner. Refusals return a reason and
-- change nothing: code (unknown, used or expired: one answer, so a code cannot be probed), member (already in an organization), slug (taken).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_org_create(p_user uuid, p_name text, p_slug text, p_code_hash text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_code public.signup_codes%ROWTYPE;
    v_name text := btrim(coalesce(p_name, ''));
    v_org uuid;
BEGIN
    IF char_length(v_name) NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION 'a name of 1 to 100 characters is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_slug IS NULL OR p_slug !~ '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$' THEN
        RAISE EXCEPTION 'a slug of 3 to 40 lowercase letters, digits and hyphens is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_code_hash IS NULL OR p_code_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN jsonb_build_object('created', false, 'reason', 'code');
    END IF;
    SELECT * INTO v_code FROM public.signup_codes WHERE code_hash = p_code_hash AND used_at IS NULL AND expires_at > now() FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('created', false, 'reason', 'code');
    END IF;
    IF EXISTS (SELECT 1 FROM public.organization_members WHERE user_id = p_user) THEN
        RETURN jsonb_build_object('created', false, 'reason', 'member');
    END IF;
    IF EXISTS (SELECT 1 FROM public.organizations WHERE slug = p_slug) THEN
        RETURN jsonb_build_object('created', false, 'reason', 'slug');
    END IF;
    INSERT INTO public.organizations (name, slug) VALUES (v_name, p_slug) RETURNING id INTO v_org;
    INSERT INTO public.organization_members (organization_id, user_id, role) VALUES (v_org, p_user, 'owner');
    UPDATE public.signup_codes SET used_at = now(), used_by = p_user, used_org = v_org WHERE id = v_code.id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (v_org, p_user, 'organization.created', 'organization', v_org, NULL, jsonb_build_object('slug', p_slug, 'signup_code_id', v_code.id));
    RETURN jsonb_build_object('created', true, 'organization_id', v_org);
END $$;

-- -----------------------------------------------------------------------------
-- control_member_invite_create(): an admin or owner invites someone at a role up to their own (never owner), for 1 to 30 days, at most 20 pending.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_member_invite_create(p_org uuid, p_actor uuid, p_role text, p_token_hash text, p_expires_at timestamptz)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_actor_role text;
    v_id uuid;
BEGIN
    IF p_role IS NULL OR p_role NOT IN ('admin', 'security_operator', 'viewer') THEN
        RAISE EXCEPTION 'an invite can grant admin, security_operator or viewer' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'malformed token hash' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_expires_at IS NULL OR p_expires_at < now() + interval '1 hour' OR p_expires_at > now() + interval '30 days' THEN
        RAISE EXCEPTION 'the expiry must be between 1 hour and 30 days from now' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM 1 FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    SELECT role INTO v_actor_role FROM public.organization_members WHERE organization_id = p_org AND user_id = p_actor;
    IF v_actor_role IS NULL OR public.role_rank(v_actor_role) < 3 OR public.role_rank(p_role) > public.role_rank(v_actor_role) THEN
        RAISE EXCEPTION 'not allowed to grant this role' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF (SELECT count(*) FROM public.member_invites WHERE organization_id = p_org AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()) >= 20 THEN
        RETURN jsonb_build_object('created', false, 'limit', true);
    END IF;
    INSERT INTO public.member_invites (organization_id, role, token_hash, created_by, expires_at) VALUES (p_org, p_role, p_token_hash, p_actor, p_expires_at)
    RETURNING id INTO v_id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'member.invited', 'invite', v_id, NULL, jsonb_build_object('role', p_role, 'expires_at', p_expires_at));
    RETURN jsonb_build_object('created', true, 'id', v_id, 'expires_at', p_expires_at);
END $$;

CREATE OR REPLACE FUNCTION public.control_member_invite_revoke(p_org uuid, p_actor uuid, p_invite_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_invite public.member_invites%ROWTYPE;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.organization_members WHERE organization_id = p_org AND user_id = p_actor AND public.role_rank(role) >= 3) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT * INTO v_invite FROM public.member_invites WHERE id = p_invite_id AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invite not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_invite.used_at IS NOT NULL OR v_invite.revoked_at IS NOT NULL THEN
        RETURN jsonb_build_object('changed', false, 'id', v_invite.id);
    END IF;
    UPDATE public.member_invites SET revoked_at = now() WHERE id = v_invite.id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'member.invite_revoked', 'invite', v_invite.id, NULL, jsonb_build_object('role', v_invite.role));
    RETURN jsonb_build_object('changed', true, 'id', v_invite.id);
END $$;

-- -----------------------------------------------------------------------------
-- control_member_invite_accept(): a signed-in user with no organization joins with a single-use token. Unknown, used, revoked and expired tokens
-- are one answer (reason "invite"). The inviter must still hold a role that may grant it (a demoted admin's old invites die with the demotion).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_member_invite_accept(p_user uuid, p_token_hash text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_invite public.member_invites%ROWTYPE;
BEGIN
    IF p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN jsonb_build_object('joined', false, 'reason', 'invite');
    END IF;
    SELECT * INTO v_invite FROM public.member_invites
     WHERE token_hash = p_token_hash AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now() FOR UPDATE;
    IF NOT FOUND OR NOT EXISTS (
        SELECT 1 FROM public.organization_members m
         WHERE m.organization_id = v_invite.organization_id AND m.user_id = v_invite.created_by
           AND public.role_rank(m.role) >= 3 AND public.role_rank(m.role) >= public.role_rank(v_invite.role)) THEN
        RETURN jsonb_build_object('joined', false, 'reason', 'invite');
    END IF;
    IF EXISTS (SELECT 1 FROM public.organization_members WHERE user_id = p_user) THEN
        RETURN jsonb_build_object('joined', false, 'reason', 'member');
    END IF;
    INSERT INTO public.organization_members (organization_id, user_id, role) VALUES (v_invite.organization_id, p_user, v_invite.role);
    UPDATE public.member_invites SET used_at = now(), used_by = p_user WHERE id = v_invite.id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (v_invite.organization_id, p_user, 'member.joined', 'member', p_user, NULL, jsonb_build_object('role', v_invite.role, 'invite_id', v_invite.id));
    RETURN jsonb_build_object('joined', true, 'organization_id', v_invite.organization_id, 'role', v_invite.role);
END $$;

-- -----------------------------------------------------------------------------
-- control_member_remove() / control_member_set_role(): admin or owner acts on a member of the SAME organization. The actor must hold at least the target's
-- current role and the new one; only an owner can create or change an owner; the last owner can never be removed or demoted (also when it is the actor).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_member_remove(p_org uuid, p_actor uuid, p_user uuid)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_actor text;
    v_target text;
BEGIN
    PERFORM 1 FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found'; END IF;
    SELECT role INTO v_actor FROM public.organization_members WHERE organization_id = p_org AND user_id = p_actor;
    SELECT role INTO v_target FROM public.organization_members WHERE organization_id = p_org AND user_id = p_user;
    IF v_target IS NULL THEN RAISE EXCEPTION 'member not found' USING ERRCODE = 'no_data_found'; END IF;
    IF v_actor IS NULL OR public.role_rank(v_actor) < 3 OR public.role_rank(v_actor) < public.role_rank(v_target) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF v_target = 'owner' AND (SELECT count(*) FROM public.organization_members WHERE organization_id = p_org AND role = 'owner') <= 1 THEN
        RAISE EXCEPTION 'the last owner cannot be removed' USING ERRCODE = 'check_violation';
    END IF;
    DELETE FROM public.organization_members WHERE organization_id = p_org AND user_id = p_user;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'member.removed', 'member', p_user, NULL, jsonb_build_object('role', v_target));
    RETURN jsonb_build_object('removed', true, 'user_id', p_user);
END $$;

CREATE OR REPLACE FUNCTION public.control_member_set_role(p_org uuid, p_actor uuid, p_user uuid, p_role text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_actor text;
    v_target text;
BEGIN
    IF p_role IS NULL OR p_role NOT IN ('owner', 'admin', 'security_operator', 'viewer') THEN
        RAISE EXCEPTION 'unknown role' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM 1 FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found'; END IF;
    SELECT role INTO v_actor FROM public.organization_members WHERE organization_id = p_org AND user_id = p_actor;
    SELECT role INTO v_target FROM public.organization_members WHERE organization_id = p_org AND user_id = p_user;
    IF v_target IS NULL THEN RAISE EXCEPTION 'member not found' USING ERRCODE = 'no_data_found'; END IF;
    IF v_actor IS NULL OR public.role_rank(v_actor) < 3
       OR public.role_rank(v_actor) < public.role_rank(v_target) OR public.role_rank(v_actor) < public.role_rank(p_role) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF v_target = p_role THEN
        RETURN jsonb_build_object('changed', false, 'user_id', p_user);
    END IF;
    IF v_target = 'owner' AND p_role <> 'owner' AND (SELECT count(*) FROM public.organization_members WHERE organization_id = p_org AND role = 'owner') <= 1 THEN
        RAISE EXCEPTION 'the last owner cannot be demoted' USING ERRCODE = 'check_violation';
    END IF;
    UPDATE public.organization_members SET role = p_role WHERE organization_id = p_org AND user_id = p_user;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'member.role_changed', 'member', p_user, NULL, jsonb_build_object('from', v_target, 'to', p_role));
    RETURN jsonb_build_object('changed', true, 'user_id', p_user, 'from', v_target, 'to', p_role);
END $$;

-- -----------------------------------------------------------------------------
-- list_organization_members(): members with the e-mail Supabase Auth holds for them (auth.users is not reachable through the API).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.list_organization_members(p_org uuid)
RETURNS TABLE (user_id uuid, email text, role text, joined_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT m.user_id, u.email::text, m.role, m.created_at
      FROM public.organization_members m JOIN auth.users u ON u.id = m.user_id
     WHERE m.organization_id = p_org
     ORDER BY public.role_rank(m.role) DESC, m.created_at
$$;

REVOKE EXECUTE ON FUNCTION public.role_rank(text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_org_create(uuid, text, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_member_invite_create(uuid, uuid, text, text, timestamptz) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_member_invite_revoke(uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_member_invite_accept(uuid, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_member_remove(uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_member_set_role(uuid, uuid, uuid, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.list_organization_members(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.role_rank(text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_org_create(uuid, text, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_member_invite_create(uuid, uuid, text, text, timestamptz) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_member_invite_revoke(uuid, uuid, uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_member_invite_accept(uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_member_remove(uuid, uuid, uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_member_set_role(uuid, uuid, uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.list_organization_members(uuid) TO service_role;

COMMIT;
