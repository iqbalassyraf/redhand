-- =============================================================================
-- Budget Guard: an organization default daily limit for NEW agents.
-- Rollback: supabase/rollbacks/20261106000200_budget_default.down.sql
-- Plan: docs/plans/phase2-m3-budget-guard.md (section 12)   ADR: docs/adr/0010-budget-guard.md
--
-- organizations.default_daily_call_limit  NULL = no default (new agents start with no limit). When set,
-- redhand-core gives every newly registered agent that daily limit (an audited budget change). Existing
-- agents are never changed by the default.
--
-- Changing the default is audited, compare-and-set (the caller passes the value its decision was based
-- on), idempotent, tenant-scoped, SECURITY INVOKER with a fixed search_path, service_role only.
-- =============================================================================

BEGIN;

ALTER TABLE public.organizations
    ADD COLUMN default_daily_call_limit INTEGER
    CHECK (default_daily_call_limit IS NULL OR default_daily_call_limit BETWEEN 1 AND 10000000);

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked',
    'passport.safe_mode_enabled', 'passport.safe_mode_disabled',
    'organization.safe_mode_enabled', 'organization.safe_mode_disabled',
    'passport.budget_changed', 'organization.budget_default_changed'
));

CREATE OR REPLACE FUNCTION public.control_org_budget_default(
    p_org uuid, p_actor uuid, p_limit integer, p_reason text, p_expected integer
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
BEGIN
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_org.default_daily_call_limit IS DISTINCT FROM p_expected THEN
        RETURN jsonb_build_object('conflict', true);
    END IF;
    IF v_org.default_daily_call_limit IS NOT DISTINCT FROM p_limit THEN
        RETURN jsonb_build_object('changed', false, 'default_daily_call_limit', v_org.default_daily_call_limit);
    END IF;

    UPDATE public.organizations SET default_daily_call_limit = p_limit WHERE id = p_org;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'organization.budget_default_changed', 'organization', p_org, p_reason,
            jsonb_build_object('old_limit', v_org.default_daily_call_limit, 'new_limit', p_limit));
    RETURN jsonb_build_object('changed', true, 'default_daily_call_limit', p_limit);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.control_org_budget_default(uuid, uuid, integer, text, integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.control_org_budget_default(uuid, uuid, integer, text, integer) TO service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';
