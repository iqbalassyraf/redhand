-- =============================================================================
-- Safe Mode (Phase 2, M2): per-agent and per-organization read-only switch.
-- Rollback: supabase/rollbacks/20261104000000_safe_mode.down.sql
-- Plan: docs/plans/phase2-m2-safe-mode.md   ADR: docs/adr/0009-safe-mode.md
--
-- While Safe Mode is on (agent flag OR organization flag), the gateway allows only tools
-- covered by a scope whose access is 'read'. redhand-core reads the flags for the gateway
-- through /internal/v1/gateway-context; these functions change them.
--
-- Each function applies the change and writes its audit row in one transaction, is
-- idempotent (no change means no audit row), is scoped to the organization, is SECURITY
-- INVOKER with a fixed search_path, and is executable only by service_role.
-- =============================================================================

BEGIN;

ALTER TABLE public.agents ADD COLUMN safe_mode BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.organizations ADD COLUMN safe_mode BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked',
    'passport.safe_mode_enabled', 'passport.safe_mode_disabled',
    'organization.safe_mode_enabled', 'organization.safe_mode_disabled'
));

CREATE OR REPLACE FUNCTION public.control_agent_safe_mode(
    p_org uuid, p_agent uuid, p_actor uuid, p_enabled boolean, p_reason text
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_agent public.agents%ROWTYPE;
BEGIN
    -- The row lock serialises concurrent changes to the same agent.
    SELECT * INTO v_agent FROM public.agents WHERE id = p_agent AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'agent not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_agent.safe_mode = p_enabled THEN
        RETURN jsonb_build_object('changed', false, 'agent_id', v_agent.id, 'enabled', v_agent.safe_mode);
    END IF;

    UPDATE public.agents SET safe_mode = p_enabled WHERE id = v_agent.id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor,
            CASE WHEN p_enabled THEN 'passport.safe_mode_enabled' ELSE 'passport.safe_mode_disabled' END,
            'agent', v_agent.id, p_reason, jsonb_build_object('enabled', p_enabled));
    RETURN jsonb_build_object('changed', true, 'agent_id', v_agent.id, 'enabled', p_enabled);
END;
$$;

CREATE OR REPLACE FUNCTION public.control_org_safe_mode(
    p_org uuid, p_actor uuid, p_enabled boolean, p_reason text
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
    IF v_org.safe_mode = p_enabled THEN
        RETURN jsonb_build_object('changed', false, 'enabled', v_org.safe_mode);
    END IF;

    UPDATE public.organizations SET safe_mode = p_enabled WHERE id = p_org;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor,
            CASE WHEN p_enabled THEN 'organization.safe_mode_enabled' ELSE 'organization.safe_mode_disabled' END,
            'organization', p_org, p_reason, jsonb_build_object('enabled', p_enabled));
    RETURN jsonb_build_object('changed', true, 'enabled', p_enabled);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.control_agent_safe_mode(uuid, uuid, uuid, boolean, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_org_safe_mode(uuid, uuid, boolean, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.control_agent_safe_mode(uuid, uuid, uuid, boolean, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_org_safe_mode(uuid, uuid, boolean, text) TO service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';
