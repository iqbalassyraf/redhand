-- =============================================================================
-- Black Box: delete captured payloads now (Phase 3 M2c). Rollback: supabase/rollbacks/20261114000000_blackbox_clear_payloads.down.sql
--
-- Payloads are otherwise cleared only at the payload retention. This lets an admin remove them at once
-- (data minimisation: turning capture off does not delete what was captured). Only the two payload columns
-- are set to NULL, which the append-only trigger allows; events and the hash chain are untouched, so
-- verification still passes. Audited with the count, never the content. service_role only; the role check
-- is made in redhand-core.
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
    'organization.blackbox_payloads_cleared'
));

CREATE OR REPLACE FUNCTION public.control_clear_payloads(p_org uuid, p_actor uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_cleared bigint;
BEGIN
    IF p_org IS NULL OR p_actor IS NULL THEN
        RAISE EXCEPTION 'organization and actor are required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM 1 FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    UPDATE public.agent_events SET arguments_redacted = NULL, result_excerpt = NULL
    WHERE organization_id = p_org AND (arguments_redacted IS NOT NULL OR result_excerpt IS NOT NULL);
    GET DIAGNOSTICS v_cleared = ROW_COUNT;
    IF v_cleared > 0 THEN
        INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
        VALUES (p_org, p_actor, 'organization.blackbox_payloads_cleared', 'organization', p_org, p_reason,
                jsonb_build_object('events_cleared', v_cleared));
    END IF;
    RETURN jsonb_build_object('cleared', v_cleared);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.control_clear_payloads(uuid, uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.control_clear_payloads(uuid, uuid, text) TO service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';
