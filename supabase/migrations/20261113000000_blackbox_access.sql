-- =============================================================================
-- Black Box access (Phase 3 M2c): reading a captured payload and exporting the timeline both leave a trace.
-- Rollback: supabase/rollbacks/20261113000000_blackbox_access.down.sql
-- Plan: docs/plans/phase3-plan.md (M2c)   ADR: docs/adr/0011-black-box-recorder.md
--
-- read_event_payload() returns a stored payload and writes its audit row in ONE transaction, so there is no way
-- to read a payload through it without leaving a trace, and a failed audit write returns nothing. A missing
-- event writes no audit row. audit_blackbox_export() records the start of an export before any row is read.
-- Both are scoped by p_org in SQL and are service_role only; who may call them is decided in redhand-core.
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
    'organization.blackbox_payload_viewed', 'organization.blackbox_exported'
));

CREATE OR REPLACE FUNCTION public.read_event_payload(p_org uuid, p_actor uuid, p_seq bigint)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_row public.agent_events%ROWTYPE;
BEGIN
    IF p_org IS NULL OR p_actor IS NULL OR p_seq IS NULL OR p_seq < 1 THEN
        RAISE EXCEPTION 'organization, actor and a positive seq are required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO v_row FROM public.agent_events WHERE organization_id = p_org AND seq = p_seq;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('found', false);
    END IF;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'organization.blackbox_payload_viewed', 'organization', p_org, NULL,
            jsonb_build_object('seq', p_seq,
                               'had_arguments', v_row.arguments_redacted IS NOT NULL,
                               'had_result', v_row.result_excerpt IS NOT NULL));
    RETURN jsonb_build_object(
        'found', true, 'seq', v_row.seq,
        'arguments_redacted', v_row.arguments_redacted, 'result_excerpt', v_row.result_excerpt);
END;
$$;

CREATE OR REPLACE FUNCTION public.audit_blackbox_export(p_org uuid, p_actor uuid, p_details jsonb)
RETURNS void
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_org IS NULL OR p_actor IS NULL OR p_details IS NULL OR jsonb_typeof(p_details) <> 'object' THEN
        RAISE EXCEPTION 'organization, actor and details are required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.organizations WHERE id = p_org) THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'organization.blackbox_exported', 'organization', p_org, NULL, p_details);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.read_event_payload(uuid, uuid, bigint) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.audit_blackbox_export(uuid, uuid, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.read_event_payload(uuid, uuid, bigint) TO service_role;
GRANT EXECUTE ON FUNCTION public.audit_blackbox_export(uuid, uuid, jsonb) TO service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';
