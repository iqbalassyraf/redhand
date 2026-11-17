-- =============================================================================
-- Phase 4.5 C1b: telemetry trust (docs/plans/phase45-c1-sdk-keys.md, ADR 0024 amendment).
-- Rollback: supabase/rollbacks/20261128000000_reported_only.down.sql
--
-- Telemetry ingest used to upsert the agent row on every batch, overwriting an existing passport's name and framework (any SDK key holder could rename a
-- passport whose external id it knew) and creating an ordinary active passport for every new agent id. Now:
--   - telemetry_resolve_agent() finds an existing passport and changes only its heartbeat; a new agent id becomes a passport with reported_only = true;
--   - a reported-only passport cannot use the gateway (core refuses its token exchange and reports it as not active to the gateway) until an admin
--     promotes it with control_passport_promote() (audited as passport.promoted).
-- New: agents.reported_only (default false: every existing passport keeps working), the two functions. Changed: the audit action list.
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
    'passport.promoted'
));

ALTER TABLE public.agents ADD COLUMN reported_only BOOLEAN NOT NULL DEFAULT false;

-- -----------------------------------------------------------------------------
-- telemetry_resolve_agent(): the agent a telemetry batch reports for. Never changes an existing passport except its heartbeat.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.telemetry_resolve_agent(p_org uuid, p_external text, p_environment text, p_name text, p_framework text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_row public.agents%ROWTYPE;
BEGIN
    IF p_external IS NULL OR char_length(btrim(p_external)) NOT BETWEEN 1 AND 128 THEN
        RAISE EXCEPTION 'an external agent id of 1 to 128 characters is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_environment IS NULL OR p_environment NOT IN ('development', 'staging', 'production') THEN
        RAISE EXCEPTION 'unknown environment' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO public.agents AS a (organization_id, external_agent_id, environment, name, framework, last_heartbeat_at, reported_only)
    VALUES (p_org, p_external, p_environment::agent_environment, left(coalesce(nullif(btrim(p_name), ''), p_external), 256),
            left(coalesce(nullif(btrim(p_framework), ''), 'custom'), 64), now(), true)
    ON CONFLICT (organization_id, external_agent_id, environment) DO UPDATE SET last_heartbeat_at = now()
    RETURNING * INTO v_row;
    RETURN jsonb_build_object('id', v_row.id, 'organization_id', v_row.organization_id, 'status', v_row.status, 'expires_at', v_row.expires_at,
                              'reported_only', v_row.reported_only, 'name', v_row.name);
END $$;

-- -----------------------------------------------------------------------------
-- control_passport_promote(): turns a reported-only passport into an ordinary one (it still needs scopes and an agent key to call tools).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_passport_promote(p_org uuid, p_agent uuid, p_actor uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_agent public.agents%ROWTYPE;
BEGIN
    SELECT * INTO v_agent FROM public.agents WHERE id = p_agent AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'agent not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_agent.status::text = 'revoked' THEN
        RAISE EXCEPTION 'a revoked passport cannot be promoted' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT v_agent.reported_only THEN
        RETURN jsonb_build_object('changed', false, 'agent_id', v_agent.id);
    END IF;
    UPDATE public.agents SET reported_only = false WHERE id = v_agent.id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'passport.promoted', 'agent', v_agent.id, p_reason, jsonb_build_object('external_agent_id', v_agent.external_agent_id));
    RETURN jsonb_build_object('changed', true, 'agent_id', v_agent.id);
END $$;

REVOKE EXECUTE ON FUNCTION public.telemetry_resolve_agent(uuid, text, text, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_passport_promote(uuid, uuid, uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.telemetry_resolve_agent(uuid, text, text, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_passport_promote(uuid, uuid, uuid, text) TO service_role;

COMMIT;
