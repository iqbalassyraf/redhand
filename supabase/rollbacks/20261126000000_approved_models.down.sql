-- Rollback for 20261126000000_approved_models.sql: drops the new functions and table and the two new columns (the organization's approved list and each
-- agent's model alert stamp are lost: stated data loss), deletes any findings of kind 'model' and any silence on RAD-MDL-001 (they could not satisfy the
-- restored checks), restores the previous finding/suppression checks, control_radar_suppression_create() and agent_risk_signals(), and the previous audit
-- list (NOT VALID: control_audit_log is append-only, so existing organization.approved_models_changed rows stay).

BEGIN;

DELETE FROM public.radar_suppressions WHERE rule_id = 'RAD-MDL-001';
DELETE FROM public.security_findings WHERE kind = 'model';

DROP FUNCTION IF EXISTS public.record_model_findings(uuid, uuid, jsonb);
DROP FUNCTION IF EXISTS public.control_approved_models(uuid, uuid, jsonb, text, integer);
DROP FUNCTION IF EXISTS public.approved_models_list(uuid);
DROP TABLE IF EXISTS public.approved_models;
ALTER TABLE public.agents DROP COLUMN IF EXISTS model_last_alert_at;
ALTER TABLE public.organizations DROP COLUMN IF EXISTS approved_models_version;

ALTER TABLE public.security_findings DROP CONSTRAINT security_findings_rule_id_check;
ALTER TABLE public.security_findings ADD CONSTRAINT security_findings_rule_id_check CHECK (rule_id ~ '^RAD-(INJ|OUT|LOOP|DST)-[0-9]{3}$');
ALTER TABLE public.security_findings DROP CONSTRAINT security_findings_kind_check;
ALTER TABLE public.security_findings ADD CONSTRAINT security_findings_kind_check CHECK (kind IN ('injection', 'output', 'loop', 'destination'));
ALTER TABLE public.radar_suppressions DROP CONSTRAINT radar_suppressions_rule_id_check;
ALTER TABLE public.radar_suppressions ADD CONSTRAINT radar_suppressions_rule_id_check CHECK (rule_id ~ '^RAD-(INJ|OUT|LOOP|DST)-[0-9]{3}$');

CREATE OR REPLACE FUNCTION public.control_radar_suppression_create(p_org uuid, p_actor uuid, p_agent uuid, p_rule text, p_days integer, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_existing public.radar_suppressions%ROWTYPE;
    v_id uuid;
    v_expires timestamptz;
BEGIN
    IF p_rule IS NULL OR p_rule !~ '^RAD-(INJ|OUT|LOOP|DST)-[0-9]{3}$' OR p_days IS NULL OR p_days NOT BETWEEN 1 AND 90
       OR p_reason IS NULL OR char_length(btrim(p_reason)) NOT BETWEEN 3 AND 300 THEN
        RAISE EXCEPTION 'a rule id, 1 to 90 days and a reason of 3 to 300 characters are required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM 1 FROM public.agents WHERE id = p_agent AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'agent not found' USING ERRCODE = 'no_data_found';
    END IF;
    SELECT * INTO v_existing FROM public.radar_suppressions WHERE agent_id = p_agent AND rule_id = p_rule AND revoked_at IS NULL;
    IF FOUND THEN
        IF v_existing.expires_at > now() THEN
            RETURN jsonb_build_object('created', false, 'id', v_existing.id, 'expires_at', v_existing.expires_at);
        END IF;
        UPDATE public.radar_suppressions SET revoked_at = now(), revoked_by = p_actor WHERE id = v_existing.id;  -- expired: make room
    END IF;
    IF (SELECT count(*) FROM public.radar_suppressions WHERE organization_id = p_org AND revoked_at IS NULL AND expires_at > now()) >= 100 THEN
        RETURN jsonb_build_object('created', false, 'limit', true);
    END IF;
    v_expires := now() + make_interval(days => p_days);
    INSERT INTO public.radar_suppressions (organization_id, agent_id, rule_id, reason, created_by, expires_at)
    VALUES (p_org, p_agent, p_rule, btrim(p_reason), p_actor, v_expires) RETURNING id INTO v_id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'radar_suppression.created', 'agent', p_agent, btrim(p_reason),
            jsonb_build_object('suppression', v_id, 'rule', p_rule, 'days', p_days));
    RETURN jsonb_build_object('created', true, 'id', v_id, 'expires_at', v_expires);
END;
$$;

CREATE OR REPLACE FUNCTION public.agent_risk_signals(p_org uuid, p_agent uuid, p_now timestamptz)
RETURNS TABLE (agent_id uuid, signal text, recent_all integer, older_all integer, recent_action integer, older_action integer)
LANGUAGE sql
STABLE
SET search_path = public, pg_temp
AS $$
    WITH a AS (
        SELECT g.id, g.risk_released_at FROM public.agents g
        WHERE g.organization_id = p_org AND (p_agent IS NULL OR g.id = p_agent)
    ),
    ev AS (
        SELECT t.agent_id, 'trip'::text AS signal, t.occurred_at AS at
        FROM public.honeytrips t JOIN a ON a.id = t.agent_id
        WHERE t.organization_id = p_org AND t.occurred_at > p_now - interval '7 days' AND t.occurred_at <= p_now
        UNION ALL
        SELECT f.agent_id,
               CASE WHEN f.review_status = 'confirmed' THEN 'confirmed_finding'
                    WHEN f.kind = 'destination' THEN 'destination_open'
                    WHEN f.kind = 'loop' THEN 'loop_open'
                    ELSE 'radar_open' END,
               f.last_seen_at
        FROM public.security_findings f JOIN a ON a.id = f.agent_id
        WHERE f.organization_id = p_org AND f.last_seen_at > p_now - interval '7 days' AND f.last_seen_at <= p_now
          AND (
              f.review_status = 'confirmed'
              OR (f.review_status = 'open' AND f.confidence <> 'low' AND NOT EXISTS (
                  SELECT 1 FROM public.radar_suppressions s
                  WHERE s.agent_id = f.agent_id AND s.rule_id = f.rule_id AND s.revoked_at IS NULL AND s.expires_at > p_now))
          )
        UNION ALL
        SELECT e.agent_id, 'refusal', e.occurred_at
        FROM public.agent_events e JOIN a ON a.id = e.agent_id
        WHERE e.organization_id = p_org AND e.decision = 'BLOCK' AND e.occurred_at > p_now - interval '7 days' AND e.occurred_at <= p_now
          AND EXISTS (SELECT 1 FROM unnest(e.reasons) r
                      WHERE r LIKE '%is not in this agent''s passport scopes.' OR r LIKE '%is not approved: its current version has not been reviewed.')
        UNION ALL
        SELECT b.agent_id, 'budget_limit', b.limit_reached_at
        FROM public.agent_budget_state b JOIN a ON a.id = b.agent_id
        WHERE b.limit_reached_at > p_now - interval '24 hours' AND b.limit_reached_at <= p_now
    )
    SELECT ev.agent_id, ev.signal,
           (count(*) FILTER (WHERE ev.at > p_now - interval '24 hours'))::integer,
           (count(*) FILTER (WHERE ev.at <= p_now - interval '24 hours'))::integer,
           (count(*) FILTER (WHERE ev.at > p_now - interval '24 hours' AND (a.risk_released_at IS NULL OR ev.at > a.risk_released_at)))::integer,
           (count(*) FILTER (WHERE ev.at <= p_now - interval '24 hours' AND (a.risk_released_at IS NULL OR ev.at > a.risk_released_at)))::integer
    FROM ev JOIN a ON a.id = ev.agent_id
    GROUP BY ev.agent_id, ev.signal
$$;

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
    'passport.spend_limit_changed'
)) NOT VALID;

COMMIT;
