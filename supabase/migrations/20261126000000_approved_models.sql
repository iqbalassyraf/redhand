-- =============================================================================
-- Phase 4.5 B4b: approved models, detective (docs/plans/phase45-b4-spend.md, ADR 0023 amendment).
-- Rollback: supabase/rollbacks/20261126000000_approved_models.down.sql
--
-- An organization may keep a list of approved models (at most 50). While the list is not empty, a model an agent's SDK reports that is not on it
-- becomes ONE finding per agent, model and 5-minute window: rule RAD-MDL-001, kind 'model' (place 'call', family 'model'), the sanitized
-- provider/model in tool_name, with its own 10-minute alert cooldown. An empty list means no check (owner decision D5). Detective only: nothing is
-- refused, and a model finding adds NO points to the Risk score (decision D4), whether open or confirmed.
--
-- New: approved_models, organizations.approved_models_version, agents.model_last_alert_at, approved_models_list(), control_approved_models(),
-- record_model_findings(). Changed: the audit action list (every earlier action kept), the finding rule and kind checks and the suppression rule
-- check (MDL added), control_radar_suppression_create() (only its rule check), agent_risk_signals() (only: kind 'model' is excluded).
-- record_security_findings() is NOT changed: model findings have their own small writer, which keeps the gateway's large function untouched.
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
    'organization.approved_models_changed'
));

CREATE TABLE public.approved_models (
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider ~ '^[a-z0-9][a-z0-9_.:/-]{0,63}$'),
    model TEXT NOT NULL CHECK (model ~ '^[a-z0-9][a-z0-9_.:/-]{0,127}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, provider, model)
);
ALTER TABLE public.approved_models ENABLE ROW LEVEL SECURITY;  -- core uses the service role; no policies, nobody else reads it

ALTER TABLE public.organizations ADD COLUMN approved_models_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE public.agents ADD COLUMN model_last_alert_at TIMESTAMPTZ;

ALTER TABLE public.security_findings DROP CONSTRAINT security_findings_rule_id_check;
ALTER TABLE public.security_findings ADD CONSTRAINT security_findings_rule_id_check CHECK (rule_id ~ '^RAD-(INJ|OUT|LOOP|DST|MDL)-[0-9]{3}$');
ALTER TABLE public.security_findings DROP CONSTRAINT security_findings_kind_check;
ALTER TABLE public.security_findings ADD CONSTRAINT security_findings_kind_check CHECK (kind IN ('injection', 'output', 'loop', 'destination', 'model'));
ALTER TABLE public.radar_suppressions DROP CONSTRAINT radar_suppressions_rule_id_check;
ALTER TABLE public.radar_suppressions ADD CONSTRAINT radar_suppressions_rule_id_check CHECK (rule_id ~ '^RAD-(INJ|OUT|LOOP|DST|MDL)-[0-9]{3}$');

-- Suppression accepts RAD-MDL-001 (the only change: the rule pattern).
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
    IF p_rule IS NULL OR p_rule !~ '^RAD-(INJ|OUT|LOOP|DST|MDL)-[0-9]{3}$' OR p_days IS NULL OR p_days NOT BETWEEN 1 AND 90
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

-- Risk signals: as in the Risk Engine migration, except that findings of kind 'model' are never counted.
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
          AND f.kind <> 'model'  -- approved-model findings add no points (owner decision D4), confirmed or not
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

-- -----------------------------------------------------------------------------
-- approved_models_list(): the organization's list, sorted.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.approved_models_list(p_org uuid)
RETURNS TABLE (provider text, model text)
LANGUAGE sql
STABLE
SET search_path = public, pg_temp
AS $$
    SELECT m.provider, m.model FROM public.approved_models m WHERE m.organization_id = p_org ORDER BY m.provider, m.model
$$;

-- -----------------------------------------------------------------------------
-- control_approved_models(): replaces the organization's whole list, with the audit row, in one transaction. Entries are trimmed and lower-cased,
-- must be plain names ([a-z0-9] then [a-z0-9_.:/-]) and are de-duplicated; at most 50. Compare-and-set on the list's version: a caller that
-- decided (for example "clearing needs a confirmation") against an older version gets {conflict: true} and nothing changes. Idempotent: the same
-- list changes nothing and writes no audit row.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_approved_models(p_org uuid, p_actor uuid, p_items jsonb, p_reason text, p_expected_version integer)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
    v_new jsonb;
    v_old jsonb;
BEGIN
    IF p_items IS NULL OR jsonb_typeof(p_items) <> 'array' OR jsonb_array_length(p_items) > 50 THEN
        RAISE EXCEPTION 'items must be an array of at most 50' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(p_items) e
               WHERE jsonb_typeof(e) <> 'object'
                  OR jsonb_typeof(e -> 'provider') IS DISTINCT FROM 'string' OR jsonb_typeof(e -> 'model') IS DISTINCT FROM 'string'
                  OR lower(btrim(e ->> 'provider')) !~ '^[a-z0-9][a-z0-9_.:/-]{0,63}$'
                  OR lower(btrim(e ->> 'model')) !~ '^[a-z0-9][a-z0-9_.:/-]{0,127}$') THEN
        RAISE EXCEPTION 'each item needs a plain provider and model name' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_org.approved_models_version IS DISTINCT FROM p_expected_version THEN
        RETURN jsonb_build_object('conflict', true);
    END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('provider', x.provider, 'model', x.model) ORDER BY x.provider, x.model), '[]'::jsonb) INTO v_new
    FROM (SELECT DISTINCT lower(btrim(e ->> 'provider')) AS provider, lower(btrim(e ->> 'model')) AS model FROM jsonb_array_elements(p_items) e) x;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('provider', m.provider, 'model', m.model) ORDER BY m.provider, m.model), '[]'::jsonb) INTO v_old
    FROM public.approved_models m WHERE m.organization_id = p_org;
    IF v_new = v_old THEN
        RETURN jsonb_build_object('changed', false, 'version', v_org.approved_models_version, 'count', jsonb_array_length(v_old));
    END IF;
    DELETE FROM public.approved_models WHERE organization_id = p_org;
    INSERT INTO public.approved_models (organization_id, provider, model)
    SELECT p_org, e ->> 'provider', e ->> 'model' FROM jsonb_array_elements(v_new) e;
    UPDATE public.organizations SET approved_models_version = approved_models_version + 1 WHERE id = p_org;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'organization.approved_models_changed', 'organization', p_org, p_reason,
            jsonb_build_object('old_count', jsonb_array_length(v_old), 'new_count', jsonb_array_length(v_new)));
    RETURN jsonb_build_object('changed', true, 'version', v_org.approved_models_version + 1, 'count', jsonb_array_length(v_new));
END $$;

-- -----------------------------------------------------------------------------
-- record_model_findings(): p_items is the distinct (provider, model) pairs one ingest batch reported (at most 20). With an empty list nothing
-- happens. A pair that is not approved (exactly, or as a dated id model-YYYYMMDD of an approved model) becomes a finding, unless the agent has a
-- live silence on RAD-MDL-001. The model name is reduced to plain characters before it is stored. Alerts: one per agent per 10 minutes.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.record_model_findings(p_org uuid, p_agent uuid, p_items jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_agent public.agents%ROWTYPE;
    v_item jsonb;
    v_provider text; v_model text; v_name text; v_base text;
    v_window timestamptz := to_timestamp(floor(extract(epoch FROM now()) / 300) * 300);
    v_new integer := 0; v_coalesced integer := 0; v_suppressed integer := 0; v_skipped integer := 0;
    v_first text;
    v_inserted boolean;
    v_alert boolean := false;
    v_listed boolean;
BEGIN
    IF p_items IS NULL OR jsonb_typeof(p_items) <> 'array' OR jsonb_array_length(p_items) > 20 THEN
        RAISE EXCEPTION 'items must be an array of at most 20' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO v_agent FROM public.agents WHERE id = p_agent AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'agent not found' USING ERRCODE = 'no_data_found';
    END IF;
    SELECT EXISTS (SELECT 1 FROM public.approved_models WHERE organization_id = p_org) INTO v_listed;
    IF NOT v_listed THEN
        RETURN jsonb_build_object('new', 0, 'coalesced', 0, 'suppressed', 0, 'skipped', 0, 'alert', false, 'agent', v_agent.name, 'model', NULL, 'listed', false);
    END IF;

    FOR v_item IN SELECT * FROM jsonb_array_elements(p_items) LOOP
        IF jsonb_typeof(v_item) <> 'object' OR jsonb_typeof(v_item -> 'provider') IS DISTINCT FROM 'string' OR jsonb_typeof(v_item -> 'model') IS DISTINCT FROM 'string' THEN
            v_skipped := v_skipped + 1;
            CONTINUE;
        END IF;
        v_provider := lower(left(btrim(v_item ->> 'provider'), 64));
        v_model := lower(left(btrim(v_item ->> 'model'), 128));
        IF v_model = '' THEN v_skipped := v_skipped + 1; CONTINUE; END IF;
        v_base := CASE WHEN v_model ~ '^.+-[0-9]{8}$' THEN left(v_model, length(v_model) - 9) ELSE NULL END;
        IF EXISTS (SELECT 1 FROM public.approved_models m
                   WHERE m.organization_id = p_org AND m.provider = v_provider AND (m.model = v_model OR m.model = v_base)) THEN
            CONTINUE;
        END IF;
        -- plain characters only, whatever the SDK sent: this text reaches the dashboard and a chat
        v_name := left(regexp_replace(CASE WHEN v_provider = '' THEN v_model ELSE v_provider || '/' || v_model END, '[^a-z0-9_.:/-]', '_', 'g'), 128);
        IF EXISTS (SELECT 1 FROM public.radar_suppressions
                   WHERE agent_id = p_agent AND rule_id = 'RAD-MDL-001' AND revoked_at IS NULL AND expires_at > now()) THEN
            v_suppressed := v_suppressed + 1;
            CONTINUE;
        END IF;
        INSERT INTO public.security_findings AS f (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, evasion,
                                                   tool_name, server_slug, would_block, occurrences, window_start)
        VALUES (p_org, p_agent, 'RAD-MDL-001', 'model', 'model', 'medium', 'high', 'call', '{}', v_name, '', false, 1, v_window)
        ON CONFLICT (organization_id, agent_id, rule_id, tool_name, place, window_start) DO UPDATE SET
            occurrences = least(f.occurrences + 1, 1000000), last_seen_at = now()
        RETURNING (xmax = 0) INTO v_inserted;
        IF v_inserted THEN
            v_new := v_new + 1;
            v_first := coalesce(v_first, v_name);
        ELSE
            v_coalesced := v_coalesced + 1;
        END IF;
    END LOOP;

    IF v_new > 0 AND (v_agent.model_last_alert_at IS NULL OR v_agent.model_last_alert_at < now() - interval '10 minutes') THEN
        UPDATE public.agents SET model_last_alert_at = now() WHERE id = p_agent;
        v_alert := true;
    END IF;
    RETURN jsonb_build_object('new', v_new, 'coalesced', v_coalesced, 'suppressed', v_suppressed, 'skipped', v_skipped, 'alert', v_alert,
                              'agent', v_agent.name, 'model', v_first, 'listed', true);
END $$;

REVOKE EXECUTE ON FUNCTION public.approved_models_list(uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_approved_models(uuid, uuid, jsonb, text, integer) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.record_model_findings(uuid, uuid, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.approved_models_list(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_approved_models(uuid, uuid, jsonb, text, integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.record_model_findings(uuid, uuid, jsonb) TO service_role;

COMMIT;
