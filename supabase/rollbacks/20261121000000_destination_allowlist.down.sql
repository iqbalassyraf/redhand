-- Rollback for 20261121000000_destination_allowlist.sql: deletes destination findings, RAD-DST suppressions and every allowlist (stated data
-- loss), drops the new functions, table and columns, restores M6's function bodies and checks, and restores the audit CHECK list without the
-- three new actions (NOT VALID: control_audit_log is append-only, so existing passport.destination_* rows stay).

BEGIN;

DELETE FROM public.security_findings WHERE kind = 'destination';
DELETE FROM public.radar_suppressions WHERE rule_id LIKE 'RAD-DST-%';

DROP FUNCTION IF EXISTS public.control_destination_mode(uuid, uuid, uuid, text, text, text);
DROP FUNCTION IF EXISTS public.control_destination_remove(uuid, uuid, uuid, uuid, text);
DROP FUNCTION IF EXISTS public.control_destination_add(uuid, uuid, uuid, text, text);
DROP FUNCTION IF EXISTS public.destination_settings(uuid, uuid);

ALTER TABLE public.radar_suppressions DROP CONSTRAINT radar_suppressions_rule_id_check;
ALTER TABLE public.radar_suppressions ADD CONSTRAINT radar_suppressions_rule_id_check CHECK (rule_id ~ '^RAD-(INJ|OUT|LOOP)-[0-9]{3}$');
ALTER TABLE public.security_findings DROP CONSTRAINT security_findings_kind_check;
ALTER TABLE public.security_findings ADD CONSTRAINT security_findings_kind_check CHECK (kind IN ('injection', 'output', 'loop'));
ALTER TABLE public.security_findings DROP CONSTRAINT security_findings_rule_id_check;
ALTER TABLE public.security_findings ADD CONSTRAINT security_findings_rule_id_check CHECK (rule_id ~ '^RAD-(INJ|OUT|LOOP)-[0-9]{3}$');

-- M6's bodies, copied verbatim from 20261120000000_loop_detection.sql.
CREATE OR REPLACE FUNCTION public.record_security_findings(p_org uuid, p_agent uuid, p_items jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
    v_agent public.agents%ROWTYPE;
    v_item jsonb;
    v_rule text; v_kind text; v_family text; v_sev text; v_conf text; v_place text; v_tool text; v_server text;
    v_evasion text[]; v_occ integer; v_would boolean;
    v_window timestamptz := to_timestamp(floor(extract(epoch FROM now()) / 300) * 300);
    v_new integer := 0; v_coalesced integer := 0; v_suppressed integer := 0; v_capped integer := 0; v_skipped integer := 0; v_disabled integer := 0;
    v_rules text[] := '{}';
    v_inserted boolean;
    v_alert boolean := false;
    v_expected_kind text;
    v_new_loop integer := 0;
    v_loop_tool text;
    v_alert_loop boolean := false;
    c_levels CONSTANT text[] := ARRAY['low', 'medium', 'high'];
BEGIN
    IF p_items IS NULL OR jsonb_typeof(p_items) <> 'array' OR jsonb_array_length(p_items) > 20 THEN
        RAISE EXCEPTION 'items must be an array of at most 20' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    SELECT * INTO v_agent FROM public.agents WHERE id = p_agent AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'agent not found' USING ERRCODE = 'no_data_found';
    END IF;

    FOR v_item IN SELECT * FROM jsonb_array_elements(p_items) LOOP
        IF jsonb_typeof(v_item) <> 'object' THEN v_skipped := v_skipped + 1; CONTINUE; END IF;
        v_rule := v_item->>'rule_id';
        v_kind := v_item->>'kind';
        v_family := v_item->>'family';
        v_sev := v_item->>'severity';
        v_conf := v_item->>'confidence';
        v_place := v_item->>'place';
        v_tool := left(coalesce(v_item->>'tool_name', ''), 128);
        v_server := left(coalesce(v_item->>'server', ''), 63);
        v_would := coalesce((v_item->>'would_block') = 'true', false);
        -- The kind must match the rule's prefix. Computed here because plpgsql reads an IF condition up to its first THEN.
        v_expected_kind := CASE WHEN v_rule LIKE 'RAD-INJ-%' THEN 'injection' WHEN v_rule LIKE 'RAD-OUT-%' THEN 'output' ELSE 'loop' END;
        IF v_rule IS NULL OR v_rule !~ '^RAD-(INJ|OUT|LOOP)-[0-9]{3}$'
           OR v_kind IS NULL OR v_kind NOT IN ('injection', 'output', 'loop')
           OR v_kind <> v_expected_kind
           OR v_family IS NULL OR v_family !~ '^[a-z][a-z-]{1,23}$'
           OR v_sev IS NULL OR v_sev <> ALL (c_levels) OR v_conf IS NULL OR v_conf <> ALL (c_levels)
           OR v_place IS NULL OR v_place NOT IN ('text', 'hidden', 'decoded', 'call')
           OR (v_kind = 'loop') <> (v_place = 'call') THEN
            v_skipped := v_skipped + 1;
            CONTINUE;
        END IF;
        v_occ := CASE WHEN (v_item->>'occurrences') ~ '^[0-9]{10,}$' THEN 1000
                      WHEN (v_item->>'occurrences') ~ '^[0-9]{1,9}$' THEN least(greatest((v_item->>'occurrences')::integer, 1), 1000)
                      ELSE 1 END;
        v_evasion := COALESCE((
            SELECT array_agg(DISTINCT e) FROM jsonb_array_elements_text(
                CASE WHEN jsonb_typeof(v_item->'evasion') = 'array' THEN v_item->'evasion' ELSE '[]'::jsonb END) AS e
            WHERE e IN ('invisible', 'lookalike', 'leet', 'encoded', 'hidden')), '{}');

        IF (v_kind = 'injection' AND v_org.radar_mode = 'off') OR (v_kind = 'output' AND v_org.output_check_mode = 'off')
           OR (v_kind = 'loop' AND v_org.loop_mode = 'off') THEN
            v_disabled := v_disabled + 1;
            CONTINUE;
        END IF;
        IF EXISTS (SELECT 1 FROM public.radar_suppressions
                   WHERE agent_id = p_agent AND rule_id = v_rule AND revoked_at IS NULL AND expires_at > now()) THEN
            v_suppressed := v_suppressed + 1;
            CONTINUE;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM public.security_findings
                       WHERE organization_id = p_org AND agent_id = p_agent AND rule_id = v_rule AND tool_name = v_tool
                         AND place = v_place AND window_start = v_window)
           AND (SELECT count(*) FROM public.security_findings WHERE agent_id = p_agent AND first_seen_at > now() - interval '24 hours') >= 2000 THEN
            v_capped := v_capped + 1;
            CONTINUE;
        END IF;

        INSERT INTO public.security_findings AS f (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, evasion,
                                                   tool_name, server_slug, would_block, occurrences, window_start)
        VALUES (p_org, p_agent, v_rule, v_family, v_kind, v_sev, v_conf, v_place, v_evasion, v_tool, v_server, v_would, v_occ, v_window)
        ON CONFLICT (organization_id, agent_id, rule_id, tool_name, place, window_start) DO UPDATE SET
            occurrences = least(f.occurrences + EXCLUDED.occurrences, 1000000),
            last_seen_at = now(),
            would_block = f.would_block OR EXCLUDED.would_block,
            severity = CASE WHEN array_position(c_levels, EXCLUDED.severity) > array_position(c_levels, f.severity) THEN EXCLUDED.severity ELSE f.severity END,
            confidence = CASE WHEN array_position(c_levels, EXCLUDED.confidence) > array_position(c_levels, f.confidence) THEN EXCLUDED.confidence ELSE f.confidence END
        RETURNING (xmax = 0) INTO v_inserted;
        IF v_inserted THEN
            v_new := v_new + 1;
            IF v_kind = 'loop' THEN
                v_new_loop := v_new_loop + 1;
                v_loop_tool := coalesce(v_loop_tool, v_tool);
            ELSIF cardinality(v_rules) < 5 AND NOT (v_rule = ANY (v_rules)) THEN
                v_rules := v_rules || v_rule;
            END IF;
        ELSE
            v_coalesced := v_coalesced + 1;
        END IF;
    END LOOP;

    -- Each kind has its own 10-minute alert cooldown, so a loop alert cannot hide an injection alert (or the other way round).
    IF v_new - v_new_loop > 0 AND (v_agent.radar_last_alert_at IS NULL OR v_agent.radar_last_alert_at < now() - interval '10 minutes') THEN
        UPDATE public.agents SET radar_last_alert_at = now() WHERE id = p_agent;
        v_alert := true;
    END IF;
    IF v_new_loop > 0 AND (v_agent.loop_last_alert_at IS NULL OR v_agent.loop_last_alert_at < now() - interval '10 minutes') THEN
        UPDATE public.agents SET loop_last_alert_at = now() WHERE id = p_agent;
        v_alert_loop := true;
    END IF;
    RETURN jsonb_build_object('new', v_new, 'coalesced', v_coalesced, 'suppressed', v_suppressed, 'capped', v_capped,
                              'skipped', v_skipped, 'disabled', v_disabled, 'alert', v_alert, 'agent', v_agent.name, 'rules', to_jsonb(v_rules),
                              'loop_new', v_new_loop, 'loop_alert', v_alert_loop, 'loop_tool', v_loop_tool);
END;
$$;

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
    IF p_rule IS NULL OR p_rule !~ '^RAD-(INJ|OUT|LOOP)-[0-9]{3}$' OR p_days IS NULL OR p_days NOT BETWEEN 1 AND 90
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

ALTER TABLE public.security_findings DROP COLUMN IF EXISTS detail;
DROP TABLE IF EXISTS public.agent_destinations;
ALTER TABLE public.agents
    DROP COLUMN IF EXISTS destination_last_alert_at, DROP COLUMN IF EXISTS destination_mode_changed_at, DROP COLUMN IF EXISTS destination_mode;

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
    'organization.loop_settings_changed'
)) NOT VALID;

COMMIT;
