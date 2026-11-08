-- =============================================================================
-- Prompt Injection Radar and output checks, data layer (Phase 4 M4.2). Rollback:
-- supabase/rollbacks/20261117000000_radar_findings.down.sql.   Plan: docs/plans/phase4-m4-plan.md (sections 3, 6 and 11)
--
-- The gateway (M4.3) scans tool results and reports findings. record_security_findings() stores them COALESCED: one row per
-- agent, rule, tool, place and 5-minute window, with a count. A finding never contains the scanned text: it holds a fixed
-- rule id, family, severity, confidence, a coarse place and evasion tags (all validated here), so a finding cannot itself carry
-- an attack to whoever reads it. Per organization there are two modes, injection and output: off or observe (the default).
-- block is refused until the measured gate exists (M4.6): fail closed.
-- Owners can mark a finding confirmed or false alarm, and suppress one rule for one agent for a limited time (audited).
-- All functions are service_role only; who may call them is decided in redhand-core.
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
    'radar_suppression.created', 'radar_suppression.revoked'
));

-- Modes and the time each last changed (the per-organization block gate in M4.6 needs "how long has this been in observe").
ALTER TABLE public.organizations
    ADD COLUMN radar_mode TEXT NOT NULL DEFAULT 'observe' CHECK (radar_mode IN ('off', 'observe', 'block')),
    ADD COLUMN output_check_mode TEXT NOT NULL DEFAULT 'observe' CHECK (output_check_mode IN ('off', 'observe', 'block')),
    ADD COLUMN radar_mode_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN output_check_mode_changed_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE public.agents ADD COLUMN radar_last_alert_at TIMESTAMPTZ;

CREATE TABLE public.security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL CHECK (rule_id ~ '^RAD-(INJ|OUT)-[0-9]{3}$'),
    family TEXT NOT NULL CHECK (family ~ '^[a-z][a-z-]{1,23}$'),
    kind TEXT NOT NULL CHECK (kind IN ('injection', 'output')),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    place TEXT NOT NULL CHECK (place IN ('text', 'hidden', 'decoded')),
    evasion TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(evasion) <= 5 AND evasion <@ ARRAY['invisible', 'lookalike', 'leet', 'encoded', 'hidden']),
    tool_name TEXT NOT NULL DEFAULT '' CHECK (char_length(tool_name) <= 128),
    server_slug TEXT NOT NULL DEFAULT '' CHECK (char_length(server_slug) <= 63),
    would_block BOOLEAN NOT NULL DEFAULT FALSE,
    occurrences INTEGER NOT NULL DEFAULT 1 CHECK (occurrences BETWEEN 1 AND 1000000),
    window_start TIMESTAMPTZ NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    review_status TEXT NOT NULL DEFAULT 'open' CHECK (review_status IN ('open', 'confirmed', 'false_alarm')),
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    review_note TEXT CHECK (review_note IS NULL OR char_length(review_note) <= 300),
    UNIQUE (organization_id, agent_id, rule_id, tool_name, place, window_start)
);
CREATE INDEX idx_security_findings_org_time ON public.security_findings(organization_id, last_seen_at DESC);
CREATE INDEX idx_security_findings_agent_time ON public.security_findings(agent_id, first_seen_at);
ALTER TABLE public.security_findings ENABLE ROW LEVEL SECURITY;  -- core uses the service role; no policies, nobody else reads it

CREATE TABLE public.radar_suppressions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL CHECK (rule_id ~ '^RAD-(INJ|OUT)-[0-9]{3}$'),
    reason TEXT NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 3 AND 300),
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '90 days')
);
-- At most one live suppression per agent and rule (live = not revoked; an expired one is simply ignored).
CREATE UNIQUE INDEX uq_radar_suppression_live ON public.radar_suppressions(agent_id, rule_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_radar_suppressions_org ON public.radar_suppressions(organization_id, created_at DESC);
ALTER TABLE public.radar_suppressions ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- record_security_findings(): the gateway's report. Idempotent in the sense that matters: repeats coalesce into one row with
-- a count. Bounded: at most 20 items per call, 2,000 new rows per agent per 24 hours (more are counted as capped, never
-- stored). The organization claimed is checked against the agent's real owner. Invalid items are skipped, not trusted.
-- -----------------------------------------------------------------------------
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
        IF v_rule IS NULL OR v_rule !~ '^RAD-(INJ|OUT)-[0-9]{3}$'
           OR v_kind IS NULL OR v_kind NOT IN ('injection', 'output')
           OR (v_kind = 'injection') <> (v_rule LIKE 'RAD-INJ-%')
           OR v_family IS NULL OR v_family !~ '^[a-z][a-z-]{1,23}$'
           OR v_sev IS NULL OR v_sev <> ALL (c_levels) OR v_conf IS NULL OR v_conf <> ALL (c_levels)
           OR v_place IS NULL OR v_place NOT IN ('text', 'hidden', 'decoded') THEN
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

        IF (v_kind = 'injection' AND v_org.radar_mode = 'off') OR (v_kind = 'output' AND v_org.output_check_mode = 'off') THEN
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
            IF cardinality(v_rules) < 5 AND NOT (v_rule = ANY (v_rules)) THEN v_rules := v_rules || v_rule; END IF;
        ELSE
            v_coalesced := v_coalesced + 1;
        END IF;
    END LOOP;

    IF v_new > 0 AND (v_agent.radar_last_alert_at IS NULL OR v_agent.radar_last_alert_at < now() - interval '10 minutes') THEN
        UPDATE public.agents SET radar_last_alert_at = now() WHERE id = p_agent;
        v_alert := true;
    END IF;
    RETURN jsonb_build_object('new', v_new, 'coalesced', v_coalesced, 'suppressed', v_suppressed, 'capped', v_capped,
                              'skipped', v_skipped, 'disabled', v_disabled, 'alert', v_alert, 'agent', v_agent.name, 'rules', to_jsonb(v_rules));
END;
$$;

-- -----------------------------------------------------------------------------
-- control_radar_settings(): compare-and-set on both modes, idempotent, audited. block is refused (the gate arrives in M4.6).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_radar_settings(
    p_org uuid, p_actor uuid, p_injection text, p_output text, p_expected_injection text, p_expected_output text, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
BEGIN
    IF p_injection NOT IN ('off', 'observe') OR p_output NOT IN ('off', 'observe') THEN
        RAISE EXCEPTION 'mode must be off or observe (block is not available yet)' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_org.radar_mode IS DISTINCT FROM p_expected_injection OR v_org.output_check_mode IS DISTINCT FROM p_expected_output THEN
        RETURN jsonb_build_object('conflict', true, 'radar_mode', v_org.radar_mode, 'output_check_mode', v_org.output_check_mode);
    END IF;
    IF v_org.radar_mode = p_injection AND v_org.output_check_mode = p_output THEN
        RETURN jsonb_build_object('conflict', false, 'changed', false, 'radar_mode', p_injection, 'output_check_mode', p_output);
    END IF;
    UPDATE public.organizations SET
        radar_mode = p_injection,
        output_check_mode = p_output,
        radar_mode_changed_at = CASE WHEN radar_mode <> p_injection THEN now() ELSE radar_mode_changed_at END,
        output_check_mode_changed_at = CASE WHEN output_check_mode <> p_output THEN now() ELSE output_check_mode_changed_at END
    WHERE id = p_org;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'organization.radar_settings_changed', 'organization', p_org, p_reason,
            jsonb_build_object('old_injection', v_org.radar_mode, 'new_injection', p_injection,
                               'old_output', v_org.output_check_mode, 'new_output', p_output));
    RETURN jsonb_build_object('conflict', false, 'changed', true, 'radar_mode', p_injection, 'output_check_mode', p_output);
END;
$$;

-- -----------------------------------------------------------------------------
-- control_finding_review(): mark a finding confirmed or a false alarm. Compare-and-set on the status the reviewer saw.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_finding_review(p_org uuid, p_actor uuid, p_finding uuid, p_status text, p_expected text, p_note text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_row public.security_findings%ROWTYPE;
BEGIN
    IF p_status NOT IN ('confirmed', 'false_alarm') OR (p_note IS NOT NULL AND char_length(p_note) > 300) THEN
        RAISE EXCEPTION 'status must be confirmed or false_alarm and the note at most 300 characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO v_row FROM public.security_findings WHERE id = p_finding AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'finding not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_row.review_status IS DISTINCT FROM p_expected THEN
        RETURN jsonb_build_object('conflict', true, 'review_status', v_row.review_status);
    END IF;
    IF v_row.review_status = p_status THEN
        RETURN jsonb_build_object('conflict', false, 'changed', false, 'review_status', p_status);
    END IF;
    UPDATE public.security_findings SET review_status = p_status, reviewed_by = p_actor, reviewed_at = now(), review_note = p_note WHERE id = p_finding;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'radar_finding.reviewed', 'organization', p_org, p_note,
            jsonb_build_object('finding', p_finding, 'rule', v_row.rule_id, 'agent', v_row.agent_id, 'old_status', v_row.review_status, 'new_status', p_status));
    RETURN jsonb_build_object('conflict', false, 'changed', true, 'review_status', p_status);
END;
$$;

-- -----------------------------------------------------------------------------
-- Suppression: one rule on one agent, for 1 to 90 days (default 30), with a reason. Idempotent while a live one exists.
-- At most 100 live suppressions per organization.
-- -----------------------------------------------------------------------------
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
    IF p_rule IS NULL OR p_rule !~ '^RAD-(INJ|OUT)-[0-9]{3}$' OR p_days IS NULL OR p_days NOT BETWEEN 1 AND 90
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

CREATE OR REPLACE FUNCTION public.control_radar_suppression_revoke(p_org uuid, p_actor uuid, p_suppression uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_row public.radar_suppressions%ROWTYPE;
BEGIN
    SELECT * INTO v_row FROM public.radar_suppressions WHERE id = p_suppression AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'suppression not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_row.revoked_at IS NOT NULL THEN
        RETURN jsonb_build_object('revoked', false);
    END IF;
    UPDATE public.radar_suppressions SET revoked_at = now(), revoked_by = p_actor WHERE id = p_suppression;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'radar_suppression.revoked', 'agent', v_row.agent_id, p_reason,
            jsonb_build_object('suppression', p_suppression, 'rule', v_row.rule_id));
    RETURN jsonb_build_object('revoked', true);
END;
$$;

-- -----------------------------------------------------------------------------
-- radar_summary(): the evidence an owner needs before trusting a mode: the last 7 days, by review status.
-- would_block counts findings that block mode would have stopped (recorded by the gateway from M4.3).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.radar_summary(p_org uuid)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
BEGIN
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    RETURN jsonb_build_object(
        'radar_mode', v_org.radar_mode, 'output_check_mode', v_org.output_check_mode,
        'radar_mode_changed_at', v_org.radar_mode_changed_at, 'output_check_mode_changed_at', v_org.output_check_mode_changed_at,
        'last_7_days', COALESCE((
            SELECT jsonb_build_object(
                'findings', count(*), 'occurrences', COALESCE(sum(occurrences), 0),
                'would_block', count(*) FILTER (WHERE would_block),
                'open', count(*) FILTER (WHERE review_status = 'open'),
                'confirmed', count(*) FILTER (WHERE review_status = 'confirmed'),
                'false_alarm', count(*) FILTER (WHERE review_status = 'false_alarm'),
                'would_block_open', count(*) FILTER (WHERE would_block AND review_status = 'open'))
            FROM public.security_findings WHERE organization_id = p_org AND last_seen_at > now() - interval '7 days'), '{}'::jsonb));
END;
$$;

-- Findings are kept 90 days; expired and revoked suppressions 90 days after they ended (documented in the M4 plan).
CREATE OR REPLACE FUNCTION public.purge_findings()
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_findings bigint;
    v_suppressions bigint;
BEGIN
    DELETE FROM public.security_findings WHERE last_seen_at < now() - interval '90 days';
    GET DIAGNOSTICS v_findings = ROW_COUNT;
    DELETE FROM public.radar_suppressions
    WHERE (revoked_at IS NOT NULL AND revoked_at < now() - interval '90 days') OR (revoked_at IS NULL AND expires_at < now() - interval '90 days');
    GET DIAGNOSTICS v_suppressions = ROW_COUNT;
    RETURN jsonb_build_object('findings', v_findings, 'suppressions', v_suppressions);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.record_security_findings(uuid, uuid, jsonb) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_radar_settings(uuid, uuid, text, text, text, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_finding_review(uuid, uuid, uuid, text, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_radar_suppression_create(uuid, uuid, uuid, text, integer, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_radar_suppression_revoke(uuid, uuid, uuid, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.radar_summary(uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.purge_findings() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_security_findings(uuid, uuid, jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_radar_settings(uuid, uuid, text, text, text, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_finding_review(uuid, uuid, uuid, text, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_radar_suppression_create(uuid, uuid, uuid, text, integer, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_radar_suppression_revoke(uuid, uuid, uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.radar_summary(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.purge_findings() TO service_role;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_cron') THEN
        CREATE EXTENSION IF NOT EXISTS pg_cron;
        PERFORM cron.schedule('redhand-purge-findings', '37 19 * * *', 'SELECT public.purge_findings()');
        RAISE NOTICE 'scheduled redhand-purge-findings';
    ELSE
        RAISE NOTICE 'pg_cron is not available here: schedule purge_findings() yourself (daily)';
    END IF;
END;
$$;

COMMIT;

NOTIFY pgrst, 'reload schema';
