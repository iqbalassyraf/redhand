-- =============================================================================
-- Radar evidence from real traffic (Phase 4 M4.6b). Rollback: supabase/rollbacks/20261118000000_radar_scan_counts.down.sql.
-- Plan: docs/plans/phase4-m4-6-block-gate.md.  ADR: docs/adr/0016-block-gate.md.
--
-- The gateway counts, per organization and check, how many tool results it scanned and how many a check flagged, BEFORE its repeat limit and
-- BEFORE suppressions, and sends the totals about once a minute (record_radar_scan_counts). Only numbers are stored: no text, no tool name,
-- no agent. radar_readiness_inputs() hands core the raw inputs for the last 7 UTC days; the judgement (can this organization even consider
-- blocking?) is made in core. It grants nothing: block mode is still refused everywhere. All functions are service_role only.
-- =============================================================================

BEGIN;

CREATE TABLE public.radar_scan_counts (
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('injection', 'output')),
    rules_fingerprint TEXT NOT NULL CHECK (rules_fingerprint = 'unknown' OR rules_fingerprint ~ '^[0-9a-f]{16}(\+model)?$'),
    scanned BIGINT NOT NULL DEFAULT 0 CHECK (scanned >= 0),
    dropped BIGINT NOT NULL DEFAULT 0 CHECK (dropped >= 0),
    errors BIGINT NOT NULL DEFAULT 0 CHECK (errors >= 0),
    flagged BIGINT NOT NULL DEFAULT 0 CHECK (flagged >= 0),
    strong BIGINT NOT NULL DEFAULT 0 CHECK (strong >= 0),
    PRIMARY KEY (organization_id, day, kind, rules_fingerprint),
    CHECK (flagged <= scanned AND strong <= flagged)
);
ALTER TABLE public.radar_scan_counts ENABLE ROW LEVEL SECURITY;  -- core uses the service role; no policies, nobody else reads it

CREATE TABLE public.radar_rule_counts (
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    rule_id TEXT NOT NULL CHECK (rule_id ~ '^RAD-(INJ|OUT)-[0-9]{3}$'),
    rules_fingerprint TEXT NOT NULL CHECK (rules_fingerprint = 'unknown' OR rules_fingerprint ~ '^[0-9a-f]{16}(\+model)?$'),
    flagged BIGINT NOT NULL DEFAULT 0 CHECK (flagged >= 0),
    strong BIGINT NOT NULL DEFAULT 0 CHECK (strong >= 0),
    PRIMARY KEY (organization_id, day, rule_id, rules_fingerprint),
    CHECK (strong <= flagged)
);
ALTER TABLE public.radar_rule_counts ENABLE ROW LEVEL SECURITY;

-- One row per report the gateway sent, so a report that is retried (or delivered twice) is counted once. Kept 7 days.
CREATE TABLE public.radar_count_reports (
    report_id UUID PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE public.radar_count_reports ENABLE ROW LEVEL SECURITY;

-- A non-negative count from untrusted json: NULL when it is not plain digits, never an error, never above p_max.
CREATE OR REPLACE FUNCTION public.radar_count_of(p_value text, p_max bigint)
RETURNS bigint
LANGUAGE sql
IMMUTABLE
SET search_path = public, pg_temp
AS $$
    SELECT CASE WHEN p_value IS NULL OR p_value !~ '^[0-9]{1,18}$' THEN NULL ELSE LEAST(p_value::bigint, p_max) END
$$;

-- -----------------------------------------------------------------------------
-- record_radar_scan_counts(): the gateway's totals since its last report, for the UTC day they arrive. At most 50 items. An item that is
-- not strictly valid is skipped whole (never trusted, never partly stored): an unknown organization, an unknown check, a count that is not
-- a number, more flagged than scanned, more strong than flagged, or a rule entry that does not fit. Counts add up (idempotency is not
-- a retried or duplicated report (same p_report_id) is counted once; a lost report only lowers the numbers, and the consistency check in core
-- notices a gap against the stored findings).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.record_radar_scan_counts(p_report_id uuid, p_fingerprint text, p_items jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_item jsonb; v_rule jsonb;
    v_org uuid; v_kind text;
    v_scanned bigint; v_dropped bigint; v_errors bigint; v_flagged bigint; v_strong bigint;
    v_rid text; v_rf bigint; v_rs bigint;
    v_day date := (now() AT TIME ZONE 'UTC')::date;
    v_recorded integer := 0; v_skipped integer := 0;
    v_ok boolean;
    c_max CONSTANT bigint := 1000000;
BEGIN
    IF p_report_id IS NULL THEN
        RAISE EXCEPTION 'a report id is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_items IS NULL OR jsonb_typeof(p_items) <> 'array' OR jsonb_array_length(p_items) > 50 THEN
        RAISE EXCEPTION 'items must be an array of at most 50' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_fingerprint IS NULL OR NOT (p_fingerprint = 'unknown' OR p_fingerprint ~ '^[0-9a-f]{16}(\+model)?$') THEN
        RAISE EXCEPTION 'invalid rules fingerprint' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO public.radar_count_reports (report_id) VALUES (p_report_id) ON CONFLICT (report_id) DO NOTHING;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('recorded', 0, 'skipped', 0, 'duplicate', true);  -- already counted: a retry or a double delivery
    END IF;
    FOR v_item IN SELECT * FROM jsonb_array_elements(p_items) LOOP
        v_ok := jsonb_typeof(v_item) = 'object';
        IF v_ok THEN
            v_kind := v_item->>'kind';
            v_scanned := public.radar_count_of(v_item->>'scanned', c_max);
            v_dropped := public.radar_count_of(v_item->>'dropped', c_max);
            v_errors := public.radar_count_of(v_item->>'errors', c_max);
            v_flagged := public.radar_count_of(v_item->>'flagged', c_max);
            v_strong := public.radar_count_of(v_item->>'strong', c_max);
            v_ok := v_kind IN ('injection', 'output')
                AND v_scanned IS NOT NULL AND v_dropped IS NOT NULL AND v_errors IS NOT NULL AND v_flagged IS NOT NULL AND v_strong IS NOT NULL
                AND v_flagged <= v_scanned AND v_strong <= v_flagged
                AND (v_item->>'organization_id') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                AND jsonb_typeof(COALESCE(v_item->'rules', '[]'::jsonb)) = 'array'
                AND jsonb_array_length(COALESCE(v_item->'rules', '[]'::jsonb)) <= 40;
        END IF;
        IF v_ok THEN
            v_org := (v_item->>'organization_id')::uuid;
            v_ok := EXISTS (SELECT 1 FROM public.organizations WHERE id = v_org);
        END IF;
        IF v_ok THEN
            FOR v_rule IN SELECT * FROM jsonb_array_elements(COALESCE(v_item->'rules', '[]'::jsonb)) LOOP
                v_rid := CASE WHEN jsonb_typeof(v_rule) = 'object' THEN v_rule->>'rule_id' END;
                v_rf := CASE WHEN jsonb_typeof(v_rule) = 'object' THEN public.radar_count_of(v_rule->>'flagged', c_max) END;
                v_rs := CASE WHEN jsonb_typeof(v_rule) = 'object' THEN public.radar_count_of(v_rule->>'strong', c_max) END;
                IF v_rid IS NULL OR v_rid !~ '^RAD-(INJ|OUT)-[0-9]{3}$' OR (v_kind = 'injection') <> (v_rid LIKE 'RAD-INJ-%')
                   OR v_rf IS NULL OR v_rs IS NULL OR v_rf > v_scanned OR v_rs > v_rf THEN
                    v_ok := false;
                    EXIT;
                END IF;
            END LOOP;
        END IF;
        IF NOT v_ok THEN
            v_skipped := v_skipped + 1;
            CONTINUE;
        END IF;
        INSERT INTO public.radar_scan_counts AS c (organization_id, day, kind, rules_fingerprint, scanned, dropped, errors, flagged, strong)
        VALUES (v_org, v_day, v_kind, p_fingerprint, v_scanned, v_dropped, v_errors, v_flagged, v_strong)
        ON CONFLICT (organization_id, day, kind, rules_fingerprint) DO UPDATE SET
            scanned = c.scanned + EXCLUDED.scanned, dropped = c.dropped + EXCLUDED.dropped, errors = c.errors + EXCLUDED.errors,
            flagged = c.flagged + EXCLUDED.flagged, strong = c.strong + EXCLUDED.strong;
        FOR v_rule IN SELECT * FROM jsonb_array_elements(COALESCE(v_item->'rules', '[]'::jsonb)) LOOP
            INSERT INTO public.radar_rule_counts AS r (organization_id, day, rule_id, rules_fingerprint, flagged, strong)
            VALUES (v_org, v_day, v_rule->>'rule_id', p_fingerprint,
                    public.radar_count_of(v_rule->>'flagged', c_max), public.radar_count_of(v_rule->>'strong', c_max))
            ON CONFLICT (organization_id, day, rule_id, rules_fingerprint) DO UPDATE SET
                flagged = r.flagged + EXCLUDED.flagged, strong = r.strong + EXCLUDED.strong;
        END LOOP;
        v_recorded := v_recorded + 1;
    END LOOP;
    RETURN jsonb_build_object('recorded', v_recorded, 'skipped', v_skipped, 'duplicate', false);
END;
$$;

-- -----------------------------------------------------------------------------
-- radar_readiness_inputs(): raw inputs for the last 7 UTC days (today included) for one organization and, per check ("injection" and
-- "output"): the mode and when it last changed, what was scanned, dropped, errored and flagged, the rules fingerprints seen, per-rule
-- flagged and strong counts, the occurrences stored in findings, strong findings still open, rules with a strong finding marked a false
-- alarm, silences that were live at any time in the window (a silence hides findings, so even a revoked one counts), and the most findings
-- one agent produced on one UTC day (the daily cap is 2,000 per 24 hours). Core judges these; nothing here grants anything.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.radar_readiness_inputs(p_org uuid)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
    v_first date := (now() AT TIME ZONE 'UTC')::date - 6;
    v_ws timestamptz := (((now() AT TIME ZONE 'UTC')::date - 6)::timestamp AT TIME ZONE 'UTC');
    v_kinds jsonb := '{}'::jsonb;
    v_kind text;
    v_prefix text;
BEGIN
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    FOREACH v_kind IN ARRAY ARRAY['injection', 'output'] LOOP
        v_prefix := CASE WHEN v_kind = 'injection' THEN 'RAD-INJ-%' ELSE 'RAD-OUT-%' END;
        v_kinds := v_kinds || jsonb_build_object(v_kind, jsonb_build_object(
            'mode', CASE WHEN v_kind = 'injection' THEN v_org.radar_mode ELSE v_org.output_check_mode END,
            'mode_changed_at', CASE WHEN v_kind = 'injection' THEN v_org.radar_mode_changed_at ELSE v_org.output_check_mode_changed_at END,
            'scanned', COALESCE((SELECT sum(scanned) FROM public.radar_scan_counts WHERE organization_id = p_org AND kind = v_kind AND day >= v_first), 0),
            'dropped', COALESCE((SELECT sum(dropped) FROM public.radar_scan_counts WHERE organization_id = p_org AND kind = v_kind AND day >= v_first), 0),
            'errors', COALESCE((SELECT sum(errors) FROM public.radar_scan_counts WHERE organization_id = p_org AND kind = v_kind AND day >= v_first), 0),
            'flagged', COALESCE((SELECT sum(flagged) FROM public.radar_scan_counts WHERE organization_id = p_org AND kind = v_kind AND day >= v_first), 0),
            'strong', COALESCE((SELECT sum(strong) FROM public.radar_scan_counts WHERE organization_id = p_org AND kind = v_kind AND day >= v_first), 0),
            'fingerprints', COALESCE((SELECT jsonb_agg(DISTINCT rules_fingerprint) FROM public.radar_scan_counts
                                      WHERE organization_id = p_org AND kind = v_kind AND day >= v_first), '[]'::jsonb),
            'rules', COALESCE((SELECT jsonb_object_agg(rule_id, jsonb_build_object('flagged', f, 'strong', s)) FROM (
                                  SELECT rule_id, sum(flagged) AS f, sum(strong) AS s FROM public.radar_rule_counts
                                  WHERE organization_id = p_org AND day >= v_first AND rule_id LIKE v_prefix GROUP BY rule_id) x), '{}'::jsonb),
            'stored_occurrences', COALESCE((SELECT jsonb_object_agg(rule_id, n) FROM (
                                  SELECT rule_id, sum(occurrences) AS n FROM public.security_findings
                                  WHERE organization_id = p_org AND kind = v_kind AND window_start >= v_ws GROUP BY rule_id) x), '{}'::jsonb),
            'strong_open', (SELECT count(*) FROM public.security_findings
                            WHERE organization_id = p_org AND kind = v_kind AND window_start >= v_ws AND would_block AND review_status = 'open'),
            'false_alarm_rules', COALESCE((SELECT jsonb_agg(DISTINCT rule_id) FROM public.security_findings
                            WHERE organization_id = p_org AND kind = v_kind AND window_start >= v_ws AND would_block AND review_status = 'false_alarm'), '[]'::jsonb),
            'silences_in_window', (SELECT count(*) FROM public.radar_suppressions
                            WHERE organization_id = p_org AND rule_id LIKE v_prefix AND expires_at >= v_ws AND (revoked_at IS NULL OR revoked_at >= v_ws)),
            'max_findings_per_agent_day', COALESCE((SELECT max(n) FROM (
                            SELECT count(*) AS n FROM public.security_findings WHERE organization_id = p_org AND window_start >= v_ws
                            GROUP BY agent_id, (window_start AT TIME ZONE 'UTC')::date) x), 0)
        ));
    END LOOP;
    RETURN jsonb_build_object('now', now(), 'window_start', v_ws, 'kinds', v_kinds);
END;
$$;

-- Counts are kept 90 days, like findings (purge_findings is replaced with the same body plus the two new deletes).
CREATE OR REPLACE FUNCTION public.purge_findings()
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_findings bigint;
    v_suppressions bigint;
    v_counts bigint;
    v_rule_counts bigint;
    v_reports bigint;
BEGIN
    DELETE FROM public.security_findings WHERE last_seen_at < now() - interval '90 days';
    GET DIAGNOSTICS v_findings = ROW_COUNT;
    DELETE FROM public.radar_suppressions
    WHERE (revoked_at IS NOT NULL AND revoked_at < now() - interval '90 days') OR (revoked_at IS NULL AND expires_at < now() - interval '90 days');
    GET DIAGNOSTICS v_suppressions = ROW_COUNT;
    DELETE FROM public.radar_scan_counts WHERE day < (now() AT TIME ZONE 'UTC')::date - 90;
    GET DIAGNOSTICS v_counts = ROW_COUNT;
    DELETE FROM public.radar_rule_counts WHERE day < (now() AT TIME ZONE 'UTC')::date - 90;
    GET DIAGNOSTICS v_rule_counts = ROW_COUNT;
    DELETE FROM public.radar_count_reports WHERE received_at < now() - interval '7 days';
    GET DIAGNOSTICS v_reports = ROW_COUNT;
    RETURN jsonb_build_object('findings', v_findings, 'suppressions', v_suppressions, 'scan_counts', v_counts + v_rule_counts + v_reports);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.radar_count_of(text, bigint) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.record_radar_scan_counts(uuid, text, jsonb) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.radar_readiness_inputs(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.radar_count_of(text, bigint) TO service_role;
GRANT EXECUTE ON FUNCTION public.record_radar_scan_counts(uuid, text, jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.radar_readiness_inputs(uuid) TO service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';
