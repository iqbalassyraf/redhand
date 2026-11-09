-- SQL tests for supabase/migrations/20261118000000_radar_scan_counts.sql (Phase 4 M4.6b).

\set ON_ERROR_STOP on
\set QUIET on

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'CHECK FAILED: %', p_msg; END IF;
    RAISE NOTICE 'ok: %', p_msg;
END $$;

CREATE FUNCTION pg_temp.expect_error(p_sql text, p_sqlstate text, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE = p_sqlstate THEN RAISE NOTICE 'ok: % (SQLSTATE %)', p_msg, p_sqlstate; RETURN; END IF;
        RAISE EXCEPTION 'CHECK FAILED: % -- expected % but got % (%)', p_msg, p_sqlstate, SQLSTATE, SQLERRM;
    END;
    RAISE EXCEPTION 'CHECK FAILED: % -- expected SQLSTATE % but it succeeded', p_msg, p_sqlstate;
END $$;

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000e2e0a001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000e2e00001', 'Scan Org A', 'scan-org-a'),
    ('00000000-0000-0000-0000-0000e2e00002', 'Scan Org B', 'scan-org-b');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000e2e0000a', '00000000-0000-0000-0000-0000e2e00001', 'scan-bot-a', 'Scan Bot A'),
    ('00000000-0000-0000-0000-0000e2e0000b', '00000000-0000-0000-0000-0000e2e00002', 'scan-bot-b', 'Scan Bot B');

CREATE FUNCTION pg_temp.count_item(p_org uuid, p_kind text, p_scanned int, p_flagged int, p_strong int, p_rules jsonb DEFAULT '[]', p_extra jsonb DEFAULT '{}')
RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object('organization_id', p_org, 'kind', p_kind, 'scanned', p_scanned, 'dropped', 0, 'errors', 0,
                              'flagged', p_flagged, 'strong', p_strong, 'rules', p_rules) || p_extra
$$;

DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-0000e2e00001';
    b uuid := '00000000-0000-0000-0000-0000e2e00002';
    ag uuid := '00000000-0000-0000-0000-0000e2e0000a';
    actor uuid := '00000000-0000-0000-0000-0000e2e0a001';
    fp text := '0123456789abcdef';
    r jsonb; i jsonb; f uuid;
BEGIN
    -- recording adds up per organization, day, check and rules version
    r := public.record_radar_scan_counts(gen_random_uuid(), fp, jsonb_build_array(
        pg_temp.count_item(a, 'injection', 100, 6, 4, '[{"rule_id":"RAD-INJ-001","flagged":5,"strong":4},{"rule_id":"RAD-INJ-008","flagged":2,"strong":0}]'),
        pg_temp.count_item(a, 'output', 100, 1, 1, '[{"rule_id":"RAD-OUT-001","flagged":1,"strong":1}]')));
    PERFORM pg_temp.check((r->>'recorded')::int = 2 AND (r->>'skipped')::int = 0, 'two valid items are recorded');
    PERFORM public.record_radar_scan_counts(gen_random_uuid(), fp, jsonb_build_array(pg_temp.count_item(a, 'injection', 50, 2, 1, '[{"rule_id":"RAD-INJ-001","flagged":2,"strong":1}]', '{"dropped": 3, "errors": 1}')));
    i := public.radar_readiness_inputs(a)->'kinds'->'injection';
    PERFORM pg_temp.check((i->>'scanned')::int = 150 AND (i->>'flagged')::int = 8 AND (i->>'strong')::int = 5
        AND (i->>'dropped')::int = 3 AND (i->>'errors')::int = 1, 'repeated reports add up');
    PERFORM pg_temp.check((i->'rules'->'RAD-INJ-001'->>'flagged')::int = 7 AND (i->'rules'->'RAD-INJ-001'->>'strong')::int = 5
        AND (i->'rules'->'RAD-INJ-008'->>'strong')::int = 0 AND i->'rules' ? 'RAD-OUT-001' = false, 'per-rule counts add up and stay with their own check');
    PERFORM pg_temp.check(i->'fingerprints' = jsonb_build_array(fp) AND (public.radar_readiness_inputs(a)->'kinds'->'output'->>'scanned')::int = 100, 'the rules version and the other check are kept apart');

    -- another organization sees none of it
    PERFORM pg_temp.check((public.radar_readiness_inputs(b)->'kinds'->'injection'->>'scanned')::int = 0
        AND public.radar_readiness_inputs(b)->'kinds'->'injection'->'rules' = '{}'::jsonb, 'another organization sees none of the counts');

    -- an item that is not strictly valid is skipped whole, never partly stored
    r := public.record_radar_scan_counts(gen_random_uuid(), fp, jsonb_build_array(
        pg_temp.count_item(a, 'injection', 10, 11, 0),                                            -- more flagged than scanned
        pg_temp.count_item(a, 'injection', 10, 3, 4),                                             -- more strong than flagged
        pg_temp.count_item(a, 'secrets', 10, 0, 0),                                               -- unknown check
        pg_temp.count_item(a, 'injection', 10, 1, 1, '[{"rule_id":"RAD-OUT-001","flagged":1,"strong":1}]'),  -- rule of the other check
        pg_temp.count_item(a, 'injection', 10, 1, 1, '[{"rule_id":"free text","flagged":1,"strong":1}]'),    -- not a rule id
        pg_temp.count_item(a, 'injection', 10, 1, 1, '[{"rule_id":"RAD-INJ-001","flagged":11,"strong":1}]'), -- rule flagged more than scanned
        pg_temp.count_item(a, 'injection', 10, 1, 1, '[{"rule_id":"RAD-INJ-001","flagged":1,"strong":2}]'),  -- rule strong above flagged
        pg_temp.count_item(a, 'injection', 10, 1, 1, '[{"rule_id":"RAD-INJ-001","flagged":1,"strong":1},7]'),-- one bad entry spoils the item
        pg_temp.count_item('00000000-0000-0000-0000-0000e2eeeeee', 'injection', 10, 0, 0),         -- unknown organization
        pg_temp.count_item(a, 'injection', 10, 0, 0, '[]', '{"organization_id": "not-a-uuid"}'),
        pg_temp.count_item(a, 'injection', 10, 0, 0, '[]', '{"scanned": "ten"}'),
        pg_temp.count_item(a, 'injection', 10, 0, 0, '[]', '{"scanned": -1}'),
        pg_temp.count_item(a, 'injection', 10, 0, 0, '[]', '{"errors": null}'),
        '"just a string"'::jsonb, '7'::jsonb));
    PERFORM pg_temp.check((r->>'recorded')::int = 0 AND (r->>'skipped')::int = 15, 'every invalid item is skipped');
    PERFORM pg_temp.check((public.radar_readiness_inputs(a)->'kinds'->'injection'->>'scanned')::int = 150, 'and none of them changed a count');

    -- the same report delivered twice is counted once
    r := public.record_radar_scan_counts('00000000-0000-0000-0000-0000e2e0d001', fp, jsonb_build_array(pg_temp.count_item(b, 'injection', 40, 2, 1, '[{"rule_id":"RAD-INJ-001","flagged":2,"strong":1}]')));
    PERFORM pg_temp.check((r->>'recorded')::int = 1 AND (r->>'duplicate')::boolean = false, 'a new report is recorded');
    r := public.record_radar_scan_counts('00000000-0000-0000-0000-0000e2e0d001', fp, jsonb_build_array(pg_temp.count_item(b, 'injection', 40, 2, 1, '[{"rule_id":"RAD-INJ-001","flagged":2,"strong":1}]')));
    PERFORM pg_temp.check((r->>'recorded')::int = 0 AND (r->>'duplicate')::boolean, 'the same report id again is recognised as a duplicate');
    PERFORM pg_temp.check((public.radar_readiness_inputs(b)->'kinds'->'injection'->>'scanned')::int = 40
        AND (public.radar_readiness_inputs(b)->'kinds'->'injection'->'rules'->'RAD-INJ-001'->>'flagged')::int = 2, 'a duplicate changes no count');
    PERFORM pg_temp.expect_error(format('SELECT public.record_radar_scan_counts(NULL, %L, ''[]'')', fp), '22023', 'a report id is required');

    -- huge numbers are clamped, not trusted
    PERFORM public.record_radar_scan_counts(gen_random_uuid(), fp, jsonb_build_array(pg_temp.count_item(b, 'output', 5, 0, 0, '[]', '{"dropped": 99999999999}')));
    PERFORM pg_temp.check((public.radar_readiness_inputs(b)->'kinds'->'output'->>'dropped')::bigint = 1000000, 'an absurd count is clamped');

    -- the call itself is bounded
    PERFORM pg_temp.expect_error(format('SELECT public.record_radar_scan_counts(gen_random_uuid(), %L, %L)', fp, (SELECT jsonb_agg(pg_temp.count_item(a, 'output', 1, 0, 0)) FROM generate_series(1, 51))), '22023', 'more than 50 items is refused');
    PERFORM pg_temp.expect_error(format('SELECT public.record_radar_scan_counts(gen_random_uuid(), %L, ''{}'')', fp), '22023', 'items must be an array');
    PERFORM pg_temp.expect_error('SELECT public.record_radar_scan_counts(gen_random_uuid(), ''not a fingerprint'', ''[]'')', '22023', 'a malformed rules fingerprint is refused');
    PERFORM pg_temp.expect_error('SELECT public.record_radar_scan_counts(gen_random_uuid(), NULL, ''[]'')', '22023', 'a missing rules fingerprint is refused');
    PERFORM pg_temp.check((public.record_radar_scan_counts(gen_random_uuid(), 'unknown', '[]')->>'recorded')::int = 0 AND (public.record_radar_scan_counts(gen_random_uuid(), fp || '+model', '[]')->>'skipped')::int = 0, 'unknown and +model are valid fingerprints');
    PERFORM pg_temp.expect_error(format('SELECT public.radar_readiness_inputs(%L)', '00000000-0000-0000-0000-0000e2eeeeee'), 'P0002', 'an unknown organization has no inputs');
END $$;

CREATE FUNCTION pg_temp.item(p_rule text, p_tool text, p_would boolean) RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'rule_id', p_rule, 'kind', CASE WHEN p_rule LIKE 'RAD-INJ-%' THEN 'injection' ELSE 'output' END,
        'family', 'override', 'severity', 'high', 'confidence', 'medium', 'place', 'text', 'tool_name', p_tool, 'server', 'helpdesk',
        'evasion', '[]'::jsonb, 'would_block', p_would)
$$;

-- the window: the last 7 UTC days, today included
DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-0000e2e00001';
    b uuid := '00000000-0000-0000-0000-0000e2e00002';
    ag uuid := '00000000-0000-0000-0000-0000e2e0000a';
    actor uuid := '00000000-0000-0000-0000-0000e2e0a001';
    fp text := '0123456789abcdef';
    today date := (now() AT TIME ZONE 'UTC')::date;
    i jsonb; r jsonb; f uuid; sup uuid;
BEGIN
    INSERT INTO public.radar_scan_counts (organization_id, day, kind, rules_fingerprint, scanned) VALUES
        (a, today - 7, 'injection', 'ffffffffffffffff', 1000), (a, today - 6, 'injection', 'eeeeeeeeeeeeeeee', 11);
    i := public.radar_readiness_inputs(a)->'kinds'->'injection';
    PERFORM pg_temp.check((i->>'scanned')::int = 150 + 11, 'seven days ago is outside the window, six days ago is inside');
    PERFORM pg_temp.check(i->'fingerprints' @> jsonb_build_array(fp, 'eeeeeeeeeeeeeeee') AND NOT i->'fingerprints' @> '["ffffffffffffffff"]'::jsonb, 'the rules versions seen in the window are listed, old ones are not');
    PERFORM pg_temp.check((public.radar_readiness_inputs(a)->>'window_start')::timestamptz = ((today - 6)::timestamp AT TIME ZONE 'UTC'), 'the window starts at midnight UTC six days ago');

    -- findings feed the review inputs
    PERFORM public.record_security_findings(a, ag, jsonb_build_array(pg_temp.item('RAD-INJ-001', 't1', true), pg_temp.item('RAD-INJ-008', 't1', true), pg_temp.item('RAD-INJ-002', 't1', false), pg_temp.item('RAD-OUT-001', 't1', true)));
    i := public.radar_readiness_inputs(a)->'kinds'->'injection';
    PERFORM pg_temp.check((i->>'strong_open')::int = 2, 'strong findings that are still open are counted; a low-confidence one is not');
    PERFORM pg_temp.check((public.radar_readiness_inputs(a)->'kinds'->'output'->>'strong_open')::int = 1, 'each check counts its own findings');
    PERFORM pg_temp.check((i->'stored_occurrences'->>'RAD-INJ-001')::int = 1 AND NOT i->'stored_occurrences' ? 'RAD-OUT-001', 'stored occurrences are kept per rule and per check');
    SELECT id INTO f FROM public.security_findings WHERE agent_id = ag AND rule_id = 'RAD-INJ-008';
    PERFORM public.control_finding_review(a, actor, f, 'false_alarm', 'open', 'harmless runbook');
    i := public.radar_readiness_inputs(a)->'kinds'->'injection';
    PERFORM pg_temp.check((i->>'strong_open')::int = 1 AND i->'false_alarm_rules' = '["RAD-INJ-008"]'::jsonb, 'a strong finding marked false alarm names its rule and is no longer open');
    SELECT id INTO f FROM public.security_findings WHERE agent_id = ag AND rule_id = 'RAD-INJ-002';
    PERFORM public.control_finding_review(a, actor, f, 'false_alarm', 'open', 'low one');
    PERFORM pg_temp.check(public.radar_readiness_inputs(a)->'kinds'->'injection'->'false_alarm_rules' = '["RAD-INJ-008"]'::jsonb, 'a low-confidence finding marked false alarm does not taint its rule');
    SELECT id INTO f FROM public.security_findings WHERE agent_id = ag AND rule_id = 'RAD-INJ-001';
    PERFORM public.control_finding_review(a, actor, f, 'confirmed', 'open', 'a real attack');
    PERFORM pg_temp.check((public.radar_readiness_inputs(a)->'kinds'->'injection'->>'strong_open')::int = 0, 'a confirmed finding is reviewed');
    PERFORM pg_temp.check((public.radar_readiness_inputs(a)->'kinds'->'injection'->>'max_findings_per_agent_day')::int >= 4, 'the busiest agent-day is reported');
    INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES ('00000000-0000-0000-0000-0000e2e000a2', a, 'scan-bot-a2', 'Scan Bot A2');
    PERFORM public.record_security_findings(a, '00000000-0000-0000-0000-0000e2e000a2', jsonb_build_array(
        pg_temp.item('RAD-INJ-001', 'x1', true), pg_temp.item('RAD-INJ-001', 'x2', true), pg_temp.item('RAD-INJ-001', 'x3', true)));
    PERFORM pg_temp.check((public.radar_readiness_inputs(a)->'kinds'->'injection'->>'max_findings_per_agent_day')::int = 4,
        'the busiest agent-day is per agent: another agent''s findings do not add to it');
    PERFORM pg_temp.check((public.radar_readiness_inputs(b)->'kinds'->'injection'->>'strong_open')::int = 0
        AND public.radar_readiness_inputs(b)->'kinds'->'injection'->'false_alarm_rules' = '[]'::jsonb, 'another organization sees none of the review state');

    -- silences: even a revoked one counts, because while it was live it hid findings; one that ended before the window does not
    PERFORM pg_temp.check((public.radar_readiness_inputs(a)->'kinds'->'injection'->>'silences_in_window')::int = 0, 'no silence yet');
    sup := (public.control_radar_suppression_create(a, actor, ag, 'RAD-INJ-001', 5, 'noisy runbook')->>'id')::uuid;
    PERFORM pg_temp.check((public.radar_readiness_inputs(a)->'kinds'->'injection'->>'silences_in_window')::int = 1
        AND (public.radar_readiness_inputs(a)->'kinds'->'output'->>'silences_in_window')::int = 0, 'a live silence counts for its own check only');
    PERFORM public.control_radar_suppression_revoke(a, actor, sup, 'oops');
    PERFORM pg_temp.check((public.radar_readiness_inputs(a)->'kinds'->'injection'->>'silences_in_window')::int = 1, 'a revoked silence still counts: it hid findings while it was live');
    UPDATE public.radar_suppressions SET created_at = now() - interval '30 days', expires_at = now() - interval '20 days', revoked_at = now() - interval '25 days' WHERE id = sup;
    PERFORM pg_temp.check((public.radar_readiness_inputs(a)->'kinds'->'injection'->>'silences_in_window')::int = 0, 'a silence that ended before the window does not count');

    -- modes and the time they last changed
    i := public.radar_readiness_inputs(a)->'kinds'->'injection';
    PERFORM pg_temp.check(i->>'mode' = 'observe' AND (i->>'mode_changed_at')::timestamptz IS NOT NULL, 'the mode and its change time are reported');
    PERFORM public.control_radar_settings(a, actor, 'off', 'observe', 'observe', 'observe', 'test');
    i := public.radar_readiness_inputs(a)->'kinds'->'injection';
    PERFORM pg_temp.check(i->>'mode' = 'off' AND (i->>'mode_changed_at')::timestamptz > now() - interval '1 minute'
        AND public.radar_readiness_inputs(a)->'kinds'->'output'->>'mode' = 'observe', 'a mode change is visible per check');

    -- retention and cascade
    UPDATE public.radar_scan_counts SET day = today - 91 WHERE organization_id = a AND rules_fingerprint = 'eeeeeeeeeeeeeeee';
    r := public.purge_findings();
    INSERT INTO public.radar_count_reports (report_id, received_at) VALUES ('00000000-0000-0000-0000-0000e2e0d002', now() - interval '8 days');
    r := public.purge_findings();
    PERFORM pg_temp.check(NOT EXISTS (SELECT 1 FROM public.radar_count_reports WHERE report_id = '00000000-0000-0000-0000-0000e2e0d002')
        AND EXISTS (SELECT 1 FROM public.radar_count_reports WHERE report_id = '00000000-0000-0000-0000-0000e2e0d001'), 'report ids older than 7 days are forgotten, recent ones kept');
    PERFORM pg_temp.check((r->>'scan_counts')::int >= 1 AND NOT EXISTS (SELECT 1 FROM public.radar_scan_counts WHERE rules_fingerprint = 'eeeeeeeeeeeeeeee'), 'counts older than 90 days are purged');
    PERFORM pg_temp.check(r ? 'findings' AND r ? 'suppressions', 'the purge still reports findings and suppressions');
    INSERT INTO public.organizations (id, name, slug) VALUES ('00000000-0000-0000-0000-0000e2e00003', 'Scan Org C', 'scan-org-c');
    PERFORM public.record_radar_scan_counts(gen_random_uuid(), fp, jsonb_build_array(pg_temp.count_item('00000000-0000-0000-0000-0000e2e00003', 'output', 5, 1, 1, '[{"rule_id":"RAD-OUT-001","flagged":1,"strong":1}]')));
    PERFORM pg_temp.check((SELECT count(*) = 1 FROM public.radar_rule_counts WHERE organization_id = '00000000-0000-0000-0000-0000e2e00003'), 'counts exist before the organization is deleted');
    DELETE FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000e2e00003';
    PERFORM pg_temp.check((SELECT count(*) = 0 FROM public.radar_rule_counts WHERE organization_id = '00000000-0000-0000-0000-0000e2e00003')
        AND (SELECT count(*) = 0 FROM public.radar_scan_counts WHERE organization_id = '00000000-0000-0000-0000-0000e2e00003'), 'counts go with their organization');
END $$;

-- table constraints hold even for a caller that bypasses the functions
DO $$
DECLARE a text := '00000000-0000-0000-0000-0000e2e00001';
BEGIN
    PERFORM pg_temp.expect_error(format($q$INSERT INTO public.radar_scan_counts (organization_id, day, kind, rules_fingerprint, scanned, flagged) VALUES (%L, current_date, 'output', 'unknown', 1, 2)$q$, a), '23514', 'flagged cannot exceed scanned');
    PERFORM pg_temp.expect_error(format($q$INSERT INTO public.radar_scan_counts (organization_id, day, kind, rules_fingerprint, scanned, flagged, strong) VALUES (%L, current_date, 'output', 'unknown', 5, 1, 2)$q$, a), '23514', 'strong cannot exceed flagged');
    PERFORM pg_temp.expect_error(format($q$INSERT INTO public.radar_scan_counts (organization_id, day, kind, rules_fingerprint, scanned) VALUES (%L, current_date, 'secrets', 'unknown', 1)$q$, a), '23514', 'only the two checks exist');
    PERFORM pg_temp.expect_error(format($q$INSERT INTO public.radar_scan_counts (organization_id, day, kind, rules_fingerprint, scanned) VALUES (%L, current_date, 'output', 'a free text note', 1)$q$, a), '23514', 'the fingerprint cannot hold free text');
    PERFORM pg_temp.expect_error(format($q$INSERT INTO public.radar_scan_counts (organization_id, day, kind, rules_fingerprint, scanned) VALUES (%L, current_date, 'output', 'unknown', -1)$q$, a), '23514', 'counts cannot be negative');
    PERFORM pg_temp.expect_error(format($q$INSERT INTO public.radar_rule_counts (organization_id, day, rule_id, rules_fingerprint, flagged) VALUES (%L, current_date, 'ignore previous instructions', 'unknown', 1)$q$, a), '23514', 'a rule id must look like a rule id');
    PERFORM pg_temp.expect_error(format($q$INSERT INTO public.radar_rule_counts (organization_id, day, rule_id, rules_fingerprint, flagged, strong) VALUES (%L, current_date, 'RAD-INJ-001', 'unknown', 1, 2)$q$, a), '23514', 'a rule cannot have more strong than flagged');
END $$;

SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.record_radar_scan_counts(uuid,text,jsonb)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.record_radar_scan_counts(uuid,text,jsonb)', 'EXECUTE')
    AND NOT has_function_privilege('authenticated', 'public.radar_readiness_inputs(uuid)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.radar_readiness_inputs(uuid)', 'EXECUTE')
    AND NOT has_function_privilege('authenticated', 'public.radar_count_of(text,bigint)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.record_radar_scan_counts(uuid,text,jsonb)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.radar_readiness_inputs(uuid)', 'EXECUTE'), 'functions are service_role only');
SELECT pg_temp.check((SELECT relrowsecurity FROM pg_class WHERE relname = 'radar_scan_counts') AND (SELECT relrowsecurity FROM pg_class WHERE relname = 'radar_rule_counts'), 'row level security is on');

\echo ALL SQL TESTS PASSED
