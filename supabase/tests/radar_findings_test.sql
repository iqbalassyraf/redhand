-- SQL tests for supabase/migrations/20261117000000_radar_findings.sql (Phase 4 M4.2).

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

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000e1e0a001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000e1e00001', 'Radar Org A', 'radar-org-a'),
    ('00000000-0000-0000-0000-0000e1e00002', 'Radar Org B', 'radar-org-b');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000e1e0000a', '00000000-0000-0000-0000-0000e1e00001', 'radar-bot-a', 'Radar Bot A'),
    ('00000000-0000-0000-0000-0000e1e0000c', '00000000-0000-0000-0000-0000e1e00001', 'radar-bot-c', 'Radar Bot C'),
    ('00000000-0000-0000-0000-0000e1e0000b', '00000000-0000-0000-0000-0000e1e00002', 'radar-bot-b', 'Radar Bot B');

CREATE FUNCTION pg_temp.item(p_rule text, p_tool text DEFAULT 'get_ticket', p_extra jsonb DEFAULT '{}') RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'rule_id', p_rule, 'kind', CASE WHEN p_rule LIKE 'RAD-INJ-%' THEN 'injection' ELSE 'output' END,
        'family', CASE WHEN p_rule LIKE 'RAD-INJ-%' THEN 'override' ELSE 'xss' END,
        'severity', 'high', 'confidence', 'medium', 'place', 'text', 'tool_name', p_tool, 'server', 'helpdesk',
        'evasion', '[]'::jsonb, 'would_block', false) || p_extra
$$;

DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-0000e1e00001';
    b uuid := '00000000-0000-0000-0000-0000e1e00002';
    ag uuid := '00000000-0000-0000-0000-0000e1e0000a';
    ac uuid := '00000000-0000-0000-0000-0000e1e0000c';
    bg uuid := '00000000-0000-0000-0000-0000e1e0000b';
    actor uuid := '00000000-0000-0000-0000-0000e1e0a001';
    r jsonb; f1 uuid; sup uuid; i integer;
BEGIN
    PERFORM pg_temp.check((SELECT radar_mode = 'observe' AND output_check_mode = 'observe' FROM public.organizations WHERE id = a), 'both modes default to observe');

    -- recording and coalescing
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.item('RAD-INJ-001'), pg_temp.item('RAD-OUT-001')));
    PERFORM pg_temp.check((r->>'new')::int = 2 AND (r->>'coalesced')::int = 0 AND (r->>'alert')::boolean AND r->>'agent' = 'Radar Bot A', 'two findings are recorded and alert once');
    PERFORM pg_temp.check(jsonb_array_length(r->'rules') = 2, 'the alert carries rule ids only');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.item('RAD-INJ-001', 'get_ticket', '{"occurrences": 4, "would_block": true, "severity": "high", "confidence": "high"}')));
    PERFORM pg_temp.check((r->>'new')::int = 0 AND (r->>'coalesced')::int = 1 AND NOT (r->>'alert')::boolean, 'a repeat in the same window coalesces and does not alert again');
    SELECT id INTO f1 FROM public.security_findings WHERE agent_id = ag AND rule_id = 'RAD-INJ-001';
    PERFORM pg_temp.check((SELECT occurrences = 5 AND would_block AND confidence = 'high' FROM public.security_findings WHERE id = f1), 'the count adds up, would_block sticks, confidence takes the higher');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.item('RAD-INJ-001', 'other_tool')));
    PERFORM pg_temp.check((r->>'new')::int = 1, 'a different tool is a different row');
    PERFORM pg_temp.check((SELECT count(*) = 3 FROM public.security_findings WHERE agent_id = ag), 'three rows so far');

    -- the alert is rate limited per agent
    UPDATE public.agents SET radar_last_alert_at = now() - interval '11 minutes' WHERE id = ag;
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.item('RAD-INJ-002')));
    PERFORM pg_temp.check((r->>'alert')::boolean, 'a new finding alerts again after 10 minutes');

    -- validation: bad items are skipped, never stored
    r := public.record_security_findings(a, ag, jsonb_build_array(
        pg_temp.item('NOT-A-RULE'), pg_temp.item('RAD-INJ-003', 'x', '{"severity": "extreme"}'),
        pg_temp.item('RAD-INJ-003', 'x', '{"kind": "output"}'), pg_temp.item('RAD-INJ-003', 'x', '{"place": "elsewhere"}'),
        pg_temp.item('RAD-INJ-003', 'x', '{"family": "Bad Family"}'), to_jsonb('a string'::text), pg_temp.item('RAD-OUT-002')));
    PERFORM pg_temp.check((r->>'skipped')::int = 6 AND (r->>'new')::int = 1, 'six malformed items are skipped and the valid one is kept');
    PERFORM pg_temp.check((SELECT count(*) = 0 FROM public.security_findings WHERE rule_id = 'RAD-INJ-003'), 'nothing malformed reached the table');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.item('RAD-OUT-003', 'tool', '{"evasion": ["invisible", "lookalike", "bogus", "invisible"]}')));
    PERFORM pg_temp.check((SELECT evasion = ARRAY['invisible', 'lookalike'] FROM public.security_findings WHERE rule_id = 'RAD-OUT-003'), 'unknown evasion tags are dropped and duplicates collapsed');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.item('RAD-OUT-004', 'tool', '{"occurrences": 99999999}')));
    PERFORM pg_temp.check((SELECT occurrences = 1000 FROM public.security_findings WHERE rule_id = 'RAD-OUT-004'), 'an oversized count is clamped');
    PERFORM pg_temp.expect_error(format('SELECT public.record_security_findings(%L, %L, ''{}'')', a, ag), '22023', 'items must be an array');
    PERFORM pg_temp.expect_error(format('SELECT public.record_security_findings(%L, %L, %L)', a, ag,
        (SELECT jsonb_agg(pg_temp.item('RAD-INJ-001')) FROM generate_series(1, 21))), '22023', 'more than 20 items refused');

    -- tenant isolation
    PERFORM pg_temp.expect_error(format('SELECT public.record_security_findings(%L, %L, ''[]'')', b, ag), 'P0002', 'organization B cannot report for A''s agent');
    PERFORM pg_temp.expect_error(format('SELECT public.record_security_findings(%L, %L, ''[]'')', gen_random_uuid(), ag), 'P0002', 'unknown organization refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_finding_review(%L, %L, %L, ''false_alarm'', ''open'', NULL)', b, actor, f1), 'P0002', 'organization B cannot review A''s finding');
    PERFORM pg_temp.expect_error(format('SELECT public.control_radar_suppression_create(%L, %L, %L, ''RAD-INJ-001'', 30, ''noise'')', b, actor, ag), 'P0002', 'organization B cannot suppress on A''s agent');
    PERFORM pg_temp.expect_error(format('SELECT public.radar_summary(%L)', gen_random_uuid()), 'P0002', 'unknown organization has no summary');

    -- mode switches
    r := public.control_radar_settings(a, actor, 'off', 'observe', 'observe', 'observe', 'too noisy');
    PERFORM pg_temp.check((r->>'changed')::boolean AND r->>'radar_mode' = 'off', 'injection mode can be turned off');
    PERFORM pg_temp.check((SELECT radar_mode_changed_at > now() - interval '1 minute' FROM public.organizations WHERE id = a), 'the change time is recorded');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.item('RAD-INJ-004'), pg_temp.item('RAD-OUT-005')));
    PERFORM pg_temp.check((r->>'disabled')::int = 1 AND (r->>'new')::int = 1, 'injection findings are not stored while injection is off, output findings are');
    r := public.control_radar_settings(a, actor, 'observe', 'observe', 'observe', 'observe', NULL);
    PERFORM pg_temp.check((r->>'conflict')::boolean AND r->>'radar_mode' = 'off', 'a stale expectation is a conflict');
    r := public.control_radar_settings(a, actor, 'off', 'observe', 'off', 'observe', NULL);
    PERFORM pg_temp.check(NOT (r->>'changed')::boolean AND NOT (r->>'conflict')::boolean, 'repeating the current modes changes nothing');
    PERFORM pg_temp.expect_error(format('SELECT public.control_radar_settings(%L, %L, ''block'', ''observe'', ''off'', ''observe'', NULL)', a, actor), '22023', 'block mode is refused until the gate exists');
    PERFORM pg_temp.expect_error(format('SELECT public.control_radar_settings(%L, %L, ''bogus'', ''observe'', ''off'', ''observe'', NULL)', a, actor), '22023', 'unknown mode refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_radar_settings(%L, %L, ''off'', ''observe'', ''off'', ''observe'', NULL)', gen_random_uuid(), actor), 'P0002', 'unknown organization refused');
    PERFORM public.control_radar_settings(a, actor, 'observe', 'observe', 'off', 'observe', 'back on');
    PERFORM pg_temp.check((SELECT count(*) = 2 FROM public.control_audit_log WHERE action = 'organization.radar_settings_changed' AND organization_id = a), 'both changes are audited');
    PERFORM pg_temp.check((SELECT details->>'old_injection' = 'observe' AND details->>'new_injection' = 'off' FROM public.control_audit_log WHERE action = 'organization.radar_settings_changed' ORDER BY created_at LIMIT 1), 'the audit row carries the old and new mode');

    -- review
    r := public.control_finding_review(a, actor, f1, 'false_alarm', 'open', 'a security article');
    PERFORM pg_temp.check((r->>'changed')::boolean AND r->>'review_status' = 'false_alarm', 'an open finding can be marked a false alarm');
    r := public.control_finding_review(a, actor, f1, 'confirmed', 'open', NULL);
    PERFORM pg_temp.check((r->>'conflict')::boolean AND r->>'review_status' = 'false_alarm', 'reviewing from a stale status is a conflict');
    r := public.control_finding_review(a, actor, f1, 'confirmed', 'false_alarm', 'on reflection it was real');
    PERFORM pg_temp.check((r->>'changed')::boolean AND (SELECT review_status = 'confirmed' AND reviewed_by = actor FROM public.security_findings WHERE id = f1), 'a review can be changed on purpose');
    r := public.control_finding_review(a, actor, f1, 'confirmed', 'confirmed', NULL);
    PERFORM pg_temp.check(NOT (r->>'changed')::boolean, 'repeating the same review changes nothing');
    PERFORM pg_temp.expect_error(format('SELECT public.control_finding_review(%L, %L, %L, ''open'', ''confirmed'', NULL)', a, actor, f1), '22023', 'a finding cannot be set back to open');
    PERFORM pg_temp.expect_error(format('SELECT public.control_finding_review(%L, %L, %L, ''confirmed'', ''open'', %L)', a, actor, f1, repeat('x', 301)), '22023', 'an oversized note is refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_finding_review(%L, %L, %L, ''confirmed'', ''open'', NULL)', a, actor, gen_random_uuid()), 'P0002', 'unknown finding refused');
    PERFORM pg_temp.check((SELECT count(*) = 2 FROM public.control_audit_log WHERE action = 'radar_finding.reviewed'), 'each real review change is audited, conflicts and repeats are not');

    -- suppression
    r := public.control_radar_suppression_create(a, actor, ag, 'RAD-INJ-005', 30, 'known noisy tool');
    PERFORM pg_temp.check((r->>'created')::boolean, 'a suppression is created');
    sup := (r->>'id')::uuid;
    PERFORM pg_temp.check((SELECT expires_at BETWEEN now() + interval '29 days' AND now() + interval '31 days' FROM public.radar_suppressions WHERE id = sup), 'it expires in 30 days');
    r := public.control_radar_suppression_create(a, actor, ag, 'RAD-INJ-005', 10, 'again');
    PERFORM pg_temp.check(NOT (r->>'created')::boolean AND (r->>'id')::uuid = sup, 'creating a live suppression again is idempotent');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.item('RAD-INJ-005'), pg_temp.item('RAD-INJ-006')));
    PERFORM pg_temp.check((r->>'suppressed')::int = 1 AND (r->>'new')::int = 1, 'a suppressed rule is not recorded for that agent, other rules are');
    r := public.record_security_findings(a, ac, jsonb_build_array(pg_temp.item('RAD-INJ-005')));
    PERFORM pg_temp.check((r->>'suppressed')::int = 0 AND (r->>'new')::int = 1, 'the suppression applies to one agent only');
    UPDATE public.radar_suppressions SET created_at = now() - interval '40 days', expires_at = now() - interval '10 days' WHERE id = sup;
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.item('RAD-INJ-005', 'late')));
    PERFORM pg_temp.check((r->>'suppressed')::int = 0 AND (r->>'new')::int = 1, 'an expired suppression no longer applies');
    r := public.control_radar_suppression_create(a, actor, ag, 'RAD-INJ-005', 7, 'renewed after expiry');
    PERFORM pg_temp.check((r->>'created')::boolean AND (SELECT revoked_at IS NOT NULL FROM public.radar_suppressions WHERE id = sup), 'creating over an expired one makes room by revoking it');
    sup := (r->>'id')::uuid;
    r := public.control_radar_suppression_revoke(a, actor, sup, 'no longer needed');
    PERFORM pg_temp.check((r->>'revoked')::boolean, 'a suppression can be revoked');
    r := public.control_radar_suppression_revoke(a, actor, sup, NULL);
    PERFORM pg_temp.check(NOT (r->>'revoked')::boolean, 'revoking twice changes nothing');
    PERFORM pg_temp.expect_error(format('SELECT public.control_radar_suppression_revoke(%L, %L, %L, NULL)', b, actor, sup), 'P0002', 'organization B cannot revoke A''s suppression');
    PERFORM pg_temp.expect_error(format('SELECT public.control_radar_suppression_create(%L, %L, %L, ''RAD-INJ-001'', 91, ''too long'')', a, actor, ag), '22023', 'more than 90 days refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_radar_suppression_create(%L, %L, %L, ''RAD-INJ-001'', 0, ''too short'')', a, actor, ag), '22023', 'zero days refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_radar_suppression_create(%L, %L, %L, ''honeytoken'', 5, ''not a radar rule'')', a, actor, ag), '22023', 'only Radar rule ids can be suppressed (never a honeytoken check)');
    PERFORM pg_temp.expect_error(format('SELECT public.control_radar_suppression_create(%L, %L, %L, ''RAD-INJ-001'', 5, ''  '')', a, actor, ag), '22023', 'a reason is required');
    PERFORM pg_temp.check((SELECT count(*) = 2 FROM public.control_audit_log WHERE action = 'radar_suppression.created') AND
        (SELECT count(*) = 1 FROM public.control_audit_log WHERE action = 'radar_suppression.revoked'), 'suppression changes are audited');
    FOR i IN 1..100 LOOP
        INSERT INTO public.radar_suppressions (organization_id, agent_id, rule_id, reason, created_by, expires_at)
        VALUES (a, ac, 'RAD-OUT-' || lpad((100 + i)::text, 3, '0'), 'bulk', actor, now() + interval '5 days');
    END LOOP;
    r := public.control_radar_suppression_create(a, actor, ag, 'RAD-OUT-007', 5, 'one too many');
    PERFORM pg_temp.check((r->>'limit')::boolean AND NOT (r->>'created')::boolean, 'at most 100 live suppressions per organization');

    -- the daily cap per agent
    DELETE FROM public.security_findings WHERE agent_id = ac;
    INSERT INTO public.security_findings (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, tool_name, window_start)
    SELECT a, ac, 'RAD-INJ-001', 'override', 'injection', 'low', 'low', 'text', 't' || g, now() - interval '1 hour' FROM generate_series(1, 2000) g;
    r := public.record_security_findings(a, ac, jsonb_build_array(pg_temp.item('RAD-INJ-001', 'brand_new_tool')));
    PERFORM pg_temp.check((r->>'capped')::int = 1 AND (r->>'new')::int = 0, 'past 2,000 new rows in 24 hours a new row is counted as capped, not stored');

    -- summary
    r := public.radar_summary(a);
    PERFORM pg_temp.check(r->>'radar_mode' = 'observe' AND (r->'last_7_days'->>'findings')::int > 0 AND (r->'last_7_days'->>'would_block')::int >= 1
        AND (r->'last_7_days'->>'confirmed')::int >= 1, 'the summary counts findings, would-block and reviewed ones');
    PERFORM pg_temp.check((public.radar_summary(b)->'last_7_days'->>'findings') IS NULL OR (public.radar_summary(b)->'last_7_days'->>'findings')::int = 0, 'another organization sees none of them');

    -- retention
    UPDATE public.security_findings SET last_seen_at = now() - interval '91 days' WHERE agent_id = ac AND tool_name = 't1';
    r := public.purge_findings();
    PERFORM pg_temp.check((r->>'findings')::int = 1, 'findings older than 90 days are purged');
    UPDATE public.radar_suppressions SET revoked_at = now() - interval '91 days', expires_at = now() - interval '100 days', created_at = now() - interval '130 days' WHERE id = sup;
    r := public.purge_findings();
    PERFORM pg_temp.check((r->>'suppressions')::int >= 1, 'long-gone suppressions are purged');

    -- cascade: findings and suppressions go with their agent, and a deleted agent cannot be reported against
    PERFORM public.record_security_findings(b, bg, jsonb_build_array(pg_temp.item('RAD-INJ-001')));
    PERFORM public.control_radar_suppression_create(b, actor, bg, 'RAD-INJ-002', 5, 'cascade check');
    PERFORM pg_temp.check((SELECT count(*) = 1 FROM public.security_findings WHERE agent_id = bg), 'a finding exists for B''s agent before deletion');
    DELETE FROM public.agents WHERE id = bg;
    PERFORM pg_temp.check((SELECT count(*) = 0 FROM public.security_findings WHERE agent_id = bg)
        AND (SELECT count(*) = 0 FROM public.radar_suppressions WHERE agent_id = bg), 'findings and suppressions go with their agent');
    PERFORM pg_temp.expect_error(format('SELECT public.record_security_findings(%L, %L, ''[]'')', b, bg), 'P0002', 'a deleted agent cannot be reported against');
END $$;

-- table constraints hold even for a caller that bypasses the functions
DO $$
BEGIN
    PERFORM pg_temp.expect_error($q$INSERT INTO public.security_findings (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, window_start)
        VALUES ('00000000-0000-0000-0000-0000e1e00001', '00000000-0000-0000-0000-0000e1e0000a', 'free text here', 'override', 'injection', 'low', 'low', 'text', now())$q$, '23514', 'a rule id must look like a rule id');
    PERFORM pg_temp.expect_error($q$INSERT INTO public.security_findings (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, evasion, window_start)
        VALUES ('00000000-0000-0000-0000-0000e1e00001', '00000000-0000-0000-0000-0000e1e0000a', 'RAD-INJ-001', 'override', 'injection', 'low', 'low', 'text', ARRAY['ignore all previous instructions'], now())$q$, '23514', 'evasion tags are an allowlist, so free text cannot be stored');
    PERFORM pg_temp.expect_error($q$INSERT INTO public.security_findings (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, tool_name, window_start)
        VALUES ('00000000-0000-0000-0000-0000e1e00001', '00000000-0000-0000-0000-0000e1e0000a', 'RAD-INJ-001', 'override', 'injection', 'low', 'low', 'text', repeat('x', 129), now())$q$, '23514', 'the tool name is capped');
    PERFORM pg_temp.expect_error($q$UPDATE public.organizations SET radar_mode = 'maybe' WHERE id = '00000000-0000-0000-0000-0000e1e00001'$q$, '23514', 'only the three modes exist');
END $$;

SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.record_security_findings(uuid,uuid,jsonb)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.control_radar_settings(uuid,uuid,text,text,text,text,text)', 'EXECUTE')
    AND NOT has_function_privilege('authenticated', 'public.radar_summary(uuid)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.purge_findings()', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.control_finding_review(uuid,uuid,uuid,text,text,text)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.control_radar_suppression_create(uuid,uuid,uuid,text,integer,text)', 'EXECUTE'), 'functions are service_role only');
SELECT pg_temp.check((SELECT relrowsecurity FROM pg_class WHERE relname = 'security_findings') AND (SELECT relrowsecurity FROM pg_class WHERE relname = 'radar_suppressions'), 'row level security is on');

\echo ALL SQL TESTS PASSED
