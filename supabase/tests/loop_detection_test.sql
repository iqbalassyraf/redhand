-- SQL tests for supabase/migrations/20261120000000_loop_detection.sql (Phase 4 M6).

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

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000100a0001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-000010000001', 'Loop Org A', 'loop-org-a'),
    ('00000000-0000-0000-0000-000010000002', 'Loop Org B', 'loop-org-b');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-00001000000a', '00000000-0000-0000-0000-000010000001', 'loop-bot-a', 'Loop Bot A'),
    ('00000000-0000-0000-0000-00001000000b', '00000000-0000-0000-0000-000010000002', 'loop-bot-b', 'Loop Bot B');

CREATE FUNCTION pg_temp.loop_item(p_tool text DEFAULT 'get_status', p_extra jsonb DEFAULT '{}') RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'rule_id', 'RAD-LOOP-001', 'kind', 'loop', 'family', 'loop', 'severity', 'medium', 'confidence', 'high', 'place', 'call',
        'tool_name', p_tool, 'server', 'helpdesk', 'evasion', '[]'::jsonb, 'would_block', false) || p_extra
$$;

CREATE FUNCTION pg_temp.inj_item(p_extra jsonb DEFAULT '{}') RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'rule_id', 'RAD-INJ-001', 'kind', 'injection', 'family', 'override', 'severity', 'high', 'confidence', 'medium', 'place', 'text',
        'tool_name', 'get_ticket', 'server', 'helpdesk', 'evasion', '[]'::jsonb, 'would_block', false) || p_extra
$$;

DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-000010000001';
    b uuid := '00000000-0000-0000-0000-000010000002';
    ag uuid := '00000000-0000-0000-0000-00001000000a';
    bg uuid := '00000000-0000-0000-0000-00001000000b';
    actor uuid := '00000000-0000-0000-0000-0000100a0001';
    r jsonb; i integer;
BEGIN
    -- defaults (F-D4: 20 identical calls in 60 seconds, observe)
    PERFORM pg_temp.check((SELECT loop_mode = 'observe' AND loop_limit = 20 AND loop_window_seconds = 60 FROM public.organizations WHERE id = a),
        'an organization defaults to observe, 20 calls, 60 seconds');

    -- recording, coalescing and the alert
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.loop_item()));
    PERFORM pg_temp.check((r->>'new')::int = 1 AND (r->>'loop_new')::int = 1 AND (r->>'loop_alert')::boolean AND r->>'loop_tool' = 'get_status',
        'a loop finding is stored and raises the loop alert');
    PERFORM pg_temp.check(NOT (r->>'alert')::boolean AND jsonb_array_length(r->'rules') = 0,
        'the injection alert and its rule list are not touched by a loop');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.loop_item('get_status', '{"occurrences": 6}')));
    PERFORM pg_temp.check((r->>'new')::int = 0 AND (r->>'coalesced')::int = 1 AND NOT (r->>'loop_alert')::boolean,
        'a repeat in the same window coalesces and does not alert again');
    PERFORM pg_temp.check((SELECT occurrences = 7 FROM public.security_findings WHERE agent_id = ag AND rule_id = 'RAD-LOOP-001'), 'the count adds up');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.loop_item('other_tool')));
    PERFORM pg_temp.check((r->>'new')::int = 1 AND NOT (r->>'loop_alert')::boolean, 'a second tool is a second row inside the 10-minute cooldown');
    UPDATE public.agents SET loop_last_alert_at = now() - interval '11 minutes' WHERE id = ag;
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.loop_item('third_tool')));
    PERFORM pg_temp.check((r->>'loop_alert')::boolean, 'the loop alert returns after 10 minutes');

    -- separate cooldowns: a loop alert does not hide an injection alert, and the other way round
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.inj_item()));
    PERFORM pg_temp.check((r->>'alert')::boolean AND NOT (r->>'loop_alert')::boolean, 'an injection finding alerts although a loop alert just fired');
    UPDATE public.agents SET loop_last_alert_at = NULL, radar_last_alert_at = now() WHERE id = ag;
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.loop_item('fourth_tool')));
    PERFORM pg_temp.check((r->>'loop_alert')::boolean, 'a loop finding alerts although an injection alert just fired');

    -- the kind, the rule and the place must agree
    r := public.record_security_findings(a, ag, jsonb_build_array(
        pg_temp.loop_item('x', '{"kind": "injection"}'), pg_temp.loop_item('x', '{"kind": "output"}'),
        pg_temp.loop_item('x', '{"place": "text"}'), pg_temp.inj_item('{"place": "call"}'),
        pg_temp.inj_item('{"rule_id": "RAD-LOOP-001"}'), pg_temp.loop_item('x', '{"rule_id": "RAD-INJ-001"}'),
        pg_temp.loop_item('x', '{"rule_id": "RAD-LOP-001"}'), pg_temp.loop_item('x', '{"kind": "destination"}')));
    PERFORM pg_temp.check((r->>'skipped')::int = 8 AND (r->>'new')::int = 0, 'eight inconsistent or unknown items are skipped');
    PERFORM pg_temp.check((SELECT count(*) = 0 FROM public.security_findings WHERE tool_name = 'x'), 'none of them reached the table');

    -- readiness and the summary of the injection and output checks never see a loop
    r := public.radar_summary(a);
    PERFORM pg_temp.check((r->'last_7_days'->>'findings')::int = 1, 'radar_summary counts only the injection finding, not the four loop findings');
    r := public.loop_settings(a);
    PERFORM pg_temp.check((r->'last_7_days'->>'findings')::int = 4 AND r->>'loop_mode' = 'observe', 'loop_settings counts the four loop findings');
    PERFORM pg_temp.check((SELECT count(*) = 0 FROM public.security_findings WHERE kind = 'loop' AND rule_id NOT LIKE 'RAD-LOOP-%'), 'every loop row has a loop rule id');

    -- tenant isolation
    PERFORM pg_temp.expect_error(format('SELECT public.record_security_findings(%L, %L, ''[]'')', b, ag), 'P0002', 'an agent of another organization cannot be reported against');
    r := public.loop_settings(b);
    PERFORM pg_temp.check((r->'last_7_days'->>'findings')::int = 0, 'another organization sees no loop findings of this one');
    PERFORM pg_temp.expect_error(format('SELECT public.loop_settings(%L)', gen_random_uuid()), 'P0002', 'loop_settings needs a real organization');

    -- mode off stores nothing
    r := public.control_loop_settings(a, actor, 'off', 20, 60, 'observe', 20, 60, 'test');
    PERFORM pg_temp.check((r->>'changed')::boolean AND r->>'loop_mode' = 'off', 'the mode can be turned off');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.loop_item('while_off')));
    PERFORM pg_temp.check((r->>'disabled')::int = 1 AND (r->>'new')::int = 0, 'nothing is stored while loop detection is off');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.inj_item('{"tool_name": "while_loop_off"}')));
    PERFORM pg_temp.check((r->>'new')::int = 1, 'the injection check is unaffected by the loop mode');

    -- settings: validation, compare-and-set, idempotence, audit
    PERFORM pg_temp.expect_error(format('SELECT public.control_loop_settings(%L, %L, ''block'', 20, 60, ''off'', 20, 60, NULL)', a, actor), '22023', 'block is not a mode');
    PERFORM pg_temp.expect_error(format('SELECT public.control_loop_settings(%L, %L, NULL, 20, 60, ''off'', 20, 60, NULL)', a, actor), '22023', 'a mode is required');
    PERFORM pg_temp.expect_error(format('SELECT public.control_loop_settings(%L, %L, ''observe'', 2, 60, ''off'', 20, 60, NULL)', a, actor), '22023', 'a limit of 2 is refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_loop_settings(%L, %L, ''observe'', 1001, 60, ''off'', 20, 60, NULL)', a, actor), '22023', 'a limit of 1001 is refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_loop_settings(%L, %L, ''observe'', 20, 9, ''off'', 20, 60, NULL)', a, actor), '22023', 'a window of 9 seconds is refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_loop_settings(%L, %L, ''observe'', 20, 601, ''off'', 20, 60, NULL)', a, actor), '22023', 'a window of 601 seconds is refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_loop_settings(%L, %L, ''observe'', 20, 60, ''off'', 20, 60, %L)', a, actor, repeat('x', 301)), '22023', 'the reason is capped');
    PERFORM pg_temp.expect_error(format('SELECT public.control_loop_settings(%L, %L, ''observe'', 20, 60, ''off'', 20, 60, NULL)', gen_random_uuid(), actor), 'P0002', 'an unknown organization is refused');
    r := public.control_loop_settings(a, actor, 'throttle', 30, 120, 'observe', 20, 60, 'stale');
    PERFORM pg_temp.check((r->>'conflict')::boolean AND r->>'loop_mode' = 'off', 'a stale expectation is a conflict and reports the current values');
    r := public.control_loop_settings(a, actor, 'off', 20, 60, 'off', 20, 60, NULL);
    PERFORM pg_temp.check(NOT (r->>'conflict')::boolean AND NOT (r->>'changed')::boolean, 'repeating the current settings changes nothing');
    PERFORM pg_temp.check((SELECT count(*) = 1 FROM public.control_audit_log WHERE organization_id = a AND action = 'organization.loop_settings_changed'), 'the no-op wrote no audit row');
    r := public.control_loop_settings(a, actor, 'throttle', 30, 120, 'off', 20, 60, 'night test');
    PERFORM pg_temp.check((r->>'changed')::boolean AND r->>'loop_mode' = 'throttle' AND (r->>'loop_limit')::int = 30 AND (r->>'loop_window_seconds')::int = 120, 'throttle with a new limit and window is stored');
    PERFORM pg_temp.check((SELECT count(*) = 2 FROM public.control_audit_log WHERE organization_id = a AND action = 'organization.loop_settings_changed'
        AND actor_user_id = actor AND details ? 'old_mode' AND details ? 'new_limit'), 'each change is audited once, with the actor');
    PERFORM pg_temp.check((SELECT loop_mode_changed_at > now() - interval '1 minute' FROM public.organizations WHERE id = a), 'the time of the mode change is kept');
    r := public.control_loop_settings(a, actor, 'throttle', 40, 120, 'throttle', 30, 120, NULL);
    PERFORM pg_temp.check((r->>'changed')::boolean AND (r->>'loop_limit')::int = 40, 'changing only the limit is a change');
    PERFORM pg_temp.check((SELECT loop_mode = 'observe' FROM public.organizations WHERE id = b), 'another organization is untouched');

    -- suppression: RAD-LOOP-001 is accepted and exempts, other rule names are still refused
    PERFORM public.control_loop_settings(a, actor, 'observe', 20, 60, 'throttle', 40, 120, NULL);
    r := public.control_radar_suppression_create(a, actor, ag, 'RAD-LOOP-001', 30, 'a polling agent');
    PERFORM pg_temp.check((r->>'created')::boolean, 'a loop suppression can be created');
    PERFORM pg_temp.expect_error(format('SELECT public.control_radar_suppression_create(%L, %L, %L, ''RAD-LOP-001'', 30, ''typo'')', a, actor, ag), '22023', 'a mistyped rule is refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_radar_suppression_create(%L, %L, %L, ''RAD-LOOP-001'', 30, ''wrong org'')', b, actor, ag), 'P0002', 'an agent of another organization cannot be suppressed');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.loop_item('suppressed_tool')));
    PERFORM pg_temp.check((r->>'suppressed')::int = 1 AND (r->>'new')::int = 0, 'a suppressed loop finding is counted as suppressed, not stored');

    -- the finding cap is shared with the other kinds (2,000 new rows per agent per 24 hours)
    FOR i IN 1..2000 LOOP
        INSERT INTO public.security_findings (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, tool_name, window_start)
        VALUES (b, bg, 'RAD-LOOP-001', 'loop', 'loop', 'medium', 'high', 'call', 'tool_' || i, now());
    END LOOP;
    r := public.record_security_findings(b, bg, jsonb_build_array(pg_temp.loop_item('one_too_many')));
    PERFORM pg_temp.check((r->>'capped')::int = 1 AND (r->>'new')::int = 0, 'loop findings count toward the per-agent daily cap');
END $$;

-- table constraints hold even for a caller that bypasses the functions
DO $$
BEGIN
    PERFORM pg_temp.expect_error($q$UPDATE public.organizations SET loop_mode = 'block' WHERE id = '00000000-0000-0000-0000-000010000001'$q$, '23514', 'only the three loop modes exist');
    PERFORM pg_temp.expect_error($q$UPDATE public.organizations SET loop_limit = 2 WHERE id = '00000000-0000-0000-0000-000010000001'$q$, '23514', 'the limit has a floor');
    PERFORM pg_temp.expect_error($q$UPDATE public.organizations SET loop_window_seconds = 601 WHERE id = '00000000-0000-0000-0000-000010000001'$q$, '23514', 'the window has a ceiling');
    PERFORM pg_temp.expect_error($q$INSERT INTO public.security_findings (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, window_start)
        VALUES ('00000000-0000-0000-0000-000010000001', '00000000-0000-0000-0000-00001000000a', 'RAD-LOOP-1', 'loop', 'loop', 'low', 'low', 'call', now())$q$, '23514', 'a loop rule id must have three digits');
    PERFORM pg_temp.expect_error($q$INSERT INTO public.security_findings (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, window_start)
        VALUES ('00000000-0000-0000-0000-000010000001', '00000000-0000-0000-0000-00001000000a', 'RAD-LOOP-001', 'loop', 'destination', 'low', 'low', 'call', now())$q$, '23514', 'an unknown kind cannot be stored');
END $$;

-- the audit list accepts the new action and still refuses an unknown one
DO $$
BEGIN
    PERFORM pg_temp.expect_error($q$INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id)
        VALUES ('00000000-0000-0000-0000-000010000001', '00000000-0000-0000-0000-0000100a0001', 'organization.loop_dance', 'organization', '00000000-0000-0000-0000-000010000001')$q$, '23514', 'an unknown audit action is refused');
END $$;

SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.control_loop_settings(uuid,uuid,text,integer,integer,text,integer,integer,text)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.control_loop_settings(uuid,uuid,text,integer,integer,text,integer,integer,text)', 'EXECUTE')
    AND NOT has_function_privilege('authenticated', 'public.loop_settings(uuid)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.loop_settings(uuid)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.control_loop_settings(uuid,uuid,text,integer,integer,text,integer,integer,text)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.loop_settings(uuid)', 'EXECUTE'), 'the new functions are service_role only');
SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.record_security_findings(uuid,uuid,jsonb)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.control_radar_suppression_create(uuid,uuid,uuid,text,integer,text)', 'EXECUTE')
    AND NOT has_function_privilege('authenticated', 'public.radar_summary(uuid)', 'EXECUTE'), 'the replaced functions are still service_role only');

\echo ALL SQL TESTS PASSED
