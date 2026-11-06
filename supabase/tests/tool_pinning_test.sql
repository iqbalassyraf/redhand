-- SQL tests for supabase/migrations/20261116000000_tool_pinning.sql (Phase 4 M3).

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

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000f1f0a001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000f1f00001', 'Pin Org A', 'pin-org-a'),
    ('00000000-0000-0000-0000-0000f1f00002', 'Pin Org B', 'pin-org-b');
INSERT INTO public.mcp_servers (id, organization_id, slug, name, url) VALUES
    ('00000000-0000-0000-0000-0000f1f0000a', '00000000-0000-0000-0000-0000f1f00001', 'srv-a', 'Server A', 'https://a.example/mcp'),
    ('00000000-0000-0000-0000-0000f1f0000b', '00000000-0000-0000-0000-0000f1f00002', 'srv-b', 'Server B', 'https://b.example/mcp');

CREATE FUNCTION pg_temp.tool(p_name text, p_digest_char text, p_desc text DEFAULT 'does a thing') RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object('name', p_name, 'digest', repeat(p_digest_char, 64), 'description', p_desc, 'schema', '{"type":"object"}', 'rules', '[]'::jsonb)
$$;

DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-0000f1f00001';
    b uuid := '00000000-0000-0000-0000-0000f1f00002';
    sa uuid := '00000000-0000-0000-0000-0000f1f0000a';
    sb uuid := '00000000-0000-0000-0000-0000f1f0000b';
    actor uuid := '00000000-0000-0000-0000-0000f1f0a001';
    r jsonb; pin1 uuid; pin2 uuid;
BEGIN
    PERFORM pg_temp.check((SELECT pin_mode = 'alert' FROM public.mcp_servers WHERE id = sa), 'the default pin mode is alert');

    -- first sight: new versions, one alert
    r := public.record_tool_observation(a, sa, jsonb_build_array(pg_temp.tool('list_invoices', 'a'), pg_temp.tool('get_invoice', 'b')));
    PERFORM pg_temp.check((r->>'new')::int = 2 AND (r->>'changed')::int = 0 AND (r->>'alert')::boolean, 'two new tools are recorded and alert once');
    PERFORM pg_temp.check((SELECT count(*) = 2 AND bool_and(status = 'pending' AND change_kind = 'new') FROM public.mcp_tool_pins WHERE server_id = sa), 'they are pending and new');
    PERFORM pg_temp.check((SELECT count(*) = 2 FROM public.control_audit_log WHERE action = 'tool_pin.pending' AND actor_user_id = '00000000-0000-0000-0000-000000000000'), 'each is audited by the system actor');

    -- idempotent: the same digests again change nothing and do not alert again
    r := public.record_tool_observation(a, sa, jsonb_build_array(pg_temp.tool('list_invoices', 'a')));
    PERFORM pg_temp.check((r->>'new')::int = 0 AND NOT (r->>'alert')::boolean, 'a repeat records nothing and does not alert');
    PERFORM pg_temp.check((SELECT count(*) = 2 FROM public.mcp_tool_pins WHERE server_id = sa), 'still two rows');

    -- approve one, then a changed description appears
    SELECT id INTO pin1 FROM public.mcp_tool_pins WHERE server_id = sa AND tool_name = 'list_invoices';
    r := public.control_tool_pin(a, actor, pin1, 'approve', 'baseline');
    PERFORM pg_temp.check(NOT (r->>'conflict')::boolean AND r->>'status' = 'approved', 'a pending version can be approved');
    r := public.control_tool_pin(a, actor, pin1, 'approve', 'again');
    PERFORM pg_temp.check((r->>'conflict')::boolean AND r->>'status' = 'approved', 'deciding twice is a conflict, not a second change');
    UPDATE public.mcp_servers SET pin_last_alert_at = now() - interval '11 minutes' WHERE id = sa;
    r := public.record_tool_observation(a, sa, jsonb_build_array(pg_temp.tool('list_invoices', 'c', 'now also sends data elsewhere')));
    PERFORM pg_temp.check((r->>'changed')::int = 1 AND (r->>'alert')::boolean, 'a changed description is a changed version and alerts');
    PERFORM pg_temp.check((SELECT change_kind = 'changed' AND status = 'pending' FROM public.mcp_tool_pins WHERE server_id = sa AND digest = repeat('c', 64)), 'it is pending and marked changed');
    PERFORM pg_temp.check((SELECT status = 'approved' FROM public.mcp_tool_pins WHERE id = pin1), 'the approved version stays approved until the change is approved');

    -- alert rate limit: a further change within 10 minutes is recorded without a second alert
    r := public.record_tool_observation(a, sa, jsonb_build_array(pg_temp.tool('get_invoice', 'd')));
    PERFORM pg_temp.check((r->>'new')::int + (r->>'changed')::int = 1 AND NOT (r->>'alert')::boolean, 'a second change inside 10 minutes does not alert again');

    -- approving the changed version supersedes the old one: one approved version per tool
    SELECT id INTO pin2 FROM public.mcp_tool_pins WHERE server_id = sa AND digest = repeat('c', 64);
    PERFORM public.control_tool_pin(a, actor, pin2, 'approve', NULL);
    PERFORM pg_temp.check((SELECT status = 'superseded' FROM public.mcp_tool_pins WHERE id = pin1) AND
        (SELECT count(*) = 1 FROM public.mcp_tool_pins WHERE server_id = sa AND tool_name = 'list_invoices' AND status = 'approved'), 'approving a change supersedes the old approved version');

    -- reject
    PERFORM public.record_tool_observation(a, sa, jsonb_build_array(pg_temp.tool('list_invoices', 'e', 'rug pull')));
    PERFORM public.control_tool_pin(a, actor, (SELECT id FROM public.mcp_tool_pins WHERE digest = repeat('e', 64)), 'reject', 'suspicious');
    PERFORM pg_temp.check((SELECT status = 'rejected' FROM public.mcp_tool_pins WHERE digest = repeat('e', 64)) AND
        (SELECT count(*) = 1 FROM public.mcp_tool_pins WHERE server_id = sa AND tool_name = 'list_invoices' AND status = 'approved'), 'a rejected version leaves the approved one in place');

    -- approve all: newest pending per tool, older pending rejected
    PERFORM public.record_tool_observation(a, sa, jsonb_build_array(pg_temp.tool('t1', '1'), pg_temp.tool('t1', '2'), pg_temp.tool('t2', '3')));
    r := public.control_tool_pins_approve_all(a, actor, sa, 'baseline');
    PERFORM pg_temp.check((r->>'approved')::int >= 3, 'approve-all approves one version per tool with a pending change');
    PERFORM pg_temp.check((SELECT count(*) = 1 FROM public.mcp_tool_pins WHERE server_id = sa AND tool_name = 't1' AND status = 'approved'), 'only one t1 version is approved');
    PERFORM pg_temp.check((SELECT count(*) = 1 FROM public.control_audit_log WHERE action = 'tool_pin.approved_all'), 'approve-all is one audit row with the count');

    -- tenant isolation
    PERFORM pg_temp.expect_error(format('SELECT public.record_tool_observation(%L, %L, ''[]'')', b, sa), 'P0002', 'organization B cannot record against A''s server');
    PERFORM pg_temp.expect_error(format('SELECT public.control_tool_pin(%L, %L, %L, ''approve'', NULL)', b, actor, pin1), 'P0002', 'organization B cannot decide A''s pin');
    PERFORM pg_temp.expect_error(format('SELECT public.control_tool_pins_approve_all(%L, %L, %L, NULL)', b, actor, sa), 'P0002', 'organization B cannot approve A''s tools');
    PERFORM pg_temp.expect_error(format('SELECT public.control_server_pin_mode(%L, %L, %L, ''enforce'', ''alert'', NULL)', b, actor, sa), 'P0002', 'organization B cannot change A''s pin mode');

    -- input checks
    PERFORM pg_temp.expect_error(format('SELECT public.control_tool_pin(%L, %L, %L, ''delete'', NULL)', a, actor, pin1), '22023', 'unknown decision refused');
    PERFORM pg_temp.expect_error(format('SELECT public.record_tool_observation(%L, %L, ''{}'')', a, sa), '22023', 'tools must be an array');
    r := public.record_tool_observation(a, sa, jsonb_build_array(jsonb_build_object('name', '', 'digest', repeat('f', 64)), jsonb_build_object('name', 'x', 'digest', 'nothex'), pg_temp.tool('ok_tool', '9')));
    PERFORM pg_temp.check((r->>'skipped')::int = 2 AND (r->>'new')::int = 1, 'malformed items are skipped, valid ones kept');

    -- bounds
    FOR i IN 1..19 LOOP
        PERFORM public.record_tool_observation(a, sa, jsonb_build_array(pg_temp.tool('chatty', lpad(to_hex(i), 1, '0') || '', 'v' || i) || jsonb_build_object('digest', lpad(i::text, 64, '7'))));
    END LOOP;
    PERFORM pg_temp.check((SELECT count(*) <= 20 FROM public.mcp_tool_pins WHERE server_id = sa AND tool_name = 'chatty'), 'versions per tool are capped at 20');

    -- pin mode
    r := public.control_server_pin_mode(a, actor, sa, 'enforce', 'alert', 'tighten');
    PERFORM pg_temp.check((r->>'changed')::boolean AND r->>'pin_mode' = 'enforce', 'pin mode changes with compare-and-set');
    r := public.control_server_pin_mode(a, actor, sa, 'off', 'alert', NULL);
    PERFORM pg_temp.check((r->>'conflict')::boolean AND r->>'pin_mode' = 'enforce', 'a stale expectation is a conflict');
    r := public.control_server_pin_mode(a, actor, sa, 'enforce', 'enforce', NULL);
    PERFORM pg_temp.check(NOT (r->>'changed')::boolean, 'repeating the current mode changes nothing');
    PERFORM pg_temp.check((SELECT count(*) = 1 FROM public.control_audit_log WHERE action = 'mcp_server.pin_mode_changed' AND details->>'new_mode' = 'enforce'), 'the change is audited once');
    PERFORM pg_temp.expect_error(format('SELECT public.control_server_pin_mode(%L, %L, %L, ''bogus'', ''enforce'', NULL)', a, actor, sa), '22023', 'unknown mode refused');
    PERFORM public.control_server_pin_mode(a, actor, sa, 'off', 'enforce', NULL);
    r := public.record_tool_observation(a, sa, jsonb_build_array(pg_temp.tool('after_off', 'a')));
    PERFORM pg_temp.check((r->>'skipped')::int = 1 AND (r->>'new')::int = 0, 'nothing is recorded while pinning is off');

    -- deleting the server removes its pins
    DELETE FROM public.mcp_servers WHERE id = sb;
    PERFORM pg_temp.check((SELECT count(*) = 0 FROM public.mcp_tool_pins WHERE server_id = sb), 'pins go with their server');
END $$;

SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.record_tool_observation(uuid,uuid,jsonb)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.control_tool_pin(uuid,uuid,uuid,text,text)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.control_server_pin_mode(uuid,uuid,uuid,text,text,text)', 'EXECUTE'), 'functions are service_role only');
SELECT pg_temp.check((SELECT relrowsecurity FROM pg_class WHERE relname = 'mcp_tool_pins'), 'row level security is on');

\echo ALL SQL TESTS PASSED
