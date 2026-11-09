-- SQL tests for supabase/migrations/20261115000000_honeytokens.sql (Phase 3 M3/M4).

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

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000b0b0a001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000b0b00001', 'Honey Org A', 'honey-org-a'),
    ('00000000-0000-0000-0000-0000b0b00002', 'Honey Org B', 'honey-org-b');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000b0b0000a', '00000000-0000-0000-0000-0000b0b00001', 'hny-bot-a', 'Honey Bot A'),
    ('00000000-0000-0000-0000-0000b0b0000b', '00000000-0000-0000-0000-0000b0b00002', 'hny-bot-b', 'Honey Bot B');

DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-0000b0b00001';
    b uuid := '00000000-0000-0000-0000-0000b0b00002';
    bot_a uuid := '00000000-0000-0000-0000-0000b0b0000a';
    bot_b uuid := '00000000-0000-0000-0000-0000b0b0000b';
    actor uuid := '00000000-0000-0000-0000-0000b0b0a001';
    t jsonb; tool jsonb; r jsonb; r2 jsonb;
    trip uuid := gen_random_uuid();
BEGIN
    -- honeytokens ------------------------------------------------------------------------------------------
    t := public.control_honeytoken_create(a, actor, 'Decoy prod key', 'api_key', repeat('a', 64), 'wxyz', 'freeze', 'alert');
    PERFORM pg_temp.check(t->>'hint' = 'wxyz' AND NOT (t ? 'digest'), 'create returns the hint and never the digest');
    PERFORM pg_temp.check((SELECT details::text NOT LIKE '%aaaaaaaa%' FROM public.control_audit_log WHERE action = 'honeytoken.created'),
        'the audit row has no digest');
    PERFORM pg_temp.expect_error(format('SELECT public.control_honeytoken_create(%L, %L, ''dup'', ''api_key'', %L, ''wxyz'', ''freeze'', ''alert'')', a, actor, repeat('a', 64)),
        '23505', 'the same digest cannot be registered twice in an organization');
    PERFORM public.control_honeytoken_create(b, actor, 'Same digest, other org', 'api_key', repeat('a', 64), 'wxyz', 'alert', 'alert');
    PERFORM pg_temp.check(true, 'another organization may use the same digest');
    PERFORM pg_temp.expect_error(format('SELECT public.control_honeytoken_create(%L, %L, ''x'', ''bogus'', %L, ''wxyz'', ''freeze'', ''alert'')', a, actor, repeat('b', 64)),
        '23514', 'unknown kind is refused');

    FOR i IN 1..49 LOOP
        PERFORM public.control_honeytoken_create(a, actor, 'bulk ' || i, 'password', lpad(i::text, 64, 'c'), 'abcd', 'alert', 'alert');
    END LOOP;
    PERFORM pg_temp.expect_error(format('SELECT public.control_honeytoken_create(%L, %L, ''one too many'', ''password'', %L, ''abcd'', ''alert'', ''alert'')', a, actor, repeat('d', 64)),
        '23514', 'at most 50 active honeytokens per organization');
    PERFORM public.control_honeytoken_retire(a, actor, (t->>'id')::uuid);
    PERFORM public.control_honeytoken_create(a, actor, 'room again', 'password', repeat('e', 64), 'abcd', 'alert', 'alert');
    PERFORM pg_temp.check(true, 'retiring frees a slot');
    PERFORM pg_temp.check(NOT (public.control_honeytoken_retire(a, actor, (t->>'id')::uuid)->>'changed')::boolean, 'retiring twice is a no-op');
    PERFORM pg_temp.expect_error(format('SELECT public.control_honeytoken_retire(%L, %L, %L)', b, actor, t->>'id'), 'P0002', 'another organization cannot retire it');

    -- trips ------------------------------------------------------------------------------------------------
    UPDATE public.honeytokens SET status = 'retired', retired_at = now() WHERE organization_id = a AND label = 'room again';
    t := public.control_honeytoken_create(a, actor, 'Trip me', 'aws_key', repeat('f', 64), 'qrst', 'freeze', 'alert');
    r := public.record_trip(a, trip, bot_a, 'honeytoken', (t->>'id')::uuid, 'arguments', 'send_email', 'mail');
    PERFORM pg_temp.check((r->>'recorded')::boolean AND r->>'action' = 'freeze' AND r->>'label' = 'Trip me' AND (r->>'alert')::boolean,
        'a trip in arguments uses the use action and asks for an alert');
    r2 := public.record_trip(a, trip, bot_a, 'honeytoken', (t->>'id')::uuid, 'arguments', 'send_email', 'mail');
    PERFORM pg_temp.check(NOT (r2->>'recorded')::boolean AND r2->>'reason' = 'duplicate', 'a retried trip id is not counted twice');
    PERFORM pg_temp.check((SELECT trip_count = 1 AND last_tripped_at IS NOT NULL FROM public.honeytokens WHERE id = (t->>'id')::uuid), 'the honeytoken counts one trip');
    PERFORM pg_temp.check((SELECT count(*) = 1 AND bool_and(actor_user_id = '00000000-0000-0000-0000-000000000000' AND target_id = bot_a)
        FROM public.control_audit_log WHERE action = 'honeytoken.tripped' AND organization_id = a), 'one audit row, system actor, targeting the agent');
    PERFORM pg_temp.check((SELECT details::text NOT LIKE '%ffffffff%' FROM public.control_audit_log WHERE action = 'honeytoken.tripped'), 'the trip audit has no digest');
    r := public.record_trip(a, gen_random_uuid(), bot_a, 'honeytoken', (t->>'id')::uuid, 'arguments', 'send_email', 'mail');
    PERFORM pg_temp.check((r->>'recorded')::boolean AND NOT (r->>'alert')::boolean, 'a second trip within 5 minutes is recorded but not alerted again');
    r := public.record_trip(a, gen_random_uuid(), bot_a, 'honeytoken', (t->>'id')::uuid, 'result', 'read_doc', 'docs');
    PERFORM pg_temp.check(r->>'action' = 'alert' AND (r->>'alert')::boolean, 'a trip in a result uses the read action');
    PERFORM pg_temp.expect_error(format('SELECT public.record_trip(%L, gen_random_uuid(), %L, ''honeytoken'', %L, ''arguments'', ''x'', ''y'')', a, bot_b, t->>'id'),
        'P0002', 'an agent of another organization is refused');
END $$;

DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-0000b0b00001';
    b uuid := '00000000-0000-0000-0000-0000b0b00002';
    bot_a uuid := '00000000-0000-0000-0000-0000b0b0000a';
    bot_b uuid := '00000000-0000-0000-0000-0000b0b0000b';
    actor uuid := '00000000-0000-0000-0000-0000b0b0a001';
    t jsonb; tool jsonb; other jsonb; r jsonb;
BEGIN
    -- another organization's honeytoken cannot be tripped through this one's agent
    other := public.control_honeytoken_create(b, actor, 'B only', 'api_key', repeat('9', 64), 'zzzz', 'freeze', 'alert');
    r := public.record_trip(a, gen_random_uuid(), bot_a, 'honeytoken', (other->>'id')::uuid, 'arguments', 'x', 'y');
    PERFORM pg_temp.check(NOT (r->>'recorded')::boolean AND r->>'reason' = 'unknown_reference', 'a reference from another organization is not recorded');
    r := public.record_trip(a, gen_random_uuid(), bot_a, 'honeytoken', gen_random_uuid(), 'arguments', 'x', 'y');
    PERFORM pg_temp.check(NOT (r->>'recorded')::boolean, 'an unknown reference is not recorded and not an error');
    PERFORM pg_temp.expect_error(format('SELECT public.record_trip(%L, gen_random_uuid(), %L, ''honeytoken'', gen_random_uuid(), ''call'', '''', '''')', a, bot_a), '22023', 'a honeytoken cannot be tripped by a call');

    -- honey tools ------------------------------------------------------------------------------------------
    tool := public.control_honey_tool_create(a, actor, bot_a, 'deepwiki', 'export_all_customer_records', 'Exports every customer record', 'alert');
    PERFORM pg_temp.check(tool->>'name' = 'export_all_customer_records' AND tool->>'action' = 'alert', 'honey tool created, default action alert');
    PERFORM pg_temp.expect_error(format('SELECT public.control_honey_tool_create(%L, %L, %L, ''deepwiki'', ''export_all_customer_records'', ''dup'', ''alert'')', a, actor, bot_a),
        '23505', 'an active honey tool name is unique per agent and server');
    PERFORM pg_temp.expect_error(format('SELECT public.control_honey_tool_create(%L, %L, %L, ''s'', ''bad name!'', ''d'', ''alert'')', a, actor, bot_a), '23514', 'tool names are restricted');
    PERFORM pg_temp.expect_error(format('SELECT public.control_honey_tool_create(%L, %L, %L, ''s'', ''export_all'', ''d'', ''alert'')', b, actor, bot_a), 'P0002', 'another organization cannot add a tool to this agent');
    FOR i IN 1..4 LOOP
        PERFORM public.control_honey_tool_create(a, actor, bot_a, 'deepwiki', 'decoy_tool_' || i, 'd', 'alert');
    END LOOP;
    PERFORM pg_temp.expect_error(format('SELECT public.control_honey_tool_create(%L, %L, %L, ''deepwiki'', ''decoy_tool_9'', ''d'', ''alert'')', a, actor, bot_a),
        '23514', 'at most 5 active honey tools per agent');
    r := public.record_trip(a, gen_random_uuid(), bot_a, 'honey_tool', (tool->>'id')::uuid, 'call', 'export_all_customer_records', 'deepwiki');
    PERFORM pg_temp.check((r->>'recorded')::boolean AND r->>'action' = 'alert' AND (r->>'alert')::boolean, 'a honey tool trip is recorded');
    PERFORM pg_temp.check((SELECT trip_count = 1 FROM public.honey_tools WHERE id = (tool->>'id')::uuid), 'the honey tool counts the trip');
    PERFORM pg_temp.check((SELECT count(*) = 1 FROM public.control_audit_log WHERE action = 'honey_tool.tripped'), 'honey tool trip audited');
    PERFORM public.control_honey_tool_retire(a, actor, (tool->>'id')::uuid);
    r := public.record_trip(a, gen_random_uuid(), bot_a, 'honey_tool', (tool->>'id')::uuid, 'call', 'export_all_customer_records', 'deepwiki');
    PERFORM pg_temp.check(NOT (r->>'recorded')::boolean, 'a retired honey tool no longer records trips');
    t := public.purge_honey();
    PERFORM pg_temp.check((t->>'trips')::int = 0, 'purge keeps recent data');
END $$;

-- canaries (Phase 4 M5a) -------------------------------------------------------------------------------------
INSERT INTO public.organizations (id, name, slug) VALUES ('00000000-0000-0000-0000-0000b0b00003', 'Canary Org C', 'canary-org-c');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000b0b0000c', '00000000-0000-0000-0000-0000b0b00003', 'cny-bot-c', 'Canary Bot C');

DO $$
DECLARE
    c uuid := '00000000-0000-0000-0000-0000b0b00003';
    bot_c uuid := '00000000-0000-0000-0000-0000b0b0000c';
    actor uuid := '00000000-0000-0000-0000-0000b0b0a001';
    can jsonb; pw jsonb; r jsonb; tool jsonb;
BEGIN
    can := public.control_honeytoken_create(c, actor, 'System prompt canary', 'canary', repeat('7', 64), 'qqqq', 'alert', 'alert');
    PERFORM pg_temp.check(can->>'kind' = 'canary' AND can->>'action_on_use' = 'alert' AND NOT (can ? 'digest'), 'a canary can be created and returns no digest');
    PERFORM pg_temp.check((SELECT details->>'kind' = 'canary' AND details::text NOT LIKE '%7777777%' FROM public.control_audit_log
        WHERE action = 'honeytoken.created' AND organization_id = c), 'the canary creation audit names the kind and has no digest');
    PERFORM pg_temp.expect_error(format('SELECT public.control_honeytoken_create(%L, %L, ''x'', ''canary_x'', %L, ''wxyz'', ''alert'', ''alert'')', c, actor, repeat('8', 64)),
        '23514', 'an unknown kind is still refused');

    r := public.record_trip(c, gen_random_uuid(), bot_c, 'honeytoken', (can->>'id')::uuid, 'arguments', 'send_email', 'mail');
    PERFORM pg_temp.check((r->>'recorded')::boolean AND r->>'kind' = 'canary' AND r->>'action' = 'alert' AND (r->>'alert')::boolean,
        'a canary trip returns its kind and uses the use action');
    PERFORM pg_temp.check((SELECT details->>'kind' = 'canary' FROM public.control_audit_log WHERE action = 'honeytoken.tripped' AND organization_id = c),
        'the trip audit records the kind');
    r := public.record_trip(c, gen_random_uuid(), bot_c, 'honeytoken', (can->>'id')::uuid, 'result', 'read_doc', 'docs');
    PERFORM pg_temp.check(r->>'kind' = 'canary' AND r->>'action' = 'alert', 'a canary trip in a result uses the read action');

    pw := public.control_honeytoken_create(c, actor, 'Plain decoy', 'password', repeat('6', 64), 'pppp', 'freeze', 'alert');
    r := public.record_trip(c, gen_random_uuid(), bot_c, 'honeytoken', (pw->>'id')::uuid, 'arguments', 'x', 'y');
    PERFORM pg_temp.check(r->>'kind' = 'password' AND r->>'action' = 'freeze', 'other honeytoken kinds still behave as before and report their kind');

    tool := public.control_honey_tool_create(c, actor, bot_c, 'deepwiki', 'export_everything', 'Exports everything', 'alert');
    r := public.record_trip(c, gen_random_uuid(), bot_c, 'honey_tool', (tool->>'id')::uuid, 'call', 'export_everything', 'deepwiki');
    PERFORM pg_temp.check((r->>'recorded')::boolean AND NOT (r ? 'kind'), 'a decoy tool trip has no kind');
    PERFORM pg_temp.check((SELECT NOT (details ? 'kind') FROM public.control_audit_log WHERE action = 'honey_tool.tripped' AND organization_id = c),
        'a decoy tool trip audit has no kind');

    -- canaries share the 50 active honeytokens limit
    FOR i IN 1..48 LOOP
        PERFORM public.control_honeytoken_create(c, actor, 'fill ' || i, 'password', lpad(i::text, 64, '5'), 'ffff', 'alert', 'alert');
    END LOOP;
    PERFORM pg_temp.expect_error(format('SELECT public.control_honeytoken_create(%L, %L, ''one too many'', ''canary'', %L, ''abcd'', ''alert'', ''alert'')', c, actor, repeat('4', 64)),
        '23514', 'a canary counts toward the 50 active honeytokens limit');

    PERFORM public.control_honeytoken_retire(c, actor, (can->>'id')::uuid);
    r := public.record_trip(c, gen_random_uuid(), bot_c, 'honeytoken', (can->>'id')::uuid, 'arguments', 'x', 'y');
    PERFORM pg_temp.check(NOT (r->>'recorded')::boolean, 'a retired canary no longer records trips');
END $$;

SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.record_trip(uuid,uuid,uuid,text,uuid,text,text,text)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.control_honeytoken_create(uuid,uuid,text,text,text,text,text,text)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.record_trip(uuid,uuid,uuid,text,uuid,text,text,text)', 'EXECUTE'),
    'all functions are service_role only');
SELECT pg_temp.check((SELECT bool_and(relrowsecurity) FROM pg_class WHERE relname IN ('honeytokens', 'honey_tools', 'honeytrips')), 'row level security is on');

\echo ALL SQL TESTS PASSED
