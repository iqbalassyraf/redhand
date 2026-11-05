-- SQL tests for supabase/migrations/20261112000000_blackbox_payload_capture.sql (Phase 3 M2b).
-- Run by scripts/test_migrations.sh after all migrations are applied.

\set ON_ERROR_STOP on
\set QUIET on

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'CHECK FAILED: %', p_msg;
    END IF;
    RAISE NOTICE 'ok: %', p_msg;
END $$;

CREATE FUNCTION pg_temp.expect_error(p_sql text, p_sqlstate text, p_msg text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE = p_sqlstate THEN
            RAISE NOTICE 'ok: % (SQLSTATE %)', p_msg, p_sqlstate;
            RETURN;
        END IF;
        RAISE EXCEPTION 'CHECK FAILED: % -- expected SQLSTATE % but got % (%)', p_msg, p_sqlstate, SQLSTATE, SQLERRM;
    END;
    RAISE EXCEPTION 'CHECK FAILED: % -- expected SQLSTATE % but the statement succeeded', p_msg, p_sqlstate;
END $$;

-- One event, with optional payload fields.
CREATE FUNCTION pg_temp.evt(p_agent uuid, p_args jsonb DEFAULT NULL, p_result jsonb DEFAULT NULL) RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'agent_id', p_agent, 'occurred_at', now(), 'gateway_instance', 'instance-pppp',
        'server', 'fs', 'method', 'tools/call', 'tool_name', 'read_file', 'decision', 'ALLOW',
        'reasons', '[]'::jsonb, 'upstream_status', 200, 'latency_ms', 1.5,
        'argument_keys', jsonb_build_array('path'), 'arguments_sha256', repeat('c', 64),
        'result_size_bytes', 100, 'redaction_count', 0, 'credential_jti', 'jti-p')
    || CASE WHEN p_args IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('arguments_redacted', p_args) END
    || CASE WHEN p_result IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('result_excerpt', p_result) END
$$;

-- Fixtures: organization A (capture on), organization B (capture off, the default) -------------------------
INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000c0c0e0a1');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000c0c0e001', 'Capture Org A', 'capture-org-a'),
    ('00000000-0000-0000-0000-0000c0c0e002', 'Capture Org B', 'capture-org-b');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000c0c0e00a', '00000000-0000-0000-0000-0000c0c0e001', 'cap-bot-a', 'Cap Bot A'),
    ('00000000-0000-0000-0000-0000c0c0e00b', '00000000-0000-0000-0000-0000c0c0e002', 'cap-bot-b', 'Cap Bot B');

-- 1. The flag is the database's decision ---------------------------------------------------------------------
SELECT pg_temp.check(
    (SELECT NOT payload_capture_enabled FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000c0c0e001'),
    'capture is off by default');
DO $$
DECLARE
    org uuid := '00000000-0000-0000-0000-0000c0c0e001';
    bot uuid := '00000000-0000-0000-0000-0000c0c0e00a';
    r jsonb;
BEGIN
    r := public.record_events('instance-pppp', gen_random_uuid(), org, jsonb_build_array(
        pg_temp.evt(bot, '{"text": "{\"path\":\"/tmp/a\"}", "truncated": false, "original_bytes": 17}',
                         '{"text": "ok", "truncated": false, "original_bytes": 2}')));
    PERFORM pg_temp.check((r->>'accepted')::int = 1 AND (r->>'rejected')::int = 0,
        'with capture off the event is accepted even though the batch carries payloads');
    PERFORM pg_temp.check(
        (SELECT arguments_redacted IS NULL AND result_excerpt IS NULL FROM public.agent_events WHERE organization_id = org AND seq = 1),
        'with capture off no payload is stored, whatever the gateway sent');
END $$;

SELECT public.control_payload_capture('00000000-0000-0000-0000-0000c0c0e001', '00000000-0000-0000-0000-0000c0c0e0a1', TRUE, 'test', FALSE);

-- 2. Capture on: payloads are stored, the chain is unaffected -------------------------------------------------
DO $$
DECLARE
    org uuid := '00000000-0000-0000-0000-0000c0c0e001';
    bot uuid := '00000000-0000-0000-0000-0000c0c0e00a';
    r jsonb;
    v jsonb;
    big jsonb := jsonb_build_object('text', repeat('x', 20000), 'truncated', true, 'original_bytes', 99999);
BEGIN
    r := public.record_events('instance-pppp', gen_random_uuid(), org, jsonb_build_array(
        pg_temp.evt(bot, '{"text": "{\"path\":\"/tmp/a\"}", "truncated": false, "original_bytes": 17}',
                         '{"text": "ok", "truncated": false, "original_bytes": 2}'),
        pg_temp.evt(bot, '{"text": "args only", "truncated": false, "original_bytes": 9}'),
        pg_temp.evt(bot, NULL, NULL),
        pg_temp.evt(bot, '"not an object"', '[1, 2]'),
        pg_temp.evt(bot, big, big)));
    PERFORM pg_temp.check((r->>'accepted')::int = 5 AND (r->>'rejected')::int = 0,
        'with capture on all five events are accepted, including ones whose payloads are unusable');
    PERFORM pg_temp.check(
        (SELECT arguments_redacted->>'text' = '{"path":"/tmp/a"}' AND result_excerpt->>'text' = 'ok'
         FROM public.agent_events WHERE organization_id = org AND seq = 2),
        'with capture on both payloads are stored as sent');
    PERFORM pg_temp.check(
        (SELECT arguments_redacted->>'text' = 'args only' AND result_excerpt IS NULL
         FROM public.agent_events WHERE organization_id = org AND seq = 3),
        'a payload may carry only arguments (a refused call has no result)');
    PERFORM pg_temp.check(
        (SELECT arguments_redacted IS NULL AND result_excerpt IS NULL FROM public.agent_events WHERE organization_id = org AND seq = 4),
        'an event without payloads stores none');
    PERFORM pg_temp.check(
        (SELECT arguments_redacted IS NULL AND result_excerpt IS NULL FROM public.agent_events WHERE organization_id = org AND seq = 5),
        'a payload that is not a JSON object is dropped, the event is kept');
    PERFORM pg_temp.check(
        (SELECT arguments_redacted IS NULL AND result_excerpt IS NULL FROM public.agent_events WHERE organization_id = org AND seq = 6),
        'a payload over 16 KB is dropped, the event is kept');
    v := public.verify_events(org, 1, 6);
    PERFORM pg_temp.check((v->>'ok')::boolean AND (v->>'checked')::int = 6,
        'the chain verifies with payloads present and absent (the hash does not cover them)');
END $$;
SELECT pg_temp.expect_error(
    $$UPDATE public.agent_events SET arguments_redacted = jsonb_build_object('text', repeat('y', 20000))
      WHERE organization_id = '00000000-0000-0000-0000-0000c0c0e001' AND seq = 2$$,
    '42501', 'a payload cannot be written to a stored event');
SELECT pg_temp.check(
    NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'agent_events_payload_size' AND NOT convalidated),
    'the payload size constraint is in force');

-- 3. Another organization is unaffected -------------------------------------------------------------------------
DO $$
DECLARE
    orgb uuid := '00000000-0000-0000-0000-0000c0c0e002';
    botb uuid := '00000000-0000-0000-0000-0000c0c0e00b';
BEGIN
    PERFORM public.record_events('instance-pppp', gen_random_uuid(), orgb,
        jsonb_build_array(pg_temp.evt(botb, '{"text": "secretish", "truncated": false, "original_bytes": 8}')));
    PERFORM pg_temp.check(
        (SELECT arguments_redacted IS NULL FROM public.agent_events WHERE organization_id = orgb AND seq = 1),
        'turning capture on for one organization does not capture another''s payloads');
END $$;

-- 4. Payload retention still clears captured payloads (M2a) -----------------------------------------------------------
DO $$
DECLARE org uuid := '00000000-0000-0000-0000-0000c0c0e001';
BEGIN
    ALTER TABLE public.agent_events DISABLE TRIGGER trg_agent_events_append_only;
    UPDATE public.agent_events SET received_at = now() - interval '10 days' WHERE organization_id = org AND seq = 2;
    ALTER TABLE public.agent_events ENABLE TRIGGER trg_agent_events_append_only;
    PERFORM public.purge_events();
    PERFORM pg_temp.check(
        (SELECT arguments_redacted IS NULL AND result_excerpt IS NULL FROM public.agent_events WHERE organization_id = org AND seq = 2),
        'a captured payload older than the payload retention is cleared');
    PERFORM pg_temp.check(
        (SELECT arguments_redacted IS NOT NULL FROM public.agent_events WHERE organization_id = org AND seq = 3),
        'a captured payload within the payload retention is kept');
    PERFORM pg_temp.check((public.verify_events(org, 1, 6)->>'ok')::boolean, 'the chain still verifies after payloads are cleared');
END $$;

-- 5. control_payload_capture ------------------------------------------------------------------------------------------
DO $$
DECLARE
    org uuid := '00000000-0000-0000-0000-0000c0c0e002';
    actor uuid := '00000000-0000-0000-0000-0000c0c0e0a1';
    r jsonb;
BEGIN
    r := public.control_payload_capture(org, actor, TRUE, 'x', TRUE);
    PERFORM pg_temp.check((r->>'conflict')::boolean, 'a stale expected value is a conflict and changes nothing');
    PERFORM pg_temp.check((SELECT NOT payload_capture_enabled FROM public.organizations WHERE id = org),
        'the conflict left capture off');
    r := public.control_payload_capture(org, actor, FALSE, 'x', FALSE);
    PERFORM pg_temp.check(NOT (r->>'changed')::boolean, 'setting the current value changes nothing');
    r := public.control_payload_capture(org, actor, TRUE, 'for the audit', FALSE);
    PERFORM pg_temp.check((r->>'changed')::boolean AND (SELECT payload_capture_enabled FROM public.organizations WHERE id = org),
        'capture is turned on');
    PERFORM pg_temp.check(
        (SELECT count(*) FROM public.control_audit_log
         WHERE organization_id = org AND action = 'organization.payload_capture_changed' AND actor_user_id = actor
           AND reason = 'for the audit' AND details->>'old_enabled' = 'false' AND details->>'new_enabled' = 'true') = 1,
        'turning capture on is audited once, with old and new values');
    r := public.control_payload_capture(org, actor, FALSE, 'off again', TRUE);
    PERFORM pg_temp.check((r->>'changed')::boolean AND (SELECT NOT payload_capture_enabled FROM public.organizations WHERE id = org),
        'capture is turned off again');
    PERFORM pg_temp.check(
        (SELECT count(*) FROM public.control_audit_log WHERE organization_id = org AND action = 'organization.payload_capture_changed') = 2,
        'both changes are audited');
    PERFORM pg_temp.check(
        (SELECT payload_capture_enabled FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000c0c0e001'),
        'another organization keeps its setting');
END $$;
SELECT pg_temp.expect_error(
    $$SELECT public.control_payload_capture('00000000-0000-0000-0000-0000c0c0e0ff', '00000000-0000-0000-0000-0000c0c0e0a1', TRUE, NULL, FALSE)$$,
    'P0002', 'an unknown organization is not found');
SELECT pg_temp.expect_error(
    $$SELECT public.control_payload_capture('00000000-0000-0000-0000-0000c0c0e002', '00000000-0000-0000-0000-0000c0c0e0a1', NULL, NULL, FALSE)$$,
    '22023', 'a null enabled value is refused');

-- 6. Access --------------------------------------------------------------------------------------------------------------------
DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['control_payload_capture(uuid,uuid,boolean,text,boolean)', 'record_events(text,uuid,uuid,jsonb)'] LOOP
        PERFORM pg_temp.check(NOT has_function_privilege('anon', 'public.' || f, 'EXECUTE')
                          AND NOT has_function_privilege('authenticated', 'public.' || f, 'EXECUTE'),
            f || ' is not executable by anon or authenticated');
        PERFORM pg_temp.check(has_function_privilege('service_role', 'public.' || f, 'EXECUTE'), f || ' is executable by service_role');
    END LOOP;
END $$;

DO $$ BEGIN RAISE NOTICE 'ALL SQL TESTS PASSED (blackbox_payload)'; END $$;
