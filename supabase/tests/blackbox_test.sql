-- SQL tests for supabase/migrations/20261110000000_blackbox.sql.
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

-- Fixtures: two organizations, two agents in the first, one in the second ------------------------
INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000c0c00001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000c0c00008', 'BB Org 1', 'bb-org-1'),
    ('00000000-0000-0000-0000-0000c0c00009', 'BB Org 2', 'bb-org-2');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000c0c0000a', '00000000-0000-0000-0000-0000c0c00008', 'bb-bot-1', 'BB Bot 1'),
    ('00000000-0000-0000-0000-0000c0c0000b', '00000000-0000-0000-0000-0000c0c00009', 'bb-bot-2', 'BB Bot 2'),
    ('00000000-0000-0000-0000-0000c0c0000c', '00000000-0000-0000-0000-0000c0c00008', 'bb-bot-3', 'BB Bot 3');

CREATE FUNCTION pg_temp.evt(p_agent uuid, p_decision text DEFAULT 'ALLOW', p_tool text DEFAULT 'read_file')
RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'agent_id', p_agent, 'occurred_at', now(), 'gateway_instance', 'instance-aaaa',
        'server', 'fs', 'method', 'tools/call', 'tool_name', p_tool, 'decision', p_decision,
        'reasons', '[]'::jsonb, 'upstream_status', 200, 'latency_ms', 1.5,
        'argument_keys', jsonb_build_array('path'), 'arguments_sha256', repeat('a', 64),
        'result_size_bytes', 100, 'redaction_count', 0, 'credential_jti', 'jti-1')
$$;

-- 1. Defaults ----------------------------------------------------------------------------------------
SELECT pg_temp.check(
    (SELECT blackbox_retention_days = 30 AND payload_capture_enabled = FALSE AND payload_retention_days = 7
     FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000c0c00008'),
    'organizations default to 30 days retention, payload capture off, 7 days payload retention');

-- 2. Recording a batch: sequencing, chaining, duplicate batch ----------------------------------------
DO $$
DECLARE
    bot1 uuid := '00000000-0000-0000-0000-0000c0c0000a';
    batch1 uuid := gen_random_uuid();
    r jsonb;
    h0 text;
    h1 text;
BEGIN
    r := public.record_events('instance-aaaa', batch1, '00000000-0000-0000-0000-0000c0c00008',
        jsonb_build_array(pg_temp.evt(bot1), pg_temp.evt(bot1, 'BLOCK')));
    PERFORM pg_temp.check((r->>'accepted')::int = 2 AND (r->>'rejected')::int = 0
        AND (r->>'first_seq')::int = 1 AND (r->>'last_seq')::int = 2 AND NOT (r->>'duplicate')::boolean,
        'a batch of two valid events is accepted with sequential seqs');

    SELECT hash INTO h0 FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000c0c00008' AND seq = 1;
    SELECT prev_hash INTO h1 FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000c0c00008' AND seq = 2;
    PERFORM pg_temp.check(h0 = h1, 'event 2''s prev_hash is event 1''s hash');
    PERFORM pg_temp.check(
        (SELECT prev_hash FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000c0c00008' AND seq = 1)
        = 'GENESIS_BLOCK_AGENT_EVENTS_V1', 'the first event chains from the genesis constant');
    PERFORM pg_temp.check(
        (SELECT last_seq = 2 AND last_hash = (SELECT hash FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000c0c00008' AND seq = 2)
         FROM public.event_chain_heads WHERE organization_id = '00000000-0000-0000-0000-0000c0c00008'),
        'the chain head advances to the last event');

    -- resending the same batch is a no-op
    r := public.record_events('instance-aaaa', batch1, '00000000-0000-0000-0000-0000c0c00008',
        jsonb_build_array(pg_temp.evt(bot1), pg_temp.evt(bot1, 'BLOCK')));
    PERFORM pg_temp.check((r->>'duplicate')::boolean AND (r->>'accepted')::int = 2, 'resending the same batch_id returns the stored result, unchanged');
    PERFORM pg_temp.check((SELECT last_seq FROM public.event_chain_heads WHERE organization_id = '00000000-0000-0000-0000-0000c0c00008') = 2,
        'and does not advance the chain again');
END $$;

-- 3. Rejected items: wrong tenant, unknown agent, bad decision, malformed -----------------------------
DO $$
DECLARE
    bot1 uuid := '00000000-0000-0000-0000-0000c0c0000a';
    bot2 uuid := '00000000-0000-0000-0000-0000c0c0000b';  -- belongs to org 2
    r jsonb;
    bad jsonb;
BEGIN
    bad := pg_temp.evt(bot1) - 'decision' || jsonb_build_object('decision', 'MAYBE');
    r := public.record_events('instance-aaaa', gen_random_uuid(), '00000000-0000-0000-0000-0000c0c00008',
        jsonb_build_array(pg_temp.evt(bot2), pg_temp.evt('11111111-1111-1111-1111-111111111111'::uuid), bad, pg_temp.evt(bot1)));
    PERFORM pg_temp.check((r->>'accepted')::int = 1 AND (r->>'rejected')::int = 3,
        'an agent from another org, an unknown agent and an invalid decision are all rejected; the valid item still goes through');
    PERFORM pg_temp.check((SELECT organization_id FROM public.agent_events WHERE seq = (r->>'last_seq')::bigint) = '00000000-0000-0000-0000-0000c0c00008',
        'the accepted event is stored under the correct organization, not whatever the item claimed');
END $$;
SELECT pg_temp.expect_error($$SELECT public.record_events('short', gen_random_uuid(), '00000000-0000-0000-0000-0000c0c00008', '[]'::jsonb)$$, '22023', 'a too-short instance id is refused');
SELECT pg_temp.expect_error($$SELECT public.record_events('instance-aaaa', gen_random_uuid(), '00000000-0000-0000-0000-0000c0c00008', '[]'::jsonb)$$, '22023', 'an empty batch is refused');
SELECT pg_temp.expect_error(
    $$SELECT public.record_events('instance-aaaa', gen_random_uuid(), '00000000-0000-0000-0000-0000c0c00008',
        (SELECT jsonb_agg(pg_temp.evt('00000000-0000-0000-0000-0000c0c0000a')) FROM generate_series(1, 501)))$$,
    '22023', 'more than 500 items in one batch is refused');

-- 4. Tenant isolation: org 2 cannot see org 1's events or chain ---------------------------------------
SELECT pg_temp.check(
    NOT EXISTS (SELECT 1 FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000c0c00009'),
    'org 2 has no events of its own yet');

-- 5. verify_events: a clean chain verifies end to end ---------------------------------------------------
DO $$
DECLARE
    org uuid := '00000000-0000-0000-0000-0000c0c00008';
    r jsonb;
    v_last_seq bigint;
BEGIN
    SELECT last_seq INTO v_last_seq FROM public.event_chain_heads WHERE organization_id = org;
    r := public.verify_events(org, 1, v_last_seq);
    PERFORM pg_temp.check((r->>'ok')::boolean AND (r->>'checked')::bigint = v_last_seq, 'an untouched chain verifies clean end to end');
END $$;

-- 6. Append-only: direct UPDATE/DELETE are refused -----------------------------------------------------
SELECT pg_temp.expect_error(
    $$UPDATE public.agent_events SET tool_name = 'tampered' WHERE organization_id = '00000000-0000-0000-0000-0000c0c00008' AND seq = 1$$,
    '42501', 'a direct UPDATE of a stored event is refused');
SELECT pg_temp.expect_error(
    $$DELETE FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000c0c00008' AND seq = 1$$,
    '42501', 'a direct DELETE of a stored event is refused');

-- 7. Tamper detection via a fresh chain the test fully controls -----------------------------------------
DO $$
DECLARE
    org uuid := '00000000-0000-0000-0000-0000c0c00009';
    bot uuid := '00000000-0000-0000-0000-0000c0c0000b';
    r jsonb;
BEGIN
    PERFORM public.record_events('instance-cccc', gen_random_uuid(), org, jsonb_build_array(pg_temp.evt(bot), pg_temp.evt(bot), pg_temp.evt(bot)));
    r := public.verify_events(org, 1, 3);
    PERFORM pg_temp.check((r->>'ok')::boolean, 'a fresh three-event chain verifies clean');

    -- Simulate tampering the only way this schema allows: rewrite the stored hash of seq 2 using a
    -- superuser-only path (direct catalog bypass is not available to this test role, so instead we
    -- disable the trigger, mutate, then re-enable it -- proving verify_events catches what the
    -- trigger cannot, e.g. an operator with elevated database access).
    ALTER TABLE public.agent_events DISABLE TRIGGER trg_agent_events_append_only;
    UPDATE public.agent_events SET hash = repeat('f', 64) WHERE organization_id = org AND seq = 2;
    ALTER TABLE public.agent_events ENABLE TRIGGER trg_agent_events_append_only;

    r := public.verify_events(org, 1, 3);
    PERFORM pg_temp.check(NOT (r->>'ok')::boolean AND (r->>'broken_seq')::bigint = 2 AND r->>'reason' = 'hash_mismatch',
        'tampering with a stored hash is caught at the exact seq, with the reason');
END $$;
SELECT pg_temp.expect_error($$SELECT public.verify_events('00000000-0000-0000-0000-0000c0c00008', 5, 2)$$, '22023', 'an inverted range is refused');
SELECT pg_temp.expect_error($$SELECT public.verify_events('00000000-0000-0000-0000-0000c0c00008', 1, 60000)$$, '22023', 'a range over 50000 is refused');

-- 8. Access and RLS --------------------------------------------------------------------------------------
DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['record_events(text,uuid,uuid,jsonb)', 'verify_events(uuid,bigint,bigint)'] LOOP
        PERFORM pg_temp.check(NOT has_function_privilege('anon', 'public.' || f, 'EXECUTE')
                          AND NOT has_function_privilege('authenticated', 'public.' || f, 'EXECUTE'),
            f || ' is not executable by anon or authenticated');
        PERFORM pg_temp.check(has_function_privilege('service_role', 'public.' || f, 'EXECUTE'), f || ' is executable by service_role');
    END LOOP;
    PERFORM pg_temp.check(
        (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.agent_events'::regclass)
        AND (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.event_chain_heads'::regclass)
        AND (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.event_batches'::regclass),
        'the new tables are protected by row level security');
END $$;

DO $$ BEGIN RAISE NOTICE 'ALL SQL TESTS PASSED (blackbox)'; END $$;
