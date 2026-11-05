-- SQL tests for supabase/migrations/20261111000000_blackbox_retention.sql (Phase 3 M2a).
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

-- Ages events (received_at is not covered by the hash, so the chain stays valid). Only a test, running
-- as the database owner, can do this: the application cannot (the trigger refuses it, as checked below).
CREATE FUNCTION pg_temp.age_events(p_org uuid, p_seqs bigint[], p_days integer) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    ALTER TABLE public.agent_events DISABLE TRIGGER trg_agent_events_append_only;
    UPDATE public.agent_events SET received_at = now() - make_interval(days => p_days)
    WHERE organization_id = p_org AND seq = ANY (p_seqs);
    ALTER TABLE public.agent_events ENABLE TRIGGER trg_agent_events_append_only;
END $$;

CREATE FUNCTION pg_temp.evt(p_agent uuid, p_tool text DEFAULT 'read_file') RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'agent_id', p_agent, 'occurred_at', now(), 'gateway_instance', 'instance-rrrr',
        'server', 'fs', 'method', 'tools/call', 'tool_name', p_tool, 'decision', 'ALLOW',
        'reasons', '[]'::jsonb, 'upstream_status', 200, 'latency_ms', 1.5,
        'argument_keys', jsonb_build_array('path'), 'arguments_sha256', repeat('b', 64),
        'result_size_bytes', 100, 'redaction_count', 0, 'credential_jti', 'jti-r')
$$;

-- Fixtures: organization A with 5 events, organization B with 2 ---------------------------------------
INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000c0c0d0a1');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000c0c0d001', 'Retention Org A', 'retention-org-a'),
    ('00000000-0000-0000-0000-0000c0c0d002', 'Retention Org B', 'retention-org-b');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000c0c0d00a', '00000000-0000-0000-0000-0000c0c0d001', 'ret-bot-a', 'Ret Bot A'),
    ('00000000-0000-0000-0000-0000c0c0d00b', '00000000-0000-0000-0000-0000c0c0d002', 'ret-bot-b', 'Ret Bot B');
SELECT public.record_events('instance-rrrr', gen_random_uuid(), '00000000-0000-0000-0000-0000c0c0d001',
    jsonb_build_array(pg_temp.evt('00000000-0000-0000-0000-0000c0c0d00a'), pg_temp.evt('00000000-0000-0000-0000-0000c0c0d00a'),
                      pg_temp.evt('00000000-0000-0000-0000-0000c0c0d00a')));
SELECT public.record_events('instance-rrrr', gen_random_uuid(), '00000000-0000-0000-0000-0000c0c0d001',
    jsonb_build_array(pg_temp.evt('00000000-0000-0000-0000-0000c0c0d00a'), pg_temp.evt('00000000-0000-0000-0000-0000c0c0d00a')));
SELECT public.record_events('instance-rrrr', gen_random_uuid(), '00000000-0000-0000-0000-0000c0c0d002',
    jsonb_build_array(pg_temp.evt('00000000-0000-0000-0000-0000c0c0d00b'), pg_temp.evt('00000000-0000-0000-0000-0000c0c0d00b')));
SELECT pg_temp.check(
    (SELECT count(*) FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d001') = 5,
    'fixtures: organization A has five events');

-- 1. What the trigger still refuses -------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $$DELETE FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d001' AND seq = 5$$,
    '42501', 'an event ahead of the anchor cannot be deleted');
SELECT pg_temp.expect_error(
    $$UPDATE public.agent_events SET tool_name = 'x' WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d001' AND seq = 5$$,
    '42501', 'a stored field cannot be changed');
SELECT pg_temp.expect_error(
    $$UPDATE public.agent_events SET received_at = now() - interval '400 days' WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d001' AND seq = 5$$,
    '42501', 'an event cannot be aged by the application to get it purged');
SELECT pg_temp.expect_error(
    $$UPDATE public.agent_events SET arguments_redacted = '{"a": 1}' WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d001' AND seq = 5$$,
    '42501', 'a payload cannot be written after the event was stored');
SELECT pg_temp.expect_error(
    $$UPDATE public.agent_events SET result_excerpt = NULL, tool_name = 'y' WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d001' AND seq = 5$$,
    '42501', 'clearing a payload cannot be combined with any other change');

-- 2. The anchor guard ---------------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $$UPDATE public.event_chain_heads SET anchor_seq = 2,
        anchor_prev_hash = (SELECT hash FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d001' AND seq = 2)
      WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d001'$$,
    '42501', 'the anchor cannot move onto an event younger than the retention period');

-- 3. Purge: nothing old yet ---------------------------------------------------------------------------
DO $$
DECLARE r jsonb;
BEGIN
    r := public.purge_events();
    PERFORM pg_temp.check((r->>'events_deleted')::int = 0, 'a purge with no old events deletes nothing');
    PERFORM pg_temp.check(
        (SELECT anchor_seq FROM public.event_chain_heads WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d001') = 0,
        'the anchor does not move when nothing is old');
END $$;

-- 4. Purge a prefix: events 1, 2 and 4 are old, 3 is not, so only 1 and 2 go -------------------------
SELECT pg_temp.age_events('00000000-0000-0000-0000-0000c0c0d001', ARRAY[1, 2, 4]::bigint[], 40);
SELECT pg_temp.expect_error(
    $$UPDATE public.event_chain_heads SET anchor_seq = 2, anchor_prev_hash = repeat('0', 64)
      WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d001'$$,
    '42501', 'the anchor must record the real hash of the event it points at');
DO $$
DECLARE
    org uuid := '00000000-0000-0000-0000-0000c0c0d001';
    r jsonb;
    v jsonb;
BEGIN
    r := public.purge_events();
    PERFORM pg_temp.check((r->>'events_deleted')::int = 2 AND (r->>'organizations_purged')::int = 1,
        'old events are purged: two deleted, one organization');
    PERFORM pg_temp.check(
        (SELECT anchor_seq FROM public.event_chain_heads WHERE organization_id = org) = 2,
        'the anchor stops before the first event still within retention (seq 4 is old but seq 3 is not)');
    PERFORM pg_temp.check(
        (SELECT array_agg(seq ORDER BY seq) FROM public.agent_events WHERE organization_id = org) = ARRAY[3, 4, 5]::bigint[],
        'events 3 to 5 are kept');
    v := public.verify_events(org, 3, 5);
    PERFORM pg_temp.check((v->>'ok')::boolean AND (v->>'checked')::int = 3, 'the kept range still verifies from the anchor');
    PERFORM pg_temp.check(
        (SELECT count(*) FROM public.control_audit_log
         WHERE organization_id = org AND action = 'organization.blackbox_purged'
           AND actor_user_id = '00000000-0000-0000-0000-000000000000'
           AND details->>'new_anchor_seq' = '2' AND details->>'events_deleted' = '2') = 1,
        'the purge is audited under the system actor, with the anchor move and the count');
    PERFORM pg_temp.check(
        (SELECT count(*) FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d002') = 2
        AND (SELECT anchor_seq FROM public.event_chain_heads WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d002') = 0,
        'another organization is untouched');
    r := public.purge_events();
    PERFORM pg_temp.check((r->>'events_deleted')::int = 0, 'running the purge again changes nothing');
END $$;
SELECT pg_temp.expect_error(
    $$UPDATE public.event_chain_heads SET anchor_seq = 1,
        anchor_prev_hash = 'GENESIS_BLOCK_AGENT_EVENTS_V1' WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d001'$$,
    '42501', 'the anchor cannot move backwards');

-- 5. Batched: at most p_max_events_per_org per run, the next run continues -----------------------------
SELECT pg_temp.age_events('00000000-0000-0000-0000-0000c0c0d001', ARRAY[3]::bigint[], 40);
DO $$
DECLARE org uuid := '00000000-0000-0000-0000-0000c0c0d001';
BEGIN
    PERFORM public.purge_events(1);
    PERFORM pg_temp.check((SELECT anchor_seq FROM public.event_chain_heads WHERE organization_id = org) = 3,
        'a capped run moves the anchor by at most the cap');
    PERFORM public.purge_events(1);
    PERFORM pg_temp.check((SELECT anchor_seq FROM public.event_chain_heads WHERE organization_id = org) = 4,
        'the next run continues where the last one stopped');
    PERFORM pg_temp.check((public.verify_events(org, 5, 5)->>'ok')::boolean, 'the last kept event still verifies');
END $$;
SELECT pg_temp.expect_error($$SELECT public.purge_events(0)$$, '22023', 'a zero cap is refused');

-- 6. Payload retention: payloads are cleared, the event and the chain stay ------------------------------
DO $$
DECLARE org uuid := '00000000-0000-0000-0000-0000c0c0d001';
BEGIN
    -- Simulates an event captured with a payload 10 days ago (payload capture itself is M2b).
    ALTER TABLE public.agent_events DISABLE TRIGGER trg_agent_events_append_only;
    UPDATE public.agent_events SET arguments_redacted = '{"path": "/tmp/x"}', result_excerpt = '{"ok": true}',
        received_at = now() - interval '10 days'
    WHERE organization_id = org AND seq = 5;
    ALTER TABLE public.agent_events ENABLE TRIGGER trg_agent_events_append_only;
    PERFORM public.purge_events();
    PERFORM pg_temp.check(
        (SELECT arguments_redacted IS NULL AND result_excerpt IS NULL FROM public.agent_events WHERE organization_id = org AND seq = 5),
        'payloads older than the payload retention are cleared');
    PERFORM pg_temp.check((SELECT count(*) FROM public.agent_events WHERE organization_id = org AND seq = 5) = 1,
        'the event itself is kept while within the event retention');
    PERFORM pg_temp.check((public.verify_events(org, 5, 5)->>'ok')::boolean, 'clearing a payload does not break the chain');
END $$;

-- 7. Old batch ids are dropped --------------------------------------------------------------------------
DO $$
DECLARE n integer;
BEGIN
    UPDATE public.event_batches SET received_at = now() - interval '3 days'
    WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d002';
    PERFORM public.purge_events();
    SELECT count(*) INTO n FROM public.event_batches WHERE organization_id = '00000000-0000-0000-0000-0000c0c0d002';
    PERFORM pg_temp.check(n = 0, 'batch ids older than two days are dropped');
END $$;

-- 8. control_blackbox_retention -----------------------------------------------------------------------
DO $$
DECLARE
    org uuid := '00000000-0000-0000-0000-0000c0c0d001';
    actor uuid := '00000000-0000-0000-0000-0000c0c0d0a1';
    r jsonb;
BEGIN
    r := public.control_blackbox_retention(org, actor, 14, 3, 'shorter', 30, 1);
    PERFORM pg_temp.check((r->>'conflict')::boolean, 'a stale expected value is a conflict and changes nothing');
    r := public.control_blackbox_retention(org, actor, 30, 7, 'same', 30, 7);
    PERFORM pg_temp.check(NOT (r->>'changed')::boolean, 'setting the current values changes nothing');
    r := public.control_blackbox_retention(org, actor, 14, 3, 'shorter', 30, 7);
    PERFORM pg_temp.check((r->>'changed')::boolean
        AND (SELECT blackbox_retention_days = 14 AND payload_retention_days = 3 FROM public.organizations WHERE id = org),
        'the retention periods are changed');
    PERFORM pg_temp.check(
        (SELECT count(*) FROM public.control_audit_log
         WHERE organization_id = org AND action = 'organization.blackbox_retention_changed' AND actor_user_id = actor
           AND details->>'old_retention_days' = '30' AND details->>'new_retention_days' = '14') = 1,
        'the change is audited once, with old and new values');
    PERFORM pg_temp.check(
        (SELECT blackbox_retention_days FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000c0c0d002') = 30,
        'another organization keeps its retention');
END $$;
SELECT pg_temp.expect_error(
    $$SELECT public.control_blackbox_retention('00000000-0000-0000-0000-0000c0c0d001', '00000000-0000-0000-0000-0000c0c0d0a1', 5, 3, NULL, 14, 3)$$,
    '23514', 'a retention below 7 days is refused');
SELECT pg_temp.expect_error(
    $$SELECT public.control_blackbox_retention('00000000-0000-0000-0000-0000c0c0d0ff', '00000000-0000-0000-0000-0000c0c0d0a1', 30, 7, NULL, 30, 7)$$,
    'P0002', 'an unknown organization is not found');

-- 9. Access ---------------------------------------------------------------------------------------------
DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['purge_events(integer)',
                             'control_blackbox_retention(uuid,uuid,integer,integer,text,integer,integer)'] LOOP
        PERFORM pg_temp.check(NOT has_function_privilege('anon', 'public.' || f, 'EXECUTE')
                          AND NOT has_function_privilege('authenticated', 'public.' || f, 'EXECUTE'),
            f || ' is not executable by anon or authenticated');
        PERFORM pg_temp.check(has_function_privilege('service_role', 'public.' || f, 'EXECUTE'), f || ' is executable by service_role');
    END LOOP;
END $$;

DO $$ BEGIN RAISE NOTICE 'ALL SQL TESTS PASSED (blackbox_retention)'; END $$;
