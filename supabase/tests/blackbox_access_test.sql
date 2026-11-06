-- SQL tests for supabase/migrations/20261113000000_blackbox_access.sql (Phase 3 M2c).
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

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000acce5a01');
INSERT INTO public.organizations (id, name, slug, payload_capture_enabled) VALUES
    ('00000000-0000-0000-0000-0000acce5001', 'Access Org A', 'access-org-a', true),
    ('00000000-0000-0000-0000-0000acce5002', 'Access Org B', 'access-org-b', false);
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000acce500a', '00000000-0000-0000-0000-0000acce5001', 'acc-bot-a', 'Acc Bot A');

DO $$
DECLARE
    org uuid := '00000000-0000-0000-0000-0000acce5001';
    other uuid := '00000000-0000-0000-0000-0000acce5002';
    actor uuid := '00000000-0000-0000-0000-0000acce5a01';
    seq1 bigint;
    r jsonb;
    audits_before int;
BEGIN
    PERFORM public.record_events('instance-acces', gen_random_uuid(), org, jsonb_build_array(jsonb_build_object(
        'agent_id', '00000000-0000-0000-0000-0000acce500a', 'occurred_at', now(), 'gateway_instance', 'instance-acces',
        'server', 'fs', 'method', 'tools/call', 'tool_name', 'read_file', 'decision', 'ALLOW',
        'reasons', '[]'::jsonb, 'upstream_status', 200, 'latency_ms', 1.5,
        'argument_keys', jsonb_build_array('path'), 'arguments_sha256', repeat('d', 64),
        'result_size_bytes', 10, 'redaction_count', 0, 'credential_jti', 'jti-a',
        'arguments_redacted', jsonb_build_object('text', '{"path":"/x"}', 'truncated', false, 'original_bytes', 13))));
    SELECT max(seq) INTO seq1 FROM public.agent_events WHERE organization_id = org;

    -- 1. A read returns the payload and writes exactly one audit row, atomically.
    SELECT count(*) INTO audits_before FROM public.control_audit_log WHERE action = 'organization.blackbox_payload_viewed';
    r := public.read_event_payload(org, actor, seq1);
    PERFORM pg_temp.check((r->>'found')::boolean AND r->'arguments_redacted'->>'text' = '{"path":"/x"}',
        'read_event_payload returns the stored payload');
    PERFORM pg_temp.check((SELECT count(*) FROM public.control_audit_log
        WHERE action = 'organization.blackbox_payload_viewed') = audits_before + 1, 'the read wrote one audit row');
    PERFORM pg_temp.check((SELECT details->>'seq' = seq1::text AND (details->>'had_arguments')::boolean
        AND NOT (details->>'had_result')::boolean AND actor_user_id = actor AND organization_id = org
        FROM public.control_audit_log WHERE action = 'organization.blackbox_payload_viewed'
        ORDER BY created_at DESC, id DESC LIMIT 1), 'the audit row names the actor, event and what it held');
    PERFORM pg_temp.check(NOT (SELECT details::text LIKE '%/x%' FROM public.control_audit_log
        WHERE action = 'organization.blackbox_payload_viewed' ORDER BY created_at DESC, id DESC LIMIT 1),
        'the audit row never contains payload text');

    -- 2. Tenant scope: another organization cannot read it, and a miss writes no audit row.
    audits_before := (SELECT count(*) FROM public.control_audit_log WHERE action = 'organization.blackbox_payload_viewed');
    r := public.read_event_payload(other, actor, seq1);
    PERFORM pg_temp.check(NOT (r->>'found')::boolean AND r->'arguments_redacted' IS NULL, 'another organization gets nothing');
    r := public.read_event_payload(org, actor, seq1 + 1000);
    PERFORM pg_temp.check(NOT (r->>'found')::boolean, 'a missing seq is not found');
    PERFORM pg_temp.check((SELECT count(*) FROM public.control_audit_log
        WHERE action = 'organization.blackbox_payload_viewed') = audits_before, 'a miss writes no audit row');

    -- 3. Input checks.
    PERFORM pg_temp.expect_error(format('SELECT public.read_event_payload(%L, %L, 0)', org, actor), '22023', 'seq must be positive');
    PERFORM pg_temp.expect_error(format('SELECT public.read_event_payload(NULL, %L, 1)', actor), '22023', 'organization required');

    -- 4. Export audit.
    PERFORM public.audit_blackbox_export(org, actor, jsonb_build_object('format', 'jsonl', 'include_payloads', true));
    PERFORM pg_temp.check((SELECT details->>'format' = 'jsonl' FROM public.control_audit_log
        WHERE action = 'organization.blackbox_exported' AND organization_id = org), 'export audit row written');
    PERFORM pg_temp.expect_error(format('SELECT public.audit_blackbox_export(%L, %L, ''[]''::jsonb)', org, actor), '22023', 'details must be an object');
    PERFORM pg_temp.expect_error(format('SELECT public.audit_blackbox_export(%L, %L, ''{}''::jsonb)', gen_random_uuid(), actor), 'P0002', 'unknown organization');
END $$;

-- 5. Only service_role may call them.
SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.read_event_payload(uuid,uuid,bigint)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.read_event_payload(uuid,uuid,bigint)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.read_event_payload(uuid,uuid,bigint)', 'EXECUTE'),
    'read_event_payload is service_role only');
SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.audit_blackbox_export(uuid,uuid,jsonb)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.audit_blackbox_export(uuid,uuid,jsonb)', 'EXECUTE'),
    'audit_blackbox_export is service_role only');

\echo ALL SQL TESTS PASSED
