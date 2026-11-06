-- SQL tests for supabase/migrations/20261114000000_blackbox_clear_payloads.sql (Phase 3 M2c).

\set ON_ERROR_STOP on
\set QUIET on

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'CHECK FAILED: %', p_msg; END IF;
    RAISE NOTICE 'ok: %', p_msg;
END $$;

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000c1ea0a01');
INSERT INTO public.organizations (id, name, slug, payload_capture_enabled) VALUES
    ('00000000-0000-0000-0000-0000c1ea0001', 'Clear Org A', 'clear-org-a', true),
    ('00000000-0000-0000-0000-0000c1ea0002', 'Clear Org B', 'clear-org-b', true);
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000c1ea000a', '00000000-0000-0000-0000-0000c1ea0001', 'clr-bot-a', 'Clr A'),
    ('00000000-0000-0000-0000-0000c1ea000b', '00000000-0000-0000-0000-0000c1ea0002', 'clr-bot-b', 'Clr B');

CREATE FUNCTION pg_temp.evt(p_agent uuid) RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'agent_id', p_agent, 'occurred_at', now(), 'gateway_instance', 'instance-clear',
        'server', 'fs', 'method', 'tools/call', 'tool_name', 'read_file', 'decision', 'ALLOW',
        'reasons', '[]'::jsonb, 'upstream_status', 200, 'latency_ms', 1.5,
        'argument_keys', jsonb_build_array('path'), 'arguments_sha256', repeat('e', 64),
        'result_size_bytes', 10, 'redaction_count', 0, 'credential_jti', 'jti-c',
        'arguments_redacted', jsonb_build_object('text', '{"a":1}', 'truncated', false, 'original_bytes', 7),
        'result_excerpt', jsonb_build_object('text', 'ok', 'truncated', false, 'original_bytes', 2))
$$;

DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-0000c1ea0001';
    b uuid := '00000000-0000-0000-0000-0000c1ea0002';
    actor uuid := '00000000-0000-0000-0000-0000c1ea0a01';
    r jsonb;
    v jsonb;
BEGIN
    PERFORM public.record_events('instance-clear', gen_random_uuid(), a, jsonb_build_array(pg_temp.evt('00000000-0000-0000-0000-0000c1ea000a'), pg_temp.evt('00000000-0000-0000-0000-0000c1ea000a')));
    PERFORM public.record_events('instance-clear', gen_random_uuid(), b, jsonb_build_array(pg_temp.evt('00000000-0000-0000-0000-0000c1ea000b')));

    r := public.control_clear_payloads(a, actor, 'test');
    PERFORM pg_temp.check((r->>'cleared')::int = 2, 'clears every payload of the organization');
    PERFORM pg_temp.check((SELECT count(*) FROM public.agent_events WHERE organization_id = a AND (arguments_redacted IS NOT NULL OR result_excerpt IS NOT NULL)) = 0, 'no payload remains');
    PERFORM pg_temp.check((SELECT count(*) FROM public.agent_events WHERE organization_id = a) = 2, 'the events themselves stay');
    PERFORM pg_temp.check((SELECT count(*) FROM public.agent_events WHERE organization_id = b AND arguments_redacted IS NOT NULL) = 1, 'another organization is untouched');
    v := public.verify_events(a, 1, (SELECT max(seq) FROM public.agent_events WHERE organization_id = a));
    PERFORM pg_temp.check((v->>'ok')::boolean, 'the hash chain still verifies');
    PERFORM pg_temp.check((SELECT details->>'events_cleared' = '2' AND actor_user_id = actor AND details::text NOT LIKE '%ok%'
        FROM public.control_audit_log WHERE action = 'organization.blackbox_payloads_cleared' AND organization_id = a),
        'audited with the count and no content');

    r := public.control_clear_payloads(a, actor, 'again');
    PERFORM pg_temp.check((r->>'cleared')::int = 0 AND (SELECT count(*) FROM public.control_audit_log
        WHERE action = 'organization.blackbox_payloads_cleared' AND organization_id = a) = 1, 'repeating clears nothing and is not audited again');
END $$;

SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.control_clear_payloads(uuid,uuid,text)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.control_clear_payloads(uuid,uuid,text)', 'EXECUTE'), 'service_role only');

\echo ALL SQL TESTS PASSED
