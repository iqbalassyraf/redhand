-- SQL tests for supabase/migrations/20261123000000_behaviour_baseline.sql (Phase 4.5 B2, behaviour baseline).

\set ON_ERROR_STOP on
\set QUIET on

-- The SQL tests share one database: this file runs inside a transaction that is rolled back at the end.
BEGIN;

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'CHECK FAILED: %', p_msg; END IF;
    RAISE NOTICE 'ok: %', p_msg;
END $$;

INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-000050000001', 'Behaviour Org A', 'behaviour-org-a'),
    ('00000000-0000-0000-0000-000050000002', 'Behaviour Org B', 'behaviour-org-b');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-00005000000a', '00000000-0000-0000-0000-000050000001', 'beh-bot-a', 'Beh Bot A'),
    ('00000000-0000-0000-0000-00005000000b', '00000000-0000-0000-0000-000050000002', 'beh-bot-b', 'Beh Bot B');

CREATE FUNCTION pg_temp.event(p_agent uuid, p_seq bigint, p_at timestamptz, p_method text, p_tool text, p_decision text) RETURNS void
LANGUAGE sql AS $$
    INSERT INTO public.agent_events (organization_id, agent_id, seq, occurred_at, gateway_instance, method, tool_name, decision, prev_hash, hash, batch_id)
    SELECT g.organization_id, p_agent, p_seq, p_at, 'test', p_method, p_tool, p_decision, 'x', 'y', gen_random_uuid()
    FROM public.agents g WHERE g.id = p_agent
$$;

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The trigger: tool calls only, grouped per agent, hour and tool, refusals counted, hour truncated in UTC whatever the session says.
SET LOCAL timezone = 'Asia/Kolkata';  -- +05:30: truncating in the session's zone would give a half-hour, not a UTC hour
SELECT pg_temp.event('00000000-0000-0000-0000-00005000000a', 800001, '2026-11-13 16:05+00', 'tools/call', 'read_ticket', 'ALLOW');
SELECT pg_temp.event('00000000-0000-0000-0000-00005000000a', 800002, '2026-11-13 16:40+00', 'tools/call', 'read_ticket', 'BLOCK');
SELECT pg_temp.event('00000000-0000-0000-0000-00005000000a', 800003, '2026-11-13 16:59+00', 'tools/call', 'read_ticket', 'ALLOW');
SELECT pg_temp.event('00000000-0000-0000-0000-00005000000a', 800004, '2026-11-13 16:10+00', 'tools/call', 'send_email', 'ALLOW');
SELECT pg_temp.event('00000000-0000-0000-0000-00005000000a', 800005, '2026-11-13 17:00+00', 'tools/call', 'read_ticket', 'ALLOW');
SELECT pg_temp.event('00000000-0000-0000-0000-00005000000a', 800006, '2026-11-13 16:20+00', 'tools/list', '', 'ALLOW');
SELECT pg_temp.event('00000000-0000-0000-0000-00005000000a', 800007, '2026-11-13 16:21+00', 'initialize', '', 'ALLOW');
SELECT pg_temp.event('00000000-0000-0000-0000-00005000000b', 800008, '2026-11-13 16:30+00', 'tools/call', 'read_ticket', 'ALLOW');
RESET timezone;

SELECT pg_temp.check((SELECT calls = 3 AND refused = 1 FROM public.agent_tool_hourly
                      WHERE agent_id = '00000000-0000-0000-0000-00005000000a' AND tool_name = 'read_ticket' AND hour = '2026-11-13 16:00+00'),
    'three calls to one tool in one UTC hour are one row (3 calls, 1 refused), even with the session in Asia/Kolkata');
SELECT pg_temp.check((SELECT calls = 1 FROM public.agent_tool_hourly
                      WHERE agent_id = '00000000-0000-0000-0000-00005000000a' AND tool_name = 'read_ticket' AND hour = '2026-11-13 17:00+00'),
    'the next hour is its own row');
SELECT pg_temp.check((SELECT calls = 1 AND refused = 0 FROM public.agent_tool_hourly
                      WHERE agent_id = '00000000-0000-0000-0000-00005000000a' AND tool_name = 'send_email'), 'another tool is its own row');
SELECT pg_temp.check((SELECT count(*) FROM public.agent_tool_hourly WHERE agent_id = '00000000-0000-0000-0000-00005000000a') = 3,
    'tools/list and initialize are not counted');
SELECT pg_temp.check((SELECT sum(calls) FROM public.agent_tool_hourly WHERE agent_id = '00000000-0000-0000-0000-00005000000a')
                   = (SELECT count(*) FROM public.agent_events WHERE agent_id = '00000000-0000-0000-0000-00005000000a' AND method = 'tools/call'),
    'the roll-up adds up to the Black Box');
SELECT pg_temp.check((SELECT bool_and(hour = date_trunc('hour', hour, 'UTC')) FROM public.agent_tool_hourly), 'every hour is a whole UTC hour');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The read function: organization-scoped, bounded by time.
SELECT pg_temp.check((SELECT count(*) FROM public.agent_behaviour_hours('00000000-0000-0000-0000-000050000001', NULL,
                      '2026-11-13 00:00+00', '2026-11-14 00:00+00')) = 3, 'organization A reads its three rows');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_behaviour_hours('00000000-0000-0000-0000-000050000001', NULL,
                      '2026-11-13 00:00+00', '2026-11-14 00:00+00') WHERE agent_id = '00000000-0000-0000-0000-00005000000b'),
    'organization A never sees B''s agent');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_behaviour_hours('00000000-0000-0000-0000-000050000001',
                      '00000000-0000-0000-0000-00005000000b', '2026-11-13 00:00+00', '2026-11-14 00:00+00')),
    'asking organization A for B''s agent by id returns nothing');
SELECT pg_temp.check((SELECT count(*) FROM public.agent_behaviour_hours('00000000-0000-0000-0000-000050000001',
                      '00000000-0000-0000-0000-00005000000a', '2026-11-13 16:30+00', '2026-11-13 17:00+00')) = 1,
    'p_since and p_until bound the hours (16:00 is before 16:30, 17:00 is included)');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The purge: older than 35 days goes, the rest stays.
INSERT INTO public.agent_tool_hourly (organization_id, agent_id, hour, tool_name, calls) VALUES
    ('00000000-0000-0000-0000-000050000001', '00000000-0000-0000-0000-00005000000a', date_trunc('hour', now() - interval '40 days', 'UTC'), 'old', 1),
    ('00000000-0000-0000-0000-000050000001', '00000000-0000-0000-0000-00005000000a', date_trunc('hour', now() - interval '20 days', 'UTC'), 'kept', 1);
SELECT pg_temp.check(public.purge_behaviour() >= 1, 'the purge deletes old hours');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_tool_hourly WHERE tool_name = 'old')
                 AND EXISTS (SELECT 1 FROM public.agent_tool_hourly WHERE tool_name = 'kept'), 'only hours older than 35 days are purged');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Integrity: a half hour or more refusals than calls is refused by the table itself.
DO $$
BEGIN
    BEGIN
        INSERT INTO public.agent_tool_hourly (organization_id, agent_id, hour, tool_name, calls)
        VALUES ('00000000-0000-0000-0000-000050000001', '00000000-0000-0000-0000-00005000000a', '2026-11-13 16:30+00', 'x', 1);
        RAISE EXCEPTION 'CHECK FAILED: a half-hour row was accepted';
    EXCEPTION WHEN check_violation THEN RAISE NOTICE 'ok: a row must sit on a whole hour';
    END;
    BEGIN
        INSERT INTO public.agent_tool_hourly (organization_id, agent_id, hour, tool_name, calls, refused)
        VALUES ('00000000-0000-0000-0000-000050000001', '00000000-0000-0000-0000-00005000000a', '2026-11-13 18:00+00', 'x', 1, 2);
        RAISE EXCEPTION 'CHECK FAILED: more refusals than calls was accepted';
    EXCEPTION WHEN check_violation THEN RAISE NOTICE 'ok: refusals never exceed calls';
    END;
END $$;

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Grants: the service role only; the table is not readable through the signed-in role.
SELECT pg_temp.check(has_function_privilege('service_role', 'public.agent_behaviour_hours(uuid, uuid, timestamptz, timestamptz)', 'EXECUTE')
                 AND has_function_privilege('service_role', 'public.purge_behaviour()', 'EXECUTE'), 'the service role can call the functions');
SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.agent_behaviour_hours(uuid, uuid, timestamptz, timestamptz)', 'EXECUTE')
                 AND NOT has_function_privilege('anon', 'public.purge_behaviour()', 'EXECUTE'), 'signed-in users and anon cannot');
SELECT pg_temp.check((SELECT relrowsecurity FROM pg_class WHERE oid = 'public.agent_tool_hourly'::regclass), 'row level security is on');

ROLLBACK;
