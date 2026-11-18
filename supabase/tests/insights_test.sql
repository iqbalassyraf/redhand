-- SQL tests for supabase/migrations/20261202000000_insights.sql (dashboard redesign S2): the organization-scoped, read-only insights summary.

\set ON_ERROR_STOP on
\set QUIET on

BEGIN;

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'CHECK FAILED: %', p_msg; END IF;
    RAISE NOTICE 'ok: %', p_msg;
END $$;

INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000a1500001', 'Insights A', 'insights-a'), ('00000000-0000-0000-0000-0000a1500002', 'Insights B', 'insights-b');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000a15000a1', '00000000-0000-0000-0000-0000a1500001', 'a-1', 'Agent A1'),
    ('00000000-0000-0000-0000-0000a15000a2', '00000000-0000-0000-0000-0000a1500001', 'a-2', 'Agent A2'),
    ('00000000-0000-0000-0000-0000a15000b1', '00000000-0000-0000-0000-0000a1500002', 'b-1', 'Agent B1');

-- Events written straight into the table (the chain fields are placeholders: this function never reads them).
CREATE FUNCTION pg_temp.ev(p_org uuid, p_agent uuid, p_seq bigint, p_at timestamptz, p_server text, p_tool text, p_decision text, p_reasons text[],
                           p_bytes int, p_latency numeric) RETURNS void LANGUAGE sql AS $$
    INSERT INTO public.agent_events (organization_id, agent_id, seq, occurred_at, gateway_instance, server, method, tool_name, decision, reasons,
                                     result_size_bytes, latency_ms, prev_hash, hash, batch_id)
    VALUES (p_org, p_agent, p_seq, p_at, 'gw-test-0001', p_server, 'tools/call', p_tool, p_decision, p_reasons, p_bytes, p_latency, 'p', 'h', gen_random_uuid())
$$;

-- Org A: window ends at a fixed "now" so bucket edges are exact. 12 five-minute buckets.
SELECT pg_temp.ev('00000000-0000-0000-0000-0000a1500001', '00000000-0000-0000-0000-0000a15000a1', 1, '2026-11-18 10:02:00+00', 'xero', 'list_invoices', 'ALLOW', '{}', 1000, 10);
SELECT pg_temp.ev('00000000-0000-0000-0000-0000a1500001', '00000000-0000-0000-0000-0000a15000a1', 2, '2026-11-18 10:03:00+00', 'xero', 'list_invoices', 'ALLOW', '{}', 3000, 30);
SELECT pg_temp.ev('00000000-0000-0000-0000-0000a1500001', '00000000-0000-0000-0000-0000a15000a1', 3, '2026-11-18 10:07:00+00', 'xero', 'delete_invoice', 'BLOCK', '{out_of_scope}', NULL, 1);
SELECT pg_temp.ev('00000000-0000-0000-0000-0000a1500001', '00000000-0000-0000-0000-0000a15000a2', 4, '2026-11-18 10:08:00+00', 'github', 'push', 'BLOCK', '{out_of_scope,safe_mode}', NULL, 1);
SELECT pg_temp.ev('00000000-0000-0000-0000-0000a1500001', '00000000-0000-0000-0000-0000a15000a2', 5, '2026-11-18 10:30:00+00', 'github', 'list_repos', 'ERROR', '{upstream_down}', NULL, NULL);
SELECT pg_temp.ev('00000000-0000-0000-0000-0000a1500001', '00000000-0000-0000-0000-0000a15000a2', 6, '2026-11-18 10:31:00+00', 'github', 'list_repos', 'ALLOW', '{}', 500, 20);
-- Outside the window (before and exactly at the end: the end is exclusive).
SELECT pg_temp.ev('00000000-0000-0000-0000-0000a1500001', '00000000-0000-0000-0000-0000a15000a1', 7, '2026-11-18 08:59:59+00', 'xero', 'list_invoices', 'ALLOW', '{}', 99999, 99999);
SELECT pg_temp.ev('00000000-0000-0000-0000-0000a1500001', '00000000-0000-0000-0000-0000a15000a1', 8, '2026-11-18 11:00:00+00', 'xero', 'list_invoices', 'ALLOW', '{}', 99999, 99999);
-- Org B: must never be counted for A.
SELECT pg_temp.ev('00000000-0000-0000-0000-0000a1500002', '00000000-0000-0000-0000-0000a15000b1', 1, '2026-11-18 10:05:00+00', 'other', 'secret_tool', 'BLOCK', '{honeytoken}', NULL, 5);

CREATE TEMP TABLE r AS SELECT public.insights_summary('00000000-0000-0000-0000-0000a1500001', '2026-11-18 10:00:00+00', '2026-11-18 11:00:00+00', 300) AS j;

SELECT pg_temp.check((SELECT (j -> 'totals' ->> 'decisions')::int = 6 AND (j -> 'totals' ->> 'allowed')::int = 3 AND (j -> 'totals' ->> 'refused')::int = 2
                             AND (j -> 'totals' ->> 'errors')::int = 1 FROM r), 'totals count the window only, split by decision (start inclusive, end exclusive)');
SELECT pg_temp.check((SELECT (j -> 'totals' ->> 'bytes_returned')::int = 4500 FROM r), 'bytes returned sum the allowed calls in the window');
SELECT pg_temp.check((SELECT jsonb_array_length(j -> 'series') = 13 FROM r), 'the series has one point per bucket, empty buckets included (12 buckets plus the one the end falls in)');
SELECT pg_temp.check((SELECT (j -> 'series' -> 0 ->> 'allowed')::int = 2 AND (j -> 'series' -> 0 ->> 'bytes')::int = 4000 AND j -> 'series' -> 0 ->> 'bucket_start' = '2026-11-18T10:00:00Z' FROM r),
    'the first bucket holds the two allowed calls of 10:02 and 10:03');
SELECT pg_temp.check((SELECT (j -> 'series' -> 1 ->> 'refused')::int = 2 AND (j -> 'series' -> 2 ->> 'allowed')::int = 0 FROM r), 'the 10:05 bucket holds both refusals; a quiet bucket is zero');
SELECT pg_temp.check((SELECT (SELECT sum((x ->> 'allowed')::int + (x ->> 'refused')::int + (x ->> 'errors')::int) FROM jsonb_array_elements(j -> 'series') x) = 6 FROM r), 'the series adds up to the total');
SELECT pg_temp.check((SELECT j -> 'agents' -> 0 ->> 'agent_id' = '00000000-0000-0000-0000-0000a15000a2' OR j -> 'agents' -> 0 ->> 'agent_id' = '00000000-0000-0000-0000-0000a15000a1' FROM r)
                     AND (SELECT jsonb_array_length(j -> 'agents') = 2 FROM r), 'two agents, org A only (B''s agent is absent)');
SELECT pg_temp.check((SELECT NOT (j::text LIKE '%a15000b1%') AND NOT (j::text LIKE '%secret_tool%') AND NOT (j::text LIKE '%honeytoken%') FROM r), 'nothing of organization B appears anywhere in A''s summary');
SELECT pg_temp.check((SELECT j -> 'reasons' -> 0 ->> 'reason' = 'out_of_scope' AND (j -> 'reasons' -> 0 ->> 'count')::int = 2 FROM r), 'reasons rank refusals and errors, most common first');
SELECT pg_temp.check((SELECT (SELECT count(*) FROM jsonb_array_elements(j -> 'reasons') x WHERE x ->> 'reason' = 'upstream_down') = 1 FROM r), 'error reasons are counted too');
SELECT pg_temp.check((SELECT (j -> 'latency' ->> 'samples')::int = 3 AND (j -> 'latency' ->> 'p50_ms')::numeric = 20.00 FROM r), 'latency percentiles use allowed calls with a latency (10, 20, 30: p50 = 20)');
SELECT pg_temp.check((SELECT j -> 'tools' -> 0 ->> 'tool' = 'list_invoices' AND (j -> 'tools' -> 0 ->> 'calls')::int = 2 FROM r), 'tools are ranked by calls');
SELECT pg_temp.check((SELECT (SELECT count(*) FROM jsonb_array_elements(j -> 'flow')) >= 3 FROM r), 'the flow lists agent, server and outcome rows for the top agents');

-- Empty organization and empty window: zeros, never an error and never another tenant's rows.
SELECT pg_temp.check((public.insights_summary('00000000-0000-0000-0000-0000a1500001', '2026-01-01 00:00:00+00', '2026-01-01 01:00:00+00', 300) -> 'totals' ->> 'decisions')::int = 0,
    'an empty window gives zero decisions');
SELECT pg_temp.check((public.insights_summary(gen_random_uuid(), '2026-11-18 10:00:00+00', '2026-11-18 11:00:00+00', 300) -> 'totals' ->> 'decisions')::int = 0,
    'an unknown organization gives zero decisions');
SELECT pg_temp.check((public.insights_summary('00000000-0000-0000-0000-0000a1500001', '2026-01-01 00:00:00+00', '2026-01-01 01:00:00+00', 300) -> 'latency' ->> 'p50_ms') IS NULL,
    'no allowed calls means no latency figure (null, not zero)');

-- Bounds.
DO $$ BEGIN
    BEGIN PERFORM public.insights_summary('00000000-0000-0000-0000-0000a1500001', '2026-11-18 10:00:00+00', '2026-11-18 11:00:00+00', 10);
        RAISE EXCEPTION 'a 10 second bucket was accepted'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
    BEGIN PERFORM public.insights_summary('00000000-0000-0000-0000-0000a1500001', '2026-11-18 11:00:00+00', '2026-11-18 10:00:00+00', 300);
        RAISE EXCEPTION 'an inverted window was accepted'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
    BEGIN PERFORM public.insights_summary('00000000-0000-0000-0000-0000a1500001', '2026-11-01 00:00:00+00', '2026-11-18 00:00:00+00', 86400);
        RAISE EXCEPTION 'a 17 day window was accepted'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
    BEGIN PERFORM public.insights_summary('00000000-0000-0000-0000-0000a1500001', '2026-11-12 00:00:00+00', '2026-11-18 00:00:00+00', 60);
        RAISE EXCEPTION 'more than 60 buckets were accepted'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
    BEGIN PERFORM public.insights_summary(NULL, '2026-11-18 10:00:00+00', '2026-11-18 11:00:00+00', 300);
        RAISE EXCEPTION 'a null organization was accepted'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
END $$;
SELECT pg_temp.check(true, 'a tiny bucket, an inverted window, a window over 8 days, more than 60 buckets and a null organization are refused');

-- Read only: calling it changed nothing.
SELECT pg_temp.check((SELECT count(*) FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000a1500001') = 8, 'the summary wrote nothing');

-- Access: callers other than service_role cannot run it.
SELECT pg_temp.check(NOT has_function_privilege('anon', 'public.insights_summary(uuid, timestamptz, timestamptz, integer)', 'EXECUTE')
                     AND NOT has_function_privilege('authenticated', 'public.insights_summary(uuid, timestamptz, timestamptz, integer)', 'EXECUTE')
                     AND has_function_privilege('service_role', 'public.insights_summary(uuid, timestamptz, timestamptz, integer)', 'EXECUTE'),
    'only service_role may call the summary');

DO $$ BEGIN RAISE NOTICE 'ALL SQL TESTS PASSED'; END $$;
ROLLBACK;
