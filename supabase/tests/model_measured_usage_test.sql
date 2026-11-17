-- SQL tests for supabase/migrations/20261201000000_model_measured_usage.sql (Phase 4.5 B5b: usage the proxy measured, reported by the gateway).

\set ON_ERROR_STOP on
\set QUIET on

BEGIN;

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'CHECK FAILED: %', p_msg; END IF;
    RAISE NOTICE 'ok: %', p_msg;
END $$;
CREATE FUNCTION pg_temp.row(p_agent uuid, p_model text, p_calls int, p_in bigint, p_out bigint, p_nousage int DEFAULT 0, p_at timestamptz DEFAULT now()) RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object('agent_id', p_agent, 'provider', 'anthropic', 'model', p_model, 'calls', p_calls, 'input_tokens', p_in, 'output_tokens', p_out,
                              'calls_without_usage', p_nousage, 'occurred_at', p_at)
$$;

INSERT INTO public.organizations (id, name, slug, utc_offset_minutes) VALUES
    ('00000000-0000-0000-0000-0000b5b00001', 'Measured A', 'measured-a', 480), ('00000000-0000-0000-0000-0000b5b00002', 'Measured B', 'measured-b', 0);
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000b5b000a1', '00000000-0000-0000-0000-0000b5b00001', 'a-1', 'Agent A1'),
    ('00000000-0000-0000-0000-0000b5b000b1', '00000000-0000-0000-0000-0000b5b00002', 'b-1', 'Agent B1');

-- Recording ---------------------------------------------------------------------------------------------------------------------
SELECT pg_temp.check((public.record_model_usage('00000000-0000-0000-0000-0000b5b0f001', jsonb_build_array(
        pg_temp.row('00000000-0000-0000-0000-0000b5b000a1', 'claude-sonnet-5-5', 2, 1000, 500))) ->> 'accepted')::int = 1, 'a batch with one valid row is accepted');
SELECT pg_temp.check((SELECT calls = 2 AND prompt_tokens = 1000 AND completion_tokens = 500 AND organization_id = '00000000-0000-0000-0000-0000b5b00001'
                      FROM public.agent_model_measured_daily WHERE agent_id = '00000000-0000-0000-0000-0000b5b000a1'),
    'the organization comes from the agent row, and the counts are stored');
SELECT pg_temp.check((public.record_model_usage('00000000-0000-0000-0000-0000b5b0f001', jsonb_build_array(
        pg_temp.row('00000000-0000-0000-0000-0000b5b000a1', 'claude-sonnet-5-5', 2, 1000, 500))) ->> 'duplicate')::boolean, 'the same batch sent again is recognised');
SELECT pg_temp.check((SELECT calls = 2 FROM public.agent_model_measured_daily WHERE agent_id = '00000000-0000-0000-0000-0000b5b000a1'), 'and counts nothing twice');
SELECT public.record_model_usage('00000000-0000-0000-0000-0000b5b0f002', jsonb_build_array(
    pg_temp.row('00000000-0000-0000-0000-0000b5b000a1', 'Claude-Sonnet-5-5', 1, 10, 5, 1)));
SELECT pg_temp.check((SELECT count(*) = 1 AND sum(calls) = 3 AND sum(prompt_tokens) = 1010 AND sum(calls_without_usage) = 1
                      FROM public.agent_model_measured_daily WHERE agent_id = '00000000-0000-0000-0000-0000b5b000a1'),
    'a new batch adds to the day, model names are folded to lower case, calls without usage are counted apart');

-- Refusals: nothing from a bad row, the rest of the batch still lands ---------------------------------------------------------------
SELECT pg_temp.check((public.record_model_usage('00000000-0000-0000-0000-0000b5b0f003', jsonb_build_array(
        pg_temp.row('00000000-0000-0000-0000-0000b5b0dead', 'claude-sonnet-5-5', 1, 1, 1),
        pg_temp.row('00000000-0000-0000-0000-0000b5b000b1', '', 1, 1, 1),
        pg_temp.row('00000000-0000-0000-0000-0000b5b000b1', 'claude-haiku-5-5', 0, 1, 1),
        pg_temp.row('00000000-0000-0000-0000-0000b5b000b1', 'claude-haiku-5-5', 1, -5, 1),
        pg_temp.row('00000000-0000-0000-0000-0000b5b000b1', 'claude-haiku-5-5', 1, 100, 50))) ->> 'rejected')::int = 4,
    'an unknown agent, an empty model, zero calls and a negative count are each rejected');
SELECT pg_temp.check((SELECT sum(prompt_tokens) = 100 FROM public.agent_model_measured_daily WHERE agent_id = '00000000-0000-0000-0000-0000b5b000b1'), 'while the valid row of the same batch is stored');
SELECT pg_temp.check((SELECT count(*) = 0 FROM public.agent_model_measured_daily WHERE agent_id = '00000000-0000-0000-0000-0000b5b0dead'), 'nothing is written for an agent that does not exist');
SELECT pg_temp.check((public.record_model_usage('00000000-0000-0000-0000-0000b5b0f004', jsonb_build_array(
        jsonb_build_object('agent_id', '00000000-0000-0000-0000-0000b5b000b1', 'organization_id', '00000000-0000-0000-0000-0000b5b00001', 'provider', 'anthropic',
                           'model', 'claude-opus-5-5', 'calls', 1, 'input_tokens', 7, 'output_tokens', 7, 'occurred_at', now()))) ->> 'accepted')::int = 1, 'a row that names another organization is still accepted');
SELECT pg_temp.check((SELECT organization_id = '00000000-0000-0000-0000-0000b5b00002' FROM public.agent_model_measured_daily WHERE model = 'claude-opus-5-5'),
    'but an organization named in the row is ignored: the agent decides the tenant');
CREATE FUNCTION pg_temp.raises(p_sql text) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN EXECUTE p_sql; RETURN false; EXCEPTION WHEN OTHERS THEN RETURN true; END $$;
SELECT pg_temp.check(pg_temp.raises($$SELECT public.record_model_usage('00000000-0000-0000-0000-0000b5b0f005', (SELECT jsonb_agg(pg_temp.row('00000000-0000-0000-0000-0000b5b000a1', 'm', 1, 1, 1)) FROM generate_series(1, 501)))$$),
    'a batch of more than 500 rows is refused outright');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.model_usage_batches WHERE batch_id = '00000000-0000-0000-0000-0000b5b0f005'), 'and its batch id is not burned');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.record_model_usage('00000000-0000-0000-0000-0000b5b0f006', '{"not":"an array"}'::jsonb)$$), 'a batch that is not an array is refused');

-- Day boundary at the organization's offset ---------------------------------------------------------------------------------------
SELECT public.record_model_usage('00000000-0000-0000-0000-0000b5b0f007', jsonb_build_array(
    pg_temp.row('00000000-0000-0000-0000-0000b5b000a1', 'claude-edge', 1, 1, 1, 0, (date_trunc('day', now() AT TIME ZONE 'utc') + interval '23 hours 30 minutes') AT TIME ZONE 'utc' - interval '1 day')));
SELECT pg_temp.check((SELECT day = ((date_trunc('day', now() AT TIME ZONE 'utc') - interval '1 day' + interval '23 hours 30 minutes' + interval '8 hours')::date) FROM public.agent_model_measured_daily WHERE model = 'claude-edge'),
    'a call at 23:30 UTC lands on the next day for an organization at UTC+8');
SELECT public.record_model_usage('00000000-0000-0000-0000-0000b5b0f008', jsonb_build_array(
    pg_temp.row('00000000-0000-0000-0000-0000b5b000a1', 'claude-future', 1, 1, 1, 0, now() + interval '3 days'),
    pg_temp.row('00000000-0000-0000-0000-0000b5b000a1', 'claude-ancient', 1, 1, 1, 0, now() - interval '40 days')));
SELECT pg_temp.check((SELECT day <= ((now() AT TIME ZONE 'utc') + interval '8 hours')::date FROM public.agent_model_measured_daily WHERE model = 'claude-future'), 'a time in the future counts as now');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_model_measured_daily WHERE model = 'claude-ancient'), 'a call older than 35 days is not written');

-- Cardinality: at most 50 models per agent and day ---------------------------------------------------------------------------------
SELECT public.record_model_usage('00000000-0000-0000-0000-0000b5b0f009', (SELECT jsonb_agg(pg_temp.row('00000000-0000-0000-0000-0000b5b000b1', 'flood-' || g, 1, 1, 1)) FROM generate_series(1, 60) g));
SELECT pg_temp.check((SELECT count(*) <= 52 FROM public.agent_model_measured_daily WHERE agent_id = '00000000-0000-0000-0000-0000b5b000b1' AND day = (now() AT TIME ZONE 'utc')::date)
                     AND EXISTS (SELECT 1 FROM public.agent_model_measured_daily WHERE model = '(other)'), 'distinct models per agent and day are capped and the rest folded into one row');

-- Reading -------------------------------------------------------------------------------------------------------------------
SELECT pg_temp.check((SELECT count(*) > 0 FROM public.agent_model_measured_usage('00000000-0000-0000-0000-0000b5b00001', NULL, current_date - 3, current_date + 1)), 'the read function returns an organization''s rows');
SELECT pg_temp.check((SELECT count(*) = 0 FROM public.agent_model_measured_usage('00000000-0000-0000-0000-0000b5b00001', '00000000-0000-0000-0000-0000b5b000b1', current_date - 3, current_date + 1)),
    'and never another organization''s agent');
SELECT pg_temp.check((SELECT count(*) = 0 FROM public.agent_model_daily WHERE agent_id = '00000000-0000-0000-0000-0000b5b000a1'), 'measured usage never lands in the reported table');

-- Purge -----------------------------------------------------------------------------------------------------------------------
INSERT INTO public.agent_model_measured_daily (organization_id, agent_id, day, provider, model, calls, prompt_tokens, completion_tokens, calls_without_usage)
VALUES ('00000000-0000-0000-0000-0000b5b00001', '00000000-0000-0000-0000-0000b5b000a1', current_date - 120, 'anthropic', 'old', 1, 1, 1, 0);
UPDATE public.model_usage_batches SET received_at = now() - interval '10 days' WHERE batch_id = '00000000-0000-0000-0000-0000b5b0f002';
SELECT public.purge_model_measured();
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_model_measured_daily WHERE model = 'old'), 'days older than 90 are purged');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.model_usage_batches WHERE batch_id = '00000000-0000-0000-0000-0000b5b0f002') AND EXISTS (SELECT 1 FROM public.model_usage_batches WHERE batch_id = '00000000-0000-0000-0000-0000b5b0f001'),
    'batch ids older than 7 days are purged, recent ones stay');

-- Who can call what ---------------------------------------------------------------------------------------------------------------
SELECT pg_temp.check(NOT has_function_privilege('anon', 'public.record_model_usage(uuid, jsonb)', 'EXECUTE') AND NOT has_function_privilege('authenticated', 'public.record_model_usage(uuid, jsonb)', 'EXECUTE')
                     AND NOT has_function_privilege('authenticated', 'public.agent_model_measured_usage(uuid, uuid, date, date)', 'EXECUTE') AND has_function_privilege('service_role', 'public.record_model_usage(uuid, jsonb)', 'EXECUTE'),
    'only the service role can record or read measured usage');
SELECT pg_temp.check((SELECT relrowsecurity FROM pg_class WHERE relname = 'agent_model_measured_daily') AND (SELECT relrowsecurity FROM pg_class WHERE relname = 'model_usage_batches'), 'both new tables are row-level-security closed');

-- The tenant manifest (ADR 0027) must know the new table: deletion and export cover it ------------------------------------------------
SELECT pg_temp.check(EXISTS (SELECT 1 FROM jsonb_array_elements(public.tenant_data_manifest()) e WHERE e ->> 'table' = 'agent_model_measured_daily'), 'the tenant manifest lists agent_model_measured_daily');

DO $$ BEGIN RAISE NOTICE 'ALL SQL TESTS PASSED'; END $$;
ROLLBACK;
