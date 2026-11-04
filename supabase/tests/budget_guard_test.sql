-- SQL tests for supabase/migrations/20261105000000_budget_guard.sql.
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
INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000a0a00001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000a0a00008', 'Budget Org 1', 'budget-org-1'),
    ('00000000-0000-0000-0000-0000a0a00009', 'Budget Org 2', 'budget-org-2');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000a0a0000a', '00000000-0000-0000-0000-0000a0a00008', 'budget-bot-1', 'Budget Bot 1'),
    ('00000000-0000-0000-0000-0000a0a0000b', '00000000-0000-0000-0000-0000a0a00009', 'budget-bot-2', 'Budget Bot 2'),
    ('00000000-0000-0000-0000-0000a0a0000c', '00000000-0000-0000-0000-0000a0a00008', 'budget-bot-3', 'Budget Bot 3');

-- 1. Defaults and constraints -----------------------------------------------------------------------
SELECT pg_temp.check(
    (SELECT daily_call_limit IS NULL AND budget_action = 'deny' FROM public.agents WHERE id = '00000000-0000-0000-0000-0000a0a0000a')
    AND (SELECT utc_offset_minutes = 480 FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000a0a00008'),
    'agents default to no limit and deny; organizations default to UTC+8');
SELECT pg_temp.expect_error($$UPDATE public.agents SET daily_call_limit = 0 WHERE id = '00000000-0000-0000-0000-0000a0a0000a'$$, '23514', 'a limit of 0 is refused by the database');
SELECT pg_temp.expect_error($$UPDATE public.agents SET daily_call_limit = 10000001 WHERE id = '00000000-0000-0000-0000-0000a0a0000a'$$, '23514', 'a limit above 10,000,000 is refused');
SELECT pg_temp.expect_error($$UPDATE public.agents SET budget_action = 'ignore' WHERE id = '00000000-0000-0000-0000-0000a0a0000a'$$, '23514', 'an unknown budget action is refused');
SELECT pg_temp.expect_error($$UPDATE public.organizations SET utc_offset_minutes = 900 WHERE id = '00000000-0000-0000-0000-0000a0a00008'$$, '23514', 'an impossible UTC offset is refused');

-- 2. Changing a limit ---------------------------------------------------------------------------------
DO $$
DECLARE r jsonb;
BEGIN
    r := public.control_agent_budget('00000000-0000-0000-0000-0000a0a00008', '00000000-0000-0000-0000-0000a0a0000a',
                                     '00000000-0000-0000-0000-0000a0a00001', 10, 'deny', 'cap it');
    PERFORM pg_temp.check((r->>'changed')::boolean AND (r->>'daily_call_limit')::int = 10, 'limit set to 10');
    PERFORM pg_temp.check(
        (SELECT count(*) FROM public.control_audit_log
         WHERE action = 'passport.budget_changed' AND target_id = '00000000-0000-0000-0000-0000a0a0000a'
           AND reason = 'cap it' AND (details->>'new_limit')::int = 10 AND details->>'old_limit' IS NULL) = 1,
        'the change is audited with old and new values');

    r := public.control_agent_budget('00000000-0000-0000-0000-0000a0a00008', '00000000-0000-0000-0000-0000a0a0000a',
                                     '00000000-0000-0000-0000-0000a0a00001', 10, 'deny', NULL);
    PERFORM pg_temp.check(NOT (r->>'changed')::boolean, 'repeating the same limit changes nothing');
    PERFORM pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'passport.budget_changed') = 1,
                          'repeating writes no second audit row');

    r := public.control_agent_budget('00000000-0000-0000-0000-0000a0a00008', '00000000-0000-0000-0000-0000a0a0000c',
                                     '00000000-0000-0000-0000-0000a0a00001', 100, 'freeze', NULL);
    PERFORM pg_temp.check((r->>'budget_action') = 'freeze', 'the action can be set to freeze');
    r := public.control_agent_budget('00000000-0000-0000-0000-0000a0a00008', '00000000-0000-0000-0000-0000a0a0000c',
                                     '00000000-0000-0000-0000-0000a0a00001', NULL, 'deny', NULL);
    PERFORM pg_temp.check((r->>'changed')::boolean AND (r->'daily_call_limit') = 'null'::jsonb, 'a limit can be removed');
END $$;
SELECT pg_temp.expect_error(
    $$SELECT public.control_agent_budget('00000000-0000-0000-0000-0000a0a00009', '00000000-0000-0000-0000-0000a0a0000a',
                                         '00000000-0000-0000-0000-0000a0a00001', 5, 'deny', NULL)$$,
    'P0002', 'another organization cannot change the limit');
SELECT pg_temp.expect_error(
    $$SELECT public.control_agent_budget('00000000-0000-0000-0000-0000a0a00008', '00000000-0000-0000-0000-0000a0a0000a',
                                         '00000000-0000-0000-0000-0000a0a00001', 0, 'deny', NULL)$$,
    '23514', 'an invalid limit through the function is refused');
SELECT pg_temp.check((SELECT daily_call_limit FROM public.agents WHERE id = '00000000-0000-0000-0000-0000a0a0000a') = 10,
                     'refused calls changed nothing');

-- 3. Reporting usage: cumulative, monotonic, summed across instances -------------------------------------
CREATE FUNCTION pg_temp.report(p_instance text, p_agent uuid, p_calls bigint, p_day date DEFAULT (now() AT TIME ZONE 'utc')::date)
RETURNS jsonb LANGUAGE sql AS $$
    SELECT public.record_usage(p_instance, jsonb_build_array(jsonb_build_object(
        'agent_id', p_agent, 'day_key', p_day, 'calls', p_calls)))
$$;

DO $$
DECLARE
    bot1 uuid := '00000000-0000-0000-0000-0000a0a0000a';
    r jsonb;
BEGIN
    r := pg_temp.report('instance-aaaa', bot1, 5);
    PERFORM pg_temp.check((r->>'accepted')::int = 1 AND jsonb_array_length(r->'events') = 0, 'a report below 80% is accepted without alerts');
    r := pg_temp.report('instance-aaaa', bot1, 3);
    PERFORM pg_temp.check(
        (SELECT calls FROM public.agent_usage_daily WHERE agent_id = bot1 AND instance_id = 'instance-aaaa') = 5,
        'a lower (stale) report never lowers the stored count');
    r := pg_temp.report('instance-aaaa', bot1, 5);
    PERFORM pg_temp.check(jsonb_array_length(r->'events') = 0, 'resending the same total is harmless');

    r := pg_temp.report('instance-bbbb', bot1, 3);
    PERFORM pg_temp.check(
        (SELECT sum(calls) FROM public.agent_usage_daily WHERE agent_id = bot1) = 8
        AND jsonb_array_length(r->'events') = 1 AND r->'events'->0->>'kind' = 'warn'
        AND (r->'events'->0->>'used')::int = 8,
        'two instances are summed and crossing 80% raises one warn alert');
    r := pg_temp.report('instance-bbbb', bot1, 3);
    PERFORM pg_temp.check(jsonb_array_length(r->'events') = 0, 'the 80% alert is raised once per day');

    r := pg_temp.report('instance-aaaa', bot1, 7);
    PERFORM pg_temp.check(r->'events'->0->>'kind' = 'limit' AND (r->'events'->0->>'used')::int = 10
        AND r->'events'->0->>'budget_action' = 'deny' AND (r->'events'->0->>'utc_offset_minutes')::int = 480,
        'reaching the limit raises one limit alert with the details the caller needs');
    r := pg_temp.report('instance-aaaa', bot1, 9);
    PERFORM pg_temp.check(jsonb_array_length(r->'events') = 0, 'the limit alert is raised once per day');
    PERFORM pg_temp.check((SELECT warned_at IS NOT NULL AND limit_reached_at IS NOT NULL FROM public.agent_budget_state
                           WHERE agent_id = bot1 AND day_key = (now() AT TIME ZONE 'utc')::date), 'the alert state is stored');

    PERFORM pg_temp.check(public.usage_by_others('00000000-0000-0000-0000-0000a0a00008', bot1, (now() AT TIME ZONE 'utc')::date, 'instance-aaaa') = 3,
        'usage by others excludes the caller');
    PERFORM pg_temp.check(public.usage_by_others('00000000-0000-0000-0000-0000a0a00008', bot1, (now() AT TIME ZONE 'utc')::date, 'instance-zzzz') = 12,
        'a new instance sees everything the others reported');
    PERFORM pg_temp.check(public.usage_by_others('00000000-0000-0000-0000-0000a0a00009', bot1, (now() AT TIME ZONE 'utc')::date, 'instance-zzzz') = 0,
        'usage by others is scoped by organization');

    -- jumping from nothing straight past the limit raises only the limit alert
    r := pg_temp.report('instance-aaaa', '00000000-0000-0000-0000-0000a0a0000c', 50);
    PERFORM pg_temp.check(jsonb_array_length(r->'events') = 0, 'an agent with no limit never raises alerts, but is still counted');
    PERFORM pg_temp.check((SELECT count(*) FROM public.agent_budget_state WHERE agent_id = '00000000-0000-0000-0000-0000a0a0000c') = 0,
        'no alert state is kept for an agent with no limit');
    PERFORM public.control_agent_budget('00000000-0000-0000-0000-0000a0a00008', '00000000-0000-0000-0000-0000a0a0000c',
                                        '00000000-0000-0000-0000-0000a0a00001', 40, 'freeze', NULL);
    r := pg_temp.report('instance-aaaa', '00000000-0000-0000-0000-0000a0a0000c', 60);
    PERFORM pg_temp.check(jsonb_array_length(r->'events') = 1 AND r->'events'->0->>'kind' = 'limit'
        AND r->'events'->0->>'budget_action' = 'freeze', 'passing the limit in one jump raises a single limit alert');
END $$;

-- 4. Dashboard totals, tenancy, input validation -------------------------------------------------------
DO $$
DECLARE r jsonb; u jsonb;
BEGIN
    u := public.org_usage('00000000-0000-0000-0000-0000a0a00008', (now() AT TIME ZONE 'utc')::date);
    PERFORM pg_temp.check(jsonb_array_length(u) = 2, 'organization usage lists its two agents with usage');
    PERFORM pg_temp.check(NOT EXISTS (SELECT 1 FROM jsonb_array_elements(u) e WHERE e->>'agent_id' = '00000000-0000-0000-0000-0000a0a0000b'),
        'organization usage never includes another organization''s agent');

    r := public.record_usage('instance-aaaa', jsonb_build_array(
        jsonb_build_object('agent_id', gen_random_uuid(), 'day_key', (now() AT TIME ZONE 'utc')::date, 'calls', 1),
        jsonb_build_object('agent_id', '00000000-0000-0000-0000-0000a0a0000a', 'day_key', (now() AT TIME ZONE 'utc')::date + 5, 'calls', 1),
        jsonb_build_object('agent_id', '00000000-0000-0000-0000-0000a0a0000a', 'day_key', (now() AT TIME ZONE 'utc')::date, 'calls', -4),
        jsonb_build_object('agent_id', 'not-a-uuid', 'day_key', (now() AT TIME ZONE 'utc')::date, 'calls', 1),
        jsonb_build_object('agent_id', '00000000-0000-0000-0000-0000a0a0000a', 'day_key', 'garbage', 'calls', 1)));
    PERFORM pg_temp.check((r->>'accepted')::int = 0 AND (r->>'rejected')::int = 5,
        'unknown agents, far-away days, negative counts and malformed items are all rejected');
END $$;
SELECT pg_temp.expect_error($$SELECT public.record_usage('short', '[]'::jsonb)$$, '22023', 'a too-short instance id is refused');
SELECT pg_temp.expect_error($$SELECT public.record_usage('instance-aaaa', '{"a":1}'::jsonb)$$, '22023', 'items that are not an array are refused');
SELECT pg_temp.expect_error(
    $$SELECT public.record_usage('instance-aaaa', (SELECT jsonb_agg(jsonb_build_object('agent_id', gen_random_uuid(), 'day_key', current_date, 'calls', 1)) FROM generate_series(1, 1001)))$$,
    '22023', 'more than 1000 items are refused');

-- 5. Frozen-by-budget marker and retention ---------------------------------------------------------------
SELECT pg_temp.check(public.mark_budget_frozen('00000000-0000-0000-0000-0000a0a0000c', (now() AT TIME ZONE 'utc')::date),
    'the auto-freeze marker is set the first time');
SELECT pg_temp.check(NOT public.mark_budget_frozen('00000000-0000-0000-0000-0000a0a0000c', (now() AT TIME ZONE 'utc')::date),
    'and not again, so the auto-freeze happens once per day');
INSERT INTO public.agent_usage_daily (agent_id, organization_id, day_key, instance_id, calls) VALUES
    ('00000000-0000-0000-0000-0000a0a0000a', '00000000-0000-0000-0000-0000a0a00008', (now() AT TIME ZONE 'utc')::date - 100, 'instance-old1', 3);
INSERT INTO public.agent_budget_state (agent_id, day_key) VALUES
    ('00000000-0000-0000-0000-0000a0a0000a', (now() AT TIME ZONE 'utc')::date - 100);
SELECT public.purge_usage();
SELECT pg_temp.check(
    NOT EXISTS (SELECT 1 FROM public.agent_usage_daily WHERE instance_id = 'instance-old1')
    AND NOT EXISTS (SELECT 1 FROM public.agent_budget_state WHERE day_key < (now() AT TIME ZONE 'utc')::date - 90),
    'rows older than 90 days are purged');
SELECT pg_temp.check(EXISTS (SELECT 1 FROM public.agent_usage_daily WHERE instance_id = 'instance-aaaa'), 'recent rows are kept');

-- 6. Atomic: a failing audit insert undoes a limit change ---------------------------------------------------
CREATE FUNCTION public.zz_budget_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'simulated audit failure'; END $$;
CREATE TRIGGER zz_budget_fail_audit BEFORE INSERT ON public.control_audit_log
    FOR EACH ROW EXECUTE FUNCTION public.zz_budget_fail_audit();
SELECT pg_temp.expect_error(
    $$SELECT public.control_agent_budget('00000000-0000-0000-0000-0000a0a00009', '00000000-0000-0000-0000-0000a0a0000b',
                                         '00000000-0000-0000-0000-0000a0a00001', 7, 'freeze', NULL)$$,
    'P0001', 'atomic: a failing audit aborts the limit change');
SELECT pg_temp.check((SELECT daily_call_limit IS NULL AND budget_action = 'deny' FROM public.agents WHERE id = '00000000-0000-0000-0000-0000a0a0000b'),
    'atomic: the agent is unchanged after the failed audit');
DROP TRIGGER zz_budget_fail_audit ON public.control_audit_log;
DROP FUNCTION public.zz_budget_fail_audit();

-- 7. Access ---------------------------------------------------------------------------------------------------
DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'control_agent_budget(uuid,uuid,uuid,integer,text,text)', 'record_usage(text,jsonb)', 'mark_budget_frozen(uuid,date)',
        'usage_by_others(uuid,uuid,date,text)', 'org_usage(uuid,date)', 'purge_usage()'
    ] LOOP
        PERFORM pg_temp.check(NOT has_function_privilege('anon', 'public.' || f, 'EXECUTE')
                          AND NOT has_function_privilege('authenticated', 'public.' || f, 'EXECUTE'),
            f || ' is not executable by anon or authenticated');
        PERFORM pg_temp.check(has_function_privilege('service_role', 'public.' || f, 'EXECUTE'), f || ' is executable by service_role');
    END LOOP;
    PERFORM pg_temp.check(
        (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.agent_usage_daily'::regclass)
        AND (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.agent_budget_state'::regclass),
        'usage and alert-state tables are protected by row level security');
END $$;

DO $$ BEGIN RAISE NOTICE 'ALL SQL TESTS PASSED (budget_guard)'; END $$;
