-- SQL tests for supabase/migrations/20261125000000_model_spend.sql (Phase 4.5 B4a, model spend roll-up).

\set ON_ERROR_STOP on
\set QUIET on

-- The SQL tests share one database: this file runs inside a transaction that is rolled back at the end.
BEGIN;

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'CHECK FAILED: %', p_msg; END IF;
    RAISE NOTICE 'ok: %', p_msg;
END $$;

CREATE FUNCTION pg_temp.raises(p_sql text) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE p_sql;
    RETURN false;
EXCEPTION WHEN OTHERS THEN
    RETURN true;
END $$;

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000600a0001');
-- Org A is on the default offset (UTC+8, 480); org B starts its day at UTC (0).
INSERT INTO public.organizations (id, name, slug, utc_offset_minutes) VALUES
    ('00000000-0000-0000-0000-000060000001', 'Spend Org A', 'spend-org-a', 480),
    ('00000000-0000-0000-0000-000060000002', 'Spend Org B', 'spend-org-b', 0);
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-00006000000a', '00000000-0000-0000-0000-000060000001', 'spend-bot-a', 'Spend Bot A'),
    ('00000000-0000-0000-0000-00006000000b', '00000000-0000-0000-0000-000060000002', 'spend-bot-b', 'Spend Bot B'),
    ('00000000-0000-0000-0000-00006000000c', '00000000-0000-0000-0000-000060000001', 'spend-bot-c', 'Spend Bot C');

CREATE FUNCTION pg_temp.trace(p_agent uuid, p_at timestamptz, p_provider text, p_model text, p_prompt integer, p_completion integer, p_tag text)
RETURNS void LANGUAGE sql AS $$
    INSERT INTO public.execution_traces (organization_id, agent_id, session_id, trace_id, span_id, step_type, model_provider, model_name,
                                         prompt_tokens, completion_tokens, occurred_at)
    SELECT g.organization_id, p_agent, gen_random_uuid(), 'trace-' || p_tag, 'span-' || p_tag, 'observation', p_provider, p_model,
           p_prompt, p_completion, p_at
    FROM public.agents g WHERE g.id = p_agent
$$;

CREATE FUNCTION pg_temp.row_of(p_agent uuid, p_day date, p_provider text, p_model text) RETURNS text LANGUAGE sql AS $$
    SELECT calls || '/' || prompt_tokens || '/' || completion_tokens FROM public.agent_model_daily
    WHERE agent_id = p_agent AND day = p_day AND provider = p_provider AND model = p_model
$$;

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The trigger: spans with a model and some tokens, grouped per agent, day, provider and model.
SET LOCAL timezone = 'Asia/Kolkata';  -- +05:30: the day must come from the organization's offset, never from the session's zone
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000a', now() - interval '1 hour', 'anthropic', 'claude-sonnet-5-5', 1000, 200, 'a1');
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000a', now() - interval '2 hours', 'anthropic', 'claude-sonnet-5-5', 500, 50, 'a2');
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000a', now() - interval '3 hours', 'Anthropic', 'Claude-Sonnet-5-5', 10, 1, 'a3');
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000a', now() - interval '1 hour', 'anthropic', 'claude-haiku-5-5', 70, 7, 'a4');
RESET timezone;

SELECT pg_temp.check((SELECT sum(calls) FROM public.agent_model_daily WHERE agent_id = '00000000-0000-0000-0000-00006000000a') = 4,
    'four spans with a model and tokens are four calls');
SELECT pg_temp.check((SELECT sum(prompt_tokens) FILTER (WHERE model = 'claude-sonnet-5-5') FROM public.agent_model_daily
                      WHERE agent_id = '00000000-0000-0000-0000-00006000000a') = 1510,
    'provider and model are folded to lower case, so one model is one row whatever its spelling');
SELECT pg_temp.check((SELECT count(DISTINCT model) FROM public.agent_model_daily WHERE agent_id = '00000000-0000-0000-0000-00006000000a') = 2,
    'two models are two rows');

-- Not usage: no model, empty model, or no tokens at all ("not reported" is not zero cost, and a span with no tokens is not a call).
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000c', now(), NULL, NULL, 100, 10, 'c1');
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000c', now(), 'anthropic', '', 100, 10, 'c2');
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000c', now(), 'anthropic', 'claude-sonnet-5-5', 0, 0, 'c3');
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000c', now(), 'anthropic', 'claude-sonnet-5-5', -5, -5, 'c4');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_model_daily WHERE agent_id = '00000000-0000-0000-0000-00006000000c'),
    'a span with no model, an empty model, no tokens or negative tokens is not model use');

-- One side only counts (an output-only record), and an impossible number is dropped rather than trusted.
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000c', now(), 'openai', 'gpt-x', 0, 40, 'c5');
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000c', now(), 'openai', 'gpt-y', 1500000000, 9, 'c6');
SELECT pg_temp.check(pg_temp.row_of('00000000-0000-0000-0000-00006000000c', (now() AT TIME ZONE 'utc')::date, 'openai', 'gpt-x') IS NOT NULL
                 OR pg_temp.row_of('00000000-0000-0000-0000-00006000000c', ((now() AT TIME ZONE 'utc') + interval '8 hours')::date, 'openai', 'gpt-x') IS NOT NULL,
    'output tokens alone are a call');
SELECT pg_temp.check((SELECT sum(calls) || '/' || sum(prompt_tokens) || '/' || sum(completion_tokens) FROM public.agent_model_daily
                      WHERE agent_id = '00000000-0000-0000-0000-00006000000c' AND model = 'gpt-y') = '1/0/9',
    'a token count above 1,000,000,000 in one call is not believed (that side counts as not reported)');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The day follows the organization's offset. base() is UTC midnight three days ago: 17:00 UTC is already the next day at UTC+8 but still
-- the same day at UTC; 15:59:59 UTC is the same day in both.
CREATE FUNCTION pg_temp.base() RETURNS timestamptz LANGUAGE sql AS $$ SELECT date_trunc('day', now(), 'UTC') - interval '3 days' $$;
SET LOCAL timezone = 'America/Los_Angeles';
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000a', pg_temp.base() + interval '17 hours', 'anthropic', 'day-test', 100, 10, 'd1');
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000b', pg_temp.base() + interval '17 hours', 'anthropic', 'day-test', 100, 10, 'd2');
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000a', pg_temp.base() + interval '15 hours 59 minutes 59 seconds', 'anthropic', 'day-test', 1, 1, 'd3');
RESET timezone;
SELECT pg_temp.check(pg_temp.row_of('00000000-0000-0000-0000-00006000000a', (pg_temp.base() AT TIME ZONE 'utc')::date + 1, 'anthropic', 'day-test') = '1/100/10',
    'UTC+8 organization: 17:00 UTC is the next local day');
SELECT pg_temp.check(pg_temp.row_of('00000000-0000-0000-0000-00006000000a', (pg_temp.base() AT TIME ZONE 'utc')::date, 'anthropic', 'day-test') = '1/1/1',
    'UTC+8 organization: 15:59:59 UTC is still the same local day');
SELECT pg_temp.check(pg_temp.row_of('00000000-0000-0000-0000-00006000000b', (pg_temp.base() AT TIME ZONE 'utc')::date, 'anthropic', 'day-test') = '1/100/10',
    'UTC organization: 17:00 UTC is the same day, and the session''s time zone changed nothing');

-- A span cannot write an arbitrary day: too old is ignored, the future counts as now.
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000b', now() - interval '36 days', 'anthropic', 'too-old', 100, 10, 'o1');
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000b', now() - interval '34 days', 'anthropic', 'old-ok', 100, 10, 'o2');
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000b', now() + interval '30 days', 'anthropic', 'future', 100, 10, 'o3');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_model_daily WHERE model = 'too-old'), 'a span older than 35 days is ignored');
SELECT pg_temp.check(EXISTS (SELECT 1 FROM public.agent_model_daily WHERE model = 'old-ok'), 'a span 34 days old is counted');
SELECT pg_temp.check((SELECT max(day) FROM public.agent_model_daily WHERE model = 'future') <= (now() AT TIME ZONE 'utc')::date + 1,
    'a span dated in the future counts as now, so the SDK host''s clock cannot write another day');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- A span sent again is not counted again (ingest upserts on the span id), and one statement with many spans adds up exactly.
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000c', now() - interval '1 hour', 'anthropic', 'resend', 100, 10, 'r1');
INSERT INTO public.execution_traces (organization_id, agent_id, session_id, trace_id, span_id, step_type, model_provider, model_name,
                                     prompt_tokens, completion_tokens, occurred_at)
SELECT organization_id, agent_id, session_id, trace_id, span_id, step_type, model_provider, model_name, prompt_tokens, completion_tokens, occurred_at
FROM public.execution_traces WHERE trace_id = 'trace-r1'
ON CONFLICT (organization_id, trace_id, span_id) DO UPDATE SET prompt_tokens = EXCLUDED.prompt_tokens;
SELECT pg_temp.check((SELECT sum(calls) || '/' || sum(prompt_tokens) FROM public.agent_model_daily WHERE model = 'resend') = '1/100',
    'the same span sent again is not counted again');

INSERT INTO public.execution_traces (organization_id, agent_id, session_id, trace_id, span_id, step_type, model_provider, model_name,
                                     prompt_tokens, completion_tokens, occurred_at)
SELECT '00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000c', gen_random_uuid(), 'trace-batch', 'span-batch-' || n,
       'observation', 'anthropic', CASE WHEN n % 2 = 0 THEN 'batch-even' ELSE 'batch-odd' END, n, n * 2, now() - interval '30 minutes'
FROM generate_series(1, 100) AS n;
SELECT pg_temp.check((SELECT sum(calls) || '/' || sum(prompt_tokens) || '/' || sum(completion_tokens) FROM public.agent_model_daily
                      WHERE model IN ('batch-even', 'batch-odd')) = '100/5050/10100',
    'one statement of 100 spans over two models adds up exactly');

-- The roll-up equals a direct sum over the spans it counts (agents of this test only).
SELECT pg_temp.check(
    (SELECT sum(calls)::text || '/' || sum(prompt_tokens) || '/' || sum(completion_tokens) FROM public.agent_model_daily
      WHERE organization_id IN ('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-000060000002') AND model <> 'future' AND model <> 'old-ok')
  = (SELECT count(*)::text || '/' || sum(CASE WHEN prompt_tokens BETWEEN 1 AND 1000000000 THEN prompt_tokens ELSE 0 END)
                          || '/' || sum(CASE WHEN completion_tokens BETWEEN 1 AND 1000000000 THEN completion_tokens ELSE 0 END)
       FROM public.execution_traces
      WHERE organization_id IN ('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-000060000002')
        AND model_name IS NOT NULL AND model_name <> '' AND model_name NOT IN ('future', 'old-ok', 'too-old')
        AND (prompt_tokens BETWEEN 1 AND 1000000000 OR completion_tokens BETWEEN 1 AND 1000000000) AND occurred_at > now() - interval '35 days'),
    'the roll-up adds up to a direct sum over the spans');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The backfill recomputes the same rows from the spans (it is also the repair tool): wipe, rebuild, compare both ways.
CREATE TEMP TABLE snapshot AS SELECT * FROM public.agent_model_daily WHERE model <> 'old-ok';  -- 34 days old: outside the 30-day window below
DELETE FROM public.agent_model_daily;
SELECT public.model_spend_backfill(30);
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM (SELECT agent_id, day, provider, model, calls, prompt_tokens, completion_tokens FROM snapshot
                                                EXCEPT SELECT agent_id, day, provider, model, calls, prompt_tokens, completion_tokens
                                                FROM public.agent_model_daily) x),
    'the backfill rebuilds every live roll-up row exactly');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM (SELECT agent_id, day, provider, model, calls, prompt_tokens, completion_tokens
                                                FROM public.agent_model_daily
                                                EXCEPT SELECT agent_id, day, provider, model, calls, prompt_tokens, completion_tokens
                                                FROM snapshot) x),
    'and adds no row the live trigger did not');
SELECT public.model_spend_backfill(30);
SELECT pg_temp.check((SELECT sum(calls) FROM public.agent_model_daily WHERE model IN ('batch-even', 'batch-odd')) = 100,
    'running the backfill again does not count anything twice');
SELECT pg_temp.check(pg_temp.raises('SELECT public.model_spend_backfill(0)') AND pg_temp.raises('SELECT public.model_spend_backfill(36)'),
    'the backfill window is 1 to 35 days, the same 35 days the live trigger accepts');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- A roll-up that cannot be written never fails the ingest that triggered it: the span is kept, a warning is logged.
ALTER TABLE public.agent_model_daily RENAME TO agent_model_daily_away;
SELECT pg_temp.trace('00000000-0000-0000-0000-00006000000c', now(), 'anthropic', 'claude-sonnet-5-5', 10, 1, 'f1');
SELECT pg_temp.check(EXISTS (SELECT 1 FROM public.execution_traces WHERE trace_id = 'trace-f1'), 'the span is stored although the roll-up could not be written');
ALTER TABLE public.agent_model_daily_away RENAME TO agent_model_daily;

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Bounded cardinality: one agent and day keep at most 50 distinct models; the rest are folded into one "(other)" row, counts preserved.
INSERT INTO public.execution_traces (organization_id, agent_id, session_id, trace_id, span_id, step_type, model_provider, model_name,
                                     prompt_tokens, completion_tokens, occurred_at)
SELECT '00000000-0000-0000-0000-000060000002', '00000000-0000-0000-0000-00006000000b', gen_random_uuid(), 'trace-cap', 'span-cap-' || n,
       'observation', 'x', 'cap-model-' || lpad(n::text, 3, '0'), 1, 1, now() - interval '10 minutes'
FROM generate_series(1, 80) AS n;
SELECT pg_temp.check((SELECT count(*) FROM public.agent_model_daily WHERE agent_id = '00000000-0000-0000-0000-00006000000b'
                       AND (model LIKE 'cap-model-%' OR model = '(other)')) <= 51,
    'a hostile SDK key cannot create unbounded roll-up rows for one agent and day');
SELECT pg_temp.check((SELECT sum(calls) FROM public.agent_model_daily WHERE agent_id = '00000000-0000-0000-0000-00006000000b'
                       AND (model LIKE 'cap-model-%' OR model = '(other)')) = 80, 'no call is lost to the cap');
SELECT pg_temp.check(EXISTS (SELECT 1 FROM public.agent_model_daily WHERE agent_id = '00000000-0000-0000-0000-00006000000b' AND model = '(other)' AND provider = ''),
    'the overflow is visible as (other)');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The read function: organization-scoped, bounded by day, capped sums.
SELECT pg_temp.check((SELECT count(*) FROM public.agent_model_usage('00000000-0000-0000-0000-000060000001', NULL,
                       (now() AT TIME ZONE 'utc')::date - 40, (now() AT TIME ZONE 'utc')::date + 1)) > 0, 'organization A reads its rows');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_model_usage('00000000-0000-0000-0000-000060000001', NULL,
                       (now() AT TIME ZONE 'utc')::date - 40, (now() AT TIME ZONE 'utc')::date + 1) WHERE agent_id = '00000000-0000-0000-0000-00006000000b'),
    'organization A never sees B''s agent');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_model_usage('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000b',
                       (now() AT TIME ZONE 'utc')::date - 40, (now() AT TIME ZONE 'utc')::date + 1)),
    'asking organization A for B''s agent by id returns nothing');
SELECT pg_temp.check((SELECT count(*) FROM public.agent_model_usage('00000000-0000-0000-0000-000060000002', '00000000-0000-0000-0000-00006000000b',
                       (pg_temp.base() AT TIME ZONE 'utc')::date, (pg_temp.base() AT TIME ZONE 'utc')::date)) = 1,
    'p_since and p_until are inclusive days');
INSERT INTO public.agent_model_daily (organization_id, agent_id, day, provider, model, calls, prompt_tokens, completion_tokens)
VALUES ('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000c', '2020-01-01', 'anthropic', 'huge', 1,
        9000000000000000000, 9000000000000000000);
SELECT pg_temp.check((SELECT prompt_tokens FROM public.agent_model_usage('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000c',
                       '2020-01-01', '2020-01-01')) = 1000000000000000, 'a sum is capped at 10^15 so core''s cost arithmetic cannot overflow');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The dollar limit: set, compare-and-set, idempotent, audited, bounded, organization-scoped.
CREATE FUNCTION pg_temp.limit_of(p_agent uuid) RETURNS bigint LANGUAGE sql AS $$ SELECT spend_limit_micro_usd FROM public.agents WHERE id = p_agent $$;
SELECT pg_temp.check(pg_temp.limit_of('00000000-0000-0000-0000-00006000000a') IS NULL, 'no limit by default');
SELECT pg_temp.check((public.control_agent_spend_limit('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a',
        '00000000-0000-0000-0000-0000600a0001', 5000000, 'budget', NULL) ->> 'changed')::boolean, 'a limit is set');
SELECT pg_temp.check(pg_temp.limit_of('00000000-0000-0000-0000-00006000000a') = 5000000, 'the limit is stored in micro-dollars');
SELECT pg_temp.check(NOT (public.control_agent_spend_limit('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a',
        '00000000-0000-0000-0000-0000600a0001', 5000000, 'same', 5000000) ->> 'changed')::boolean, 'setting the same limit changes nothing');
SELECT pg_temp.check((public.control_agent_spend_limit('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a',
        '00000000-0000-0000-0000-0000600a0001', 9000000, 'stale', 1) ->> 'conflict')::boolean,
    'a caller that decided on an old limit gets a conflict and nothing changes');
SELECT pg_temp.check(pg_temp.limit_of('00000000-0000-0000-0000-00006000000a') = 5000000, 'the conflict changed nothing');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'passport.spend_limit_changed'
                       AND target_id = '00000000-0000-0000-0000-00006000000a') = 1, 'exactly one audit row, and none for the no-ops');
SELECT pg_temp.check((SELECT (details ->> 'old_limit') IS NULL AND (details ->> 'new_limit')::bigint = 5000000
                       FROM public.control_audit_log WHERE action = 'passport.spend_limit_changed'), 'the audit row says what changed');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_agent_spend_limit('00000000-0000-0000-0000-000060000002', '00000000-0000-0000-0000-00006000000a',
        '00000000-0000-0000-0000-0000600a0001', 1000000, 'wrong org', 5000000)$$), 'another organization cannot change this agent''s limit');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_agent_spend_limit('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a',
        '00000000-0000-0000-0000-0000600a0001', 0, 'zero', 5000000)$$)
                 AND pg_temp.raises($$SELECT public.control_agent_spend_limit('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a',
        '00000000-0000-0000-0000-0000600a0001', 1000000000001, 'huge', 5000000)$$), 'a limit of 0 or above one million dollars a day is refused');
SELECT pg_temp.check((public.control_agent_spend_limit('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a',
        '00000000-0000-0000-0000-0000600a0001', NULL, 'remove', 5000000) ->> 'changed')::boolean AND pg_temp.limit_of('00000000-0000-0000-0000-00006000000a') IS NULL,
    'a limit can be removed');

-- Once per agent per day, and a new limit allows the alert again.
SELECT pg_temp.check(public.spend_mark_alerted('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a', '2026-11-16'), 'the first alert of a day is allowed');
SELECT pg_temp.check(NOT public.spend_mark_alerted('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a', '2026-11-16'), 'the second is not');
SELECT pg_temp.check(NOT public.spend_mark_alerted('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a', '2026-11-15'), 'an earlier day is not alerted after a later one');
SELECT pg_temp.check(public.spend_mark_alerted('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a', '2026-11-17'), 'the next day is');
SELECT pg_temp.check(NOT public.spend_mark_alerted('00000000-0000-0000-0000-000060000002', '00000000-0000-0000-0000-00006000000a', '2026-11-30'),
    'another organization cannot mark this agent');
SELECT public.control_agent_spend_limit('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a',
        '00000000-0000-0000-0000-0000600a0001', 2000000, 'new', NULL);
SELECT pg_temp.check((SELECT spend_alerted_day FROM public.agents WHERE id = '00000000-0000-0000-0000-00006000000a') IS NULL,
    'a changed limit clears the day''s alert so crossing the new limit alerts again');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The purge: older than 90 days goes, the rest stays.
INSERT INTO public.agent_model_daily (organization_id, agent_id, day, provider, model, calls, prompt_tokens, completion_tokens) VALUES
    ('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a', (now() AT TIME ZONE 'utc')::date - 100, 'x', 'purge-old', 1, 1, 1),
    ('00000000-0000-0000-0000-000060000001', '00000000-0000-0000-0000-00006000000a', (now() AT TIME ZONE 'utc')::date - 80, 'x', 'purge-kept', 1, 1, 1);
SELECT pg_temp.check(public.purge_model_spend() >= 1, 'the purge deletes old days');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_model_daily WHERE model = 'purge-old')
                 AND EXISTS (SELECT 1 FROM public.agent_model_daily WHERE model = 'purge-kept'), 'only days older than 90 days are purged');

-- Tenant deletion takes the roll-up with it.
DELETE FROM public.organizations WHERE id = '00000000-0000-0000-0000-000060000002';
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_model_daily WHERE organization_id = '00000000-0000-0000-0000-000060000002'),
    'deleting an organization deletes its roll-up');

-- Nobody but the service role can call the functions or read the table.
SELECT pg_temp.check(NOT has_function_privilege('anon', 'public.agent_model_usage(uuid, uuid, date, date)', 'EXECUTE')
                 AND NOT has_function_privilege('authenticated', 'public.control_agent_spend_limit(uuid, uuid, uuid, bigint, text, bigint)', 'EXECUTE')
                 AND NOT has_function_privilege('authenticated', 'public.spend_mark_alerted(uuid, uuid, date)', 'EXECUTE')
                 AND NOT has_function_privilege('authenticated', 'public.model_spend_backfill(integer)', 'EXECUTE')
                 AND NOT has_function_privilege('authenticated', 'public.purge_model_spend()', 'EXECUTE')
                 AND NOT has_function_privilege('anon', 'public.model_spend_rollup()', 'EXECUTE'), 'signed-in users and anon cannot');
SELECT pg_temp.check((SELECT relrowsecurity FROM pg_class WHERE oid = 'public.agent_model_daily'::regclass), 'row level security is on');

ROLLBACK;
