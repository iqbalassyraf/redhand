-- SQL tests for supabase/migrations/20261122000000_risk_engine.sql (Phase 4.5 B1, the Risk Engine).

\set ON_ERROR_STOP on
\set QUIET on

-- The SQL tests share one database and older tests count audit rows and findings globally, so this file runs inside a transaction that
-- is rolled back at the end and leaves nothing behind.
BEGIN;

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'CHECK FAILED: %', p_msg; END IF;
    RAISE NOTICE 'ok: %', p_msg;
END $$;

CREATE FUNCTION pg_temp.expect_error(p_sql text, p_sqlstate text, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE = p_sqlstate THEN RAISE NOTICE 'ok: % (SQLSTATE %)', p_msg, p_sqlstate; RETURN; END IF;
        RAISE EXCEPTION 'CHECK FAILED: % -- expected % but got % (%)', p_msg, p_sqlstate, SQLSTATE, SQLERRM;
    END;
    RAISE EXCEPTION 'CHECK FAILED: % -- expected SQLSTATE % but it succeeded', p_msg, p_sqlstate;
END $$;

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000300a0001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-000030000001', 'Risk Org A', 'risk-org-a'),
    ('00000000-0000-0000-0000-000030000002', 'Risk Org B', 'risk-org-b');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-00003000000a', '00000000-0000-0000-0000-000030000001', 'risk-bot-a', 'Risk Bot A'),
    ('00000000-0000-0000-0000-00003000000c', '00000000-0000-0000-0000-000030000001', 'risk-bot-c', 'Risk Bot C'),
    ('00000000-0000-0000-0000-00003000000b', '00000000-0000-0000-0000-000030000002', 'risk-bot-b', 'Risk Bot B');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Defaults: alert on at 50, Safe Mode and freeze off.
SELECT pg_temp.check(
    (SELECT risk_alert_threshold = 50 AND risk_safe_mode_threshold IS NULL AND risk_freeze_threshold IS NULL
       FROM public.organizations WHERE id = '00000000-0000-0000-0000-000030000001'),
    'a new organization alerts at 50 and has Safe Mode and freeze off');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Signals for agent A. "now" is the transaction's now(); everything is dated relative to it.
CREATE FUNCTION pg_temp.finding(p_agent uuid, p_rule text, p_kind text, p_conf text, p_status text, p_age interval, p_place text DEFAULT 'text')
RETURNS void LANGUAGE sql AS $$
    INSERT INTO public.security_findings (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, window_start,
                                          first_seen_at, last_seen_at, review_status, tool_name)
    SELECT g.organization_id, p_agent, p_rule, 'test-family', p_kind, 'high', p_conf, p_place, now() - p_age, now() - p_age, now() - p_age,
           p_status, p_rule
    FROM public.agents g WHERE g.id = p_agent
$$;
CREATE FUNCTION pg_temp.event(p_agent uuid, p_seq bigint, p_decision text, p_reason text, p_age interval) RETURNS void LANGUAGE sql AS $$
    INSERT INTO public.agent_events (organization_id, agent_id, seq, occurred_at, gateway_instance, method, tool_name, decision, reasons,
                                     prev_hash, hash, batch_id)
    SELECT g.organization_id, p_agent, p_seq, now() - p_age, 'test', 'tools/call', 't', p_decision,
           CASE WHEN p_reason IS NULL THEN '{}'::text[] ELSE ARRAY[p_reason] END, 'x', 'y', gen_random_uuid()
    FROM public.agents g WHERE g.id = p_agent
$$;

-- trips: one recent, one three days old, one eight days old (outside the window)
INSERT INTO public.honeytrips (id, organization_id, agent_id, kind, ref_id, seen_in, occurred_at) VALUES
    (gen_random_uuid(), '00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'honeytoken', gen_random_uuid(), 'arguments', now() - interval '1 hour'),
    (gen_random_uuid(), '00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'honey_tool', gen_random_uuid(), 'call', now() - interval '3 days'),
    (gen_random_uuid(), '00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'honeytoken', gen_random_uuid(), 'result', now() - interval '8 days'),
    (gen_random_uuid(), '00000000-0000-0000-0000-000030000002', '00000000-0000-0000-0000-00003000000b', 'honeytoken', gen_random_uuid(), 'arguments', now() - interval '1 hour');

SELECT pg_temp.finding('00000000-0000-0000-0000-00003000000a', 'RAD-INJ-001', 'injection', 'medium', 'open', interval '2 hours');       -- radar_open
SELECT pg_temp.finding('00000000-0000-0000-0000-00003000000a', 'RAD-INJ-002', 'injection', 'low', 'open', interval '2 hours');          -- low: no
SELECT pg_temp.finding('00000000-0000-0000-0000-00003000000a', 'RAD-INJ-003', 'injection', 'high', 'false_alarm', interval '2 hours');  -- no
SELECT pg_temp.finding('00000000-0000-0000-0000-00003000000a', 'RAD-INJ-004', 'injection', 'high', 'open', interval '2 hours');         -- suppressed: no
SELECT pg_temp.finding('00000000-0000-0000-0000-00003000000a', 'RAD-INJ-005', 'injection', 'high', 'confirmed', interval '2 hours');    -- confirmed, despite a suppression
SELECT pg_temp.finding('00000000-0000-0000-0000-00003000000a', 'RAD-OUT-007', 'output', 'high', 'open', interval '4 days');             -- radar_open, older
SELECT pg_temp.finding('00000000-0000-0000-0000-00003000000a', 'RAD-OUT-001', 'output', 'high', 'open', interval '8 days');             -- outside the window
SELECT pg_temp.finding('00000000-0000-0000-0000-00003000000a', 'RAD-DST-001', 'destination', 'high', 'open', interval '1 hour', 'call'); -- destination_open
SELECT pg_temp.finding('00000000-0000-0000-0000-00003000000a', 'RAD-LOOP-001', 'loop', 'high', 'open', interval '1 hour', 'call');      -- loop_open
INSERT INTO public.radar_suppressions (organization_id, agent_id, rule_id, reason, created_by, expires_at) VALUES
    ('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'RAD-INJ-004', 'test silence', '00000000-0000-0000-0000-0000300a0001', now() + interval '1 day'),
    ('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'RAD-INJ-005', 'test silence', '00000000-0000-0000-0000-0000300a0001', now() + interval '1 day');

SELECT pg_temp.event('00000000-0000-0000-0000-00003000000a', 900001, 'BLOCK', 'Tool ''x'' on server ''s'' is not in this agent''s passport scopes.', interval '1 hour');
SELECT pg_temp.event('00000000-0000-0000-0000-00003000000a', 900002, 'BLOCK', 'Tool ''x'' on server ''s'' is not approved: its current version has not been reviewed.', interval '2 days');
SELECT pg_temp.event('00000000-0000-0000-0000-00003000000a', 900003, 'BLOCK', 'safe_mode', interval '1 hour');          -- not a refusal outside the passport
SELECT pg_temp.event('00000000-0000-0000-0000-00003000000a', 900004, 'ALLOW', NULL, interval '1 hour');

INSERT INTO public.agent_budget_state (agent_id, day_key, limit_reached_at) VALUES
    ('00000000-0000-0000-0000-00003000000a', current_date, now() - interval '3 hours'),
    ('00000000-0000-0000-0000-00003000000a', current_date - 3, now() - interval '3 days'),   -- older than 24 hours: no
    ('00000000-0000-0000-0000-00003000000b', current_date, now() - interval '1 hour');       -- organization B's agent (the budget table has no organization)

CREATE FUNCTION pg_temp.sig(p_org uuid, p_agent uuid, p_signal text) RETURNS text LANGUAGE sql AS $$
    SELECT coalesce((SELECT format('%s/%s/%s/%s', recent_all, older_all, recent_action, older_action)
                     FROM public.agent_risk_signals(p_org, p_agent, now()) WHERE signal = p_signal), 'none')
$$;

SELECT pg_temp.check(pg_temp.sig('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'trip') = '1/1/1/1',
    'trips: one in 24 hours, one older, the 8-day-old one ignored');
SELECT pg_temp.check(pg_temp.sig('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'radar_open') = '1/1/1/1',
    'open Radar findings: low confidence, false alarms, suppressed and 8-day-old ones are not counted');
SELECT pg_temp.check(pg_temp.sig('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'confirmed_finding') = '1/0/1/0',
    'a confirmed finding counts even under a suppression');
SELECT pg_temp.check(pg_temp.sig('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'destination_open') = '1/0/1/0',
    'an open destination finding is its own signal');
SELECT pg_temp.check(pg_temp.sig('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'loop_open') = '1/0/1/0',
    'an open loop finding is its own signal');
SELECT pg_temp.check(pg_temp.sig('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'refusal') = '1/1/1/1',
    'refusals: only the two passport reasons, not Safe Mode or an allowed call');
SELECT pg_temp.check(pg_temp.sig('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'budget_limit') = '1/0/1/0',
    'the budget limit counts only when reached in the last 24 hours');
SELECT pg_temp.check((SELECT count(*) FROM public.agent_risk_signals('00000000-0000-0000-0000-000030000001', NULL, now())
                      WHERE agent_id = '00000000-0000-0000-0000-00003000000a') = 7, 'every signal kind appears once for agent A');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_risk_signals('00000000-0000-0000-0000-000030000001', NULL, now())
                                 WHERE agent_id = '00000000-0000-0000-0000-00003000000c'), 'an agent with no signals returns no rows');

-- Tenancy: organization A never sees organization B's agent, even when asked for it by id.
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_risk_signals('00000000-0000-0000-0000-000030000001', NULL, now())
                                 WHERE agent_id = '00000000-0000-0000-0000-00003000000b'), 'organization A never lists B''s agent');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.agent_risk_signals('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000b', now())),
    'asking organization A for B''s agent by id returns nothing');
SELECT pg_temp.check(pg_temp.sig('00000000-0000-0000-0000-000030000002', '00000000-0000-0000-0000-00003000000b', 'trip') = '1/0/1/0',
    'organization B sees its own agent''s trip');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The release stamp: set by an unfreeze or by Safe Mode turned off, never by a freeze, Safe Mode on or a revoke.
UPDATE public.agents SET status = 'frozen' WHERE id = '00000000-0000-0000-0000-00003000000c';
SELECT pg_temp.check((SELECT risk_released_at IS NULL FROM public.agents WHERE id = '00000000-0000-0000-0000-00003000000c'), 'a freeze is not a release');
UPDATE public.agents SET status = 'active' WHERE id = '00000000-0000-0000-0000-00003000000c';
SELECT pg_temp.check((SELECT risk_released_at = now() FROM public.agents WHERE id = '00000000-0000-0000-0000-00003000000c'), 'an unfreeze stamps the release');
UPDATE public.agents SET risk_released_at = NULL, safe_mode = true WHERE id = '00000000-0000-0000-0000-00003000000c';
SELECT pg_temp.check((SELECT risk_released_at IS NULL FROM public.agents WHERE id = '00000000-0000-0000-0000-00003000000c'), 'Safe Mode on is not a release');
UPDATE public.agents SET safe_mode = false WHERE id = '00000000-0000-0000-0000-00003000000c';
SELECT pg_temp.check((SELECT risk_released_at = now() FROM public.agents WHERE id = '00000000-0000-0000-0000-00003000000c'), 'Safe Mode off stamps the release');
UPDATE public.agents SET risk_released_at = NULL, status = 'revoked' WHERE id = '00000000-0000-0000-0000-00003000000c';
SELECT pg_temp.check((SELECT risk_released_at IS NULL FROM public.agents WHERE id = '00000000-0000-0000-0000-00003000000c'), 'a revoke is not a release');

-- After a release, only later signals count towards actions; the shown counts keep everything.
UPDATE public.agents SET risk_released_at = now() - interval '90 minutes' WHERE id = '00000000-0000-0000-0000-00003000000a';
SELECT pg_temp.check(pg_temp.sig('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'trip') = '1/1/1/0',
    'after a release 90 minutes ago: the 1-hour-old trip still acts, the 3-day-old one is shown but does not act');
SELECT pg_temp.check(pg_temp.sig('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'radar_open') = '1/1/0/0',
    'a 2-hour-old finding is before the release: shown, not acted on');
SELECT pg_temp.check(pg_temp.sig('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 'budget_limit') = '1/0/0/0',
    'a limit reached before the release is shown, not acted on');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- control_risk_ladder: audited change, no change no audit, validation by the CHECK constraints.
SELECT pg_temp.check((public.control_risk_ladder('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-0000300a0001', 40, 70, 90, 'test'))->>'changed' = 'true',
    'a ladder change reports changed');
SELECT pg_temp.check((SELECT risk_alert_threshold = 40 AND risk_safe_mode_threshold = 70 AND risk_freeze_threshold = 90
                       FROM public.organizations WHERE id = '00000000-0000-0000-0000-000030000001'), 'the new ladder is stored');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE organization_id = '00000000-0000-0000-0000-000030000001'
                       AND action = 'organization.risk_ladder_changed'
                       AND details->'old'->>'alert' = '50' AND details->'new'->>'freeze' = '90') = 1, 'the change is audited with old and new values');
SELECT pg_temp.check((public.control_risk_ladder('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-0000300a0001', 40, 70, 90, 'again'))->>'changed' = 'false',
    'the same ladder again changes nothing');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE organization_id = '00000000-0000-0000-0000-000030000001'
                       AND action = 'organization.risk_ladder_changed') = 1, 'no change, no audit row');
SELECT pg_temp.check((public.control_risk_ladder('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-0000300a0001', NULL, NULL, NULL, 'all off'))->>'changed' = 'true',
    'every rung can be turned off');
SELECT pg_temp.expect_error($q$SELECT public.control_risk_ladder('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-0000300a0001', 80, 60, NULL, 'x')$q$,
    '23514', 'Safe Mode below alert is refused');
SELECT pg_temp.expect_error($q$SELECT public.control_risk_ladder('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-0000300a0001', NULL, 90, 70, 'x')$q$,
    '23514', 'freeze below Safe Mode is refused');
SELECT pg_temp.expect_error($q$SELECT public.control_risk_ladder('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-0000300a0001', 60, NULL, 50, 'x')$q$,
    '23514', 'freeze below alert is refused, even with Safe Mode off');
SELECT pg_temp.expect_error($q$SELECT public.control_risk_ladder('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-0000300a0001', 0, NULL, NULL, 'x')$q$,
    '23514', 'a threshold of 0 is refused');
SELECT pg_temp.expect_error($q$SELECT public.control_risk_ladder('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-0000300a0001', NULL, NULL, 101, 'x')$q$,
    '23514', 'a threshold of 101 is refused');
SELECT pg_temp.expect_error($q$SELECT public.control_risk_ladder('00000000-0000-0000-0000-0000300000ff', '00000000-0000-0000-0000-0000300a0001', 50, NULL, NULL, 'x')$q$,
    'P0002', 'an unknown organization is refused');
SELECT pg_temp.check((SELECT risk_alert_threshold = 50 FROM public.organizations WHERE id = '00000000-0000-0000-0000-000030000002'),
    'changing A''s ladder never touched B''s');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- risk_mark_alerted: true once per cooldown, never for another organization's agent.
SELECT pg_temp.check(public.risk_mark_alerted('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 3600), 'the first alert is allowed');
SELECT pg_temp.check(NOT public.risk_mark_alerted('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 3600), 'a second one within the hour is not');
SELECT pg_temp.check(NOT public.risk_mark_alerted('00000000-0000-0000-0000-000030000002', '00000000-0000-0000-0000-00003000000c', 3600),
    'organization B cannot mark A''s agent (one never alerted, so only the organization check can refuse it)');
SELECT pg_temp.check((SELECT risk_last_alert_at IS NULL FROM public.agents WHERE id = '00000000-0000-0000-0000-00003000000c'),
    'and nothing was stamped on it');
UPDATE public.agents SET risk_last_alert_at = now() - interval '61 minutes' WHERE id = '00000000-0000-0000-0000-00003000000a';
SELECT pg_temp.check(public.risk_mark_alerted('00000000-0000-0000-0000-000030000001', '00000000-0000-0000-0000-00003000000a', 3600), 'after the hour it is allowed again');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Grants: the service role only.
SELECT pg_temp.check(has_function_privilege('service_role', 'public.agent_risk_signals(uuid, uuid, timestamptz)', 'EXECUTE')
                 AND has_function_privilege('service_role', 'public.control_risk_ladder(uuid, uuid, integer, integer, integer, text)', 'EXECUTE')
                 AND has_function_privilege('service_role', 'public.risk_mark_alerted(uuid, uuid, integer)', 'EXECUTE'), 'the service role can call the functions');
SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.agent_risk_signals(uuid, uuid, timestamptz)', 'EXECUTE')
                 AND NOT has_function_privilege('anon', 'public.agent_risk_signals(uuid, uuid, timestamptz)', 'EXECUTE')
                 AND NOT has_function_privilege('authenticated', 'public.control_risk_ladder(uuid, uuid, integer, integer, integer, text)', 'EXECUTE')
                 AND NOT has_function_privilege('anon', 'public.risk_mark_alerted(uuid, uuid, integer)', 'EXECUTE'), 'signed-in users and anon cannot');

ROLLBACK;
