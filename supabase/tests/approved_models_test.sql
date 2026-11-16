-- SQL tests for supabase/migrations/20261126000000_approved_models.sql (Phase 4.5 B4b, approved models).

\set ON_ERROR_STOP on
\set QUIET on

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

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000700a0001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-000070000001', 'Approved Org A', 'approved-org-a'),
    ('00000000-0000-0000-0000-000070000002', 'Approved Org B', 'approved-org-b'),
    ('00000000-0000-0000-0000-000070000003', 'Approved Org C', 'approved-org-c');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-00007000000a', '00000000-0000-0000-0000-000070000001', 'appr-bot-a', 'Appr Bot A'),
    ('00000000-0000-0000-0000-00007000000b', '00000000-0000-0000-0000-000070000002', 'appr-bot-b', 'Appr Bot B');

CREATE FUNCTION pg_temp.set_list(p_org uuid, p_items jsonb, p_expected integer) RETURNS jsonb LANGUAGE sql AS $$
    SELECT public.control_approved_models(p_org, '00000000-0000-0000-0000-0000700a0001', p_items, 'test', p_expected)
$$;
CREATE FUNCTION pg_temp.record(p_org uuid, p_agent uuid, p_items jsonb) RETURNS jsonb LANGUAGE sql AS $$
    SELECT public.record_model_findings(p_org, p_agent, p_items)
$$;

-- ---------------------------------------------------------------------------------------------------------------------------------
-- No list means no check: nothing is flagged until an admin sets one (owner decision D5).
SELECT pg_temp.check((SELECT count(*) FROM public.approved_models_list('00000000-0000-0000-0000-000070000001')) = 0, 'a new organization has no approved list');
SELECT pg_temp.check((pg_temp.record('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a',
        '[{"provider":"openai","model":"gpt-x"}]') ->> 'new')::integer = 0, 'with no list nothing is flagged');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Setting the list: normalized, de-duplicated, bounded, audited, compare-and-set.
SELECT pg_temp.check((pg_temp.set_list('00000000-0000-0000-0000-000070000001',
        '[{"provider":" Anthropic ","model":"Claude-Sonnet-5-5"},{"provider":"anthropic","model":"claude-sonnet-5-5"},{"provider":"anthropic","model":"claude-haiku-5-5"}]', 0)
        ->> 'changed')::boolean, 'a list is set');
SELECT pg_temp.check((SELECT count(*) FROM public.approved_models_list('00000000-0000-0000-0000-000070000001')) = 2,
    'entries are trimmed, lower-cased and de-duplicated');
SELECT pg_temp.check((SELECT approved_models_version FROM public.organizations WHERE id = '00000000-0000-0000-0000-000070000001') = 1, 'the version counts changes');
SELECT pg_temp.check((pg_temp.set_list('00000000-0000-0000-0000-000070000001',
        '[{"provider":"anthropic","model":"claude-haiku-5-5"},{"provider":"anthropic","model":"claude-sonnet-5-5"}]', 1) ->> 'changed')::boolean = false,
    'the same list again changes nothing');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'organization.approved_models_changed') = 1, 'one audit row, none for the no-op');
SELECT pg_temp.check((pg_temp.set_list('00000000-0000-0000-0000-000070000001', '[]', 0) ->> 'conflict')::boolean,
    'a caller that decided on an old version gets a conflict');
SELECT pg_temp.check((SELECT count(*) FROM public.approved_models_list('00000000-0000-0000-0000-000070000001')) = 2, 'and nothing changed');
SELECT pg_temp.check(pg_temp.raises($$SELECT pg_temp.set_list('00000000-0000-0000-0000-000070000001', '[{"provider":"a b","model":"x"}]', 1)$$)
                 AND pg_temp.raises($$SELECT pg_temp.set_list('00000000-0000-0000-0000-000070000001', '[{"provider":"","model":"x"}]', 1)$$)
                 AND pg_temp.raises($$SELECT pg_temp.set_list('00000000-0000-0000-0000-000070000001', '[{"provider":"a","model":"<x>"}]', 1)$$)
                 AND pg_temp.raises($$SELECT pg_temp.set_list('00000000-0000-0000-0000-000070000001', '{"not":"an array"}', 1)$$)
                 AND pg_temp.raises($$SELECT pg_temp.set_list('00000000-0000-0000-0000-000070000001', '["text"]', 1)$$),
    'malformed entries, spaces, markup and a non-array are refused');
SELECT pg_temp.check(pg_temp.raises(format($$SELECT pg_temp.set_list('00000000-0000-0000-0000-000070000001', %L::jsonb, 1)$$,
        (SELECT jsonb_agg(jsonb_build_object('provider', 'p', 'model', 'm' || n)) FROM generate_series(1, 51) n))),
    'more than 50 entries are refused');
SELECT pg_temp.check((pg_temp.set_list('00000000-0000-0000-0000-000070000001',
        (SELECT jsonb_agg(jsonb_build_object('provider', 'p', 'model', 'm' || n)) FROM generate_series(1, 50) n), 1) ->> 'changed')::boolean, 'exactly 50 entries are accepted');
SELECT pg_temp.set_list('00000000-0000-0000-0000-000070000001', '[{"provider":"anthropic","model":"claude-sonnet-5-5"}]', 2);
SELECT pg_temp.check(pg_temp.raises($$SELECT pg_temp.set_list('00000000-0000-0000-0000-0000deadbeef01', '[]', 0)$$), 'an unknown organization is refused');
SELECT pg_temp.check((SELECT count(*) FROM public.approved_models_list('00000000-0000-0000-0000-000070000002')) = 0, 'organization B''s list is untouched and separate');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- The check: a model outside the list is one finding, RAD-MDL-001, named by a sanitized model.
SELECT pg_temp.check((pg_temp.record('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a',
        '[{"provider":"anthropic","model":"Claude-Sonnet-5-5"},{"provider":"anthropic","model":"claude-sonnet-5-5-20260301"}]') ->> 'new')::integer = 0,
    'approved models raise nothing, whatever the case, and a dated id of an approved model is approved');
SELECT pg_temp.check((pg_temp.record('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a',
        '[{"provider":"OpenAI","model":"GPT-X"},{"provider":"anthropic","model":"claude-sonnet-5-5"}]') ->> 'new')::integer = 1,
    'one unapproved model is one new finding');
SELECT pg_temp.check((SELECT rule_id = 'RAD-MDL-001' AND kind = 'model' AND family = 'model' AND place = 'call' AND tool_name = 'openai/gpt-x'
                             AND confidence = 'high' AND severity = 'medium' AND review_status = 'open'
                      FROM public.security_findings WHERE agent_id = '00000000-0000-0000-0000-00007000000a'), 'the finding names the normalized provider/model');
SELECT pg_temp.check((SELECT model_last_alert_at IS NOT NULL FROM public.agents WHERE id = '00000000-0000-0000-0000-00007000000a'), 'the first finding started the alert cooldown');
SELECT pg_temp.check((pg_temp.record('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a',
        '[{"provider":"openai","model":"gpt-x"}]') ->> 'new')::integer = 0, 'the same model in the same window is not a new finding');
SELECT pg_temp.check((SELECT occurrences FROM public.security_findings WHERE agent_id = '00000000-0000-0000-0000-00007000000a') = 2, 'its occurrences went up instead');
SELECT pg_temp.check((pg_temp.record('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a',
        '[{"provider":"openai","model":"gpt-y"}]') ->> 'alert')::boolean = false, 'a second model inside the cooldown is recorded but does not alert again');
UPDATE public.agents SET model_last_alert_at = now() - interval '11 minutes' WHERE id = '00000000-0000-0000-0000-00007000000a';
SELECT pg_temp.check((pg_temp.record('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a',
        '[{"provider":"openai","model":"gpt-z"}]') ->> 'alert')::boolean, 'after 10 minutes a new model alerts again');

-- Hostile names are made safe before they are stored; bad input is skipped, not fatal.
SELECT pg_temp.record('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a',
        jsonb_build_array(jsonb_build_object('provider', 'evil', 'model', E'<script>alert(1)</script>\n‮' || repeat('x', 300)), 'text', jsonb_build_object('provider', 5)));
SELECT pg_temp.check((SELECT bool_and(tool_name ~ '^[a-z0-9_.:/-]{1,128}$') FROM public.security_findings WHERE agent_id = '00000000-0000-0000-0000-00007000000a'),
    'every stored model name is plain characters and at most 128 long');
SELECT pg_temp.check(pg_temp.raises(format($$SELECT pg_temp.record('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a', %L::jsonb)$$,
        (SELECT jsonb_agg(jsonb_build_object('provider', 'p', 'model', 'm' || n)) FROM generate_series(1, 21) n))), 'more than 20 models in one report are refused');

-- Another organization's agent cannot be reported through this organization.
SELECT pg_temp.check(pg_temp.raises($$SELECT pg_temp.record('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000b', '[{"provider":"p","model":"m"}]')$$),
    'an agent of another organization is refused');

-- Another organization's list approves nothing here.
SELECT pg_temp.set_list('00000000-0000-0000-0000-000070000002', '[{"provider":"acme","model":"only-in-b"}]', 0);
SELECT pg_temp.check((pg_temp.record('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a',
        '[{"provider":"acme","model":"only-in-b"}]') ->> 'new')::integer = 1, 'a model approved by another organization is still flagged here');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- A silence works like any other rule's.
SELECT public.control_radar_suppression_create('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-0000700a0001',
        '00000000-0000-0000-0000-00007000000a', 'RAD-MDL-001', 7, 'known pilot model');
SELECT pg_temp.check((pg_temp.record('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a',
        '[{"provider":"openai","model":"gpt-silenced"}]') ->> 'suppressed')::integer = 1
    AND NOT EXISTS (SELECT 1 FROM public.security_findings WHERE tool_name = 'openai/gpt-silenced'), 'a silence stops new RAD-MDL-001 findings for that agent');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_radar_suppression_create('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-0000700a0001',
        '00000000-0000-0000-0000-00007000000a', 'RAD-XXX-001', 7, 'bad rule')$$), 'other rule ids are still refused');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Risk: a model finding adds NOTHING to the Risk score (owner decision D4), open or confirmed, and the other kinds still count.
SELECT pg_temp.check((SELECT count(*) FROM public.agent_risk_signals('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a', now())) = 0,
    'open model findings add no risk signal');
UPDATE public.security_findings SET review_status = 'confirmed' WHERE kind = 'model';
SELECT pg_temp.check((SELECT count(*) FROM public.agent_risk_signals('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a', now())) = 0,
    'even confirmed model findings add no risk signal');
INSERT INTO public.security_findings (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, tool_name, window_start)
VALUES ('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a', 'RAD-INJ-001', 'override', 'injection', 'high', 'high', 'text', 't', now());
SELECT pg_temp.check((SELECT signal FROM public.agent_risk_signals('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a', now())) = 'radar_open',
    'an injection finding still counts');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Constraints and privileges.
SELECT pg_temp.check(pg_temp.raises($$INSERT INTO public.security_findings (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, window_start)
    VALUES ('00000000-0000-0000-0000-000070000001', '00000000-0000-0000-0000-00007000000a', 'RAD-INJ-001', 'x', 'bogus', 'low', 'low', 'text', now())$$), 'an unknown kind is still refused');
SELECT pg_temp.check(NOT has_function_privilege('anon', 'public.record_model_findings(uuid, uuid, jsonb)', 'EXECUTE')
                 AND NOT has_function_privilege('authenticated', 'public.control_approved_models(uuid, uuid, jsonb, text, integer)', 'EXECUTE')
                 AND NOT has_function_privilege('authenticated', 'public.approved_models_list(uuid)', 'EXECUTE'), 'signed-in users and anon cannot call the functions');
SELECT pg_temp.check((SELECT relrowsecurity FROM pg_class WHERE oid = 'public.approved_models'::regclass), 'row level security is on');
INSERT INTO public.approved_models (organization_id, provider, model) VALUES ('00000000-0000-0000-0000-000070000003', 'p', 'm');
DELETE FROM public.organizations WHERE id = '00000000-0000-0000-0000-000070000003';  -- (one with audit rows cannot be deleted: the audit log is append-only)
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.approved_models WHERE organization_id = '00000000-0000-0000-0000-000070000003'), 'deleting an organization deletes its list');

ROLLBACK;
