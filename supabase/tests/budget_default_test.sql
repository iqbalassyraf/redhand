-- SQL tests for supabase/migrations/20261106000200_budget_default.sql.

\set ON_ERROR_STOP on
\set QUIET on

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'CHECK FAILED: %', p_msg; END IF;
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

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000b0b00001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000b0b00008', 'Default Org 1', 'default-org-1'),
    ('00000000-0000-0000-0000-0000b0b00009', 'Default Org 2', 'default-org-2');

SELECT pg_temp.check((SELECT default_daily_call_limit IS NULL FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000b0b00008'),
    'an organization has no default limit unless one is set');
SELECT pg_temp.expect_error($$UPDATE public.organizations SET default_daily_call_limit = 0 WHERE id = '00000000-0000-0000-0000-0000b0b00008'$$, '23514', 'a default of 0 is refused');
SELECT pg_temp.expect_error($$UPDATE public.organizations SET default_daily_call_limit = 10000001 WHERE id = '00000000-0000-0000-0000-0000b0b00008'$$, '23514', 'a default above 10,000,000 is refused');

DO $$
DECLARE r jsonb;
BEGIN
    r := public.control_org_budget_default('00000000-0000-0000-0000-0000b0b00008', '00000000-0000-0000-0000-0000b0b00001', 200, 'cap new agents', NULL);
    PERFORM pg_temp.check((r->>'changed')::boolean AND (r->>'default_daily_call_limit')::int = 200, 'the default is set');
    PERFORM pg_temp.check((SELECT count(*) FROM public.control_audit_log
        WHERE action = 'organization.budget_default_changed' AND target_type = 'organization'
          AND target_id = '00000000-0000-0000-0000-0000b0b00008' AND reason = 'cap new agents'
          AND details->>'old_limit' IS NULL AND (details->>'new_limit')::int = 200) = 1, 'the change is audited with old and new values');
    r := public.control_org_budget_default('00000000-0000-0000-0000-0000b0b00008', '00000000-0000-0000-0000-0000b0b00001', 200, NULL, 200);
    PERFORM pg_temp.check(NOT (r->>'changed')::boolean, 'setting the same value changes nothing');
    PERFORM pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'organization.budget_default_changed') = 1, 'and writes no second audit row');
    r := public.control_org_budget_default('00000000-0000-0000-0000-0000b0b00008', '00000000-0000-0000-0000-0000b0b00001', 50, NULL, 7);
    PERFORM pg_temp.check((r->>'conflict')::boolean, 'a stale expectation returns a conflict');
    PERFORM pg_temp.check((SELECT default_daily_call_limit FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000b0b00008') = 200, 'and changes nothing');
    r := public.control_org_budget_default('00000000-0000-0000-0000-0000b0b00008', '00000000-0000-0000-0000-0000b0b00001', NULL, 'remove', 200);
    PERFORM pg_temp.check((r->>'changed')::boolean AND (r->'default_daily_call_limit') = 'null'::jsonb, 'the default can be removed');
    PERFORM pg_temp.check((SELECT default_daily_call_limit IS NULL FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000b0b00009'), 'another organization is untouched');
END $$;
SELECT pg_temp.expect_error($$SELECT public.control_org_budget_default('00000000-0000-0000-0000-0000b0b000ff', '00000000-0000-0000-0000-0000b0b00001', 5, NULL, NULL)$$, 'P0002', 'an unknown organization is not found');
SELECT pg_temp.expect_error($$SELECT public.control_org_budget_default('00000000-0000-0000-0000-0000b0b00008', '00000000-0000-0000-0000-0000b0b00001', 0, NULL, NULL)$$, '23514', 'an invalid value through the function is refused');

CREATE FUNCTION public.zz_default_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'simulated audit failure'; END $$;
CREATE TRIGGER zz_default_fail_audit BEFORE INSERT ON public.control_audit_log FOR EACH ROW EXECUTE FUNCTION public.zz_default_fail_audit();
SELECT pg_temp.expect_error($$SELECT public.control_org_budget_default('00000000-0000-0000-0000-0000b0b00009', '00000000-0000-0000-0000-0000b0b00001', 9, NULL, NULL)$$, 'P0001', 'atomic: a failing audit aborts the change');
SELECT pg_temp.check((SELECT default_daily_call_limit IS NULL FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000b0b00009'), 'atomic: the organization is unchanged');
DROP TRIGGER zz_default_fail_audit ON public.control_audit_log;
DROP FUNCTION public.zz_default_fail_audit();

SELECT pg_temp.check(NOT has_function_privilege('anon', 'public.control_org_budget_default(uuid,uuid,integer,text,integer)', 'EXECUTE')
                 AND NOT has_function_privilege('authenticated', 'public.control_org_budget_default(uuid,uuid,integer,text,integer)', 'EXECUTE')
                 AND has_function_privilege('service_role', 'public.control_org_budget_default(uuid,uuid,integer,text,integer)', 'EXECUTE'),
    'only service_role may execute it');

DO $$ BEGIN RAISE NOTICE 'ALL SQL TESTS PASSED (budget_default)'; END $$;
