-- SQL tests for supabase/migrations/20261104000000_safe_mode.sql.
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

-- Fixtures: two organizations, one agent each --------------------------------------------------
INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000000000b1');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000000000b8', 'Safe Org 1', 'safe-org-1'),
    ('00000000-0000-0000-0000-0000000000b9', 'Safe Org 2', 'safe-org-2');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000000000ba', '00000000-0000-0000-0000-0000000000b8', 'safe-bot-1', 'Safe Bot 1'),
    ('00000000-0000-0000-0000-0000000000bb', '00000000-0000-0000-0000-0000000000b9', 'safe-bot-2', 'Safe Bot 2');

-- 1. Defaults ----------------------------------------------------------------------------------
SELECT pg_temp.check(
    NOT (SELECT safe_mode FROM public.agents WHERE id = '00000000-0000-0000-0000-0000000000ba')
    AND NOT (SELECT safe_mode FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000000000b8'),
    'Safe Mode is off by default for agents and organizations');

-- 2. Agent flag --------------------------------------------------------------------------------
DO $$
DECLARE r jsonb;
BEGIN
    r := public.control_agent_safe_mode('00000000-0000-0000-0000-0000000000b8', '00000000-0000-0000-0000-0000000000ba',
                                        '00000000-0000-0000-0000-0000000000b1', true, 'incident');
    PERFORM pg_temp.check((r->>'changed')::boolean AND (r->>'enabled')::boolean, 'agent: turned on');
    PERFORM pg_temp.check((SELECT safe_mode FROM public.agents WHERE id = '00000000-0000-0000-0000-0000000000ba'), 'agent: flag stored');
    PERFORM pg_temp.check(
        (SELECT count(*) FROM public.control_audit_log
         WHERE action = 'passport.safe_mode_enabled' AND target_type = 'agent'
           AND target_id = '00000000-0000-0000-0000-0000000000ba' AND reason = 'incident') = 1,
        'agent: audited with actor and reason');

    r := public.control_agent_safe_mode('00000000-0000-0000-0000-0000000000b8', '00000000-0000-0000-0000-0000000000ba',
                                        '00000000-0000-0000-0000-0000000000b1', true, NULL);
    PERFORM pg_temp.check(NOT (r->>'changed')::boolean, 'agent: repeating changes nothing');
    PERFORM pg_temp.check(
        (SELECT count(*) FROM public.control_audit_log WHERE action = 'passport.safe_mode_enabled') = 1,
        'agent: repeating writes no second audit row');

    r := public.control_agent_safe_mode('00000000-0000-0000-0000-0000000000b8', '00000000-0000-0000-0000-0000000000ba',
                                        '00000000-0000-0000-0000-0000000000b1', false, NULL);
    PERFORM pg_temp.check((r->>'changed')::boolean AND NOT (r->>'enabled')::boolean, 'agent: turned off');
    PERFORM pg_temp.check(
        (SELECT count(*) FROM public.control_audit_log WHERE action = 'passport.safe_mode_disabled') = 1,
        'agent: turning off is audited');
END $$;

SELECT pg_temp.expect_error(
    $$SELECT public.control_agent_safe_mode('00000000-0000-0000-0000-0000000000b9', '00000000-0000-0000-0000-0000000000ba',
                                            '00000000-0000-0000-0000-0000000000b1', true, NULL)$$,
    'P0002', 'agent: another organization cannot change it');
SELECT pg_temp.check(
    NOT (SELECT safe_mode FROM public.agents WHERE id = '00000000-0000-0000-0000-0000000000ba'),
    'agent: refused cross-tenant call changed nothing');

-- 3. Organization flag -------------------------------------------------------------------------
DO $$
DECLARE r jsonb;
BEGIN
    r := public.control_org_safe_mode('00000000-0000-0000-0000-0000000000b8', '00000000-0000-0000-0000-0000000000b1', true, 'incident');
    PERFORM pg_temp.check((r->>'changed')::boolean, 'organization: turned on');
    PERFORM pg_temp.check((SELECT safe_mode FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000000000b8'), 'organization: flag stored');
    PERFORM pg_temp.check(
        NOT (SELECT safe_mode FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000000000b9')
        AND NOT (SELECT safe_mode FROM public.agents WHERE id = '00000000-0000-0000-0000-0000000000bb'),
        'organization: another tenant is untouched');
    PERFORM pg_temp.check(
        (SELECT count(*) FROM public.control_audit_log
         WHERE action = 'organization.safe_mode_enabled' AND target_type = 'organization'
           AND target_id = '00000000-0000-0000-0000-0000000000b8') = 1,
        'organization: audited');
    r := public.control_org_safe_mode('00000000-0000-0000-0000-0000000000b8', '00000000-0000-0000-0000-0000000000b1', true, NULL);
    PERFORM pg_temp.check(NOT (r->>'changed')::boolean, 'organization: repeating changes nothing');
END $$;
SELECT pg_temp.expect_error(
    $$SELECT public.control_org_safe_mode('00000000-0000-0000-0000-0000000000ff', '00000000-0000-0000-0000-0000000000b1', true, NULL)$$,
    'P0002', 'organization: unknown organization is not found');

-- 4. Atomic: a failing audit insert undoes the change ----------------------------------------------
CREATE FUNCTION public.zz_safe_mode_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'simulated audit failure'; END $$;
CREATE TRIGGER zz_safe_mode_fail_audit BEFORE INSERT ON public.control_audit_log
    FOR EACH ROW EXECUTE FUNCTION public.zz_safe_mode_fail_audit();
SELECT pg_temp.expect_error(
    $$SELECT public.control_agent_safe_mode('00000000-0000-0000-0000-0000000000b9', '00000000-0000-0000-0000-0000000000bb',
                                            '00000000-0000-0000-0000-0000000000b1', true, NULL)$$,
    'P0001', 'atomic: a failing audit aborts the agent change');
SELECT pg_temp.check(
    NOT (SELECT safe_mode FROM public.agents WHERE id = '00000000-0000-0000-0000-0000000000bb'),
    'atomic: agent unchanged after the failed audit');
SELECT pg_temp.expect_error(
    $$SELECT public.control_org_safe_mode('00000000-0000-0000-0000-0000000000b9', '00000000-0000-0000-0000-0000000000b1', true, NULL)$$,
    'P0001', 'atomic: a failing audit aborts the organization change');
SELECT pg_temp.check(
    NOT (SELECT safe_mode FROM public.organizations WHERE id = '00000000-0000-0000-0000-0000000000b9'),
    'atomic: organization unchanged after the failed audit');
DROP TRIGGER zz_safe_mode_fail_audit ON public.control_audit_log;
DROP FUNCTION public.zz_safe_mode_fail_audit();

-- 5. Access ------------------------------------------------------------------------------------
DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['control_agent_safe_mode(uuid,uuid,uuid,boolean,text)', 'control_org_safe_mode(uuid,uuid,boolean,text)'] LOOP
        PERFORM pg_temp.check(NOT has_function_privilege('anon', 'public.' || f, 'EXECUTE')
                          AND NOT has_function_privilege('authenticated', 'public.' || f, 'EXECUTE'),
            f || ' is not executable by anon or authenticated');
        PERFORM pg_temp.check(has_function_privilege('service_role', 'public.' || f, 'EXECUTE'),
            f || ' is executable by service_role');
    END LOOP;
END $$;

DO $$ BEGIN RAISE NOTICE 'ALL SQL TESTS PASSED (safe_mode)'; END $$;
