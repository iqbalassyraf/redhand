-- SQL tests for supabase/migrations/20261128000000_reported_only.sql (Phase 4.5 C1b, telemetry trust).

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

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000900a0001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-000090000001', 'Trust Org A', 'trust-org-a'),
    ('00000000-0000-0000-0000-000090000002', 'Trust Org B', 'trust-org-b');
INSERT INTO public.agents (id, organization_id, external_agent_id, name, framework, environment) VALUES
    ('00000000-0000-0000-0000-00009000000a', '00000000-0000-0000-0000-000090000001', 'payroll', 'Payroll bot', 'n8n', 'production');

CREATE FUNCTION pg_temp.resolve(p_org uuid, p_external text, p_name text, p_env text DEFAULT 'production') RETURNS jsonb LANGUAGE sql AS $$
    SELECT public.telemetry_resolve_agent(p_org, p_external, p_env, p_name, 'sdk-fw')
$$;

-- ---------------------------------------------------------------------------------------------------------------------------------
-- An existing passport is found, never changed (only its heartbeat moves).
SELECT pg_temp.check((pg_temp.resolve('00000000-0000-0000-0000-000090000001', 'payroll', 'Evil Name') ->> 'id') = '00000000-0000-0000-0000-00009000000a',
    'an existing passport is resolved by its external id');
SELECT pg_temp.check((SELECT name = 'Payroll bot' AND framework = 'n8n' AND NOT reported_only AND last_heartbeat_at IS NOT NULL
                      FROM public.agents WHERE id = '00000000-0000-0000-0000-00009000000a'),
    'its name, framework and reported-only flag are untouched; only the heartbeat is set');
SELECT pg_temp.check((SELECT count(*) FROM public.agents WHERE external_agent_id = 'payroll') = 1, 'no second row was made');

-- A new external id becomes a reported-only passport, and keeps its first name.
SELECT pg_temp.check((pg_temp.resolve('00000000-0000-0000-0000-000090000001', 'brand-new', 'First') ->> 'reported_only')::boolean, 'a new agent id is reported only');
SELECT pg_temp.resolve('00000000-0000-0000-0000-000090000001', 'brand-new', 'Second');
SELECT pg_temp.check((SELECT name FROM public.agents WHERE external_agent_id = 'brand-new') = 'First', 'reporting again keeps the first name');
SELECT pg_temp.check((SELECT count(*) FROM public.agents WHERE external_agent_id = 'payroll' AND organization_id = '00000000-0000-0000-0000-000090000002') = 0
                 AND (pg_temp.resolve('00000000-0000-0000-0000-000090000002', 'payroll', 'B''s own') ->> 'id') <> '00000000-0000-0000-0000-00009000000a',
    'the same external id in another organization is a separate, new agent');
SELECT pg_temp.resolve('00000000-0000-0000-0000-000090000001', 'long', repeat('n', 400));
SELECT pg_temp.check((SELECT char_length(name) FROM public.agents WHERE external_agent_id = 'long') = 256, 'an overlong name is cut to 256 characters');
SELECT pg_temp.check(pg_temp.raises($$SELECT pg_temp.resolve('00000000-0000-0000-0000-000090000001', '', 'x')$$)
                 AND pg_temp.raises($$SELECT pg_temp.resolve('00000000-0000-0000-0000-000090000001', 'x', 'x', 'moon')$$),
    'an empty external id or an unknown environment is refused');
SELECT pg_temp.check((SELECT count(*) FROM public.agents WHERE reported_only AND id = '00000000-0000-0000-0000-00009000000a') = 0
                 AND (SELECT bool_and(NOT reported_only) FROM public.agents WHERE created_at < now() - interval '1 second' OR id = '00000000-0000-0000-0000-00009000000a'),
    'existing passports default to not reported only');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Promote: audited, idempotent, organization-scoped, never for a revoked passport.
CREATE FUNCTION pg_temp.agent(p_external text, p_org uuid DEFAULT '00000000-0000-0000-0000-000090000001') RETURNS uuid LANGUAGE sql AS $$
    SELECT id FROM public.agents WHERE external_agent_id = p_external AND organization_id = p_org
$$;
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_passport_promote('00000000-0000-0000-0000-000090000002', pg_temp.agent('brand-new'), '00000000-0000-0000-0000-0000900a0001', 'x')$$),
    'another organization cannot promote this agent');
SELECT pg_temp.check((public.control_passport_promote('00000000-0000-0000-0000-000090000001', pg_temp.agent('brand-new'), '00000000-0000-0000-0000-0000900a0001', 'reviewed') ->> 'changed')::boolean,
    'the owning organization promotes it');
SELECT pg_temp.check((SELECT NOT reported_only FROM public.agents WHERE id = pg_temp.agent('brand-new')), 'it is no longer reported only');
SELECT pg_temp.check(NOT (public.control_passport_promote('00000000-0000-0000-0000-000090000001', pg_temp.agent('brand-new'), '00000000-0000-0000-0000-0000900a0001', 'again') ->> 'changed')::boolean,
    'promoting again changes nothing');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'passport.promoted') = 1, 'one audit row, none for the no-op');
UPDATE public.agents SET status = 'revoked' WHERE id = pg_temp.agent('long');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_passport_promote('00000000-0000-0000-0000-000090000001', pg_temp.agent('long'), '00000000-0000-0000-0000-0000900a0001', 'x')$$),
    'a revoked passport cannot be promoted');

SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.telemetry_resolve_agent(uuid, text, text, text, text)', 'EXECUTE')
                 AND NOT has_function_privilege('anon', 'public.control_passport_promote(uuid, uuid, uuid, text)', 'EXECUTE'), 'signed-in users and anon cannot call the functions');

ROLLBACK;
