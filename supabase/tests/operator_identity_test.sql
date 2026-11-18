-- SQL tests for supabase/migrations/20261203000000_operator_identity.sql (ADR 0032, Clerk slice C1).

\set ON_ERROR_STOP on
\set QUIET on

BEGIN;

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'CHECK FAILED: %', p_msg; END IF;
    RAISE NOTICE 'ok: %', p_msg;
END $$;

-- Supabase sign-ups keep working: an auth.users row becomes an operator with the same UUID and a supabase identity.
INSERT INTO auth.users (id, email) VALUES ('00000000-0000-0000-0000-00000c1e0001', 'alice@example.com');
SELECT pg_temp.check((SELECT email = 'alice@example.com' FROM public.operators WHERE id = '00000000-0000-0000-0000-00000c1e0001'), 'a Supabase user becomes an operator with the same id');
SELECT pg_temp.check(EXISTS (SELECT 1 FROM public.operator_identities WHERE provider = 'supabase' AND subject = '00000000-0000-0000-0000-00000c1e0001'), 'with a supabase identity');
UPDATE auth.users SET email = 'alice@new.example.com' WHERE id = '00000000-0000-0000-0000-00000c1e0001';
SELECT pg_temp.check((SELECT email = 'alice@new.example.com' FROM public.operators WHERE id = '00000000-0000-0000-0000-00000c1e0001'), 'an e-mail change follows');

-- Clerk: created on first use, the same id afterwards, never matched by e-mail.
CREATE TEMP TABLE ids AS SELECT public.operator_resolve('clerk', 'user_2abcDEF', 'bob@example.com') AS a, public.operator_resolve('clerk', 'user_2abcDEF', 'bob@example.com') AS b;
SELECT pg_temp.check((SELECT a = b AND a IS NOT NULL FROM ids), 'the same Clerk subject always resolves to the same operator');
SELECT pg_temp.check(public.operator_resolve('clerk', 'user_attacker', 'alice@new.example.com') <> '00000000-0000-0000-0000-00000c1e0001',
    'a Clerk identity that claims an existing e-mail gets a NEW operator, never the existing account');
SELECT pg_temp.check((SELECT count(*) FROM public.operators WHERE email = 'alice@new.example.com') = 2, 'both people exist apart (no linking)');
SELECT pg_temp.check(public.operator_resolve('clerk', '00000000-0000-0000-0000-00000c1e0001', NULL) <> '00000000-0000-0000-0000-00000c1e0001',
    'a Clerk subject that looks like a Supabase id does not reach the Supabase account');
SELECT public.operator_resolve('clerk', 'user_2abcDEF', 'bob@changed.example.com');
SELECT pg_temp.check((SELECT o.email = 'bob@changed.example.com' FROM public.operators o JOIN public.operator_identities i ON i.operator_id = o.id WHERE i.subject = 'user_2abcDEF'),
    'a verified e-mail change refreshes the display e-mail');

DO $$ BEGIN
    BEGIN PERFORM public.operator_resolve('supabase', 'x', NULL); RAISE EXCEPTION 'supabase resolve accepted'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
    BEGIN PERFORM public.operator_resolve('clerk', '', NULL); RAISE EXCEPTION 'empty subject accepted'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
    BEGIN PERFORM public.operator_resolve('clerk', repeat('x', 256), NULL); RAISE EXCEPTION 'long subject accepted'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
    BEGIN PERFORM public.operator_resolve('google', 'x', NULL); RAISE EXCEPTION 'unknown provider accepted'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
END $$;
SELECT pg_temp.check(true, 'resolve refuses supabase, unknown providers, empty and oversized subjects');

-- A Clerk operator can be an organization member (the foreign keys point at operators now), and the member list shows the e-mail.
INSERT INTO public.organizations (id, name, slug) VALUES ('00000000-0000-0000-0000-00000c1e00f0', 'Clerk Org', 'clerk-org');
INSERT INTO public.organization_members (organization_id, user_id, role) SELECT '00000000-0000-0000-0000-00000c1e00f0', a, 'owner' FROM ids;
SELECT pg_temp.check((SELECT email = 'bob@changed.example.com' FROM public.list_organization_members('00000000-0000-0000-0000-00000c1e00f0')), 'members list the operator e-mail');
SELECT pg_temp.check((SELECT (public.tenant_table_rows(jsonb_build_object('table', 'organization_members', 'scope', 'members', 'exclude', '[]'::jsonb),
                        '00000000-0000-0000-0000-00000c1e00f0', 10) -> 'rows' -> 0 ->> 'email') = 'bob@changed.example.com'), 'the tenant export lists the operator e-mail');
DO $$ BEGIN
    BEGIN INSERT INTO public.organization_members (organization_id, user_id, role) VALUES ('00000000-0000-0000-0000-00000c1e00f0', gen_random_uuid(), 'viewer');
        RAISE EXCEPTION 'a member with no operator was accepted'; EXCEPTION WHEN foreign_key_violation THEN NULL; END;
END $$;
SELECT pg_temp.check(true, 'a member id that is not an operator is refused (foreign key)');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM pg_constraint WHERE contype = 'f' AND confrelid = 'auth.users'::regclass AND connamespace = 'public'::regnamespace),
    'no public table references auth.users any more');

-- Access.
SELECT pg_temp.check(NOT has_function_privilege('anon', 'public.operator_resolve(text, text, text)', 'EXECUTE')
                     AND NOT has_function_privilege('authenticated', 'public.operator_resolve(text, text, text)', 'EXECUTE')
                     AND has_function_privilege('service_role', 'public.operator_resolve(text, text, text)', 'EXECUTE'), 'only service_role may resolve');
SELECT pg_temp.check((SELECT relrowsecurity FROM pg_class WHERE oid = 'public.operators'::regclass) AND (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.operator_identities'::regclass),
    'row-level security is on for both tables');

DO $$ BEGIN RAISE NOTICE 'ALL SQL TESTS PASSED'; END $$;
ROLLBACK;
