-- SQL tests for supabase/migrations/20261102000100_function_hardening.sql.
-- Run by scripts/test_migrations.sh after all migrations are applied.

\set ON_ERROR_STOP on
\set QUIET on

DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY['trigger_set_updated_at', 'trigger_agents_passport_rules', 'trigger_control_audit_append_only']
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname = f
              AND p.proconfig @> ARRAY['search_path=public, pg_temp']
        ) THEN
            RAISE EXCEPTION 'CHECK FAILED: % does not have a pinned search_path', f;
        END IF;
        RAISE NOTICE 'ok: % has a pinned search_path', f;
    END LOOP;

    IF has_function_privilege('anon', 'public.get_user_organization_ids()', 'EXECUTE') THEN
        RAISE EXCEPTION 'CHECK FAILED: anon can still execute get_user_organization_ids()';
    END IF;
    RAISE NOTICE 'ok: anon cannot execute get_user_organization_ids()';

    IF NOT has_function_privilege('authenticated', 'public.get_user_organization_ids()', 'EXECUTE') THEN
        RAISE EXCEPTION 'CHECK FAILED: authenticated lost EXECUTE on get_user_organization_ids() (row level security needs it)';
    END IF;
    RAISE NOTICE 'ok: authenticated can still execute get_user_organization_ids()';
END $$;

\echo FUNCTION HARDENING TESTS PASSED
