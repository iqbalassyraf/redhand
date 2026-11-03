-- SQL tests for supabase/migrations/20261103000000_telegram_panic.sql.
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

-- Fixtures ---------------------------------------------------------------------------------
INSERT INTO auth.users (id) VALUES
    ('00000000-0000-0000-0000-0000000000d1'),   -- owner of org T1
    ('00000000-0000-0000-0000-0000000000d2'),   -- viewer of org T1
    ('00000000-0000-0000-0000-0000000000d3');   -- admin of org T2
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000000000e1', 'Telegram Org 1', 'telegram-org-1'),
    ('00000000-0000-0000-0000-0000000000e2', 'Telegram Org 2', 'telegram-org-2');
INSERT INTO public.organization_members (organization_id, user_id, role) VALUES
    ('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000d1', 'owner'),
    ('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000d2', 'viewer'),
    ('00000000-0000-0000-0000-0000000000e2', '00000000-0000-0000-0000-0000000000d3', 'admin');
INSERT INTO public.telegram_link_codes (code_hash, organization_id, user_id, expires_at) VALUES
    ('code-owner',   '00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000d1', NOW() + INTERVAL '10 minutes'),
    ('code-expired', '00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000d1', NOW() - INTERVAL '1 minute'),
    ('code-viewer',  '00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000d2', NOW() + INTERVAL '10 minutes'),
    ('code-other',   '00000000-0000-0000-0000-0000000000e2', '00000000-0000-0000-0000-0000000000d3', NOW() + INTERVAL '10 minutes');

-- 1. Linking -------------------------------------------------------------------------------
DO $$
DECLARE r jsonb;
BEGIN
    r := public.telegram_link_chat('code-owner', 1001);
    PERFORM pg_temp.check(r->>'role' = 'owner' AND (r->>'user_id')::uuid = '00000000-0000-0000-0000-0000000000d1',
        'owner code links the chat and reports the live role');
    PERFORM pg_temp.check(
        (SELECT COUNT(*) FROM public.control_audit_log
         WHERE action = 'telegram.linked' AND organization_id = '00000000-0000-0000-0000-0000000000e1') = 1,
        'linking writes an audit row');
END $$;
SELECT pg_temp.expect_error($$SELECT public.telegram_link_chat('code-owner', 1002)$$, 'P0002', 'a code cannot be used twice');
SELECT pg_temp.expect_error($$SELECT public.telegram_link_chat('code-expired', 1002)$$, 'P0002', 'an expired code is refused');
SELECT pg_temp.expect_error($$SELECT public.telegram_link_chat('no-such-code', 1002)$$, 'P0002', 'an unknown code is refused');
SELECT pg_temp.expect_error($$SELECT public.telegram_link_chat('code-viewer', 1002)$$, '42501', 'a viewer cannot link a chat');
SELECT pg_temp.check(
    (SELECT used_at IS NULL FROM public.telegram_link_codes WHERE code_hash = 'code-viewer'),
    'a refused link does not consume the code');
SELECT pg_temp.check(
    (SELECT COUNT(*) FROM public.telegram_links WHERE chat_id = 1002) = 0, 'refused links create nothing');

-- 2. One active operator per chat ----------------------------------------------------------
DO $$
BEGIN
    PERFORM public.telegram_link_chat('code-other', 1001);
    PERFORM pg_temp.check(
        (SELECT COUNT(*) FROM public.telegram_links WHERE chat_id = 1001 AND revoked_at IS NULL) = 1,
        'a chat has exactly one active link');
    PERFORM pg_temp.check(
        (SELECT organization_id FROM public.telegram_links WHERE chat_id = 1001 AND revoked_at IS NULL)
            = '00000000-0000-0000-0000-0000000000e2',
        'the newest link wins and the previous one is revoked');
END $$;
SELECT pg_temp.expect_error(
    $$INSERT INTO public.telegram_links (organization_id, user_id, chat_id)
      VALUES ('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000d1', 1001)$$,
    '23505', 'the database refuses two active links for one chat');

-- 3. Unlinking -----------------------------------------------------------------------------
DO $$
DECLARE link uuid; r jsonb;
BEGIN
    SELECT id INTO link FROM public.telegram_links WHERE chat_id = 1001 AND revoked_at IS NULL;
    PERFORM pg_temp.expect_error(
        format($f$SELECT public.telegram_unlink('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000d1', %L)$f$, link),
        'P0002', 'another organization cannot unlink this chat');
    r := public.telegram_unlink('00000000-0000-0000-0000-0000000000e2', '00000000-0000-0000-0000-0000000000d3', link);
    PERFORM pg_temp.check((r->>'changed')::boolean, 'unlink revokes the link');
    r := public.telegram_unlink('00000000-0000-0000-0000-0000000000e2', '00000000-0000-0000-0000-0000000000d3', link);
    PERFORM pg_temp.check(NOT (r->>'changed')::boolean, 'unlink is idempotent');
    PERFORM pg_temp.check(
        (SELECT COUNT(*) FROM public.control_audit_log WHERE action = 'telegram.unlinked' AND target_id = link) = 1,
        'unlink is audited exactly once');
END $$;

-- 4. Replay guard --------------------------------------------------------------------------
SELECT pg_temp.check(public.telegram_claim_update(5000), 'a new update id is accepted');
SELECT pg_temp.check(NOT public.telegram_claim_update(5000), 'a repeated update id is refused');

-- 5. Retention -----------------------------------------------------------------------------
INSERT INTO public.telegram_updates (update_id, received_at) VALUES (5001, NOW() - INTERVAL '8 days');
SELECT public.purge_telegram_updates();
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.telegram_updates WHERE update_id = 5001), 'old update ids are purged');
SELECT pg_temp.check(EXISTS (SELECT 1 FROM public.telegram_updates WHERE update_id = 5000), 'recent update ids are kept');

-- 6. Access --------------------------------------------------------------------------------
DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'telegram_link_chat(text,bigint)', 'telegram_unlink(uuid,uuid,uuid)',
        'telegram_claim_update(bigint)', 'purge_telegram_updates()'
    ] LOOP
        PERFORM pg_temp.check(NOT has_function_privilege('anon', 'public.' || f, 'EXECUTE')
                          AND NOT has_function_privilege('authenticated', 'public.' || f, 'EXECUTE'),
            f || ' is not executable by anon or authenticated');
        PERFORM pg_temp.check(has_function_privilege('service_role', 'public.' || f, 'EXECUTE'),
            f || ' is executable by service_role');
    END LOOP;
    PERFORM pg_temp.check(NOT has_table_privilege('authenticated', 'public.telegram_links', 'SELECT')
        OR (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.telegram_links'::regclass),
        'telegram_links is protected by row level security');
END $$;

DO $$ BEGIN RAISE NOTICE 'ALL SQL TESTS PASSED (telegram_panic)'; END $$;
