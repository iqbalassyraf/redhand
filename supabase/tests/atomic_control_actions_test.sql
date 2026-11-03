-- SQL tests for supabase/migrations/20261102000000_atomic_control_actions.sql.
-- Run with scripts/test_migrations.sh (fresh database, shim, all migrations, then this file).
-- Any failed check raises an exception and stops psql with a non-zero exit status.

\set ON_ERROR_STOP on
\set QUIET on

-- Helpers (session-local) ------------------------------------------------------------------
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

-- A trigger that makes every audit insert fail, to prove nothing else is applied.
CREATE FUNCTION public.zz_test_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'simulated audit failure'; END $$;

-- Fixtures ---------------------------------------------------------------------------------
INSERT INTO auth.users (id) VALUES
    ('00000000-0000-0000-0000-0000000000c1'), ('00000000-0000-0000-0000-0000000000c2');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-00000000000a', 'Org A', 'org-a'),
    ('00000000-0000-0000-0000-00000000000b', 'Org B', 'org-b');

-- 1. create_passport -----------------------------------------------------------------------
DO $$
DECLARE r jsonb;
BEGIN
    r := public.control_create_passport(
        '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000c1',
        '{"id":"00000000-0000-0000-0000-0000000000a1","external_agent_id":"bot-1","name":"Bot 1",
          "framework":"n8n","environment":"production","owner_id":"00000000-0000-0000-0000-0000000000c1",
          "scopes":[{"server":"xero","tool":"list_invoices","access":"read"}],
          "expires_at":"2099-01-01T00:00:00Z"}'::jsonb,
        '{"key_prefix":"rh_agent_aaaaaa","key_hash":"hash-1"}'::jsonb,
        '{"name":"Bot 1"}'::jsonb);
    PERFORM pg_temp.check(r ->> 'status' = 'active' AND (r ->> 'version')::int = 1, 'create: passport is active, version 1');
    PERFORM pg_temp.check((SELECT count(*) FROM public.agent_keys WHERE agent_id = '00000000-0000-0000-0000-0000000000a1' AND is_active) = 1, 'create: one active key');
    PERFORM pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'passport.created') = 1, 'create: one audit row');

    PERFORM pg_temp.expect_error($q$
        SELECT public.control_create_passport('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000c1',
          '{"id":"00000000-0000-0000-0000-0000000000f1","external_agent_id":"bot-1","name":"Dup","environment":"production",
            "owner_id":"00000000-0000-0000-0000-0000000000c1","expires_at":"2099-01-01T00:00:00Z"}'::jsonb,
          '{"key_prefix":"rh_agent_dupxxx","key_hash":"hash-dup"}'::jsonb, '{}'::jsonb)$q$,
        '23505', 'create: duplicate external id is rejected');
    PERFORM pg_temp.check((SELECT count(*) FROM public.agent_keys WHERE key_hash = 'hash-dup') = 0, 'create: rejected duplicate left no key behind');
    PERFORM pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'passport.created') = 1, 'create: rejected duplicate left no audit row');
END $$;

-- 2. freeze, idempotent guard and validation -----------------------------------------------
DO $$
DECLARE r jsonb;
BEGIN
    r := public.control_agent_change(
        '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a1',
        '00000000-0000-0000-0000-0000000000c1', 'passport.frozen', 'active',
        '{"status":"frozen","status_reason":"odd spend"}'::jsonb, false, NULL, 'odd spend', '{}'::jsonb);
    PERFORM pg_temp.check((r ->> 'conflict')::boolean = false AND r -> 'agent' ->> 'status' = 'frozen', 'freeze: applied');
    PERFORM pg_temp.check((r -> 'agent' ->> 'version')::int = 2, 'freeze: version bumped by the passport trigger');
    PERFORM pg_temp.check((SELECT reason FROM public.control_audit_log WHERE action = 'passport.frozen') = 'odd spend', 'freeze: audit row has actor reason');

    r := public.control_agent_change(
        '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a1',
        '00000000-0000-0000-0000-0000000000c1', 'passport.frozen', 'active',
        '{"status":"frozen"}'::jsonb, false, NULL, NULL, '{}'::jsonb);
    PERFORM pg_temp.check((r ->> 'conflict')::boolean AND r ->> 'status' = 'frozen', 'freeze: stale expected status returns a conflict');
    PERFORM pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'passport.frozen') = 1, 'freeze: conflict wrote no audit row');

    PERFORM pg_temp.expect_error($q$SELECT public.control_agent_change('00000000-0000-0000-0000-00000000000a',
        '00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000c1','passport.frozen',NULL,
        '{"name":"hijacked"}'::jsonb,false,NULL,NULL,'{}'::jsonb)$q$, '22023', 'validation: only whitelisted columns can change');
    PERFORM pg_temp.expect_error($q$SELECT public.control_agent_change('00000000-0000-0000-0000-00000000000a',
        '00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000c1','passport.deleted',NULL,
        '{}'::jsonb,false,NULL,NULL,'{}'::jsonb)$q$, '22023', 'validation: unknown action is rejected');
    PERFORM pg_temp.expect_error($q$SELECT public.control_agent_change('00000000-0000-0000-0000-00000000000b',
        '00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000c2','passport.frozen',NULL,
        '{"status":"frozen"}'::jsonb,false,NULL,NULL,'{}'::jsonb)$q$, 'P0002', 'tenancy: another tenant''s agent is not found');
END $$;

-- 3. Atomicity: an audit failure after the other statements leaves nothing applied ---------
CREATE TRIGGER zz_test_fail_audit BEFORE INSERT ON public.control_audit_log
    FOR EACH ROW EXECUTE FUNCTION public.zz_test_fail_audit();

DO $$
BEGIN
    -- unfreeze would reactivate the agent
    PERFORM pg_temp.expect_error($q$SELECT public.control_agent_change('00000000-0000-0000-0000-00000000000a',
        '00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000c1','passport.unfrozen','frozen',
        '{"status":"active"}'::jsonb,false,NULL,NULL,'{}'::jsonb)$q$, 'P0001', 'atomic: failing audit aborts unfreeze');
    PERFORM pg_temp.check((SELECT status::text FROM public.agents WHERE id = '00000000-0000-0000-0000-0000000000a1') = 'frozen'
        AND (SELECT version FROM public.agents WHERE id = '00000000-0000-0000-0000-0000000000a1') = 2, 'atomic: agent unchanged after failed unfreeze');

    -- key rotation: old key must stay active and no new key may appear
    PERFORM pg_temp.expect_error($q$SELECT public.control_agent_change('00000000-0000-0000-0000-00000000000a',
        '00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000c1','passport.key_rotated',NULL,
        '{}'::jsonb,true,'{"key_prefix":"rh_agent_new000","key_hash":"hash-new"}'::jsonb,NULL,'{}'::jsonb)$q$, 'P0001', 'atomic: failing audit aborts key rotation');
    PERFORM pg_temp.check((SELECT count(*) FROM public.agent_keys WHERE agent_id = '00000000-0000-0000-0000-0000000000a1' AND is_active AND key_hash = 'hash-1') = 1
        AND (SELECT count(*) FROM public.agent_keys WHERE key_hash = 'hash-new') = 0, 'atomic: old key still active, no new key after failed rotation');

    -- registration: no passport, key or row may be left behind
    PERFORM pg_temp.expect_error($q$SELECT public.control_create_passport('00000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000000c1',
        '{"id":"00000000-0000-0000-0000-0000000000f2","external_agent_id":"ghost","name":"Ghost","environment":"production",
          "owner_id":"00000000-0000-0000-0000-0000000000c1","expires_at":"2099-01-01T00:00:00Z"}'::jsonb,
        '{"key_prefix":"rh_agent_ghost0","key_hash":"hash-ghost"}'::jsonb,'{}'::jsonb)$q$, 'P0001', 'atomic: failing audit aborts registration');
    PERFORM pg_temp.check((SELECT count(*) FROM public.agents WHERE external_agent_id = 'ghost') = 0
        AND (SELECT count(*) FROM public.agent_keys WHERE key_hash = 'hash-ghost') = 0, 'atomic: failed registration left no agent or key');

    -- MCP server registration
    PERFORM pg_temp.expect_error($q$SELECT public.control_mcp_server('00000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000000c1',
        'register','{"slug":"ghost","name":"Ghost","url":"https://example.com"}'::jsonb,NULL)$q$, 'P0001', 'atomic: failing audit aborts MCP server registration');
    PERFORM pg_temp.check((SELECT count(*) FROM public.mcp_servers WHERE slug = 'ghost') = 0, 'atomic: failed registration left no server');
END $$;

DROP TRIGGER zz_test_fail_audit ON public.control_audit_log;

-- 4. Revoke is permanent and deactivates keys; reactivation is rejected atomically ---------
DO $$
DECLARE r jsonb;
BEGIN
    r := public.control_agent_change(
        '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a1',
        '00000000-0000-0000-0000-0000000000c1', 'passport.revoked', 'frozen',
        '{"status":"revoked","status_reason":"retired"}'::jsonb, true, NULL, 'retired', '{}'::jsonb);
    PERFORM pg_temp.check(r -> 'agent' ->> 'status' = 'revoked', 'revoke: applied');
    PERFORM pg_temp.check((SELECT count(*) FROM public.agent_keys WHERE agent_id = '00000000-0000-0000-0000-0000000000a1' AND is_active) = 0, 'revoke: keys deactivated in the same transaction');

    PERFORM pg_temp.expect_error($q$SELECT public.control_agent_change('00000000-0000-0000-0000-00000000000a',
        '00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000c1','passport.unfrozen',NULL,
        '{"status":"active"}'::jsonb,false,NULL,NULL,'{}'::jsonb)$q$, '23514', 'revoke: a revoked passport cannot be reactivated');
    PERFORM pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'passport.unfrozen') = 0, 'revoke: rejected reactivation wrote no audit row');
END $$;

-- 5. Key rotation, scopes and renewal ------------------------------------------------------
DO $$
DECLARE r jsonb;
BEGIN
    PERFORM public.control_create_passport(
        '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000c1',
        '{"id":"00000000-0000-0000-0000-0000000000a2","external_agent_id":"bot-2","name":"Bot 2","environment":"production",
          "owner_id":"00000000-0000-0000-0000-0000000000c1","expires_at":"2099-01-01T00:00:00Z"}'::jsonb,
        '{"key_prefix":"rh_agent_bbbbbb","key_hash":"hash-2"}'::jsonb, '{}'::jsonb);

    PERFORM pg_temp.expect_error($q$SELECT public.control_agent_change('00000000-0000-0000-0000-00000000000a',
        '00000000-0000-0000-0000-0000000000a2','00000000-0000-0000-0000-0000000000c1','passport.key_rotated','active',
        '{}'::jsonb,true,'{"key_prefix":"rh_agent_cccccc"}'::jsonb,NULL,'{}'::jsonb)$q$, '23502', 'rotate: a key without a hash is rejected');
    PERFORM pg_temp.check((SELECT count(*) FROM public.agent_keys WHERE agent_id = '00000000-0000-0000-0000-0000000000a2' AND is_active AND key_hash = 'hash-2') = 1,
        'rotate: rejected rotation kept the old key active');

    r := public.control_agent_change(
        '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a2',
        '00000000-0000-0000-0000-0000000000c1', 'passport.key_rotated', 'active',
        '{}'::jsonb, true, '{"key_prefix":"rh_agent_cccccc","key_hash":"hash-3"}'::jsonb, NULL, '{"key_prefix":"rh_agent_cccccc"}'::jsonb);
    PERFORM pg_temp.check((SELECT count(*) FROM public.agent_keys WHERE agent_id = '00000000-0000-0000-0000-0000000000a2' AND is_active) = 1
        AND (SELECT key_hash FROM public.agent_keys WHERE agent_id = '00000000-0000-0000-0000-0000000000a2' AND is_active) = 'hash-3', 'rotate: exactly the new key is active');
    PERFORM pg_temp.check((r -> 'agent' ->> 'version')::int = 1, 'rotate: version unchanged (no passport change)');

    r := public.control_agent_change(
        '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a2',
        '00000000-0000-0000-0000-0000000000c1', 'passport.scopes_changed', 'active',
        '{"scopes":[{"server":"xero","tool":"*","access":"write"}]}'::jsonb, false, NULL, NULL, '{"expansion":true}'::jsonb);
    PERFORM pg_temp.check((r -> 'agent' ->> 'version')::int = 2 AND r -> 'agent' -> 'scopes' -> 0 ->> 'tool' = '*', 'scopes: applied and version bumped');

    r := public.control_agent_change(
        '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000a2',
        '00000000-0000-0000-0000-0000000000c1', 'passport.renewed', 'active',
        '{"expires_at":"2100-06-01T00:00:00Z"}'::jsonb, false, NULL, NULL, '{}'::jsonb);
    PERFORM pg_temp.check((r -> 'agent' ->> 'expires_at')::timestamptz = '2100-06-01T00:00:00Z'::timestamptz AND (r -> 'agent' ->> 'version')::int = 3, 'renew: expiry updated and version bumped');
END $$;

-- 6. Freeze all: tenant-scoped, one transaction with its audit row -------------------------
DO $$
DECLARE r jsonb;
BEGIN
    PERFORM public.control_create_passport(
        '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000c1',
        '{"id":"00000000-0000-0000-0000-0000000000a3","external_agent_id":"bot-3","name":"Bot 3","environment":"production",
          "owner_id":"00000000-0000-0000-0000-0000000000c1","expires_at":"2099-01-01T00:00:00Z"}'::jsonb,
        '{"key_prefix":"rh_agent_dddddd","key_hash":"hash-4"}'::jsonb, '{}'::jsonb);
    PERFORM public.control_create_passport(
        '00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-0000000000c2',
        '{"id":"00000000-0000-0000-0000-0000000000b1","external_agent_id":"other-bot","name":"Other","environment":"production",
          "owner_id":"00000000-0000-0000-0000-0000000000c2","expires_at":"2099-01-01T00:00:00Z"}'::jsonb,
        '{"key_prefix":"rh_agent_eeeeee","key_hash":"hash-5"}'::jsonb, '{}'::jsonb);

    -- a failing audit write must leave every agent active
    CREATE TRIGGER zz_test_fail_audit BEFORE INSERT ON public.control_audit_log
        FOR EACH ROW EXECUTE FUNCTION public.zz_test_fail_audit();
    PERFORM pg_temp.expect_error($q$SELECT public.control_freeze_all('00000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000000c1','incident')$q$,
        'P0001', 'freeze-all: failing audit aborts the whole freeze');
    DROP TRIGGER zz_test_fail_audit ON public.control_audit_log;
    PERFORM pg_temp.check((SELECT count(*) FROM public.agents WHERE organization_id = '00000000-0000-0000-0000-00000000000a' AND status = 'active') = 2,
        'freeze-all: both active agents of the tenant are still active after the failure');

    r := public.control_freeze_all('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000c1', 'incident 42');
    PERFORM pg_temp.check(jsonb_array_length(r -> 'frozen_agent_ids') = 2, 'freeze-all: froze exactly the two active agents of the tenant');
    PERFORM pg_temp.check((SELECT status::text FROM public.agents WHERE id = '00000000-0000-0000-0000-0000000000b1') = 'active', 'freeze-all: other tenant untouched');
    PERFORM pg_temp.check((SELECT details ->> 'frozen_count' FROM public.control_audit_log WHERE action = 'organization.frozen_all') = '2', 'freeze-all: audit row records the count');

    r := public.control_freeze_all('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000c1', 'again');
    PERFORM pg_temp.check(jsonb_array_length(r -> 'frozen_agent_ids') = 0
        AND (SELECT count(*) FROM public.control_audit_log WHERE action = 'organization.frozen_all') = 2, 'freeze-all: repeating freezes nothing and is still audited');
END $$;

-- 7. MCP servers ---------------------------------------------------------------------------
DO $$
DECLARE r jsonb; v_id uuid;
BEGIN
    r := public.control_mcp_server('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000c1',
        'register', '{"slug":"xero","name":"Xero","url":"https://mcp.example.com/xero"}'::jsonb, NULL);
    v_id := (r ->> 'id')::uuid;
    PERFORM pg_temp.check(r ->> 'slug' = 'xero' AND (r ->> 'is_active')::boolean, 'mcp: registered');
    PERFORM pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'mcp_server.registered') = 1, 'mcp: registration audited');
    PERFORM pg_temp.expect_error($q$SELECT public.control_mcp_server('00000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000000c1',
        'register','{"slug":"xero","name":"Dup","url":"https://example.com"}'::jsonb,NULL)$q$, '23505', 'mcp: duplicate slug is rejected');
    PERFORM pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'mcp_server.registered') = 1, 'mcp: rejected duplicate wrote no audit row');
    PERFORM pg_temp.expect_error(format($q$SELECT public.control_mcp_server('00000000-0000-0000-0000-00000000000b','00000000-0000-0000-0000-0000000000c2','deactivate',NULL,%L::uuid)$q$, v_id),
        'P0002', 'mcp: another tenant cannot deactivate it');
    PERFORM pg_temp.expect_error($q$SELECT public.control_mcp_server('00000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000000c1','purge',NULL,NULL)$q$,
        '22023', 'mcp: unknown operation is rejected');

    r := public.control_mcp_server('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000c1', 'deactivate', NULL, v_id);
    PERFORM pg_temp.check((r ->> 'is_active')::boolean = false, 'mcp: deactivated');
    PERFORM pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'mcp_server.deactivated') = 1, 'mcp: deactivation audited');
END $$;

-- 8. Privileges: only service_role may execute the functions -------------------------------
DO $$
DECLARE f text;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'public.control_agent_change(uuid, uuid, uuid, text, text, jsonb, boolean, jsonb, text, jsonb)',
        'public.control_freeze_all(uuid, uuid, text)',
        'public.control_create_passport(uuid, uuid, jsonb, jsonb, jsonb)',
        'public.control_mcp_server(uuid, uuid, text, jsonb, uuid)']
    LOOP
        PERFORM pg_temp.check(NOT has_function_privilege('anon', f, 'EXECUTE'), 'privileges: anon cannot execute ' || f);
        PERFORM pg_temp.check(NOT has_function_privilege('authenticated', f, 'EXECUTE'), 'privileges: authenticated cannot execute ' || f);
        PERFORM pg_temp.check(has_function_privilege('service_role', f, 'EXECUTE'), 'privileges: service_role can execute ' || f);
    END LOOP;
END $$;

DROP FUNCTION public.zz_test_fail_audit();
\echo ALL SQL TESTS PASSED
