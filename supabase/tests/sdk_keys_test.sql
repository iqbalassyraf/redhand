-- SQL tests for supabase/migrations/20261127000000_sdk_keys.sql (Phase 4.5 C1a, SDK keys).

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

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000800a0001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-000080000001', 'Keys Org A', 'keys-org-a'),
    ('00000000-0000-0000-0000-000080000002', 'Keys Org B', 'keys-org-b');

CREATE FUNCTION pg_temp.hash(p_n integer) RETURNS text LANGUAGE sql AS $$ SELECT encode(sha256(convert_to('key-' || p_n, 'UTF8')), 'hex') $$;
CREATE FUNCTION pg_temp.create_key(p_org uuid, p_n integer, p_days integer DEFAULT 90, p_name text DEFAULT 'ci') RETURNS jsonb LANGUAGE sql AS $$
    SELECT public.control_sdk_key_create(p_org, '00000000-0000-0000-0000-0000800a0001', p_name, pg_temp.hash(p_n), 'rh_live_ab' || lpad(p_n::text, 2, '0'),
                                         now() + make_interval(days => p_days))
$$;

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Create: stored as a hash with a prefix, audited, bounded.
SELECT pg_temp.check((pg_temp.create_key('00000000-0000-0000-0000-000080000001', 1) ->> 'created')::boolean, 'a key is created');
SELECT pg_temp.check((SELECT is_active AND key_hash = pg_temp.hash(1) AND key_prefix = 'rh_live_ab01' AND created_by = '00000000-0000-0000-0000-0000800a0001'
                      FROM public.sdk_api_keys WHERE organization_id = '00000000-0000-0000-0000-000080000001'), 'it is stored active, as a hash, with who made it');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'sdk_key.created' AND organization_id = '00000000-0000-0000-0000-000080000001') = 1,
    'creating a key writes one audit row');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.control_audit_log WHERE action = 'sdk_key.created' AND details::text LIKE '%' || pg_temp.hash(1) || '%'),
    'the audit row does not hold the hash');
SELECT pg_temp.check(pg_temp.raises($$SELECT pg_temp.create_key('00000000-0000-0000-0000-000080000001', 2, 0)$$)
                 AND pg_temp.raises($$SELECT pg_temp.create_key('00000000-0000-0000-0000-000080000001', 2, 367)$$),
    'an expiry under one day or over 366 days is refused');
SELECT pg_temp.check(pg_temp.raises($$SELECT pg_temp.create_key('00000000-0000-0000-0000-000080000001', 2, 90, '')$$)
                 AND pg_temp.raises($$SELECT pg_temp.create_key('00000000-0000-0000-0000-000080000001', 2, 90, repeat('x', 101))$$),
    'an empty or overlong name is refused');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_sdk_key_create('00000000-0000-0000-0000-000080000001', '00000000-0000-0000-0000-0000800a0001', 'x', 'nothex', 'rh_live_abcd', now() + interval '1 day 1 hour')$$)
                 AND pg_temp.raises($$SELECT public.control_sdk_key_create('00000000-0000-0000-0000-000080000001', '00000000-0000-0000-0000-0000800a0001', 'x', pg_temp.hash(3), 'bad', now() + interval '2 days')$$),
    'a malformed hash or prefix is refused');
SELECT pg_temp.check(pg_temp.raises($$SELECT pg_temp.create_key('00000000-0000-0000-0000-000080000001', 1)$$), 'the same key hash cannot be stored twice');
SELECT pg_temp.check(pg_temp.raises($$SELECT pg_temp.create_key('00000000-0000-0000-0000-0000deadbeef', 9)$$), 'an unknown organization is refused');

-- At most 10 usable keys per organization; revoked and expired ones do not count.
SELECT pg_temp.create_key('00000000-0000-0000-0000-000080000001', n) FROM generate_series(2, 10) n;
SELECT pg_temp.check((pg_temp.create_key('00000000-0000-0000-0000-000080000001', 11) ->> 'limit')::boolean, 'an eleventh usable key is refused with limit');
SELECT pg_temp.check((SELECT count(*) FROM public.sdk_api_keys WHERE organization_id = '00000000-0000-0000-0000-000080000001') = 10, 'and not stored');
SELECT pg_temp.check((pg_temp.create_key('00000000-0000-0000-0000-000080000002', 12) ->> 'created')::boolean, 'another organization has its own limit');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Revoke: idempotent, audited, organization-scoped.
CREATE FUNCTION pg_temp.key_id(p_n integer) RETURNS uuid LANGUAGE sql AS $$ SELECT id FROM public.sdk_api_keys WHERE key_hash = pg_temp.hash(p_n) $$;
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_sdk_key_revoke('00000000-0000-0000-0000-000080000002', '00000000-0000-0000-0000-0000800a0001', pg_temp.key_id(1), 'x')$$),
    'another organization cannot revoke this key');
SELECT pg_temp.check((SELECT is_active FROM public.sdk_api_keys WHERE id = pg_temp.key_id(1)), 'and it is still active');
SELECT pg_temp.check((public.control_sdk_key_revoke('00000000-0000-0000-0000-000080000001', '00000000-0000-0000-0000-0000800a0001', pg_temp.key_id(1), 'rotated') ->> 'changed')::boolean,
    'the owning organization revokes it');
SELECT pg_temp.check((SELECT NOT is_active AND revoked_at IS NOT NULL AND revoked_by = '00000000-0000-0000-0000-0000800a0001' FROM public.sdk_api_keys WHERE id = pg_temp.key_id(1)),
    'it is inactive with who and when');
SELECT pg_temp.check(NOT (public.control_sdk_key_revoke('00000000-0000-0000-0000-000080000001', '00000000-0000-0000-0000-0000800a0001', pg_temp.key_id(1), 'again') ->> 'changed')::boolean,
    'revoking again changes nothing');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'sdk_key.revoked') = 1, 'one audit row, none for the no-op');
SELECT pg_temp.check((pg_temp.create_key('00000000-0000-0000-0000-000080000001', 13) ->> 'created')::boolean, 'a revoked key frees a slot');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Touch: last_used_at at most once a minute.
SELECT public.sdk_key_touch(pg_temp.key_id(2));
SELECT pg_temp.check((SELECT last_used_at IS NOT NULL FROM public.sdk_api_keys WHERE id = pg_temp.key_id(2)), 'touch records the first use');
UPDATE public.sdk_api_keys SET last_used_at = now() - interval '30 seconds' WHERE id = pg_temp.key_id(2);
SELECT public.sdk_key_touch(pg_temp.key_id(2));
SELECT pg_temp.check((SELECT last_used_at < now() - interval '20 seconds' FROM public.sdk_api_keys WHERE id = pg_temp.key_id(2)), 'a second touch within a minute writes nothing');
UPDATE public.sdk_api_keys SET last_used_at = now() - interval '2 minutes' WHERE id = pg_temp.key_id(2);
SELECT public.sdk_key_touch(pg_temp.key_id(2));
SELECT pg_temp.check((SELECT last_used_at > now() - interval '5 seconds' FROM public.sdk_api_keys WHERE id = pg_temp.key_id(2)), 'after a minute it is updated again');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Writes only through the audited functions: signed-in users cannot write the table directly any more; reads stay as they were.
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'sdk_api_keys' AND cmd <> 'SELECT'), 'no policy lets anyone write sdk_api_keys directly');
SELECT pg_temp.check(EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'sdk_api_keys' AND cmd = 'SELECT'), 'members can still read their organization''s keys');
SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.control_sdk_key_create(uuid, uuid, text, text, text, timestamptz)', 'EXECUTE')
                 AND NOT has_function_privilege('anon', 'public.control_sdk_key_revoke(uuid, uuid, uuid, text)', 'EXECUTE')
                 AND NOT has_function_privilege('authenticated', 'public.sdk_key_touch(uuid)', 'EXECUTE'), 'signed-in users and anon cannot call the functions');

ROLLBACK;
