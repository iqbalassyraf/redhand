-- SQL tests for supabase/migrations/20261129000000_onboarding.sql (Phase 4.5 D1: sign-up codes, invites, members).

\set ON_ERROR_STOP on
\set QUIET on

BEGIN;

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'CHECK FAILED: %', p_msg; END IF;
    RAISE NOTICE 'ok: %', p_msg;
END $$;
CREATE FUNCTION pg_temp.raises(p_sql text) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN EXECUTE p_sql; RETURN false; EXCEPTION WHEN OTHERS THEN RETURN true; END $$;
CREATE FUNCTION pg_temp.h(p text) RETURNS text LANGUAGE sql AS $$ SELECT encode(sha256(convert_to(p, 'UTF8')), 'hex') $$;

INSERT INTO auth.users (id, email) VALUES
    ('00000000-0000-0000-0000-0000900a0001', 'founder@example.test'), ('00000000-0000-0000-0000-0000900a0002', 'second@example.test'),
    ('00000000-0000-0000-0000-0000900a0003', 'third@example.test'), ('00000000-0000-0000-0000-0000900a0004', 'fourth@example.test'),
    ('00000000-0000-0000-0000-0000900a0005', 'rival@example.test');
INSERT INTO public.signup_codes (code_hash, expires_at) VALUES
    (pg_temp.h('code-1'), now() + interval '7 days'), (pg_temp.h('code-2'), now() + interval '7 days'),
    (pg_temp.h('code-expired'), now() - interval '1 minute'), (pg_temp.h('code-3'), now() + interval '7 days');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Creating an organization
SELECT pg_temp.check((public.control_org_create('00000000-0000-0000-0000-0000900a0001', 'Founder Co', 'founder-co', pg_temp.h('code-1')) ->> 'created')::boolean,
    'a code creates an organization');
SELECT pg_temp.check((SELECT role FROM public.organization_members WHERE user_id = '00000000-0000-0000-0000-0000900a0001') = 'owner', 'the creator is its owner');
SELECT pg_temp.check((SELECT used_by IS NOT NULL AND used_org IS NOT NULL FROM public.signup_codes WHERE code_hash = pg_temp.h('code-1')), 'the code records who used it and for what');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'organization.created') = 1, 'creating an organization writes one audit row');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.control_audit_log WHERE details::text LIKE '%' || pg_temp.h('code-1') || '%' OR details::text LIKE '%code-1%'),
    'the audit row never holds the code or its hash');
SELECT pg_temp.check(public.control_org_create('00000000-0000-0000-0000-0000900a0005', 'Rival', 'rival-co', pg_temp.h('code-1')) ->> 'reason' = 'code', 'a used code cannot be used again');
SELECT pg_temp.check(public.control_org_create('00000000-0000-0000-0000-0000900a0005', 'Rival', 'rival-co', pg_temp.h('code-expired')) ->> 'reason' = 'code', 'an expired code is refused');
SELECT pg_temp.check(public.control_org_create('00000000-0000-0000-0000-0000900a0005', 'Rival', 'rival-co', pg_temp.h('nope')) ->> 'reason' = 'code', 'an unknown code is refused, with the same answer');
SELECT pg_temp.check(public.control_org_create('00000000-0000-0000-0000-0000900a0005', 'Rival', 'rival-co', 'not-a-hash') ->> 'reason' = 'code', 'a malformed code hash is refused, with the same answer');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.organizations WHERE slug = 'rival-co'), 'a refused creation leaves no organization');
SELECT pg_temp.check(public.control_org_create('00000000-0000-0000-0000-0000900a0001', 'Again', 'again-co', pg_temp.h('code-2')) ->> 'reason' = 'member', 'a user who already belongs to an organization cannot create another');
SELECT pg_temp.check((SELECT used_at IS NULL FROM public.signup_codes WHERE code_hash = pg_temp.h('code-2')), 'a refusal does not burn the code');
SELECT pg_temp.check(public.control_org_create('00000000-0000-0000-0000-0000900a0005', 'Rival', 'founder-co', pg_temp.h('code-2')) ->> 'reason' = 'slug', 'a taken slug is refused');
SELECT pg_temp.check((SELECT used_at IS NULL FROM public.signup_codes WHERE code_hash = pg_temp.h('code-2')), 'and does not burn the code either');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_org_create('00000000-0000-0000-0000-0000900a0005', '', 'ok-slug', pg_temp.h('code-2'))$$), 'an empty name is refused');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_org_create('00000000-0000-0000-0000-0000900a0005', 'X', 'Bad Slug!', pg_temp.h('code-2'))$$), 'a bad slug is refused');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Invites
CREATE TEMP TABLE o AS SELECT id FROM public.organizations WHERE slug = 'founder-co';
GRANT SELECT ON o TO PUBLIC;
SELECT pg_temp.check((public.control_member_invite_create((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0001', 'viewer', pg_temp.h('inv-viewer'), now() + interval '7 days') ->> 'created')::boolean,
    'an owner can invite a viewer');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_invite_create((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0001', 'owner', pg_temp.h('inv-owner'), now() + interval '7 days')$$),
    'an invite can never grant owner');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_invite_create((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0001', 'viewer', pg_temp.h('inv-long'), now() + interval '31 days')$$),
    'an invite lives at most 30 days');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_invite_create((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0005', 'viewer', pg_temp.h('inv-x'), now() + interval '7 days')$$),
    'someone who is not a member cannot invite');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.control_audit_log WHERE details::text LIKE '%' || pg_temp.h('inv-viewer') || '%'), 'the audit row never holds the token hash');

SELECT pg_temp.check((public.control_member_invite_accept('00000000-0000-0000-0000-0000900a0002', pg_temp.h('inv-viewer')) ->> 'joined')::boolean, 'a token adds the user at the invited role');
SELECT pg_temp.check((SELECT role FROM public.organization_members WHERE user_id = '00000000-0000-0000-0000-0000900a0002') = 'viewer', 'as a viewer');
SELECT pg_temp.check(public.control_member_invite_accept('00000000-0000-0000-0000-0000900a0003', pg_temp.h('inv-viewer')) ->> 'reason' = 'invite', 'a token works once');
SELECT pg_temp.check(public.control_member_invite_accept('00000000-0000-0000-0000-0000900a0003', pg_temp.h('unknown')) ->> 'reason' = 'invite', 'an unknown token has the same answer');

SELECT public.control_member_invite_create((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0001', 'admin', pg_temp.h('inv-admin'), now() + interval '7 days');
SELECT pg_temp.check(public.control_member_invite_accept('00000000-0000-0000-0000-0000900a0002', pg_temp.h('inv-admin')) ->> 'reason' = 'member', 'a user who already belongs to an organization cannot join another');
SELECT pg_temp.check((public.control_member_invite_accept('00000000-0000-0000-0000-0000900a0003', pg_temp.h('inv-admin')) ->> 'joined')::boolean, 'a different user can use it');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_invite_create((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0002', 'viewer', pg_temp.h('inv-by-viewer'), now() + interval '7 days')$$),
    'a viewer cannot invite');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_invite_create((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0003', 'security_operator', 'zz', now() + interval '7 days')$$), 'a malformed hash is refused');
SELECT pg_temp.check((public.control_member_invite_create((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0003', 'security_operator', pg_temp.h('inv-op'), now() + interval '7 days') ->> 'created')::boolean,
    'an admin can invite up to admin');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_invite_create((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0003', 'owner', pg_temp.h('inv-o2'), now() + interval '7 days')$$), 'but never owner');

-- revoked and expired and inviter demoted
SELECT public.control_member_invite_create((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0001', 'viewer', pg_temp.h('inv-rev'), now() + interval '7 days');
SELECT pg_temp.check((public.control_member_invite_revoke((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0001', (SELECT id FROM public.member_invites WHERE token_hash = pg_temp.h('inv-rev'))) ->> 'changed')::boolean, 'an invite can be revoked');
SELECT pg_temp.check(public.control_member_invite_accept('00000000-0000-0000-0000-0000900a0004', pg_temp.h('inv-rev')) ->> 'reason' = 'invite', 'a revoked invite is refused');
SELECT pg_temp.check(NOT (public.control_member_invite_revoke((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0001', (SELECT id FROM public.member_invites WHERE token_hash = pg_temp.h('inv-rev'))) ->> 'changed')::boolean, 'revoking twice is a no-op');
UPDATE public.member_invites SET expires_at = now() - interval '1 second' WHERE token_hash = pg_temp.h('inv-op');
SELECT pg_temp.check(public.control_member_invite_accept('00000000-0000-0000-0000-0000900a0004', pg_temp.h('inv-op')) ->> 'reason' = 'invite', 'an expired invite is refused');
SELECT public.control_member_invite_create((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0003', 'viewer', pg_temp.h('inv-late'), now() + interval '7 days');
SELECT public.control_member_set_role((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0001', '00000000-0000-0000-0000-0000900a0003', 'viewer');
SELECT pg_temp.check(public.control_member_invite_accept('00000000-0000-0000-0000-0000900a0004', pg_temp.h('inv-late')) ->> 'reason' = 'invite', 'an invite from someone who is no longer an admin is dead');
SELECT public.control_member_set_role((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0001', '00000000-0000-0000-0000-0000900a0003', 'admin');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_invite_revoke('00000000-0000-0000-0000-000000000099', '00000000-0000-0000-0000-0000900a0001', gen_random_uuid())$$), 'an organization that is not the actor''s is refused');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Members: removal and roles
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_remove((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0001', '00000000-0000-0000-0000-0000900a0001')$$), 'the last owner cannot be removed');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_set_role((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0001', '00000000-0000-0000-0000-0000900a0001', 'admin')$$), 'the last owner cannot be demoted');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_remove((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0003', '00000000-0000-0000-0000-0000900a0001')$$), 'an admin cannot remove an owner');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_set_role((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0003', '00000000-0000-0000-0000-0000900a0002', 'owner')$$), 'an admin cannot make an owner');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_set_role((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0002', '00000000-0000-0000-0000-0000900a0002', 'admin')$$), 'a viewer cannot promote themselves');
SELECT pg_temp.check((public.control_member_set_role((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0003', '00000000-0000-0000-0000-0000900a0002', 'security_operator') ->> 'changed')::boolean, 'an admin can set a role up to admin');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'member.role_changed' AND details ->> 'to' = 'security_operator') = 1, 'and it is audited with from and to');
SELECT pg_temp.check(NOT (public.control_member_set_role((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0003', '00000000-0000-0000-0000-0000900a0002', 'security_operator') ->> 'changed')::boolean, 'setting the same role is a no-op');
SELECT pg_temp.check((public.control_member_set_role((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0001', '00000000-0000-0000-0000-0000900a0003', 'owner') ->> 'changed')::boolean, 'an owner can make another owner');
SELECT pg_temp.check((public.control_member_remove((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0003', '00000000-0000-0000-0000-0000900a0001') ->> 'removed')::boolean, 'with two owners one can be removed');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_remove((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0003', '00000000-0000-0000-0000-0000900a0003')$$), 'and then the remaining owner cannot remove themselves');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_set_role((SELECT id FROM o), '00000000-0000-0000-0000-0000900a0003', '00000000-0000-0000-0000-0000900a0005', 'viewer')$$), 'a user outside the organization is not found');

-- a second organization is untouched by the first one's actors
SELECT public.control_org_create('00000000-0000-0000-0000-0000900a0005', 'Rival Co', 'rival-co', pg_temp.h('code-3'));
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_remove((SELECT id FROM public.organizations WHERE slug = 'rival-co'), '00000000-0000-0000-0000-0000900a0003', '00000000-0000-0000-0000-0000900a0005')$$),
    'an owner of one organization cannot remove a member of another');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_member_set_role((SELECT id FROM public.organizations WHERE slug = 'rival-co'), '00000000-0000-0000-0000-0000900a0003', '00000000-0000-0000-0000-0000900a0005', 'viewer')$$),
    'nor change its roles');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Listing and closed tables
SELECT pg_temp.check((SELECT count(*) FROM public.list_organization_members((SELECT id FROM o))) = 2 AND
                     (SELECT email FROM public.list_organization_members((SELECT id FROM o)) LIMIT 1) IS NOT NULL, 'members are listed with their e-mail');
SELECT pg_temp.check((SELECT count(*) FROM public.list_organization_members((SELECT id FROM public.organizations WHERE slug = 'rival-co'))) = 1, 'only the asked organization''s members');
SELECT pg_temp.check((SELECT relrowsecurity FROM pg_class WHERE oid = 'public.signup_codes'::regclass) AND (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.member_invites'::regclass),
    'both tables are row-level-security closed');
SELECT pg_temp.check(NOT has_function_privilege('anon', 'public.control_org_create(uuid, text, text, text)', 'EXECUTE')
                     AND NOT has_function_privilege('authenticated', 'public.control_member_invite_accept(uuid, text)', 'EXECUTE')
                     AND NOT has_function_privilege('authenticated', 'public.list_organization_members(uuid)', 'EXECUTE'), 'no client role can call the onboarding functions');

DO $$ BEGIN RAISE NOTICE 'ALL SQL TESTS PASSED'; END $$;
ROLLBACK;
