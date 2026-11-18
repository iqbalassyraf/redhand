-- SQL tests for supabase/migrations/20261130000000_tenant_lifecycle.sql (Phase 4.5 D1: export, deletion request, purge).

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
CREATE FUNCTION pg_temp.evt(p_agent uuid) RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object('agent_id', p_agent, 'occurred_at', now(), 'gateway_instance', 'instance-aaaa', 'server', 'fs', 'method', 'tools/call',
        'tool_name', 'read_file', 'decision', 'ALLOW', 'reasons', '[]'::jsonb, 'upstream_status', 200, 'latency_ms', 1.5, 'argument_keys', jsonb_build_array('path'),
        'arguments_sha256', repeat('a', 64), 'result_size_bytes', 100, 'redaction_count', 0, 'credential_jti', 'jti-1')
$$;

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Coverage: the manifest is the single list export and purge use, so it must name every table that holds tenant data.
SELECT pg_temp.check(NOT EXISTS (
    SELECT c.table_name FROM information_schema.columns c JOIN information_schema.tables t USING (table_schema, table_name)
    WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE' AND c.column_name = 'organization_id' AND c.table_name <> 'tenant_deletions'
      AND c.table_name NOT IN (SELECT e ->> 'table' FROM jsonb_array_elements(public.tenant_data_manifest()) e)),
    'every table with an organization_id column is in the tenant data manifest');
SELECT pg_temp.check(NOT EXISTS (
    SELECT c.table_name FROM information_schema.columns c JOIN information_schema.tables t USING (table_schema, table_name)
    WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE' AND c.column_name = 'agent_id'
      AND c.table_name NOT IN (SELECT e ->> 'table' FROM jsonb_array_elements(public.tenant_data_manifest()) e)
      AND c.table_name NOT IN (SELECT table_name FROM information_schema.columns WHERE column_name = 'organization_id' AND table_schema = 'public')),
    'every table scoped only through agent_id is in the manifest too');
SELECT pg_temp.check(NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements(public.tenant_data_manifest()) e WHERE to_regclass('public.' || (e ->> 'table')) IS NULL),
    'every manifest entry names a real table');
SELECT pg_temp.check(NOT EXISTS (
    SELECT 1 FROM pg_tables p WHERE p.schemaname = 'public'
      AND p.tablename NOT IN (SELECT e ->> 'table' FROM jsonb_array_elements(public.tenant_data_manifest()) e)
      -- model_usage_batches holds batch ids only (idempotency for the gateway's usage reports): no tenant data.
      -- operators and operator_identities are people, not tenant rows (ADR 0032); a member's e-mail is exported through organization_members.
      AND p.tablename NOT IN ('radar_count_reports', 'telegram_updates', 'signup_codes', 'tenant_deletions', 'model_usage_batches', 'operators', 'operator_identities')),
    'a table in neither the manifest nor the short list of platform tables fails this test, so a new table must be classified');
SELECT pg_temp.check(NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements(public.tenant_data_manifest()) e
    JOIN information_schema.columns c ON c.table_schema = 'public' AND c.table_name = e ->> 'table'
    WHERE c.column_name ~* '(key_hash|token_hash|code_hash|secret|password|jti|webhook_url)'
      AND NOT (e -> 'exclude') ? c.column_name
      -- credential_jti is the public id of a credential that lived at most 60 seconds and has expired; it proves which credential made a call and cannot authenticate anything.
      AND c.column_name <> 'credential_jti'),
    'every secret-looking column of a manifest table is left out of the export');
SELECT pg_temp.check(NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements(public.tenant_data_manifest()) e, jsonb_array_elements_text(e -> 'exclude') x
    WHERE NOT EXISTS (SELECT 1 FROM information_schema.columns c WHERE c.table_schema = 'public' AND c.table_name = e ->> 'table' AND c.column_name = x)),
    'every excluded column exists (a rename cannot silently re-expose it)');
-- Deleting the organization must reach every manifest table: each foreign key towards organizations or agents cascades.
SELECT pg_temp.check(NOT EXISTS (
    SELECT 1 FROM pg_constraint k
    WHERE k.contype = 'f' AND k.confrelid IN ('public.organizations'::regclass, 'public.agents'::regclass)
      AND k.conrelid::regclass::text IN (SELECT e ->> 'table' FROM jsonb_array_elements(public.tenant_data_manifest()) e)
      AND k.confdeltype <> 'c'),
    'every foreign key from a manifest table to organizations or agents cascades on delete');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Two tenants with data of several kinds
INSERT INTO auth.users (id, email) VALUES
    ('00000000-0000-0000-0000-0000900b0001', 'owner-a@example.test'), ('00000000-0000-0000-0000-0000900b0002', 'admin-a@example.test'),
    ('00000000-0000-0000-0000-0000900b0003', 'owner-b@example.test');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000900b00a0', 'Org A', 'lifecycle-a'), ('00000000-0000-0000-0000-0000900b00b0', 'Org B', 'lifecycle-b');
INSERT INTO public.organization_members (organization_id, user_id, role) VALUES
    ('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001', 'owner'),
    ('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0002', 'admin'),
    ('00000000-0000-0000-0000-0000900b00b0', '00000000-0000-0000-0000-0000900b0003', 'owner');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-0000900b00a1', '00000000-0000-0000-0000-0000900b00a0', 'a-1', 'Agent A1'),
    ('00000000-0000-0000-0000-0000900b00a2', '00000000-0000-0000-0000-0000900b00a0', 'a-2', 'Agent A2'),
    ('00000000-0000-0000-0000-0000900b00b1', '00000000-0000-0000-0000-0000900b00b0', 'b-1', 'Agent B1'),
    ('00000000-0000-0000-0000-0000900b00b2', '00000000-0000-0000-0000-0000900b00b0', 'b-2', 'Agent B2');
INSERT INTO public.agent_keys (organization_id, agent_id, key_prefix, key_hash) VALUES
    ('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b00a1', 'rh_a1', repeat('a', 64)),
    ('00000000-0000-0000-0000-0000900b00b0', '00000000-0000-0000-0000-0000900b00b1', 'rh_b1', repeat('b', 64));
INSERT INTO public.sdk_api_keys (organization_id, name, key_prefix, key_hash) VALUES
    ('00000000-0000-0000-0000-0000900b00a0', 'A key', 'rh_live_aaaa', repeat('c', 64)),
    ('00000000-0000-0000-0000-0000900b00b0', 'B key', 'rh_live_bbbb', repeat('d', 64));
INSERT INTO public.member_invites (organization_id, role, token_hash, created_by, expires_at) VALUES
    ('00000000-0000-0000-0000-0000900b00a0', 'viewer', repeat('e', 64), '00000000-0000-0000-0000-0000900b0001', now() + interval '7 days');
INSERT INTO public.telegram_link_codes (code_hash, organization_id, user_id, expires_at) VALUES
    (repeat('f', 64), '00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001', now() + interval '10 minutes');
INSERT INTO public.execution_traces (organization_id, agent_id, session_id, trace_id, span_id, step_type, ephemeral_token_jti)
VALUES ('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b00a1', gen_random_uuid(), 'trace-1', 'span-1', 'action', 'secret-jti-value');
SELECT public.record_events('instance-aaaa', gen_random_uuid(), '00000000-0000-0000-0000-0000900b00a0', jsonb_build_array(pg_temp.evt('00000000-0000-0000-0000-0000900b00a1')));
SELECT public.record_events('instance-bbbb', gen_random_uuid(), '00000000-0000-0000-0000-0000900b00b0', jsonb_build_array(pg_temp.evt('00000000-0000-0000-0000-0000900b00b1')));
INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, details) VALUES
    ('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001', 'passport.created', 'agent', '00000000-0000-0000-0000-0000900b00a1', '{}'),
    ('00000000-0000-0000-0000-0000900b00b0', '00000000-0000-0000-0000-0000900b0003', 'passport.created', 'agent', '00000000-0000-0000-0000-0000900b00b1', '{}');
INSERT INTO public.agent_budget_state (agent_id, day_key) VALUES ('00000000-0000-0000-0000-0000900b00a1', current_date), ('00000000-0000-0000-0000-0000900b00b1', current_date);

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Export
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_org_export('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0002')$$),
    'an admin cannot export: only an owner');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_org_export('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0003')$$),
    'an owner of another organization cannot export this one');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_org_export('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001', 0)$$),
    'a row cap of zero is refused');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.control_audit_log WHERE action = 'organization.exported'), 'refused exports write no audit row');

CREATE TEMP TABLE exp AS SELECT public.control_org_export('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001') AS j;
GRANT SELECT ON exp TO PUBLIC;
SELECT pg_temp.check((SELECT (j ->> 'exported')::boolean FROM exp), 'an owner can export');
SELECT pg_temp.check((SELECT count(*) FROM jsonb_object_keys((SELECT j -> 'tables' FROM exp))) = jsonb_array_length(public.tenant_data_manifest()),
    'the export has one entry per manifest table');
SELECT pg_temp.check((SELECT jsonb_array_length(j -> 'tables' -> 'agents' -> 'rows') FROM exp) = 2, 'both of the organization''s agents are exported');
SELECT pg_temp.check((SELECT j::text FROM exp) NOT LIKE '%Agent B1%' AND (SELECT j::text FROM exp) NOT LIKE '%owner-b@example.test%' AND (SELECT j::text FROM exp) NOT LIKE '%rh_live_bbbb%',
    'nothing of the other organization is in the export');
SELECT pg_temp.check((SELECT j::text FROM exp) !~ '"(key_hash|token_hash|code_hash|ephemeral_token_jti|siem_webhook_url|notification_webhook_url|resume_webhook_url)"',
    'no secret column appears anywhere in the export');
SELECT pg_temp.check((SELECT j::text FROM exp) NOT LIKE '%' || repeat('c', 64) || '%' AND (SELECT j::text FROM exp) NOT LIKE '%' || repeat('e', 64) || '%'
    AND (SELECT j::text FROM exp) NOT LIKE '%' || repeat('f', 64) || '%' AND (SELECT j::text FROM exp) NOT LIKE '%secret-jti-value%',
    'no key hash, token hash, code hash or token id value appears in the export');
SELECT pg_temp.check((SELECT j -> 'tables' -> 'agent_keys' -> 'rows' -> 0 ? 'key_prefix' FROM exp), 'the key prefix (not secret) is kept');
SELECT pg_temp.check((SELECT bool_or(r ->> 'email' = 'admin-a@example.test') FROM exp, jsonb_array_elements(j -> 'tables' -> 'organization_members' -> 'rows') r), 'members carry their e-mail');
SELECT pg_temp.check((SELECT jsonb_array_length(j -> 'tables' -> 'agent_events' -> 'rows') FROM exp) = 1 AND (SELECT jsonb_array_length(j -> 'tables' -> 'agent_budget_state' -> 'rows') FROM exp) = 1,
    'events and agent-scoped tables are exported');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'organization.exported') = 1, 'an export writes one audit row');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.control_audit_log WHERE action = 'organization.exported' AND (details::text LIKE '%Agent A1%' OR details::text LIKE '%owner-a%')),
    'the audit row holds counts only, never the exported data');
SELECT pg_temp.check((SELECT NOT (public.control_org_export('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001') ->> 'exported')::boolean
                      AND public.control_org_export('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001') ->> 'reason' = 'throttled'),
    'a second export within the hour is throttled');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'organization.exported') = 1, 'a throttled export writes no audit row');
SELECT pg_temp.check((SELECT NOT (j -> 'tables' -> 'agents' ->> 'truncated')::boolean FROM exp), 'a table under the cap is not marked truncated');
CREATE TEMP TABLE exp_small AS SELECT public.control_org_export('00000000-0000-0000-0000-0000900b00b0', '00000000-0000-0000-0000-0000900b0003', 1) AS j;
SELECT pg_temp.check((SELECT (j -> 'tables' -> 'agents' ->> 'count')::int = 2 AND (j -> 'tables' -> 'agents' ->> 'truncated')::boolean
                      AND jsonb_array_length(j -> 'tables' -> 'agents' -> 'rows') = 1 FROM exp_small), 'a table over the cap says so and returns only the cap');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Deletion request
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_org_request_deletion('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0002', 'lifecycle-a')$$),
    'an admin cannot request deletion');
SELECT pg_temp.check(public.control_org_request_deletion('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001', 'lifecycle-b') ->> 'reason' = 'confirmation',
    'a wrong slug is refused');
SELECT pg_temp.check(public.control_org_request_deletion('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001', NULL) ->> 'reason' = 'confirmation',
    'a missing slug is refused');
SELECT pg_temp.check((SELECT deletion_requested_at IS NULL FROM public.organizations WHERE slug = 'lifecycle-a')
    AND (SELECT count(*) FROM public.agents WHERE organization_id = '00000000-0000-0000-0000-0000900b00a0' AND status = 'active') = 2, 'a refused request changes nothing');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_org_request_deletion('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001', 'lifecycle-a', interval '10 minutes')$$),
    'a grace period under one day is refused');
SELECT pg_temp.check((public.control_org_request_deletion('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001', 'lifecycle-a') ->> 'requested')::boolean, 'the owner can request deletion');
SELECT pg_temp.check((SELECT deletion_purge_after - deletion_requested_at = interval '7 days' FROM public.organizations WHERE slug = 'lifecycle-a'), 'the grace period is 7 days');
SELECT pg_temp.check((SELECT count(*) FROM public.agents WHERE organization_id = '00000000-0000-0000-0000-0000900b00a0' AND status = 'frozen') = 2, 'every agent is frozen');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.sdk_api_keys WHERE organization_id = '00000000-0000-0000-0000-0000900b00a0' AND is_active), 'SDK keys are switched off');
SELECT pg_temp.check((SELECT revoked_at IS NOT NULL FROM public.member_invites WHERE organization_id = '00000000-0000-0000-0000-0000900b00a0'), 'pending invites are revoked');
SELECT pg_temp.check((SELECT status = 'active' FROM public.agents WHERE id = '00000000-0000-0000-0000-0000900b00b1')
    AND (SELECT is_active FROM public.sdk_api_keys WHERE organization_id = '00000000-0000-0000-0000-0000900b00b0'), 'the other organization is untouched');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'organization.deletion_requested') = 1, 'the request is audited once');
SELECT pg_temp.check((public.control_org_request_deletion('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001', 'lifecycle-a') ->> 'already')::boolean
    AND (SELECT count(*) FROM public.control_audit_log WHERE action = 'organization.deletion_requested') = 1, 'a second request is idempotent and does not write a second audit row');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_org_purge('00000000-0000-0000-0000-0000900b00a0')$$), 'the purge is refused during the grace period');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_org_purge('00000000-0000-0000-0000-0000900b00b0')$$), 'the purge is refused for an organization with no request');

-- Cancel
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_org_cancel_deletion('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0002')$$), 'an admin cannot cancel');
SELECT pg_temp.check((public.control_org_cancel_deletion('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001') ->> 'cancelled')::boolean, 'the owner can cancel');
SELECT pg_temp.check((SELECT deletion_requested_at IS NULL AND deletion_purge_after IS NULL AND deletion_requested_by IS NULL FROM public.organizations WHERE slug = 'lifecycle-a'), 'and the dates are cleared');
SELECT pg_temp.check((SELECT count(*) FROM public.agents WHERE organization_id = '00000000-0000-0000-0000-0000900b00a0' AND status = 'frozen') = 2,
    'cancelling does not unfreeze: that stays a deliberate per-agent action');
SELECT pg_temp.check(public.control_org_cancel_deletion('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001') ->> 'reason' = 'not_requested', 'cancelling twice says nothing was pending');
SELECT pg_temp.check((SELECT count(*) FROM public.control_audit_log WHERE action = 'organization.deletion_cancelled') = 1, 'one cancel audit row');

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Purge
SELECT public.control_org_request_deletion('00000000-0000-0000-0000-0000900b00a0', '00000000-0000-0000-0000-0000900b0001', 'lifecycle-a');
UPDATE public.organizations SET deletion_requested_at = now() - interval '8 days', deletion_purge_after = now() - interval '1 day' WHERE slug = 'lifecycle-a';
CREATE TEMP TABLE purged AS SELECT public.control_org_purge('00000000-0000-0000-0000-0000900b00a0') AS j;
SELECT pg_temp.check((SELECT (j ->> 'purged')::boolean FROM purged), 'the purge runs after the grace period');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.organizations WHERE slug = 'lifecycle-a'), 'the organization is gone');
SELECT pg_temp.check((SELECT (sum(value::bigint)) = 0 FROM jsonb_each_text(public.tenant_row_counts('00000000-0000-0000-0000-0000900b00a0'))), 'no manifest table holds a row for it');
SELECT pg_temp.check(NOT EXISTS (SELECT 1 FROM public.control_audit_log WHERE organization_id = '00000000-0000-0000-0000-0000900b00a0')
    AND NOT EXISTS (SELECT 1 FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000900b00a0'), 'its audit log and Black Box events went with it');
SELECT pg_temp.check((SELECT status = 'active' FROM public.agents WHERE id = '00000000-0000-0000-0000-0000900b00b1')
    AND (SELECT count(*) FROM public.agent_events WHERE organization_id = '00000000-0000-0000-0000-0000900b00b0') = 1
    AND (SELECT count(*) FROM public.control_audit_log WHERE organization_id = '00000000-0000-0000-0000-0000900b00b0') >= 1
    AND EXISTS (SELECT 1 FROM public.organization_members WHERE user_id = '00000000-0000-0000-0000-0000900b0003'), 'the other organization keeps everything');
SELECT pg_temp.check((SELECT count(*) FROM pg_trigger WHERE tgname IN ('control_audit_log_no_update', 'trg_agent_events_append_only') AND tgenabled = 'O') = 2, 'both append-only triggers are enabled again');
SELECT pg_temp.check(pg_temp.raises($$DELETE FROM public.control_audit_log WHERE organization_id = '00000000-0000-0000-0000-0000900b00b0'$$), 'audit rows are append-only again');
SELECT pg_temp.check((SELECT count(*) FROM public.tenant_deletions WHERE organization_id = '00000000-0000-0000-0000-0000900b00a0') = 1, 'the deletion is recorded');
SELECT pg_temp.check((SELECT row_counts ->> 'agents' = '2' AND slug_sha256 = encode(sha256(convert_to('lifecycle-a', 'UTF8')), 'hex') FROM public.tenant_deletions), 'with counts and a hash of the slug');
SELECT pg_temp.check((SELECT row_to_json(d)::text FROM public.tenant_deletions d) NOT LIKE '%lifecycle-a%' AND (SELECT row_to_json(d)::text FROM public.tenant_deletions d) NOT LIKE '%Org A%',
    'the record holds no name or slug');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_org_purge('00000000-0000-0000-0000-0000900b00a0')$$), 'purging again fails: nothing left to purge');

-- A purge that cannot finish cleanly rolls everything back
UPDATE public.organizations SET deletion_requested_at = now() - interval '8 days', deletion_requested_by = '00000000-0000-0000-0000-0000900b0003', deletion_purge_after = now() - interval '1 day' WHERE slug = 'lifecycle-b';
CREATE TABLE public.zz_blocker (organization_id UUID REFERENCES public.organizations(id) ON DELETE RESTRICT);
INSERT INTO public.zz_blocker VALUES ('00000000-0000-0000-0000-0000900b00b0');
SELECT pg_temp.check(pg_temp.raises($$SELECT public.control_org_purge('00000000-0000-0000-0000-0000900b00b0')$$), 'a purge blocked by a restricting reference fails');
SELECT pg_temp.check(EXISTS (SELECT 1 FROM public.organizations WHERE slug = 'lifecycle-b') AND (SELECT count(*) FROM pg_trigger WHERE tgname IN ('control_audit_log_no_update', 'trg_agent_events_append_only') AND tgenabled = 'O') = 2,
    'and leaves the organization and both triggers as they were');
DROP TABLE public.zz_blocker;

-- ---------------------------------------------------------------------------------------------------------------------------------
-- Who can call what
SELECT pg_temp.check(NOT has_function_privilege('anon', 'public.control_org_export(uuid, uuid, integer)', 'EXECUTE')
                     AND NOT has_function_privilege('authenticated', 'public.control_org_request_deletion(uuid, uuid, text, interval)', 'EXECUTE')
                     AND NOT has_function_privilege('authenticated', 'public.control_org_cancel_deletion(uuid, uuid)', 'EXECUTE')
                     AND NOT has_function_privilege('authenticated', 'public.tenant_data_manifest()', 'EXECUTE'), 'no client role can call the lifecycle functions');
SELECT pg_temp.check(NOT has_function_privilege('anon', 'public.control_org_purge(uuid)', 'EXECUTE')
                     AND NOT has_function_privilege('authenticated', 'public.control_org_purge(uuid)', 'EXECUTE')
                     AND NOT has_function_privilege('service_role', 'public.control_org_purge(uuid)', 'EXECUTE'), 'not even the service role can purge: only the database owner');

DO $$ BEGIN RAISE NOTICE 'ALL SQL TESTS PASSED'; END $$;
ROLLBACK;
