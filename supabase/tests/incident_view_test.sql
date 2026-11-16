-- SQL tests for supabase/migrations/20261124000000_incident_view.sql (Phase 4.5 B3, the incident view).

\set ON_ERROR_STOP on
\set QUIET on

BEGIN;

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'CHECK FAILED: %', p_msg; END IF;
    RAISE NOTICE 'ok: %', p_msg;
END;
$$;

SELECT pg_temp.check(
    (SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'idx_control_audit_org_target_time')
        = 'CREATE INDEX idx_control_audit_org_target_time ON public.control_audit_log USING btree (organization_id, target_id, created_at DESC)',
    'the audit index serves one agent''s actions, newest first');

-- The planner uses it for the timeline's read (forced off sequential scans, because a test database is tiny).
SET LOCAL enable_seqscan = off;
CREATE TEMP TABLE plan_lines(line text);
DO $$
DECLARE r record;
BEGIN
    FOR r IN EXECUTE 'EXPLAIN SELECT action FROM public.control_audit_log WHERE organization_id = ''00000000-0000-0000-0000-000000000001'' AND target_id = ''00000000-0000-0000-0000-000000000002'' ORDER BY created_at DESC LIMIT 51'
    LOOP INSERT INTO plan_lines VALUES (r."QUERY PLAN"); END LOOP;
END $$;
SELECT pg_temp.check(EXISTS (SELECT 1 FROM plan_lines WHERE line LIKE '%idx_control_audit_org_target_time%'), 'the timeline''s audit read uses it');

-- The export's audit action is accepted; an unknown action is still refused.
INSERT INTO public.organizations (id, name, slug) VALUES ('00000000-0000-0000-0000-00000000b301', 'B3 test', 'b3-test');
INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, details)
VALUES ('00000000-0000-0000-0000-00000000b301', gen_random_uuid(), 'passport.timeline_exported', 'agent', gen_random_uuid(), '{"format": "csv"}');
SELECT pg_temp.check(true, 'passport.timeline_exported is an accepted audit action');
DO $$
BEGIN
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id)
    VALUES ('00000000-0000-0000-0000-00000000b301', gen_random_uuid(), 'passport.timeline_deleted', 'agent', gen_random_uuid());
    RAISE EXCEPTION 'CHECK FAILED: an unknown action was accepted';
EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'ok: an unknown audit action is still refused';
END $$;

DO $$ BEGIN RAISE NOTICE 'TESTS PASSED: incident view'; END $$;
ROLLBACK;
