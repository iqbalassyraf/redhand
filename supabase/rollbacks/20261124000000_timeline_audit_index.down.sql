-- Rollback for supabase/migrations/20261124000000_timeline_audit_index.sql. Drops the index only; no data is touched.
BEGIN;
DROP INDEX IF EXISTS public.idx_control_audit_org_target_time;
COMMIT;
