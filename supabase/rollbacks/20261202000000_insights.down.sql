-- Rolls back 20261202000000_insights.sql: the summary function and its index. Nothing else depends on them.
BEGIN;
DROP FUNCTION IF EXISTS public.insights_summary(uuid, timestamptz, timestamptz, integer);
DROP FUNCTION IF EXISTS public.insights_reason_category(text, text);
DROP INDEX IF EXISTS public.idx_agent_events_org_time;
COMMIT;
