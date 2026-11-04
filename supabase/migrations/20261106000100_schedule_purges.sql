-- =============================================================================
-- Scheduled retention: run the two purge functions every day with pg_cron.
-- Rollback: supabase/rollbacks/20261106000100_schedule_purges.down.sql
--
--   purge_telegram_updates()  removes Telegram update ids older than 7 days and used or expired link codes
--   purge_usage()             removes Budget Guard usage and alert-state rows older than 90 days
--
-- Both run at 19:17 UTC (03:17 in Malaysia), when traffic is lowest. Safe to re-run: cron.schedule
-- replaces a job of the same name. On a database without pg_cron (a plain PostgreSQL used for tests) the
-- migration does nothing and says so; the functions can then be scheduled with any other scheduler.
-- =============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_cron') THEN
        CREATE EXTENSION IF NOT EXISTS pg_cron;
        PERFORM cron.schedule('redhand-purge-telegram', '17 19 * * *', 'SELECT public.purge_telegram_updates()');
        PERFORM cron.schedule('redhand-purge-usage', '17 19 * * *', 'SELECT public.purge_usage()');
        RAISE NOTICE 'scheduled redhand-purge-telegram and redhand-purge-usage';
    ELSE
        RAISE NOTICE 'pg_cron is not available here: schedule purge_telegram_updates() and purge_usage() yourself (daily)';
    END IF;
END;
$$;
