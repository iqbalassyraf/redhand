-- Rollback for 20261106000100_schedule_purges.sql: removes the two scheduled jobs (the pg_cron extension
-- itself is left installed, since other things may use it). The purge functions keep working when called by hand.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.unschedule(jobid) FROM cron.job WHERE jobname IN ('redhand-purge-telegram', 'redhand-purge-usage');
    END IF;
END;
$$;
