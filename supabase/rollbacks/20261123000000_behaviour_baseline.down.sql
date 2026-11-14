-- Rollback for 20261123000000_behaviour_baseline.sql: unschedules the purge (when pg_cron is present), drops the trigger, the functions
-- and the roll-up table. Stated data loss: the hourly roll-up only; the Black Box events it was built from are untouched.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.unschedule('redhand-purge-behaviour');
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'redhand-purge-behaviour was not scheduled';
END;
$$;

DROP TRIGGER IF EXISTS trg_agent_events_behaviour ON public.agent_events;
DROP FUNCTION IF EXISTS public.behaviour_rollup();
DROP FUNCTION IF EXISTS public.purge_behaviour();
DROP FUNCTION IF EXISTS public.agent_behaviour_hours(uuid, uuid, timestamptz, timestamptz);
DROP TABLE IF EXISTS public.agent_tool_hourly;

COMMIT;
