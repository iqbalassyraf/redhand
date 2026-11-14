-- =============================================================================
-- Phase 4.5 B2: behaviour baseline (docs/plans/phase45-b2-behaviour-baseline.md, ADR 0020).
-- Rollback: supabase/rollbacks/20261123000000_behaviour_baseline.down.sql
--
-- An hourly roll-up of each agent's tool calls, so redhand-core can tell when an agent behaves unlike itself (a surge of calls, a tool it
-- never used) without reading weeks of raw Black Box events per page view. Counts and tool names only, both already in agent_events.
-- The rules themselves are plain Python in core (risk/behaviour.py); this file only stores and reads counts.
--
-- New: agent_tool_hourly, a row trigger on agent_events that keeps it current, agent_behaviour_hours(), purge_behaviour() (35 days), a
-- one-time backfill of the last 30 days. record_events() is NOT changed. The trigger runs inside record_events()' transaction: if it ever
-- failed, the whole Black Box batch would roll back and the gateway would send it again (it never waits on recording to enforce).
-- =============================================================================

BEGIN;

CREATE TABLE public.agent_tool_hourly (
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    hour TIMESTAMPTZ NOT NULL CHECK (hour = date_trunc('hour', hour, 'UTC')),
    tool_name TEXT NOT NULL CHECK (char_length(tool_name) <= 128),
    calls INTEGER NOT NULL CHECK (calls >= 0),
    refused INTEGER NOT NULL DEFAULT 0 CHECK (refused >= 0 AND refused <= calls),
    PRIMARY KEY (agent_id, hour, tool_name)
);
CREATE INDEX idx_agent_tool_hourly_org_hour ON public.agent_tool_hourly(organization_id, hour);
ALTER TABLE public.agent_tool_hourly ENABLE ROW LEVEL SECURITY;  -- core uses the service role; no policies, nobody else reads it

-- -----------------------------------------------------------------------------
-- The roll-up trigger. record_events() inserts one event per statement, so a row trigger costs the same as a statement trigger and is
-- simpler. Only tool calls count (not initialize, tools/list or the recorder's own gap events). Concurrent batches of one organization
-- are already serialised by record_events() (it locks the organization's chain head), so two upserts on the same row never race.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.behaviour_rollup() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    INSERT INTO public.agent_tool_hourly AS h (organization_id, agent_id, hour, tool_name, calls, refused)
    VALUES (NEW.organization_id, NEW.agent_id, date_trunc('hour', NEW.occurred_at, 'UTC'), left(NEW.tool_name, 128), 1,
            CASE WHEN NEW.decision = 'BLOCK' THEN 1 ELSE 0 END)
    ON CONFLICT (agent_id, hour, tool_name)
    DO UPDATE SET calls = h.calls + 1, refused = h.refused + EXCLUDED.refused;
    RETURN NULL;
END $$;

CREATE TRIGGER trg_agent_events_behaviour AFTER INSERT ON public.agent_events
    FOR EACH ROW WHEN (NEW.method = 'tools/call')
    EXECUTE FUNCTION public.behaviour_rollup();

-- One-time backfill: the last 30 days (the default Black Box retention), grouped. Older events add nothing to a 21-day read.
INSERT INTO public.agent_tool_hourly (organization_id, agent_id, hour, tool_name, calls, refused)
SELECT e.organization_id, e.agent_id, date_trunc('hour', e.occurred_at, 'UTC'), left(e.tool_name, 128), count(*),
       count(*) FILTER (WHERE e.decision = 'BLOCK')
FROM public.agent_events e
WHERE e.method = 'tools/call' AND e.occurred_at > now() - interval '30 days'
GROUP BY 1, 2, 3, 4;

-- -----------------------------------------------------------------------------
-- agent_behaviour_hours(): one agent's (or, with p_agent NULL, every agent's) hourly counts from p_since to p_until, organization-scoped.
-- core reads 21 days: 14 for the window plus 7 so that every replayed hour of the back-test sees a full window.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.agent_behaviour_hours(p_org uuid, p_agent uuid, p_since timestamptz, p_until timestamptz)
RETURNS TABLE (agent_id uuid, hour timestamptz, tool_name text, calls integer)
LANGUAGE sql
STABLE
SET search_path = public, pg_temp
AS $$
    SELECT h.agent_id, h.hour, h.tool_name, h.calls
    FROM public.agent_tool_hourly h
    WHERE h.organization_id = p_org AND (p_agent IS NULL OR h.agent_id = p_agent)
      AND h.hour >= p_since AND h.hour <= p_until
    ORDER BY h.agent_id, h.hour
$$;

-- -----------------------------------------------------------------------------
-- purge_behaviour(): hours older than 35 days (21 are read; the rest is margin). Counts only, so no tenant setting is needed.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.purge_behaviour() RETURNS integer
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_deleted integer;
BEGIN
    DELETE FROM public.agent_tool_hourly WHERE hour < now() - interval '35 days';
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END $$;

REVOKE EXECUTE ON FUNCTION public.behaviour_rollup() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.agent_behaviour_hours(uuid, uuid, timestamptz, timestamptz) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.purge_behaviour() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.agent_behaviour_hours(uuid, uuid, timestamptz, timestamptz) TO service_role;
GRANT EXECUTE ON FUNCTION public.purge_behaviour() TO service_role;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_cron') THEN
        CREATE EXTENSION IF NOT EXISTS pg_cron;
        PERFORM cron.schedule('redhand-purge-behaviour', '47 19 * * *', 'SELECT public.purge_behaviour()');
        RAISE NOTICE 'scheduled redhand-purge-behaviour';
    ELSE
        RAISE NOTICE 'pg_cron is not available here: schedule purge_behaviour() yourself (daily)';
    END IF;
END;
$$;

COMMIT;
