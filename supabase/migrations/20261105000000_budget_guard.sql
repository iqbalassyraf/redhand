-- =============================================================================
-- Budget Guard (Phase 2, M3): daily tool-call caps per agent.
-- Rollback: supabase/rollbacks/20261105000000_budget_guard.down.sql
-- Plan: docs/plans/phase2-m3-budget-guard.md   ADR: docs/adr/0010-budget-guard.md
--
-- What is stored: counts of tool calls per agent per day. Never payloads or arguments.
--   agents.daily_call_limit   NULL = no limit; otherwise 1..10,000,000 calls per local day
--   agents.budget_action      'deny' (refuse over the limit) or 'freeze' (also freeze the agent)
--   organizations.utc_offset_minutes   where the day starts (default 480 = UTC+8)
--   agent_usage_daily         cumulative calls reported by each gateway instance, per agent and day
--   agent_budget_state        which alerts were already raised for an agent and day (once per day)
--
-- Reports are CUMULATIVE and stored with GREATEST(), so re-sending is harmless and a stale or buggy
-- report can never lower a count. Every function is SECURITY INVOKER with a fixed search_path and
-- executable only by service_role. The organization of a usage report is always taken from the
-- agents table, never from the reporter.
--
-- Retention: usage and alert-state rows are deleted after 90 days by purge_usage(); schedule it
-- daily (docs/runbooks/budget-guard.md). Rows are deleted with their agent or organization.
-- =============================================================================

BEGIN;

ALTER TABLE public.agents
    ADD COLUMN daily_call_limit INTEGER CHECK (daily_call_limit IS NULL OR daily_call_limit BETWEEN 1 AND 10000000),
    ADD COLUMN budget_action TEXT NOT NULL DEFAULT 'deny' CHECK (budget_action IN ('deny', 'freeze'));

ALTER TABLE public.organizations
    ADD COLUMN utc_offset_minutes INTEGER NOT NULL DEFAULT 480 CHECK (utc_offset_minutes BETWEEN -720 AND 840);

CREATE TABLE public.agent_usage_daily (
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    day_key DATE NOT NULL,
    instance_id TEXT NOT NULL CHECK (char_length(instance_id) BETWEEN 8 AND 64),
    calls BIGINT NOT NULL CHECK (calls >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, day_key, instance_id)
);
CREATE INDEX idx_agent_usage_org_day ON public.agent_usage_daily(organization_id, day_key);

CREATE TABLE public.agent_budget_state (
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    day_key DATE NOT NULL,
    warned_at TIMESTAMPTZ,
    limit_reached_at TIMESTAMPTZ,
    frozen_at TIMESTAMPTZ,
    PRIMARY KEY (agent_id, day_key)
);

ALTER TABLE public.agent_usage_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_budget_state ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked',
    'passport.safe_mode_enabled', 'passport.safe_mode_disabled',
    'organization.safe_mode_enabled', 'organization.safe_mode_disabled',
    'passport.budget_changed'
));

-- -----------------------------------------------------------------------------
-- Change an agent's limit and action, with the audit row, in one transaction.
-- NULL p_limit removes the limit. Idempotent (no change, no audit row).
-- Compare-and-set: the caller passes the limit and action it based its decision on; if either has
-- changed meanwhile the function returns {conflict: true} and changes nothing, so an authorization
-- decision (raising a limit needs an admin) can never be applied to a state it was not made for.
-- A changed limit also resets today's and yesterday's once-per-day alert state, so reaching the NEW
-- limit alerts (and auto-freezes) again.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_agent_budget(
    p_org uuid, p_agent uuid, p_actor uuid, p_limit integer, p_action text, p_reason text,
    p_expected_limit integer, p_expected_action text
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_agent public.agents%ROWTYPE;
BEGIN
    SELECT * INTO v_agent FROM public.agents WHERE id = p_agent AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'agent not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_agent.daily_call_limit IS DISTINCT FROM p_expected_limit OR v_agent.budget_action IS DISTINCT FROM p_expected_action THEN
        RETURN jsonb_build_object('conflict', true);
    END IF;
    IF v_agent.daily_call_limit IS NOT DISTINCT FROM p_limit AND v_agent.budget_action = p_action THEN
        RETURN jsonb_build_object('changed', false, 'agent_id', v_agent.id,
                                  'daily_call_limit', v_agent.daily_call_limit, 'budget_action', v_agent.budget_action);
    END IF;

    UPDATE public.agents SET daily_call_limit = p_limit, budget_action = p_action WHERE id = v_agent.id;
    IF v_agent.daily_call_limit IS DISTINCT FROM p_limit THEN
        UPDATE public.agent_budget_state SET warned_at = NULL, limit_reached_at = NULL, frozen_at = NULL
        WHERE agent_id = v_agent.id AND day_key >= (now() AT TIME ZONE 'utc')::date - 1;
    END IF;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'passport.budget_changed', 'agent', v_agent.id, p_reason,
            jsonb_build_object('old_limit', v_agent.daily_call_limit, 'new_limit', p_limit,
                               'old_action', v_agent.budget_action, 'new_action', p_action));
    RETURN jsonb_build_object('changed', true, 'agent_id', v_agent.id,
                              'daily_call_limit', p_limit, 'budget_action', p_action);
END;
$$;

-- -----------------------------------------------------------------------------
-- A gateway instance reports cumulative totals. Returns the alerts that were newly triggered, so the
-- caller sends each at most once per agent per day, even with several reporters at the same time.
-- Items for unknown agents, with a day outside [today-2, today+2] (UTC) or a negative count are
-- skipped and counted as rejected.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.record_usage(p_instance text, p_items jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_item jsonb;
    v_agent public.agents%ROWTYPE;
    v_day date;
    v_calls bigint;
    v_total bigint;
    v_offset integer;
    v_accepted integer := 0;
    v_rejected integer := 0;
    v_events jsonb := '[]'::jsonb;
    v_kind text;
    v_updated integer;
BEGIN
    IF p_instance IS NULL OR char_length(p_instance) NOT BETWEEN 8 AND 64 THEN
        RAISE EXCEPTION 'invalid instance id' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_items IS NULL OR jsonb_typeof(p_items) <> 'array' OR jsonb_array_length(p_items) > 1000 THEN
        RAISE EXCEPTION 'items must be an array of at most 1000 entries' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Items are processed in agent order and each agent row is locked before its total is summed, so
    -- two reports for the same agent are serialised (the second sees the first's rows and cannot both
    -- miss a threshold) and two reports can never deadlock on each other.
    FOR v_item IN SELECT value FROM jsonb_array_elements(p_items) ORDER BY value ->> 'agent_id' LOOP
        BEGIN
            v_day := (v_item ->> 'day_key')::date;
            v_calls := (v_item ->> 'calls')::bigint;
        EXCEPTION WHEN OTHERS THEN
            v_rejected := v_rejected + 1;
            CONTINUE;
        END;
        IF v_calls IS NULL OR v_calls < 0 OR v_calls > 1000000000000
           OR v_day < (now() AT TIME ZONE 'utc')::date - 2 OR v_day > (now() AT TIME ZONE 'utc')::date + 2 THEN
            v_rejected := v_rejected + 1;
            CONTINUE;
        END IF;
        BEGIN
            SELECT * INTO v_agent FROM public.agents WHERE id = (v_item ->> 'agent_id')::uuid FOR UPDATE;
        EXCEPTION WHEN OTHERS THEN
            v_rejected := v_rejected + 1;
            CONTINUE;
        END;
        IF NOT FOUND THEN
            v_rejected := v_rejected + 1;
            CONTINUE;
        END IF;

        INSERT INTO public.agent_usage_daily (agent_id, organization_id, day_key, instance_id, calls)
        VALUES (v_agent.id, v_agent.organization_id, v_day, p_instance, v_calls)
        ON CONFLICT (agent_id, day_key, instance_id)
        DO UPDATE SET calls = GREATEST(public.agent_usage_daily.calls, EXCLUDED.calls), updated_at = now();
        v_accepted := v_accepted + 1;

        IF v_agent.daily_call_limit IS NULL THEN
            CONTINUE;
        END IF;
        SELECT COALESCE(SUM(calls), 0) INTO v_total FROM public.agent_usage_daily
        WHERE agent_id = v_agent.id AND day_key = v_day;

        INSERT INTO public.agent_budget_state (agent_id, day_key) VALUES (v_agent.id, v_day)
        ON CONFLICT DO NOTHING;

        v_kind := NULL;
        IF v_total >= v_agent.daily_call_limit THEN
            UPDATE public.agent_budget_state
            SET limit_reached_at = now(), warned_at = COALESCE(warned_at, now())
            WHERE agent_id = v_agent.id AND day_key = v_day AND limit_reached_at IS NULL;
            GET DIAGNOSTICS v_updated = ROW_COUNT;
            IF v_updated = 1 THEN v_kind := 'limit'; END IF;
        ELSIF v_total * 100 >= v_agent.daily_call_limit::bigint * 80 THEN
            UPDATE public.agent_budget_state SET warned_at = now()
            WHERE agent_id = v_agent.id AND day_key = v_day AND warned_at IS NULL;
            GET DIAGNOSTICS v_updated = ROW_COUNT;
            IF v_updated = 1 THEN v_kind := 'warn'; END IF;
        END IF;

        IF v_kind IS NOT NULL THEN
            SELECT utc_offset_minutes INTO v_offset FROM public.organizations WHERE id = v_agent.organization_id;
            v_events := v_events || jsonb_build_array(jsonb_build_object(
                'kind', v_kind, 'agent_id', v_agent.id, 'organization_id', v_agent.organization_id,
                'name', v_agent.name, 'day_key', v_day, 'used', v_total,
                'daily_call_limit', v_agent.daily_call_limit, 'budget_action', v_agent.budget_action,
                'utc_offset_minutes', v_offset));
        END IF;
    END LOOP;

    RETURN jsonb_build_object('accepted', v_accepted, 'rejected', v_rejected, 'events', v_events);
END;
$$;

-- Marks that the auto-freeze for an agent and day has been carried out (so it happens once).
CREATE OR REPLACE FUNCTION public.mark_budget_frozen(p_agent uuid, p_day date)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_updated integer;
BEGIN
    UPDATE public.agent_budget_state SET frozen_at = now()
    WHERE agent_id = p_agent AND day_key = p_day AND frozen_at IS NULL;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated = 1;
END;
$$;

-- Calls reported by every instance EXCEPT the caller (the gateway adds its own exact local count).
CREATE OR REPLACE FUNCTION public.usage_by_others(p_org uuid, p_agent uuid, p_day date, p_instance text)
RETURNS bigint
LANGUAGE sql
STABLE
SET search_path = public, pg_temp
AS $$
    SELECT COALESCE(SUM(calls), 0)::bigint FROM public.agent_usage_daily
    WHERE organization_id = p_org AND agent_id = p_agent AND day_key = p_day AND instance_id <> p_instance;
$$;

-- Today's total per agent of the organization, for the dashboard and Telegram.
CREATE OR REPLACE FUNCTION public.org_usage(p_org uuid, p_day date)
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = public, pg_temp
AS $$
    SELECT COALESCE(jsonb_agg(jsonb_build_object('agent_id', agent_id, 'calls', total)), '[]'::jsonb)
    FROM (
        SELECT agent_id, SUM(calls)::bigint AS total FROM public.agent_usage_daily
        WHERE organization_id = p_org AND day_key = p_day GROUP BY agent_id
    ) t;
$$;

CREATE OR REPLACE FUNCTION public.purge_usage()
RETURNS integer
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_usage integer;
    v_state integer;
BEGIN
    DELETE FROM public.agent_usage_daily WHERE day_key < (now() AT TIME ZONE 'utc')::date - 90;
    GET DIAGNOSTICS v_usage = ROW_COUNT;
    DELETE FROM public.agent_budget_state WHERE day_key < (now() AT TIME ZONE 'utc')::date - 90;
    GET DIAGNOSTICS v_state = ROW_COUNT;
    RETURN v_usage + v_state;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.control_agent_budget(uuid, uuid, uuid, integer, text, text, integer, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.record_usage(text, jsonb) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.mark_budget_frozen(uuid, date) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.usage_by_others(uuid, uuid, date, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.org_usage(uuid, date) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.purge_usage() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.control_agent_budget(uuid, uuid, uuid, integer, text, text, integer, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.record_usage(text, jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.mark_budget_frozen(uuid, date) TO service_role;
GRANT EXECUTE ON FUNCTION public.usage_by_others(uuid, uuid, date, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.org_usage(uuid, date) TO service_role;
GRANT EXECUTE ON FUNCTION public.purge_usage() TO service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';
