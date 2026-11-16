-- =============================================================================
-- Phase 4.5 B4a: model spend, detective (docs/plans/phase45-b4-spend.md, ADR 0023).
-- Rollback: supabase/rollbacks/20261125000000_model_spend.down.sql
--
-- A daily roll-up of the model use an agent's SDK reports (provider, model, calls, prompt and completion tokens), so redhand-core can
-- estimate cost and compare it with a dollar limit without reading raw spans (which hold thought text and payloads: B4 never reads them).
-- The numbers are SELF-REPORTED: an organization's SDK key can name any of its agents. They are never used to refuse a call.
--
-- New: agent_model_daily, a statement trigger on execution_traces that keeps it current, agent_model_usage() (read),
-- model_spend_backfill() (the one-time backfill and the repair tool), purge_model_spend() (90 days), agents.spend_limit_micro_usd,
-- agents.spend_alerted_day, control_agent_spend_limit(), spend_mark_alerted(). Changed: the audit action list (every earlier action kept).
-- Additive: an older core keeps working and simply never reads any of it.
--
-- The trigger runs inside the telemetry ingest transaction. It is a detective feature, so a failure in it is logged as a warning and the
-- span is still stored: the ingest must never fail (and the SDK retry) because a roll-up could not be written.
-- =============================================================================

BEGIN;

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked',
    'passport.safe_mode_enabled', 'passport.safe_mode_disabled',
    'organization.safe_mode_enabled', 'organization.safe_mode_disabled',
    'passport.budget_changed', 'organization.budget_default_changed',
    'organization.blackbox_retention_changed', 'organization.blackbox_purged',
    'organization.payload_capture_changed',
    'organization.blackbox_payload_viewed', 'organization.blackbox_exported',
    'organization.blackbox_payloads_cleared',
    'honeytoken.created', 'honeytoken.retired', 'honeytoken.tripped',
    'honey_tool.created', 'honey_tool.retired', 'honey_tool.tripped',
    'tool_pin.pending', 'tool_pin.approved', 'tool_pin.rejected', 'tool_pin.approved_all',
    'mcp_server.pin_mode_changed',
    'organization.radar_settings_changed', 'radar_finding.reviewed',
    'radar_suppression.created', 'radar_suppression.revoked',
    'organization.loop_settings_changed',
    'passport.destination_added', 'passport.destination_removed', 'passport.destination_mode_changed',
    'organization.risk_ladder_changed',
    'passport.timeline_exported',
    'passport.spend_limit_changed'
));

CREATE TABLE public.agent_model_daily (
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    day DATE NOT NULL,  -- the day in the organization's UTC offset at the time of the call (Budget Guard's rule)
    provider TEXT NOT NULL CHECK (char_length(provider) <= 64),
    model TEXT NOT NULL CHECK (char_length(model) BETWEEN 1 AND 128),
    calls BIGINT NOT NULL CHECK (calls >= 0),
    prompt_tokens BIGINT NOT NULL CHECK (prompt_tokens >= 0),
    completion_tokens BIGINT NOT NULL CHECK (completion_tokens >= 0),
    PRIMARY KEY (agent_id, day, provider, model)
);
CREATE INDEX idx_agent_model_daily_org_day ON public.agent_model_daily(organization_id, day);
ALTER TABLE public.agent_model_daily ENABLE ROW LEVEL SECURITY;  -- core uses the service role; no policies, nobody else reads it

-- A dollar limit in micro-dollars (1 = one millionth of a dollar; at most $1,000,000 a day). NULL means no limit. spend_alerted_day is the
-- last local day an alert was raised for the agent: at most one alert per agent per day.
ALTER TABLE public.agents
    ADD COLUMN spend_limit_micro_usd BIGINT CHECK (spend_limit_micro_usd IS NULL OR spend_limit_micro_usd BETWEEN 1 AND 1000000000000),
    ADD COLUMN spend_alerted_day DATE;

-- -----------------------------------------------------------------------------
-- The roll-up trigger, one per INSERT statement (a whole ingest batch is one statement): the batch is grouped first and the groups are
-- written in one fixed order, so two concurrent batches from one agent cannot deadlock on each other's rows. A span re-sent by the SDK
-- is an ON CONFLICT update, not an insert, so it is not counted twice (the first write wins).
--
-- What counts: a model name and at least one believable token count (1 to 1,000,000,000 on a side; anything else on that side is "not
-- reported", never trusted). A span with no model or no tokens is not model use. Spans older than 35 days are ignored and a span dated in
-- the future counts as now, so an SDK host's clock cannot write an arbitrary day. Provider and model are folded to lower case.
-- One agent and day keep at most 50 distinct (provider, model) rows; further ones are folded into a single ('', '(other)') row so a leaked
-- SDK key cannot grow the table without bound.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.model_spend_rollup() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    g record;
    v_provider text;
    v_model text;
BEGIN
    BEGIN
        FOR g IN
            SELECT s.organization_id, s.agent_id, s.day, s.provider, s.model,
                   count(*) AS calls, sum(s.vp) AS prompt_tokens, sum(s.vc) AS completion_tokens
            FROM (
                SELECT n.organization_id, n.agent_id,
                       ((LEAST(n.occurred_at, now()) AT TIME ZONE 'utc') + make_interval(mins => COALESCE(o.utc_offset_minutes, 480)))::date AS day,
                       lower(left(btrim(COALESCE(n.model_provider, '')), 64)) AS provider,
                       lower(left(btrim(n.model_name), 128)) AS model,
                       CASE WHEN n.prompt_tokens BETWEEN 1 AND 1000000000 THEN n.prompt_tokens ELSE 0 END AS vp,
                       CASE WHEN n.completion_tokens BETWEEN 1 AND 1000000000 THEN n.completion_tokens ELSE 0 END AS vc
                FROM new_rows n
                LEFT JOIN public.organizations o ON o.id = n.organization_id
                WHERE n.model_name IS NOT NULL AND btrim(n.model_name) <> '' AND n.occurred_at > now() - interval '35 days'
            ) s
            WHERE s.vp > 0 OR s.vc > 0
            GROUP BY s.organization_id, s.agent_id, s.day, s.provider, s.model
            ORDER BY s.agent_id, s.day, s.provider, s.model
        LOOP
            v_provider := g.provider;
            v_model := g.model;
            IF NOT EXISTS (SELECT 1 FROM public.agent_model_daily d
                           WHERE d.agent_id = g.agent_id AND d.day = g.day AND d.provider = g.provider AND d.model = g.model)
               AND (SELECT count(*) FROM public.agent_model_daily d
                    WHERE d.agent_id = g.agent_id AND d.day = g.day AND d.model <> '(other)') >= 50 THEN
                v_provider := '';
                v_model := '(other)';
            END IF;
            INSERT INTO public.agent_model_daily AS d (organization_id, agent_id, day, provider, model, calls, prompt_tokens, completion_tokens)
            VALUES (g.organization_id, g.agent_id, g.day, v_provider, v_model, g.calls, g.prompt_tokens, g.completion_tokens)
            ON CONFLICT (agent_id, day, provider, model)
            DO UPDATE SET calls = d.calls + EXCLUDED.calls,
                          prompt_tokens = d.prompt_tokens + EXCLUDED.prompt_tokens,
                          completion_tokens = d.completion_tokens + EXCLUDED.completion_tokens;
        END LOOP;
    EXCEPTION WHEN OTHERS THEN
        RAISE WARNING 'model_spend_rollup skipped (SQLSTATE %): spans are stored, spend roll-up for this batch is missing', SQLSTATE;
    END;
    RETURN NULL;
END $$;

CREATE TRIGGER trg_execution_traces_model_spend AFTER INSERT ON public.execution_traces
    REFERENCING NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION public.model_spend_rollup();

-- -----------------------------------------------------------------------------
-- model_spend_backfill(p_days): rebuilds the roll-up from the spans for the last p_days (1 to 35) days. It follows the trigger's rules
-- (without the 50-row cap), is safe to run again (it replaces what it rebuilds), and is the repair tool if a roll-up warning was logged.
-- Returns the number of rows written.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.model_spend_backfill(p_days integer) RETURNS integer
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_cutoff date;
    v_rows integer;
BEGIN
    IF p_days IS NULL OR p_days NOT BETWEEN 1 AND 35 THEN
        RAISE EXCEPTION 'p_days must be between 1 and 35' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    v_cutoff := (now() AT TIME ZONE 'utc')::date - p_days;
    DELETE FROM public.agent_model_daily WHERE day >= v_cutoff;
    INSERT INTO public.agent_model_daily (organization_id, agent_id, day, provider, model, calls, prompt_tokens, completion_tokens)
    SELECT s.organization_id, s.agent_id, s.day, s.provider, s.model, count(*), sum(s.vp), sum(s.vc)
    FROM (
        SELECT t.organization_id, t.agent_id,
               ((LEAST(t.occurred_at, now()) AT TIME ZONE 'utc') + make_interval(mins => COALESCE(o.utc_offset_minutes, 480)))::date AS day,
               lower(left(btrim(COALESCE(t.model_provider, '')), 64)) AS provider,
               lower(left(btrim(t.model_name), 128)) AS model,
               CASE WHEN t.prompt_tokens BETWEEN 1 AND 1000000000 THEN t.prompt_tokens ELSE 0 END AS vp,
               CASE WHEN t.completion_tokens BETWEEN 1 AND 1000000000 THEN t.completion_tokens ELSE 0 END AS vc
        FROM public.execution_traces t
        LEFT JOIN public.organizations o ON o.id = t.organization_id
        -- every span whose local day is on or after the cutoff happened at or after cutoff minus 14 hours, so one day of margin is enough
        WHERE t.occurred_at >= v_cutoff::timestamp AT TIME ZONE 'utc' - interval '1 day'
          AND t.occurred_at > now() - interval '35 days'
          AND t.model_name IS NOT NULL AND btrim(t.model_name) <> ''
    ) s
    WHERE s.day >= v_cutoff AND (s.vp > 0 OR s.vc > 0)
    GROUP BY s.organization_id, s.agent_id, s.day, s.provider, s.model;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END $$;

SELECT public.model_spend_backfill(30);

-- -----------------------------------------------------------------------------
-- agent_model_usage(): one agent's (or, with p_agent NULL, every agent's) roll-up rows for p_since..p_until (inclusive days),
-- organization-scoped. Token sums are capped at 10^15 so core's cost arithmetic cannot overflow.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.agent_model_usage(p_org uuid, p_agent uuid, p_since date, p_until date)
RETURNS TABLE (agent_id uuid, day date, provider text, model text, calls bigint, prompt_tokens bigint, completion_tokens bigint)
LANGUAGE sql
STABLE
SET search_path = public, pg_temp
AS $$
    SELECT d.agent_id, d.day, d.provider, d.model, d.calls,
           LEAST(d.prompt_tokens, 1000000000000000), LEAST(d.completion_tokens, 1000000000000000)
    FROM public.agent_model_daily d
    WHERE d.organization_id = p_org AND (p_agent IS NULL OR d.agent_id = p_agent) AND d.day >= p_since AND d.day <= p_until
    ORDER BY d.agent_id, d.day, d.provider, d.model
$$;

-- -----------------------------------------------------------------------------
-- purge_model_spend(): days older than 90. Counts and model names only, so no tenant setting is needed.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.purge_model_spend() RETURNS integer
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_deleted integer;
BEGIN
    DELETE FROM public.agent_model_daily WHERE day < (now() AT TIME ZONE 'utc')::date - 90;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END $$;

-- -----------------------------------------------------------------------------
-- control_agent_spend_limit(): change an agent's dollar limit with the audit row, in one transaction. NULL removes the limit.
-- Idempotent (no change, no audit row). Compare-and-set like control_agent_budget(): the caller passes the limit it decided against; a
-- different current limit returns {conflict: true} and changes nothing, so "raising a limit needs a confirmation" is never applied to a
-- state it was not decided for. A changed limit clears the day's alert so crossing the new limit alerts again.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_agent_spend_limit(
    p_org uuid, p_agent uuid, p_actor uuid, p_limit bigint, p_reason text, p_expected_limit bigint
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
    IF v_agent.spend_limit_micro_usd IS DISTINCT FROM p_expected_limit THEN
        RETURN jsonb_build_object('conflict', true);
    END IF;
    IF v_agent.spend_limit_micro_usd IS NOT DISTINCT FROM p_limit THEN
        RETURN jsonb_build_object('changed', false, 'agent_id', v_agent.id, 'spend_limit_micro_usd', v_agent.spend_limit_micro_usd);
    END IF;
    UPDATE public.agents SET spend_limit_micro_usd = p_limit, spend_alerted_day = NULL WHERE id = v_agent.id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'passport.spend_limit_changed', 'agent', v_agent.id, p_reason,
            jsonb_build_object('old_limit', v_agent.spend_limit_micro_usd, 'new_limit', p_limit));
    RETURN jsonb_build_object('changed', true, 'agent_id', v_agent.id, 'spend_limit_micro_usd', p_limit);
END $$;

-- -----------------------------------------------------------------------------
-- spend_mark_alerted(): true exactly once per agent per local day, even when two core instances check the same agent at once (the
-- UPDATE ... WHERE is the compare-and-set). The caller sends the alert only when this returns true. An earlier day never beats a later one.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.spend_mark_alerted(p_org uuid, p_agent uuid, p_day date) RETURNS boolean
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    UPDATE public.agents SET spend_alerted_day = p_day
     WHERE id = p_agent AND organization_id = p_org AND (spend_alerted_day IS NULL OR spend_alerted_day < p_day);
    RETURN FOUND;
END $$;

REVOKE EXECUTE ON FUNCTION public.model_spend_rollup() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.model_spend_backfill(integer) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.agent_model_usage(uuid, uuid, date, date) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.purge_model_spend() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_agent_spend_limit(uuid, uuid, uuid, bigint, text, bigint) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.spend_mark_alerted(uuid, uuid, date) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.agent_model_usage(uuid, uuid, date, date) TO service_role;
GRANT EXECUTE ON FUNCTION public.purge_model_spend() TO service_role;
GRANT EXECUTE ON FUNCTION public.control_agent_spend_limit(uuid, uuid, uuid, bigint, text, bigint) TO service_role;
GRANT EXECUTE ON FUNCTION public.spend_mark_alerted(uuid, uuid, date) TO service_role;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_cron') THEN
        CREATE EXTENSION IF NOT EXISTS pg_cron;
        PERFORM cron.schedule('redhand-purge-model-spend', '53 19 * * *', 'SELECT public.purge_model_spend()');
        RAISE NOTICE 'scheduled redhand-purge-model-spend';
    ELSE
        RAISE NOTICE 'pg_cron is not available here: schedule purge_model_spend() yourself (daily)';
    END IF;
END;
$$;

COMMIT;
