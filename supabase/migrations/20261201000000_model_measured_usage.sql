-- =============================================================================
-- Phase 4.5 B5b: usage the model proxy MEASURED (ADR 0025). Rollback: supabase/rollbacks/20261201000000_model_measured_usage.down.sql
--
-- The model proxy (off by default) counts tokens from the PROVIDER's own answer. The gateway reports them to core in batches, and they are stored apart from the
-- usage an agent's SDK reports (agent_model_daily): the two are different numbers on purpose and are never added together (an agent that both reports and goes through the proxy
-- would be counted twice). Nothing here is read by Budget Guard, Radar or the Risk Engine; B5c uses it to refuse over a dollar limit.
--   - agent_model_measured_daily: per agent, day, provider and model: calls, tokens and the calls the provider reported no usage for.
--   - model_usage_batches: batch ids seen in the last 7 days, so a retried batch counts once.
--   - record_model_usage(batch, rows): the only writer. The organization is taken from the AGENT's row, never from the payload; bad rows are rejected one by one and counted;
--     a batch of more than 500 rows is refused whole. The day uses the organization's UTC offset (the SDK roll-up's rule), a time in the future counts as now and a time more than
--     35 days old is dropped. An agent and day keep at most 50 distinct models; the rest fold into one "(other)" row.
--   - agent_model_measured_usage(): the read; purge_model_measured(): 90 days of usage, 7 days of batch ids.
--   - tenant_data_manifest() now lists the new table, so export and deletion cover it (ADR 0027).
-- =============================================================================

BEGIN;

CREATE TABLE public.agent_model_measured_daily (
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    provider TEXT NOT NULL CHECK (char_length(provider) <= 64),
    model TEXT NOT NULL CHECK (char_length(model) BETWEEN 1 AND 128),
    calls BIGINT NOT NULL CHECK (calls >= 0),
    prompt_tokens BIGINT NOT NULL CHECK (prompt_tokens >= 0),
    completion_tokens BIGINT NOT NULL CHECK (completion_tokens >= 0),
    calls_without_usage BIGINT NOT NULL DEFAULT 0 CHECK (calls_without_usage >= 0),
    PRIMARY KEY (agent_id, day, provider, model)
);
CREATE INDEX idx_agent_model_measured_org_day ON public.agent_model_measured_daily(organization_id, day);
ALTER TABLE public.agent_model_measured_daily ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.model_usage_batches (
    batch_id UUID PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE public.model_usage_batches ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.record_model_usage(p_batch uuid, p_rows jsonb) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    g record;
    v_inserted integer;
    v_accepted integer := 0;
    v_rejected integer := 0;
    v_provider text;
    v_model text;
BEGIN
    IF p_batch IS NULL OR p_rows IS NULL OR jsonb_typeof(p_rows) <> 'array' THEN
        RAISE EXCEPTION 'a batch id and an array of rows are required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF jsonb_array_length(p_rows) > 500 THEN
        RAISE EXCEPTION 'at most 500 rows in one batch' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO public.model_usage_batches (batch_id) VALUES (p_batch) ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted = 0 THEN
        RETURN jsonb_build_object('accepted', 0, 'rejected', 0, 'duplicate', true);
    END IF;

    FOR g IN
        WITH raw AS (
            SELECT CASE WHEN r ->> 'agent_id' ~ '^[0-9a-fA-F-]{36}$' THEN (r ->> 'agent_id')::uuid END AS agent_id,
                   lower(left(btrim(COALESCE(r ->> 'provider', '')), 64)) AS provider,
                   lower(left(btrim(COALESCE(r ->> 'model', '')), 128)) AS model,
                   CASE WHEN r ->> 'calls' ~ '^[0-9]{1,9}$' THEN (r ->> 'calls')::bigint END AS calls,
                   CASE WHEN r ->> 'input_tokens' ~ '^[0-9]{1,15}$' THEN (r ->> 'input_tokens')::bigint END AS vp,
                   CASE WHEN r ->> 'output_tokens' ~ '^[0-9]{1,15}$' THEN (r ->> 'output_tokens')::bigint END AS vc,
                   CASE WHEN r ->> 'calls_without_usage' ~ '^[0-9]{1,9}$' THEN (r ->> 'calls_without_usage')::bigint ELSE 0 END AS nu,
                   CASE WHEN r ->> 'occurred_at' ~ '^[0-9T:+. Z-]{10,40}$' THEN (r ->> 'occurred_at')::timestamptz END AS at
            FROM jsonb_array_elements(p_rows) r
        ), good AS (
            SELECT raw.*, a.organization_id, COALESCE(o.utc_offset_minutes, 480) AS offset_minutes
            FROM raw JOIN public.agents a ON a.id = raw.agent_id LEFT JOIN public.organizations o ON o.id = a.organization_id
            WHERE raw.model <> '' AND raw.calls >= 1 AND raw.vp IS NOT NULL AND raw.vc IS NOT NULL AND raw.at IS NOT NULL
              AND raw.at > now() - interval '35 days'
        )
        SELECT organization_id, agent_id,
               ((LEAST(at, now()) AT TIME ZONE 'utc') + make_interval(mins => offset_minutes))::date AS day,
               provider, model, sum(calls) AS calls, sum(vp) AS prompt_tokens, sum(vc) AS completion_tokens, sum(nu) AS calls_without_usage, count(*) AS n
        FROM good
        GROUP BY organization_id, agent_id, 3, provider, model
        ORDER BY agent_id, 3, provider, model
    LOOP
        v_provider := g.provider;
        v_model := g.model;
        IF NOT EXISTS (SELECT 1 FROM public.agent_model_measured_daily d WHERE d.agent_id = g.agent_id AND d.day = g.day AND d.provider = g.provider AND d.model = g.model)
           AND (SELECT count(*) FROM public.agent_model_measured_daily d WHERE d.agent_id = g.agent_id AND d.day = g.day AND d.model <> '(other)') >= 50 THEN
            v_provider := '';
            v_model := '(other)';
        END IF;
        INSERT INTO public.agent_model_measured_daily AS d (organization_id, agent_id, day, provider, model, calls, prompt_tokens, completion_tokens, calls_without_usage)
        VALUES (g.organization_id, g.agent_id, g.day, v_provider, v_model, g.calls, g.prompt_tokens, g.completion_tokens, g.calls_without_usage)
        ON CONFLICT (agent_id, day, provider, model)
        DO UPDATE SET calls = d.calls + EXCLUDED.calls, prompt_tokens = d.prompt_tokens + EXCLUDED.prompt_tokens,
                      completion_tokens = d.completion_tokens + EXCLUDED.completion_tokens, calls_without_usage = d.calls_without_usage + EXCLUDED.calls_without_usage;
        v_accepted := v_accepted + g.n::integer;
    END LOOP;
    v_rejected := jsonb_array_length(p_rows) - v_accepted;
    RETURN jsonb_build_object('accepted', v_accepted, 'rejected', v_rejected, 'duplicate', false);
END $$;

CREATE OR REPLACE FUNCTION public.agent_model_measured_usage(p_org uuid, p_agent uuid, p_since date, p_until date)
RETURNS TABLE (agent_id uuid, day date, provider text, model text, calls bigint, prompt_tokens bigint, completion_tokens bigint, calls_without_usage bigint)
LANGUAGE sql
STABLE
SET search_path = public, pg_temp
AS $$
    SELECT d.agent_id, d.day, d.provider, d.model, d.calls,
           LEAST(d.prompt_tokens, 1000000000000000), LEAST(d.completion_tokens, 1000000000000000), d.calls_without_usage
    FROM public.agent_model_measured_daily d
    WHERE d.organization_id = p_org AND (p_agent IS NULL OR d.agent_id = p_agent) AND d.day >= p_since AND d.day <= p_until
    ORDER BY d.agent_id, d.day, d.provider, d.model
$$;

CREATE OR REPLACE FUNCTION public.purge_model_measured() RETURNS integer
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_deleted integer;
BEGIN
    DELETE FROM public.agent_model_measured_daily WHERE day < (now() AT TIME ZONE 'utc')::date - 90;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    DELETE FROM public.model_usage_batches WHERE received_at < now() - interval '7 days';
    RETURN v_deleted;
END $$;

REVOKE EXECUTE ON FUNCTION public.record_model_usage(uuid, jsonb) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.agent_model_measured_usage(uuid, uuid, date, date) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.purge_model_measured() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_model_usage(uuid, jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.agent_model_measured_usage(uuid, uuid, date, date) TO service_role;

-- Export and deletion (ADR 0027) cover the new table: the manifest is redefined with one more entry.
CREATE OR REPLACE FUNCTION public.tenant_data_manifest() RETURNS jsonb
LANGUAGE sql IMMUTABLE
AS $$
SELECT jsonb_build_array(
    jsonb_build_object('table', 'organizations', 'scope', 'self', 'exclude', jsonb_build_array('siem_webhook_url')),
    jsonb_build_object('table', 'organization_members', 'scope', 'members', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agents', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_keys', 'scope', 'org', 'exclude', jsonb_build_array('key_hash')),
    jsonb_build_object('table', 'agent_destinations', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_budget_state', 'scope', 'agent', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_usage_daily', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_model_daily', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_model_measured_daily', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_tool_hourly', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'agent_events', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'event_batches', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'event_chain_heads', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'execution_traces', 'scope', 'org', 'exclude', jsonb_build_array('ephemeral_token_jti')),
    jsonb_build_object('table', 'hitl_interventions', 'scope', 'org', 'exclude', jsonb_build_array('notification_webhook_url', 'resume_webhook_url')),
    jsonb_build_object('table', 'security_events', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'security_findings', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'radar_suppressions', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'radar_rule_counts', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'radar_scan_counts', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'honeytokens', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'honey_tools', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'honeytrips', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'mcp_servers', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'mcp_tool_pins', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'approved_models', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'sdk_api_keys', 'scope', 'org', 'exclude', jsonb_build_array('key_hash')),
    jsonb_build_object('table', 'telegram_links', 'scope', 'org', 'exclude', jsonb_build_array()),
    jsonb_build_object('table', 'telegram_link_codes', 'scope', 'org', 'exclude', jsonb_build_array('code_hash')),
    jsonb_build_object('table', 'member_invites', 'scope', 'org', 'exclude', jsonb_build_array('token_hash')),
    jsonb_build_object('table', 'control_audit_log', 'scope', 'org', 'exclude', jsonb_build_array())
)
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_cron') THEN
        CREATE EXTENSION IF NOT EXISTS pg_cron;
        PERFORM cron.schedule('redhand-purge-model-measured', '57 19 * * *', 'SELECT public.purge_model_measured()');
        RAISE NOTICE 'scheduled redhand-purge-model-measured';
    ELSE
        RAISE NOTICE 'pg_cron is not available here: schedule purge_model_measured() yourself (daily)';
    END IF;
END;
$$;

COMMIT;
