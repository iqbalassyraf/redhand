-- =============================================================================
-- Insights (dashboard redesign S2): one read-only summary of an organization's gateway decisions over a time window, computed in SQL
-- from the Black Box (agent_events). It backs GET /v1/insights/summary and the dashboard's home page.
--
-- Read only: it changes no row. Tenant isolation: every read filters on p_org, which core takes from the authenticated operator, never from
-- the request. Bounds: the window is at most 8 days, the bucket between 1 minute and 1 day, and at most 60 buckets, so one call is always a
-- bounded read of one organization's indexed range. Core maps the allowed windows (1h, 24h, 7d) to a bucket; this function validates anyway.
--
-- Refusal reasons are returned as fixed categories (agent_not_active, token_stale, honeytoken, safe_mode, out_of_scope, tool_unapproved, daily_limit,
-- destination, loop, upstream_error, firewall_rule), never as the raw sentence.
-- "refused" means decision BLOCK, "errors" means ERROR. Latency is the whole call as the gateway saw it (it includes the tool's own time), over
-- ALLOW events only. No argument value, payload or captured text is read: only decision, server, tool name, reasons, sizes and latency.
-- =============================================================================

BEGIN;

CREATE INDEX IF NOT EXISTS idx_agent_events_org_time ON public.agent_events (organization_id, occurred_at DESC);

-- The gateway writes refusal reasons as plain sentences that carry the tool, server or address involved. Ranking those raw sentences would
-- scatter one cause over many rows and put customer-chosen names in a chart, so they are mapped to a small fixed set of categories first.
CREATE OR REPLACE FUNCTION public.insights_reason_category(p_reason text, p_decision text)
RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = public, pg_temp
AS $$
    SELECT CASE
        WHEN p_decision = 'ERROR' THEN 'upstream_error'
        WHEN p_reason IN ('passport_frozen', 'passport_revoked', 'passport_expired') THEN 'agent_not_active'
        WHEN p_reason = 'token_stale' THEN 'token_stale'
        WHEN p_reason IN ('honeytoken', 'honey_tool', 'honeytoken scan failed') THEN 'honeytoken'
        WHEN p_reason LIKE 'Safe Mode is on%' THEN 'safe_mode'
        WHEN p_reason LIKE '%is not in this agent''s passport scopes%' THEN 'out_of_scope'
        WHEN p_reason LIKE '%has not been reviewed%' THEN 'tool_unapproved'
        WHEN p_reason LIKE 'Daily limit of %' OR p_reason LIKE '%cannot track this agent''s usage%' THEN 'daily_limit'
        WHEN p_reason LIKE '%allowed list%' THEN 'destination'
        WHEN p_reason LIKE 'This exact call was repeated%' THEN 'loop'
        ELSE 'firewall_rule'
    END
$$;

CREATE OR REPLACE FUNCTION public.insights_summary(p_org uuid, p_since timestamptz, p_until timestamptz, p_bucket_seconds integer)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
STABLE
AS $$
DECLARE
    v_first bigint;
    v_last bigint;
    v_result jsonb;
BEGIN
    IF p_org IS NULL OR p_since IS NULL OR p_until IS NULL OR p_bucket_seconds IS NULL THEN
        RAISE EXCEPTION 'organization, window and bucket are required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_bucket_seconds < 60 OR p_bucket_seconds > 86400 THEN
        RAISE EXCEPTION 'bucket must be between 60 and 86400 seconds' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_until <= p_since OR p_until - p_since > interval '8 days' THEN
        RAISE EXCEPTION 'window must be positive and at most 8 days' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    v_first := floor(extract(epoch FROM p_since) / p_bucket_seconds)::bigint;
    v_last := floor(extract(epoch FROM p_until) / p_bucket_seconds)::bigint;
    IF v_last - v_first + 1 > 60 THEN
        RAISE EXCEPTION 'window holds more than 60 buckets' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- One statement over one materialized, organization-scoped slice of the Black Box (a single indexed range scan), so the function stays STABLE.
    WITH ev AS MATERIALIZED (
        SELECT e.agent_id, e.occurred_at, e.server, e.tool_name, e.decision, e.reasons, e.result_size_bytes, e.latency_ms
        FROM public.agent_events e
        WHERE e.organization_id = p_org AND e.occurred_at >= p_since AND e.occurred_at < p_until
    ),
    top_agents AS (
        SELECT agent_id, count(*) AS decisions, count(*) FILTER (WHERE decision = 'BLOCK') AS refused, count(*) FILTER (WHERE decision = 'ERROR') AS errors
        FROM ev GROUP BY agent_id ORDER BY count(*) DESC, agent_id LIMIT 5
    ),
    buckets AS (
        SELECT floor(extract(epoch FROM occurred_at) / p_bucket_seconds)::bigint AS k,
               count(*) FILTER (WHERE decision = 'ALLOW') AS allowed,
               count(*) FILTER (WHERE decision = 'BLOCK') AS refused,
               count(*) FILTER (WHERE decision = 'ERROR') AS errors,
               COALESCE(sum(result_size_bytes) FILTER (WHERE decision = 'ALLOW'), 0) AS bytes
        FROM ev GROUP BY 1
    )
    SELECT jsonb_build_object(
        'window_start', to_char(p_since AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        'window_end', to_char(p_until AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        'bucket_seconds', p_bucket_seconds,
        'totals', (SELECT jsonb_build_object(
            'decisions', count(*),
            'allowed', count(*) FILTER (WHERE decision = 'ALLOW'),
            'refused', count(*) FILTER (WHERE decision = 'BLOCK'),
            'errors', count(*) FILTER (WHERE decision = 'ERROR'),
            'bytes_returned', COALESCE(sum(result_size_bytes) FILTER (WHERE decision = 'ALLOW'), 0)) FROM ev),
        'series', (SELECT COALESCE(jsonb_agg(jsonb_build_object(
                'bucket_start', to_char(to_timestamp(g * p_bucket_seconds) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                'allowed', COALESCE(k.allowed, 0), 'refused', COALESCE(k.refused, 0), 'errors', COALESCE(k.errors, 0), 'bytes', COALESCE(k.bytes, 0)
            ) ORDER BY g), '[]'::jsonb) FROM generate_series(v_first, v_last) AS g LEFT JOIN buckets k ON k.k = g),
        'agents', (SELECT COALESCE(jsonb_agg(jsonb_build_object('agent_id', agent_id, 'decisions', decisions, 'refused', refused, 'errors', errors)
                                             ORDER BY decisions DESC, agent_id), '[]'::jsonb) FROM top_agents),
        'tools', (SELECT COALESCE(jsonb_agg(jsonb_build_object('server', server, 'tool', tool_name, 'calls', n, 'refused', refused) ORDER BY n DESC, tool_name), '[]'::jsonb) FROM (
            SELECT server, tool_name, count(*) AS n, count(*) FILTER (WHERE decision = 'BLOCK') AS refused FROM ev WHERE tool_name <> ''
            GROUP BY server, tool_name ORDER BY count(*) DESC, tool_name LIMIT 5) t),
        'servers', (SELECT COALESCE(jsonb_agg(jsonb_build_object('server', server, 'decisions', n, 'allowed', allowed, 'refused', refused, 'errors', errors)
                                              ORDER BY n DESC, server), '[]'::jsonb) FROM (
            SELECT server, count(*) AS n, count(*) FILTER (WHERE decision = 'ALLOW') AS allowed, count(*) FILTER (WHERE decision = 'BLOCK') AS refused,
                   count(*) FILTER (WHERE decision = 'ERROR') AS errors FROM ev GROUP BY server ORDER BY count(*) DESC, server LIMIT 8) t),
        'reasons', (SELECT COALESCE(jsonb_agg(jsonb_build_object('reason', r, 'count', n) ORDER BY n DESC, r), '[]'::jsonb) FROM (
            SELECT public.insights_reason_category(x, ev.decision) AS r, count(*) AS n FROM ev, LATERAL unnest(ev.reasons) AS x WHERE ev.decision <> 'ALLOW'
            GROUP BY 1 ORDER BY count(*) DESC, 1 LIMIT 8) t),
        'latency', (SELECT jsonb_build_object(
            'samples', count(latency_ms),
            'p50_ms', round((percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms))::numeric, 2),
            'p95_ms', round((percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms))::numeric, 2)) FROM ev WHERE decision = 'ALLOW' AND latency_ms IS NOT NULL),
        -- Agent -> server -> outcome, for the top 5 agents only (at most 40 rows).
        'flow', (SELECT COALESCE(jsonb_agg(jsonb_build_object('agent_id', agent_id, 'server', server, 'decision', decision, 'count', n)
                                           ORDER BY n DESC, agent_id, server, decision), '[]'::jsonb) FROM (
            SELECT agent_id, server, decision, count(*) AS n FROM ev WHERE agent_id IN (SELECT agent_id FROM top_agents)
            GROUP BY agent_id, server, decision ORDER BY n DESC LIMIT 40) f)
    ) INTO v_result;
    RETURN v_result;
END $$;

-- Only core (service_role) calls it, after it has checked the operator's role and taken the organization from the operator.
REVOKE EXECUTE ON FUNCTION public.insights_reason_category(text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.insights_summary(uuid, timestamptz, timestamptz, integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.insights_reason_category(text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.insights_summary(uuid, timestamptz, timestamptz, integer) TO service_role;

COMMIT;
