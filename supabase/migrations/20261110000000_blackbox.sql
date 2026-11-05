-- =============================================================================
-- Black Box Recorder (Phase 3, M1): a durable, tamper-evident, per-organization
-- record of every tool call the gateway allowed, refused or failed to forward.
-- Rollback: supabase/rollbacks/20261110000000_blackbox.down.sql
-- Plan: docs/plans/phase3-plan.md   ADR: docs/adr/0011-black-box-recorder.md
--
-- What is stored: metadata only (server, tool, decision, reasons, latency, argument key names and a
-- digest). No raw arguments or results. Payload capture (payload_capture_enabled) is a Phase 3 M2
-- feature; the columns below exist so core's context model is stable, but nothing in this migration
-- stores a payload, and no code path uses payload_capture_enabled yet.
--
-- Tamper evidence: each organization has one hash chain (event_chain_heads). record_events() is the
-- only writer; it locks that row FOR UPDATE, so concurrent gateway instances are serialised and the
-- chain cannot fork. Each row's hash covers its own fields plus the previous row's hash
-- (_blackbox_event_hash), computed and checked only in SQL so verification never depends on a client
-- recomputing it the same way. verify_events() recomputes the range and reports the first mismatch.
--
-- Append-only: a trigger refuses UPDATE and DELETE on agent_events from everyone except the
-- purge_events() function (added in Phase 3 M2, not part of this migration), which deletes rows past
-- retention and moves the chain's anchor so verification of the remaining range still succeeds.
--
-- Exactly once: event_batches remembers each batch_id the gateway has already sent; resending a batch
-- (after a lost response) returns the stored result instead of appending the events again.
-- =============================================================================

BEGIN;

ALTER TABLE public.organizations
    ADD COLUMN blackbox_retention_days INTEGER NOT NULL DEFAULT 30 CHECK (blackbox_retention_days BETWEEN 7 AND 90),
    ADD COLUMN payload_capture_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN payload_retention_days INTEGER NOT NULL DEFAULT 7 CHECK (payload_retention_days BETWEEN 1 AND 30);

CREATE TABLE public.event_chain_heads (
    organization_id UUID PRIMARY KEY REFERENCES public.organizations(id) ON DELETE CASCADE,
    last_seq BIGINT NOT NULL DEFAULT 0,
    last_hash TEXT NOT NULL DEFAULT 'GENESIS_BLOCK_AGENT_EVENTS_V1',
    anchor_seq BIGINT NOT NULL DEFAULT 0,
    anchor_prev_hash TEXT NOT NULL DEFAULT 'GENESIS_BLOCK_AGENT_EVENTS_V1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE public.agent_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    seq BIGINT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    gateway_instance TEXT NOT NULL CHECK (char_length(gateway_instance) BETWEEN 1 AND 64),
    server TEXT NOT NULL DEFAULT '' CHECK (char_length(server) <= 128),
    method TEXT NOT NULL CHECK (char_length(method) BETWEEN 1 AND 64),
    tool_name TEXT NOT NULL DEFAULT '' CHECK (char_length(tool_name) <= 128),
    decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'BLOCK', 'ERROR')),
    reasons TEXT[] NOT NULL DEFAULT '{}',
    upstream_status INTEGER,
    latency_ms NUMERIC(10, 2),
    argument_keys TEXT[] NOT NULL DEFAULT '{}',
    arguments_sha256 TEXT NOT NULL DEFAULT '',
    result_size_bytes INTEGER,
    redaction_count INTEGER NOT NULL DEFAULT 0,
    credential_jti TEXT,
    -- Payload capture (Phase 3 M2): always NULL today. The chain hashes arguments_sha256, never these
    -- columns, so purging them at payload retention cannot break verification.
    arguments_redacted JSONB,
    result_excerpt JSONB,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    batch_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, seq)
);
CREATE INDEX idx_agent_events_org_agent_time ON public.agent_events(organization_id, agent_id, occurred_at DESC);
CREATE INDEX idx_agent_events_batch ON public.agent_events(batch_id);

CREATE TABLE public.event_batches (
    batch_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    instance_id TEXT NOT NULL CHECK (char_length(instance_id) BETWEEN 8 AND 64),
    item_count INTEGER NOT NULL,
    rejected_count INTEGER NOT NULL DEFAULT 0,
    first_seq BIGINT,
    last_seq BIGINT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_event_batches_org_time ON public.event_batches(organization_id, received_at DESC);

ALTER TABLE public.event_chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.event_batches ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Append-only: nobody (including service_role application code) may UPDATE or DELETE a stored event
-- directly. The only deletion path is purge_events() (Phase 3 M2), which is not part of this
-- migration and will use `SET LOCAL` session state to bypass this trigger explicitly when it ships.
-- Until then, agent_events rows are permanent.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public._forbid_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'agent_events is append-only' USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER trg_agent_events_append_only
    BEFORE UPDATE OR DELETE ON public.agent_events
    FOR EACH ROW EXECUTE FUNCTION public._forbid_event_mutation();

-- -----------------------------------------------------------------------------
-- The chained hash of one event: covers the previous event's hash plus every stored field, in a
-- fixed order with a separator (chr(31), a control character that cannot appear in the inputs since
-- every text field is capped and application-supplied text goes through JSON encoding upstream of
-- this function only as a digest or a bounded list of keys, never as free text containing it).
-- IMMUTABLE except for timestamp formatting, which is pinned to ISO-8601 UTC with microseconds.
-- p_latency_ms is explicitly cast to numeric(10,2) INSIDE the body (not just declared that way in
-- the parameter list): PostgreSQL does not keep a parameter's typmod/scale in the function's
-- signature, so a bare "numeric" parameter can otherwise format differently depending on the scale
-- of whatever numeric the caller happens to pass, which would make the very same stored row hash
-- differently when recomputed from its own agent_events.latency_ms column (itself numeric(10,2)).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public._blackbox_event_hash(
    p_prev_hash text, p_org uuid, p_agent uuid, p_seq bigint, p_occurred_at timestamptz,
    p_instance text, p_server text, p_method text, p_tool text, p_decision text,
    p_reasons text[], p_upstream_status integer, p_latency_ms numeric,
    p_argument_keys text[], p_arguments_sha256 text, p_result_size integer,
    p_redaction_count integer, p_credential_jti text
) RETURNS text
LANGUAGE sql
IMMUTABLE
-- "extensions" is where Supabase installs pgcrypto; without it digest() cannot be resolved and this
-- function cannot even be created. See 20261110000100_blackbox_hash_search_path.sql.
SET search_path = public, extensions, pg_temp
AS $$
    SELECT encode(digest(
        p_prev_hash || chr(31) || p_org::text || chr(31) || p_agent::text || chr(31) || p_seq::text
        || chr(31) || to_char(p_occurred_at AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        || chr(31) || p_instance || chr(31) || p_server || chr(31) || p_method || chr(31) || p_tool
        || chr(31) || p_decision || chr(31) || array_to_string(p_reasons, ',')
        || chr(31) || COALESCE(p_upstream_status::text, '') || chr(31) || COALESCE(p_latency_ms::numeric(10,2)::text, '')
        || chr(31) || array_to_string(p_argument_keys, ',') || chr(31) || p_arguments_sha256
        || chr(31) || COALESCE(p_result_size::text, '') || chr(31) || p_redaction_count::text
        || chr(31) || COALESCE(p_credential_jti, ''),
        'sha256'), 'hex');
$$;

-- -----------------------------------------------------------------------------
-- A gateway instance reports a batch of events for ONE organization. The organization of every item
-- is always taken from the agents table, never from the item itself: an item whose agent does not
-- belong to p_org is rejected, so a bug or a compromised instance cannot write into another tenant's
-- chain. Resending the same batch_id is a no-op that returns the first result (exactly-once at the
-- gateway-to-core boundary; the gateway's local buffer may also resend after a timeout).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.record_events(p_instance text, p_batch_id uuid, p_org uuid, p_items jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_existing public.event_batches%ROWTYPE;
    v_head public.event_chain_heads%ROWTYPE;
    v_item jsonb;
    v_agent_id uuid;
    v_agent_org uuid;
    v_seq bigint;
    v_prev text;
    v_hash text;
    v_reasons text[];
    v_argument_keys text[];
    v_occurred_at timestamptz;
    v_accepted integer := 0;
    v_rejected integer := 0;
    v_first_seq bigint;
    v_last_seq bigint;
BEGIN
    IF p_instance IS NULL OR char_length(p_instance) NOT BETWEEN 8 AND 64 THEN
        RAISE EXCEPTION 'invalid instance id' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_batch_id IS NULL THEN
        RAISE EXCEPTION 'batch id required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_items IS NULL OR jsonb_typeof(p_items) <> 'array'
       OR jsonb_array_length(p_items) = 0 OR jsonb_array_length(p_items) > 500 THEN
        RAISE EXCEPTION 'items must be an array of 1 to 500 entries' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    SELECT * INTO v_existing FROM public.event_batches WHERE batch_id = p_batch_id;
    IF FOUND THEN
        RETURN jsonb_build_object('accepted', v_existing.item_count, 'rejected', v_existing.rejected_count,
                                   'first_seq', v_existing.first_seq, 'last_seq', v_existing.last_seq,
                                   'duplicate', true);
    END IF;

    INSERT INTO public.event_chain_heads (organization_id) VALUES (p_org) ON CONFLICT DO NOTHING;
    SELECT * INTO v_head FROM public.event_chain_heads WHERE organization_id = p_org FOR UPDATE;

    v_seq := v_head.last_seq;
    v_prev := v_head.last_hash;

    FOR v_item IN SELECT value FROM jsonb_array_elements(p_items) LOOP
        BEGIN
            v_agent_id := (v_item ->> 'agent_id')::uuid;
            v_occurred_at := COALESCE((v_item ->> 'occurred_at')::timestamptz, now());
            SELECT array_agg(x) INTO v_reasons FROM jsonb_array_elements_text(COALESCE(v_item -> 'reasons', '[]'::jsonb)) x;
            SELECT array_agg(x) INTO v_argument_keys FROM jsonb_array_elements_text(COALESCE(v_item -> 'argument_keys', '[]'::jsonb)) x;
        EXCEPTION WHEN OTHERS THEN
            v_rejected := v_rejected + 1;
            CONTINUE;
        END;

        SELECT organization_id INTO v_agent_org FROM public.agents WHERE id = v_agent_id;
        IF v_agent_org IS NULL OR v_agent_org <> p_org THEN
            v_rejected := v_rejected + 1;
            CONTINUE;
        END IF;
        IF COALESCE(v_item ->> 'decision', '') NOT IN ('ALLOW', 'BLOCK', 'ERROR')
           OR COALESCE(v_item ->> 'method', '') = '' OR char_length(v_item ->> 'method') > 64
           OR char_length(v_item ->> 'gateway_instance') NOT BETWEEN 1 AND 64 THEN
            v_rejected := v_rejected + 1;
            CONTINUE;
        END IF;

        BEGIN
            v_seq := v_seq + 1;
            v_hash := public._blackbox_event_hash(
                v_prev, p_org, v_agent_id, v_seq, v_occurred_at,
                v_item ->> 'gateway_instance', COALESCE(v_item ->> 'server', ''), v_item ->> 'method',
                COALESCE(v_item ->> 'tool_name', ''), v_item ->> 'decision',
                COALESCE(v_reasons, '{}'), (v_item ->> 'upstream_status')::integer,
                (v_item ->> 'latency_ms')::numeric, COALESCE(v_argument_keys, '{}'),
                COALESCE(v_item ->> 'arguments_sha256', ''), (v_item ->> 'result_size_bytes')::integer,
                COALESCE((v_item ->> 'redaction_count')::integer, 0), v_item ->> 'credential_jti');

            INSERT INTO public.agent_events (
                organization_id, agent_id, seq, occurred_at, gateway_instance, server, method, tool_name,
                decision, reasons, upstream_status, latency_ms, argument_keys, arguments_sha256,
                result_size_bytes, redaction_count, credential_jti, prev_hash, hash, batch_id
            ) VALUES (
                p_org, v_agent_id, v_seq, v_occurred_at, v_item ->> 'gateway_instance',
                COALESCE(v_item ->> 'server', ''), v_item ->> 'method', COALESCE(v_item ->> 'tool_name', ''),
                v_item ->> 'decision', COALESCE(v_reasons, '{}'), (v_item ->> 'upstream_status')::integer,
                (v_item ->> 'latency_ms')::numeric, COALESCE(v_argument_keys, '{}'),
                COALESCE(v_item ->> 'arguments_sha256', ''), (v_item ->> 'result_size_bytes')::integer,
                COALESCE((v_item ->> 'redaction_count')::integer, 0), v_item ->> 'credential_jti',
                v_prev, v_hash, p_batch_id);

            v_prev := v_hash;
            v_accepted := v_accepted + 1;
            IF v_first_seq IS NULL THEN v_first_seq := v_seq; END IF;
            v_last_seq := v_seq;
        EXCEPTION WHEN OTHERS THEN
            v_seq := v_seq - 1;  -- give the sequence number back; it was never committed
            v_rejected := v_rejected + 1;
        END;
    END LOOP;

    UPDATE public.event_chain_heads SET last_seq = v_seq, last_hash = v_prev, updated_at = now()
    WHERE organization_id = p_org;

    INSERT INTO public.event_batches (batch_id, organization_id, instance_id, item_count, rejected_count, first_seq, last_seq)
    VALUES (p_batch_id, p_org, p_instance, v_accepted, v_rejected, v_first_seq, v_last_seq);

    RETURN jsonb_build_object('accepted', v_accepted, 'rejected', v_rejected,
                               'first_seq', v_first_seq, 'last_seq', v_last_seq, 'duplicate', false);
END;
$$;

-- -----------------------------------------------------------------------------
-- Recomputes the hash chain over [p_from_seq, p_to_seq] (inclusive, at most 50,000 events) and
-- reports the first seq where a stored hash does not match what the chain implies. p_from_seq must
-- be within the retained range (after the organization's anchor, if any events have been purged).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.verify_events(p_org uuid, p_from_seq bigint, p_to_seq bigint)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
STABLE
AS $$
DECLARE
    v_head public.event_chain_heads%ROWTYPE;
    v_row public.agent_events%ROWTYPE;
    v_expected_prev text;
    v_computed text;
    v_checked integer := 0;
BEGIN
    SELECT * INTO v_head FROM public.event_chain_heads WHERE organization_id = p_org;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('ok', true, 'checked', 0);
    END IF;
    IF p_to_seq < p_from_seq OR p_to_seq - p_from_seq >= 50000 THEN
        RAISE EXCEPTION 'range must cover at most 50000 events' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_from_seq <= v_head.anchor_seq THEN
        RAISE EXCEPTION 'range starts at or before the retained anchor (seq %)', v_head.anchor_seq
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_from_seq = v_head.anchor_seq + 1 THEN
        v_expected_prev := v_head.anchor_prev_hash;
    ELSE
        SELECT hash INTO v_expected_prev FROM public.agent_events WHERE organization_id = p_org AND seq = p_from_seq - 1;
        IF v_expected_prev IS NULL THEN
            RAISE EXCEPTION 'predecessor of seq % is missing' , p_from_seq USING ERRCODE = 'invalid_parameter_value';
        END IF;
    END IF;

    FOR v_row IN
        SELECT * FROM public.agent_events WHERE organization_id = p_org AND seq BETWEEN p_from_seq AND p_to_seq ORDER BY seq
    LOOP
        IF v_row.prev_hash IS DISTINCT FROM v_expected_prev THEN
            RETURN jsonb_build_object('ok', false, 'broken_seq', v_row.seq, 'reason', 'prev_hash_mismatch');
        END IF;
        v_computed := public._blackbox_event_hash(
            v_row.prev_hash, v_row.organization_id, v_row.agent_id, v_row.seq, v_row.occurred_at,
            v_row.gateway_instance, v_row.server, v_row.method, v_row.tool_name, v_row.decision,
            v_row.reasons, v_row.upstream_status, v_row.latency_ms, v_row.argument_keys,
            v_row.arguments_sha256, v_row.result_size_bytes, v_row.redaction_count, v_row.credential_jti);
        IF v_computed IS DISTINCT FROM v_row.hash THEN
            RETURN jsonb_build_object('ok', false, 'broken_seq', v_row.seq, 'reason', 'hash_mismatch');
        END IF;
        v_expected_prev := v_row.hash;
        v_checked := v_checked + 1;
    END LOOP;

    RETURN jsonb_build_object('ok', true, 'checked', v_checked);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.record_events(text, uuid, uuid, jsonb) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.verify_events(uuid, bigint, bigint) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public._blackbox_event_hash(text, uuid, uuid, bigint, timestamptz, text, text, text, text, text, text[], integer, numeric, text[], text, integer, integer, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_events(text, uuid, uuid, jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.verify_events(uuid, bigint, bigint) TO service_role;
GRANT EXECUTE ON FUNCTION public._blackbox_event_hash(text, uuid, uuid, bigint, timestamptz, text, text, text, text, text, text[], integer, numeric, text[], text, integer, integer, text) TO service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';
