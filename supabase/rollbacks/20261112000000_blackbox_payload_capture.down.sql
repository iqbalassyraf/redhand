-- Rollback for 20261112000000_blackbox_payload_capture.sql: restores the M1 record_events() (no payload
-- storage), drops control_payload_capture() and the payload size constraint, and CLEARS every captured
-- payload (data minimisation: capture is being removed, so what it stored should not linger). The
-- append-only trigger allows exactly this update (M2a). The restored audit CHECK list is NOT VALID because
-- control_audit_log is append-only and existing organization.payload_capture_changed rows cannot be removed.
-- organizations.payload_capture_enabled stays (it belongs to the M1 migration) and keeps its value; with the
-- old record_events() it has no effect.

BEGIN;

UPDATE public.agent_events SET arguments_redacted = NULL, result_excerpt = NULL
WHERE arguments_redacted IS NOT NULL OR result_excerpt IS NOT NULL;

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

DROP FUNCTION IF EXISTS public.control_payload_capture(uuid, uuid, boolean, text, boolean);
ALTER TABLE public.agent_events DROP CONSTRAINT IF EXISTS agent_events_payload_size;

REVOKE EXECUTE ON FUNCTION public.record_events(text, uuid, uuid, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_events(text, uuid, uuid, jsonb) TO service_role;

ALTER TABLE public.control_audit_log DROP CONSTRAINT control_audit_log_action_check;
ALTER TABLE public.control_audit_log ADD CONSTRAINT control_audit_log_action_check CHECK (action IN (
    'passport.created', 'passport.frozen', 'passport.unfrozen', 'passport.revoked',
    'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated',
    'organization.frozen_all', 'mcp_server.registered', 'mcp_server.deactivated',
    'telegram.linked', 'telegram.unlinked',
    'passport.safe_mode_enabled', 'passport.safe_mode_disabled',
    'organization.safe_mode_enabled', 'organization.safe_mode_disabled',
    'passport.budget_changed', 'organization.budget_default_changed',
    'organization.blackbox_retention_changed', 'organization.blackbox_purged'
)) NOT VALID;

COMMIT;

NOTIFY pgrst, 'reload schema';
