-- =============================================================================
-- Black Box payload capture (Phase 3 M2b): store a redacted, size-capped excerpt of a tool call's
-- arguments and result, only for organizations that turned capture on.
-- Rollback: supabase/rollbacks/20261112000000_blackbox_payload_capture.down.sql
-- Plan: docs/plans/phase3-plan.md (section 3.1)   ADR: docs/adr/0011-black-box-recorder.md
--
-- Capture is OFF by default (organizations.payload_capture_enabled, added with the M1 migration).
-- The gateway redacts and truncates before anything leaves it; this migration makes the DATABASE enforce
-- the setting too: record_events() stores the two payload columns only when the organization's flag is
-- on, and drops (never rejects) a payload that is not a JSON object or is over 16 KB, keeping the event.
-- The hash chain covers arguments_sha256, never these columns, so clearing them at payload retention
-- (purge_events, M2a) cannot break verification.
--
-- Turning capture on or off is a control action: control_payload_capture() is compare-and-set,
-- idempotent, audited and service_role only. Who may call it is decided in redhand-core.
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
    'organization.payload_capture_changed'
));

-- Backstop for the size rule in record_events(): a JSON object of at most 16 KB per payload column.
ALTER TABLE public.agent_events ADD CONSTRAINT agent_events_payload_size CHECK (
    (arguments_redacted IS NULL OR octet_length(arguments_redacted::text) <= 16384)
    AND (result_excerpt IS NULL OR octet_length(result_excerpt::text) <= 16384)
);

-- -----------------------------------------------------------------------------
-- record_events(): as in 20261110000000_blackbox.sql, plus payload storage when the organization has
-- capture on. The capture flag is read once per batch, after the chain-head lock is taken.
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
    v_capture boolean;
    v_args jsonb;
    v_result jsonb;
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
    -- Anything but an explicit true counts as off (the restrictive reading).
    SELECT COALESCE(payload_capture_enabled, FALSE) INTO v_capture FROM public.organizations WHERE id = p_org;
    v_capture := COALESCE(v_capture, FALSE);

    v_seq := v_head.last_seq;
    v_prev := v_head.last_hash;

    FOR v_item IN SELECT value FROM jsonb_array_elements(p_items) LOOP
        BEGIN
            v_agent_id := (v_item ->> 'agent_id')::uuid;
            v_occurred_at := COALESCE((v_item ->> 'occurred_at')::timestamptz, now());
            SELECT array_agg(x) INTO v_reasons FROM jsonb_array_elements_text(COALESCE(v_item -> 'reasons', '[]'::jsonb)) x;
            SELECT array_agg(x) INTO v_argument_keys FROM jsonb_array_elements_text(COALESCE(v_item -> 'argument_keys', '[]'::jsonb)) x;
            v_args := NULL;
            v_result := NULL;
            IF v_capture THEN
                v_args := NULLIF(v_item -> 'arguments_redacted', 'null'::jsonb);
                v_result := NULLIF(v_item -> 'result_excerpt', 'null'::jsonb);
                IF v_args IS NOT NULL AND (jsonb_typeof(v_args) <> 'object' OR octet_length(v_args::text) > 16384) THEN
                    v_args := NULL;
                END IF;
                IF v_result IS NOT NULL AND (jsonb_typeof(v_result) <> 'object' OR octet_length(v_result::text) > 16384) THEN
                    v_result := NULL;
                END IF;
            END IF;
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
                result_size_bytes, redaction_count, credential_jti, arguments_redacted, result_excerpt,
                prev_hash, hash, batch_id
            ) VALUES (
                p_org, v_agent_id, v_seq, v_occurred_at, v_item ->> 'gateway_instance',
                COALESCE(v_item ->> 'server', ''), v_item ->> 'method', COALESCE(v_item ->> 'tool_name', ''),
                v_item ->> 'decision', COALESCE(v_reasons, '{}'), (v_item ->> 'upstream_status')::integer,
                (v_item ->> 'latency_ms')::numeric, COALESCE(v_argument_keys, '{}'),
                COALESCE(v_item ->> 'arguments_sha256', ''), (v_item ->> 'result_size_bytes')::integer,
                COALESCE((v_item ->> 'redaction_count')::integer, 0), v_item ->> 'credential_jti',
                v_args, v_result,
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
-- Turns payload capture on or off for an organization. Compare-and-set (the caller passes the value its
-- decision was based on), idempotent, audited, service_role only.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_payload_capture(
    p_org uuid, p_actor uuid, p_enabled boolean, p_reason text, p_expected boolean
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
BEGIN
    IF p_enabled IS NULL THEN
        RAISE EXCEPTION 'enabled must be true or false' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_org.payload_capture_enabled IS DISTINCT FROM p_expected THEN
        RETURN jsonb_build_object('conflict', true);
    END IF;
    IF v_org.payload_capture_enabled = p_enabled THEN
        RETURN jsonb_build_object('changed', false, 'payload_capture_enabled', p_enabled);
    END IF;

    UPDATE public.organizations SET payload_capture_enabled = p_enabled WHERE id = p_org;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'organization.payload_capture_changed', 'organization', p_org, p_reason,
            jsonb_build_object('old_enabled', v_org.payload_capture_enabled, 'new_enabled', p_enabled));
    RETURN jsonb_build_object('changed', true, 'payload_capture_enabled', p_enabled);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.record_events(text, uuid, uuid, jsonb) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_payload_capture(uuid, uuid, boolean, text, boolean) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_events(text, uuid, uuid, jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_payload_capture(uuid, uuid, boolean, text, boolean) TO service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';
