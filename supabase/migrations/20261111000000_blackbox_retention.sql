-- =============================================================================
-- Black Box retention (Phase 3 M2a): purge old events without breaking the chain, clear captured
-- payloads at their own retention, and let an admin change both retention periods.
-- Rollback: supabase/rollbacks/20261111000000_blackbox_retention.down.sql
-- Plan: docs/plans/phase3-plan.md (sections 3.1 and 9)   ADR: docs/adr/0011-black-box-recorder.md
--
-- How a purge keeps the chain verifiable: purge_events() first moves the organization's anchor
-- (event_chain_heads.anchor_seq / anchor_prev_hash) to the last event it will delete, then deletes every
-- event at or behind it. verify_events() already starts from the anchor, so the kept range still verifies.
--
-- What the database itself now allows, for everyone including service_role application code:
--   * DELETE of an event only at or behind its organization's anchor;
--   * UPDATE of an event only to set arguments_redacted and result_excerpt to NULL (payload retention);
--   * moving an anchor only forward, only onto an existing event whose hash it records, and only onto an
--     event older than the organization's retention. So even code with full table access cannot erase
--     events younger than the retention period (minimum 7 days) without it showing as a broken chain.
-- Someone with database superuser access can still bypass all of this (ADR 0011, limits).
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
    'organization.blackbox_retention_changed', 'organization.blackbox_purged'
));

-- -----------------------------------------------------------------------------
-- Append-only, with exactly two exceptions (replaces the M1 body; the trigger itself is unchanged).
-- The UPDATE check compares the whole row minus the two payload columns, so a column added later is
-- protected automatically rather than silently left mutable.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public._forbid_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_anchor bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        SELECT anchor_seq INTO v_anchor FROM public.event_chain_heads WHERE organization_id = OLD.organization_id;
        IF v_anchor IS NOT NULL AND OLD.seq <= v_anchor THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'agent_events is append-only: only events behind the retention anchor can be deleted'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF NEW.arguments_redacted IS NULL AND NEW.result_excerpt IS NULL
       AND (to_jsonb(NEW) - 'arguments_redacted' - 'result_excerpt')
           = (to_jsonb(OLD) - 'arguments_redacted' - 'result_excerpt') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'agent_events is append-only: only captured payloads can be cleared'
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

-- -----------------------------------------------------------------------------
-- Guards the anchor. record_events() updates event_chain_heads on every batch without touching the
-- anchor, so this costs one comparison there.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public._guard_event_anchor()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_hash text;
    v_received timestamptz;
    v_retention integer;
BEGIN
    IF NEW.anchor_seq IS NOT DISTINCT FROM OLD.anchor_seq
       AND NEW.anchor_prev_hash IS NOT DISTINCT FROM OLD.anchor_prev_hash THEN
        RETURN NEW;
    END IF;
    IF NEW.anchor_seq <= OLD.anchor_seq OR NEW.anchor_seq > NEW.last_seq THEN
        RAISE EXCEPTION 'the retention anchor can only move forward, within the chain'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT e.hash, e.received_at INTO v_hash, v_received
    FROM public.agent_events e WHERE e.organization_id = NEW.organization_id AND e.seq = NEW.anchor_seq;
    SELECT blackbox_retention_days INTO v_retention FROM public.organizations WHERE id = NEW.organization_id;
    IF v_hash IS NULL OR v_hash IS DISTINCT FROM NEW.anchor_prev_hash THEN
        RAISE EXCEPTION 'the retention anchor must record the hash of an existing event'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF v_retention IS NULL OR v_received >= now() - make_interval(days => v_retention) THEN
        RAISE EXCEPTION 'the retention anchor cannot move onto an event younger than the retention period'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_event_chain_heads_anchor_guard
    BEFORE UPDATE ON public.event_chain_heads
    FOR EACH ROW EXECUTE FUNCTION public._guard_event_anchor();

-- -----------------------------------------------------------------------------
-- Daily retention for every organization. Ages are measured by received_at (the database clock), not
-- the gateway's occurred_at. Because seq is assigned under the chain-head lock but received_at is the
-- transaction start time, received_at is not strictly increasing with seq; the anchor therefore stops
-- just before the FIRST event that is still within retention, so it only ever covers a prefix of events
-- that are all old enough. At most p_max_events_per_org events per organization are deleted per run
-- (batched, resumable: the next run continues). Batch ids older than 2 days are dropped (a gateway
-- resends a batch within minutes, so exactly-once does not need them longer).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.purge_events(p_max_events_per_org integer DEFAULT 50000)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org_id uuid;
    v_head public.event_chain_heads%ROWTYPE;
    v_retention integer;
    v_payload_retention integer;
    v_first_kept bigint;
    v_target bigint;
    v_anchor_hash text;
    v_deleted integer;
    v_cleared integer;
    v_orgs integer := 0;
    v_total_deleted bigint := 0;
    v_total_cleared bigint := 0;
    v_batches integer;
BEGIN
    IF p_max_events_per_org IS NULL OR p_max_events_per_org < 1 OR p_max_events_per_org > 1000000 THEN
        RAISE EXCEPTION 'p_max_events_per_org must be between 1 and 1000000' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    FOR v_org_id IN SELECT organization_id FROM public.event_chain_heads ORDER BY organization_id LOOP
        -- Same lock as record_events(): a purge and an ingest for one organization never interleave.
        SELECT * INTO v_head FROM public.event_chain_heads WHERE organization_id = v_org_id FOR UPDATE;
        SELECT blackbox_retention_days, payload_retention_days INTO v_retention, v_payload_retention
        FROM public.organizations WHERE id = v_head.organization_id;
        IF v_retention IS NULL THEN
            CONTINUE;
        END IF;

        SELECT min(seq) INTO v_first_kept FROM public.agent_events
        WHERE organization_id = v_head.organization_id AND seq > v_head.anchor_seq
          AND received_at >= now() - make_interval(days => v_retention);
        v_target := LEAST(COALESCE(v_first_kept - 1, v_head.last_seq), v_head.anchor_seq + p_max_events_per_org);

        IF v_target > v_head.anchor_seq THEN
            SELECT hash INTO v_anchor_hash FROM public.agent_events
            WHERE organization_id = v_head.organization_id AND seq = v_target;
            IF v_anchor_hash IS NULL THEN
                -- Never expected (seqs are contiguous). Skip this organization rather than guess.
                RAISE WARNING 'purge_events: event % of organization % is missing; skipped', v_target, v_head.organization_id;
                CONTINUE;
            END IF;
            UPDATE public.event_chain_heads SET anchor_seq = v_target, anchor_prev_hash = v_anchor_hash, updated_at = now()
            WHERE organization_id = v_head.organization_id;
            DELETE FROM public.agent_events WHERE organization_id = v_head.organization_id AND seq <= v_target;
            GET DIAGNOSTICS v_deleted = ROW_COUNT;
            INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
            VALUES (v_head.organization_id, '00000000-0000-0000-0000-000000000000', 'organization.blackbox_purged',
                    'organization', v_head.organization_id, 'Black Box retention',
                    jsonb_build_object('old_anchor_seq', v_head.anchor_seq, 'new_anchor_seq', v_target,
                                       'events_deleted', v_deleted, 'retention_days', v_retention));
            v_orgs := v_orgs + 1;
            v_total_deleted := v_total_deleted + v_deleted;
        END IF;

        UPDATE public.agent_events SET arguments_redacted = NULL, result_excerpt = NULL
        WHERE organization_id = v_head.organization_id
          AND (arguments_redacted IS NOT NULL OR result_excerpt IS NOT NULL)
          AND received_at < now() - make_interval(days => v_payload_retention);
        GET DIAGNOSTICS v_cleared = ROW_COUNT;
        v_total_cleared := v_total_cleared + v_cleared;
    END LOOP;

    DELETE FROM public.event_batches WHERE received_at < now() - interval '2 days';
    GET DIAGNOSTICS v_batches = ROW_COUNT;

    RETURN jsonb_build_object('organizations_purged', v_orgs, 'events_deleted', v_total_deleted,
                              'payloads_cleared', v_total_cleared, 'batches_deleted', v_batches);
END;
$$;

-- -----------------------------------------------------------------------------
-- An admin changes the organization's retention periods. Compare-and-set (the caller passes the values
-- its decision was based on), idempotent, audited, service_role only. A shorter event retention takes
-- effect at the next daily purge.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_blackbox_retention(
    p_org uuid, p_actor uuid, p_retention_days integer, p_payload_retention_days integer, p_reason text,
    p_expected_retention_days integer, p_expected_payload_retention_days integer
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
BEGIN
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_org.blackbox_retention_days IS DISTINCT FROM p_expected_retention_days
       OR v_org.payload_retention_days IS DISTINCT FROM p_expected_payload_retention_days THEN
        RETURN jsonb_build_object('conflict', true);
    END IF;
    IF v_org.blackbox_retention_days = p_retention_days AND v_org.payload_retention_days = p_payload_retention_days THEN
        RETURN jsonb_build_object('changed', false, 'retention_days', p_retention_days,
                                  'payload_retention_days', p_payload_retention_days);
    END IF;

    UPDATE public.organizations
    SET blackbox_retention_days = p_retention_days, payload_retention_days = p_payload_retention_days
    WHERE id = p_org;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'organization.blackbox_retention_changed', 'organization', p_org, p_reason,
            jsonb_build_object('old_retention_days', v_org.blackbox_retention_days, 'new_retention_days', p_retention_days,
                               'old_payload_retention_days', v_org.payload_retention_days,
                               'new_payload_retention_days', p_payload_retention_days));
    RETURN jsonb_build_object('changed', true, 'retention_days', p_retention_days,
                              'payload_retention_days', p_payload_retention_days);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.purge_events(integer) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_blackbox_retention(uuid, uuid, integer, integer, text, integer, integer) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public._guard_event_anchor() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.purge_events(integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_blackbox_retention(uuid, uuid, integer, integer, text, integer, integer) TO service_role;

COMMIT;

-- Daily at the same quiet hour as the other purges (19:17 UTC, 03:17 in Malaysia).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.schedule('redhand-purge-events', '17 19 * * *', 'SELECT public.purge_events()');
        RAISE NOTICE 'scheduled redhand-purge-events';
    ELSE
        RAISE NOTICE 'pg_cron is not available here: schedule purge_events() yourself (daily)';
    END IF;
END;
$$;

NOTIFY pgrst, 'reload schema';
