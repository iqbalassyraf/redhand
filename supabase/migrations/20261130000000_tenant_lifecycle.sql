-- =============================================================================
-- Phase 4.5 D1 PR3: tenant data lifecycle (ADR 0027). Rollback: supabase/rollbacks/20261130000000_tenant_lifecycle.down.sql
--
-- Until now a customer could not take their data out and deleting an organization was an improvised DBA task (docs/runbooks/tenant-data-deletion.md).
--   - tenant_data_manifest(): the ONE list of tables that hold tenant data, which columns an export must leave out (key and token hashes, webhook URLs that may hold
--     tokens) and how each table is selected. Export and purge both read it, and a SQL test fails when a table with organization_id is not in it.
--   - control_org_export(): owner-only, audited (counts only, never the data), at most one export per organization per hour. Never returns a secret column.
--   - control_org_request_deletion(): owner-only, needs the organization slug typed back, starts a 7-day grace period, freezes every agent, switches SDK keys off,
--     revokes pending invites. control_org_cancel_deletion() ends the grace period (agents stay frozen: unfreezing is a deliberate per-agent action).
--   - control_org_purge(): the ONLY deletion path. Not callable through the API (no role but the table owner can run it), refuses before the grace period ends, runs the
--     audited trigger-disable steps the runbook used to describe, deletes in one transaction, proves every manifest table is empty for the tenant, and records the
--     deletion in tenant_deletions (counts only, no personal data).
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
    'passport.spend_limit_changed',
    'organization.approved_models_changed',
    'sdk_key.created', 'sdk_key.revoked',
    'passport.promoted',
    'organization.created', 'member.invited', 'member.invite_revoked', 'member.joined', 'member.removed', 'member.role_changed',
    'organization.exported', 'organization.deletion_requested', 'organization.deletion_cancelled'
));

ALTER TABLE public.organizations
    ADD COLUMN deletion_requested_at TIMESTAMPTZ,
    ADD COLUMN deletion_requested_by UUID,
    ADD COLUMN deletion_purge_after TIMESTAMPTZ,
    ADD CONSTRAINT organizations_deletion_consistent CHECK (
        (deletion_requested_at IS NULL AND deletion_requested_by IS NULL AND deletion_purge_after IS NULL)
        OR (deletion_requested_at IS NOT NULL AND deletion_requested_by IS NOT NULL AND deletion_purge_after IS NOT NULL AND deletion_purge_after > deletion_requested_at));

-- Evidence that a tenant was deleted and when. Holds an opaque id, a hash of the slug and row counts: no names, no e-mails, no content.
CREATE TABLE public.tenant_deletions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    slug_sha256 TEXT NOT NULL CHECK (slug_sha256 ~ '^[0-9a-f]{64}$'),
    requested_at TIMESTAMPTZ NOT NULL,
    purged_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    row_counts JSONB NOT NULL
);
ALTER TABLE public.tenant_deletions ENABLE ROW LEVEL SECURITY;

-- scope: org = organization_id column; agent = rows of the organization's agents (no organization_id of their own); self = the organizations row; members = organization_members plus e-mail.
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

-- One manifest entry as rows. Dynamic SQL only ever sees a table name taken from the manifest above, quoted with %I.
CREATE OR REPLACE FUNCTION public.tenant_table_rows(p_entry jsonb, p_org uuid, p_limit integer)
RETURNS jsonb
LANGUAGE plpgsql STABLE
SET search_path = public, pg_temp
AS $$
DECLARE
    v_table text := p_entry ->> 'table';
    v_scope text := p_entry ->> 'scope';
    v_exclude text[] := ARRAY(SELECT jsonb_array_elements_text(p_entry -> 'exclude'));
    v_where text;
    v_rows jsonb;
    v_count bigint;
BEGIN
    IF v_scope = 'members' THEN
        SELECT count(*) INTO v_count FROM public.organization_members WHERE organization_id = p_org;
        SELECT COALESCE(jsonb_agg(row), '[]'::jsonb) INTO v_rows FROM (
            SELECT to_jsonb(m) || jsonb_build_object('email', u.email) AS row
            FROM public.organization_members m LEFT JOIN auth.users u ON u.id = m.user_id
            WHERE m.organization_id = p_org LIMIT p_limit) q;
    ELSE
        v_where := CASE v_scope
            WHEN 'org' THEN 'organization_id = $1'
            WHEN 'agent' THEN 'agent_id IN (SELECT id FROM public.agents WHERE organization_id = $1)'
            WHEN 'self' THEN 'id = $1'
        END;
        IF v_where IS NULL THEN RAISE EXCEPTION 'unknown manifest scope %', v_scope; END IF;
        EXECUTE format('SELECT count(*) FROM public.%I WHERE %s', v_table, v_where) INTO v_count USING p_org;
        EXECUTE format('SELECT COALESCE(jsonb_agg(to_jsonb(t) - $2), ''[]''::jsonb) FROM (SELECT * FROM public.%I WHERE %s LIMIT $3) t', v_table, v_where)
            INTO v_rows USING p_org, v_exclude, p_limit;
    END IF;
    RETURN jsonb_build_object('count', v_count, 'truncated', v_count > p_limit, 'rows', v_rows);
END $$;

CREATE OR REPLACE FUNCTION public.tenant_row_counts(p_org uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE
SET search_path = public, pg_temp
AS $$
DECLARE
    v_entry jsonb;
    v_out jsonb := '{}'::jsonb;
    v_where text;
    v_count bigint;
BEGIN
    FOR v_entry IN SELECT * FROM jsonb_array_elements(public.tenant_data_manifest()) LOOP
        v_where := CASE v_entry ->> 'scope'
            WHEN 'org' THEN 'organization_id = $1' WHEN 'members' THEN 'organization_id = $1'
            WHEN 'agent' THEN 'agent_id IN (SELECT id FROM public.agents WHERE organization_id = $1)'
            WHEN 'self' THEN 'id = $1' END;
        EXECUTE format('SELECT count(*) FROM public.%I WHERE %s', v_entry ->> 'table', v_where) INTO v_count USING p_org;
        v_out := v_out || jsonb_build_object(v_entry ->> 'table', v_count);
    END LOOP;
    RETURN v_out;
END $$;

-- -----------------------------------------------------------------------------
-- control_org_export(): returns every manifest table (at most p_limit rows each; a table over the cap says so) and audits the export, counts only.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_org_export(p_org uuid, p_actor uuid, p_limit integer DEFAULT 100000)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_entry jsonb;
    v_tables jsonb := '{}'::jsonb;
    v_counts jsonb := '{}'::jsonb;
    v_table jsonb;
    v_last timestamptz;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000000 THEN
        RAISE EXCEPTION 'p_limit must be between 1 and 1000000' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.organization_members WHERE organization_id = p_org AND user_id = p_actor AND role = 'owner') THEN
        RAISE EXCEPTION 'only an owner can export the organization' USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT max(created_at) INTO v_last FROM public.control_audit_log WHERE organization_id = p_org AND action = 'organization.exported' AND created_at > now() - interval '1 hour';
    IF v_last IS NOT NULL THEN
        RETURN jsonb_build_object('exported', false, 'reason', 'throttled', 'retry_after_seconds', GREATEST(1, ceil(extract(epoch FROM (v_last + interval '1 hour' - now())))::integer));
    END IF;
    FOR v_entry IN SELECT * FROM jsonb_array_elements(public.tenant_data_manifest()) LOOP
        v_table := public.tenant_table_rows(v_entry, p_org, p_limit);
        v_tables := v_tables || jsonb_build_object(v_entry ->> 'table', v_table);
        v_counts := v_counts || jsonb_build_object(v_entry ->> 'table', v_table -> 'count');
    END LOOP;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'organization.exported', 'organization', p_org, NULL, jsonb_build_object('row_counts', v_counts));
    RETURN jsonb_build_object('exported', true, 'generated_at', now(), 'organization_id', p_org, 'tables', v_tables);
END $$;

-- -----------------------------------------------------------------------------
-- control_org_request_deletion(): the owner types the slug back. Idempotent: a second request returns the first one's dates.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_org_request_deletion(p_org uuid, p_actor uuid, p_confirm_slug text, p_grace interval DEFAULT interval '7 days')
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
    v_frozen integer;
    v_keys integer;
    v_invites integer;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.organization_members WHERE organization_id = p_org AND user_id = p_actor AND role = 'owner') THEN
        RAISE EXCEPTION 'only an owner can delete the organization' USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found'; END IF;
    IF v_org.deletion_requested_at IS NOT NULL THEN
        RETURN jsonb_build_object('requested', true, 'already', true, 'requested_at', v_org.deletion_requested_at, 'purge_after', v_org.deletion_purge_after);
    END IF;
    IF p_confirm_slug IS DISTINCT FROM v_org.slug THEN
        RETURN jsonb_build_object('requested', false, 'reason', 'confirmation');
    END IF;
    IF p_grace < interval '1 day' OR p_grace > interval '30 days' THEN
        RAISE EXCEPTION 'the grace period is 1 to 30 days' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE public.organizations SET deletion_requested_at = now(), deletion_requested_by = p_actor, deletion_purge_after = now() + p_grace WHERE id = p_org
        RETURNING * INTO v_org;
    UPDATE public.agents SET status = 'frozen', status_reason = 'organization deletion requested' WHERE organization_id = p_org AND status = 'active';
    GET DIAGNOSTICS v_frozen = ROW_COUNT;
    UPDATE public.sdk_api_keys SET is_active = false WHERE organization_id = p_org AND is_active;
    GET DIAGNOSTICS v_keys = ROW_COUNT;
    UPDATE public.member_invites SET revoked_at = now() WHERE organization_id = p_org AND used_at IS NULL AND revoked_at IS NULL;
    GET DIAGNOSTICS v_invites = ROW_COUNT;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'organization.deletion_requested', 'organization', p_org, NULL,
            jsonb_build_object('purge_after', v_org.deletion_purge_after, 'agents_frozen', v_frozen, 'sdk_keys_deactivated', v_keys, 'invites_revoked', v_invites));
    RETURN jsonb_build_object('requested', true, 'already', false, 'requested_at', v_org.deletion_requested_at, 'purge_after', v_org.deletion_purge_after);
END $$;

CREATE OR REPLACE FUNCTION public.control_org_cancel_deletion(p_org uuid, p_actor uuid)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_was timestamptz;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.organization_members WHERE organization_id = p_org AND user_id = p_actor AND role = 'owner') THEN
        RAISE EXCEPTION 'only an owner can cancel the deletion' USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT deletion_requested_at INTO v_was FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found'; END IF;
    IF v_was IS NULL THEN RETURN jsonb_build_object('cancelled', false, 'reason', 'not_requested'); END IF;
    UPDATE public.organizations SET deletion_requested_at = NULL, deletion_requested_by = NULL, deletion_purge_after = NULL WHERE id = p_org;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'organization.deletion_cancelled', 'organization', p_org, NULL, jsonb_build_object('requested_at', v_was));
    RETURN jsonb_build_object('cancelled', true);
END $$;

-- -----------------------------------------------------------------------------
-- control_org_purge(): run by the database owner (scripts/purge_tenant.sh), never through the API. Everything in one transaction: if any table still holds a row
-- for the tenant afterwards, the whole purge is rolled back. The two append-only triggers are switched off only inside this function and back on before it returns.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_org_purge(p_org uuid)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
    v_before jsonb;
    v_after jsonb;
    v_left bigint;
BEGIN
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found'; END IF;
    IF v_org.deletion_requested_at IS NULL THEN
        RAISE EXCEPTION 'deletion was not requested' USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    IF v_org.deletion_purge_after > now() THEN
        RAISE EXCEPTION 'the grace period ends at %', v_org.deletion_purge_after USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    v_before := public.tenant_row_counts(p_org);
    ALTER TABLE public.control_audit_log DISABLE TRIGGER control_audit_log_no_update;
    ALTER TABLE public.agent_events DISABLE TRIGGER trg_agent_events_append_only;
    DELETE FROM public.organizations WHERE id = p_org;
    ALTER TABLE public.agent_events ENABLE TRIGGER trg_agent_events_append_only;
    ALTER TABLE public.control_audit_log ENABLE TRIGGER control_audit_log_no_update;
    v_after := public.tenant_row_counts(p_org);
    SELECT COALESCE(sum(value::bigint), 0) INTO v_left FROM jsonb_each_text(v_after);
    IF v_left <> 0 THEN
        RAISE EXCEPTION 'purge left % rows behind: %', v_left, v_after USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    INSERT INTO public.tenant_deletions (organization_id, slug_sha256, requested_at, row_counts)
    VALUES (p_org, encode(sha256(convert_to(v_org.slug, 'UTF8')), 'hex'), v_org.deletion_requested_at, v_before);
    RETURN jsonb_build_object('purged', true, 'row_counts', v_before);
END $$;

REVOKE EXECUTE ON FUNCTION public.tenant_data_manifest() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.tenant_table_rows(jsonb, uuid, integer) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.tenant_row_counts(uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_org_export(uuid, uuid, integer) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_org_request_deletion(uuid, uuid, text, interval) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_org_cancel_deletion(uuid, uuid) FROM PUBLIC, anon, authenticated;
-- The purge is not granted to service_role either: only the database owner can run it.
REVOKE EXECUTE ON FUNCTION public.control_org_purge(uuid) FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.tenant_data_manifest() TO service_role;
GRANT EXECUTE ON FUNCTION public.tenant_table_rows(jsonb, uuid, integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.tenant_row_counts(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_org_export(uuid, uuid, integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_org_request_deletion(uuid, uuid, text, interval) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_org_cancel_deletion(uuid, uuid) TO service_role;

COMMIT;
