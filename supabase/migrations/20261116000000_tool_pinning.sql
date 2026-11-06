-- =============================================================================
-- Tool pinning (Phase 4 M3): notice when an MCP server changes a tool after the owner approved it. Rollback:
-- supabase/rollbacks/20261116000000_tool_pinning.down.sql.   Plan: docs/plans/phase4-plan.md   ADR: docs/adr/0014-tool-pinning.md
--
-- The gateway hashes each tool (name, description, input schema) when a server's tools/list passes through it and reports
-- hashes it has not reported before. record_tool_observation() stores each new hash as a PENDING version. The owner
-- approves or rejects versions in the dashboard. Per server, pin_mode is off, alert (default: report only) or enforce
-- (hide and refuse tools whose current version is not approved). Text stored here came from a server and is untrusted:
-- it is capped, kept only for the owner's review, and shown as plain text.
-- All functions are service_role only; who may call them is decided in redhand-core.
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
    'mcp_server.pin_mode_changed'
));

ALTER TABLE public.mcp_servers
    ADD COLUMN pin_mode TEXT NOT NULL DEFAULT 'alert' CHECK (pin_mode IN ('off', 'alert', 'enforce')),
    ADD COLUMN pin_last_alert_at TIMESTAMPTZ;

CREATE TABLE public.mcp_tool_pins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    server_id UUID NOT NULL REFERENCES public.mcp_servers(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL CHECK (char_length(tool_name) BETWEEN 1 AND 128),
    digest TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'superseded')),
    change_kind TEXT NOT NULL CHECK (change_kind IN ('new', 'changed')),
    description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    schema_text TEXT NOT NULL DEFAULT '' CHECK (char_length(schema_text) <= 8000),
    rules TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(rules) <= 20),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_by UUID,
    decided_at TIMESTAMPTZ,
    UNIQUE (server_id, tool_name, digest)
);
CREATE INDEX idx_tool_pins_server_status ON public.mcp_tool_pins(organization_id, server_id, status);
ALTER TABLE public.mcp_tool_pins ENABLE ROW LEVEL SECURITY;  -- core uses the service role; no policies, nobody else reads it

-- -----------------------------------------------------------------------------
-- record_tool_observation(): the gateway saw these tool versions. Idempotent per (server, tool, digest). Bounded: 500
-- tools per server, 20 versions per tool, 200 tools per call. Returns how many are new or changed and whether to alert
-- (at most one alert per server per 10 minutes; the versions themselves are always recorded).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.record_tool_observation(p_org uuid, p_server uuid, p_tools jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    c_system CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
    v_server public.mcp_servers%ROWTYPE;
    v_tool jsonb;
    v_name text;
    v_digest text;
    v_has_approved boolean;
    v_kind text;
    v_new integer := 0;
    v_changed integer := 0;
    v_skipped integer := 0;
    v_alert boolean := false;
BEGIN
    IF p_tools IS NULL OR jsonb_typeof(p_tools) <> 'array' OR jsonb_array_length(p_tools) > 200 THEN
        RAISE EXCEPTION 'tools must be an array of at most 200' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO v_server FROM public.mcp_servers WHERE id = p_server AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'server not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_server.pin_mode = 'off' THEN
        RETURN jsonb_build_object('new', 0, 'changed', 0, 'skipped', jsonb_array_length(p_tools), 'alert', false);
    END IF;

    FOR v_tool IN SELECT * FROM jsonb_array_elements(p_tools) LOOP
        v_name := v_tool->>'name';
        v_digest := v_tool->>'digest';
        IF v_name IS NULL OR char_length(v_name) NOT BETWEEN 1 AND 128 OR v_digest IS NULL OR v_digest !~ '^[0-9a-f]{64}$' THEN
            v_skipped := v_skipped + 1;
            CONTINUE;
        END IF;
        IF EXISTS (SELECT 1 FROM public.mcp_tool_pins WHERE server_id = p_server AND tool_name = v_name AND digest = v_digest) THEN
            UPDATE public.mcp_tool_pins SET last_seen_at = now()
            WHERE server_id = p_server AND tool_name = v_name AND digest = v_digest;
            CONTINUE;
        END IF;
        IF (SELECT count(DISTINCT tool_name) FROM public.mcp_tool_pins WHERE server_id = p_server) >= 500
           AND NOT EXISTS (SELECT 1 FROM public.mcp_tool_pins WHERE server_id = p_server AND tool_name = v_name) THEN
            v_skipped := v_skipped + 1;
            CONTINUE;
        END IF;
        IF (SELECT count(*) FROM public.mcp_tool_pins WHERE server_id = p_server AND tool_name = v_name) >= 20 THEN
            DELETE FROM public.mcp_tool_pins WHERE id = (
                SELECT id FROM public.mcp_tool_pins WHERE server_id = p_server AND tool_name = v_name AND status IN ('rejected', 'superseded')
                ORDER BY last_seen_at LIMIT 1);
            IF (SELECT count(*) FROM public.mcp_tool_pins WHERE server_id = p_server AND tool_name = v_name) >= 20 THEN
                v_skipped := v_skipped + 1;
                CONTINUE;
            END IF;
        END IF;
        SELECT EXISTS (SELECT 1 FROM public.mcp_tool_pins WHERE server_id = p_server AND tool_name = v_name AND status = 'approved')
          INTO v_has_approved;
        v_kind := CASE WHEN v_has_approved THEN 'changed' ELSE 'new' END;
        INSERT INTO public.mcp_tool_pins (organization_id, server_id, tool_name, digest, change_kind, description, schema_text, rules)
        VALUES (p_org, p_server, v_name, v_digest, v_kind, left(coalesce(v_tool->>'description', ''), 2000),
                left(coalesce(v_tool->>'schema', ''), 8000),
                COALESCE((SELECT array_agg(r) FROM (SELECT left(x, 32) AS r FROM jsonb_array_elements_text(
                    CASE WHEN jsonb_typeof(v_tool->'rules') = 'array' THEN v_tool->'rules' ELSE '[]'::jsonb END) AS x LIMIT 20) q), '{}'));
        INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
        VALUES (p_org, c_system, 'tool_pin.pending', 'mcp_server', p_server, NULL,
                jsonb_build_object('tool', v_name, 'kind', v_kind, 'server', v_server.slug));
        IF v_kind = 'changed' THEN v_changed := v_changed + 1; ELSE v_new := v_new + 1; END IF;
    END LOOP;

    IF v_new + v_changed > 0 AND (v_server.pin_last_alert_at IS NULL OR v_server.pin_last_alert_at < now() - interval '10 minutes') THEN
        UPDATE public.mcp_servers SET pin_last_alert_at = now() WHERE id = p_server;
        v_alert := true;
    END IF;
    RETURN jsonb_build_object('new', v_new, 'changed', v_changed, 'skipped', v_skipped, 'alert', v_alert, 'server', v_server.slug);
END;
$$;

-- -----------------------------------------------------------------------------
-- Decisions. Only a PENDING version can be approved or rejected (compare-and-set: anything else is reported as a conflict).
-- Approving a version supersedes the tool's previously approved version, so exactly one version per tool is approved.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_tool_pin(p_org uuid, p_actor uuid, p_pin uuid, p_decision text, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_pin public.mcp_tool_pins%ROWTYPE;
BEGIN
    IF p_decision NOT IN ('approve', 'reject') THEN
        RAISE EXCEPTION 'decision must be approve or reject' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO v_pin FROM public.mcp_tool_pins WHERE id = p_pin AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'tool version not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_pin.status <> 'pending' THEN
        RETURN jsonb_build_object('conflict', true, 'status', v_pin.status);
    END IF;
    IF p_decision = 'approve' THEN
        UPDATE public.mcp_tool_pins SET status = 'superseded'
        WHERE server_id = v_pin.server_id AND tool_name = v_pin.tool_name AND status = 'approved';
        UPDATE public.mcp_tool_pins SET status = 'approved', decided_by = p_actor, decided_at = now() WHERE id = p_pin;
    ELSE
        UPDATE public.mcp_tool_pins SET status = 'rejected', decided_by = p_actor, decided_at = now() WHERE id = p_pin;
    END IF;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, CASE WHEN p_decision = 'approve' THEN 'tool_pin.approved' ELSE 'tool_pin.rejected' END,
            'mcp_server', v_pin.server_id, p_reason, jsonb_build_object('tool', v_pin.tool_name, 'kind', v_pin.change_kind, 'rules', v_pin.rules));
    RETURN jsonb_build_object('conflict', false, 'status', CASE WHEN p_decision = 'approve' THEN 'approved' ELSE 'rejected' END);
END;
$$;

-- Approves the newest pending version of every tool on a server (for the first baseline). Older pending versions of
-- the same tool are rejected. One audit row with the count.
CREATE OR REPLACE FUNCTION public.control_tool_pins_approve_all(p_org uuid, p_actor uuid, p_server uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_pin record;
    v_count integer := 0;
BEGIN
    PERFORM 1 FROM public.mcp_servers WHERE id = p_server AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'server not found' USING ERRCODE = 'no_data_found';
    END IF;
    FOR v_pin IN
        SELECT DISTINCT ON (tool_name) id, tool_name FROM public.mcp_tool_pins
        WHERE server_id = p_server AND status = 'pending' ORDER BY tool_name, last_seen_at DESC, first_seen_at DESC
    LOOP
        UPDATE public.mcp_tool_pins SET status = 'superseded' WHERE server_id = p_server AND tool_name = v_pin.tool_name AND status = 'approved';
        UPDATE public.mcp_tool_pins SET status = 'rejected', decided_by = p_actor, decided_at = now()
        WHERE server_id = p_server AND tool_name = v_pin.tool_name AND status = 'pending' AND id <> v_pin.id;
        UPDATE public.mcp_tool_pins SET status = 'approved', decided_by = p_actor, decided_at = now() WHERE id = v_pin.id;
        v_count := v_count + 1;
    END LOOP;
    IF v_count > 0 THEN
        INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
        VALUES (p_org, p_actor, 'tool_pin.approved_all', 'mcp_server', p_server, p_reason, jsonb_build_object('tools_approved', v_count));
    END IF;
    RETURN jsonb_build_object('approved', v_count);
END;
$$;

-- Compare-and-set on the server's pin mode, idempotent, audited.
CREATE OR REPLACE FUNCTION public.control_server_pin_mode(p_org uuid, p_actor uuid, p_server uuid, p_mode text, p_expected text, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_server public.mcp_servers%ROWTYPE;
BEGIN
    IF p_mode NOT IN ('off', 'alert', 'enforce') THEN
        RAISE EXCEPTION 'mode must be off, alert or enforce' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT * INTO v_server FROM public.mcp_servers WHERE id = p_server AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'server not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_server.pin_mode IS DISTINCT FROM p_expected THEN
        RETURN jsonb_build_object('conflict', true, 'pin_mode', v_server.pin_mode);
    END IF;
    IF v_server.pin_mode = p_mode THEN
        RETURN jsonb_build_object('conflict', false, 'changed', false, 'pin_mode', p_mode);
    END IF;
    UPDATE public.mcp_servers SET pin_mode = p_mode WHERE id = p_server;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'mcp_server.pin_mode_changed', 'mcp_server', p_server, p_reason,
            jsonb_build_object('old_mode', v_server.pin_mode, 'new_mode', p_mode, 'server', v_server.slug));
    RETURN jsonb_build_object('conflict', false, 'changed', true, 'pin_mode', p_mode);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.record_tool_observation(uuid, uuid, jsonb) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_tool_pin(uuid, uuid, uuid, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_tool_pins_approve_all(uuid, uuid, uuid, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_server_pin_mode(uuid, uuid, uuid, text, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_tool_observation(uuid, uuid, jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_tool_pin(uuid, uuid, uuid, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_tool_pins_approve_all(uuid, uuid, uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_server_pin_mode(uuid, uuid, uuid, text, text, text) TO service_role;

COMMIT;

NOTIFY pgrst, 'reload schema';
