-- =============================================================================
-- Honeytokens and honey tools (Phase 3 M3/M4). Rollback: supabase/rollbacks/20261115000000_honeytokens.down.sql
-- Plan: docs/plans/phase3-plan.md (3.2)   ADR: docs/adr/0012-honeytokens.md
--
-- A honeytoken is a fake credential an owner plants where only a misbehaving agent would find it. Only its
-- SHA-256 digest and last four characters are stored; the value is shown once, when it is created. A honey tool
-- is a decoy tool added to one agent's tools/list on one MCP server; a call to it is never forwarded.
-- The gateway matches by digest and reports a trip; record_trip() stores it idempotently, audits it, and tells
-- core whether to alert. Core (not the gateway) decides what happens next, from the stored action.
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
    'honey_tool.created', 'honey_tool.retired', 'honey_tool.tripped'
));

CREATE TABLE public.honeytokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    kind TEXT NOT NULL CHECK (kind IN ('api_key', 'aws_key', 'password')),
    digest TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    hint TEXT NOT NULL CHECK (char_length(hint) = 4),
    action_on_use TEXT NOT NULL DEFAULT 'freeze' CHECK (action_on_use IN ('alert', 'freeze')),
    action_on_read TEXT NOT NULL DEFAULT 'alert' CHECK (action_on_read IN ('alert', 'freeze')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at TIMESTAMPTZ,
    last_tripped_at TIMESTAMPTZ,
    trip_count INTEGER NOT NULL DEFAULT 0 CHECK (trip_count >= 0)
);
CREATE UNIQUE INDEX uq_honeytokens_org_digest ON public.honeytokens(organization_id, digest);
CREATE INDEX idx_honeytokens_org_status ON public.honeytokens(organization_id, status);

CREATE TABLE public.honey_tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    server_slug TEXT NOT NULL CHECK (char_length(server_slug) BETWEEN 1 AND 128),
    name TEXT NOT NULL CHECK (name ~ '^[A-Za-z][A-Za-z0-9_]{2,63}$'),
    description TEXT NOT NULL CHECK (char_length(description) BETWEEN 1 AND 300),
    action TEXT NOT NULL DEFAULT 'alert' CHECK (action IN ('alert', 'freeze')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at TIMESTAMPTZ,
    last_tripped_at TIMESTAMPTZ,
    trip_count INTEGER NOT NULL DEFAULT 0 CHECK (trip_count >= 0)
);
CREATE UNIQUE INDEX uq_honey_tools_active_name ON public.honey_tools(agent_id, server_slug, name) WHERE status = 'active';
CREATE INDEX idx_honey_tools_agent ON public.honey_tools(organization_id, agent_id, status);

-- One row per trip. The id comes from the gateway, so a retried report cannot be counted or alerted twice.
CREATE TABLE public.honeytrips (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('honeytoken', 'honey_tool')),
    ref_id UUID NOT NULL,
    seen_in TEXT NOT NULL CHECK (seen_in IN ('arguments', 'result', 'call')),
    tool_name TEXT NOT NULL DEFAULT '' CHECK (char_length(tool_name) <= 128),
    server_slug TEXT NOT NULL DEFAULT '' CHECK (char_length(server_slug) <= 128),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_honeytrips_org_time ON public.honeytrips(organization_id, occurred_at DESC);
CREATE INDEX idx_honeytrips_ref ON public.honeytrips(ref_id, agent_id, seen_in, occurred_at DESC);

-- Core uses the service role; with no policies, nobody else can read these tables.
ALTER TABLE public.honeytokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.honey_tools ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.honeytrips ENABLE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- Honeytokens: create / retire (audited, compare-free: retiring twice is a no-op)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_honeytoken_create(
    p_org uuid, p_actor uuid, p_label text, p_kind text, p_digest text, p_hint text,
    p_action_on_use text, p_action_on_read text
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_row public.honeytokens%ROWTYPE;
BEGIN
    PERFORM 1 FROM public.organizations WHERE id = p_org FOR UPDATE;  -- serialises the count below
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF (SELECT count(*) FROM public.honeytokens WHERE organization_id = p_org AND status = 'active') >= 50 THEN
        RAISE EXCEPTION 'at most 50 active honeytokens per organization' USING ERRCODE = 'check_violation';
    END IF;
    INSERT INTO public.honeytokens (organization_id, label, kind, digest, hint, action_on_use, action_on_read, created_by)
    VALUES (p_org, p_label, p_kind, p_digest, p_hint, p_action_on_use, p_action_on_read, p_actor)
    RETURNING * INTO v_row;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'honeytoken.created', 'organization', p_org, NULL,
            jsonb_build_object('honeytoken_id', v_row.id, 'label', v_row.label, 'kind', v_row.kind,
                               'action_on_use', v_row.action_on_use, 'action_on_read', v_row.action_on_read));
    RETURN jsonb_build_object('id', v_row.id, 'label', v_row.label, 'kind', v_row.kind, 'hint', v_row.hint,
        'action_on_use', v_row.action_on_use, 'action_on_read', v_row.action_on_read, 'status', v_row.status,
        'created_at', v_row.created_at, 'last_tripped_at', v_row.last_tripped_at, 'trip_count', v_row.trip_count);
END;
$$;

CREATE OR REPLACE FUNCTION public.control_honeytoken_retire(p_org uuid, p_actor uuid, p_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_row public.honeytokens%ROWTYPE;
BEGIN
    SELECT * INTO v_row FROM public.honeytokens WHERE id = p_id AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'honeytoken not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_row.status = 'retired' THEN
        RETURN jsonb_build_object('changed', false);
    END IF;
    UPDATE public.honeytokens SET status = 'retired', retired_at = now() WHERE id = p_id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'honeytoken.retired', 'organization', p_org, NULL,
            jsonb_build_object('honeytoken_id', p_id, 'label', v_row.label));
    RETURN jsonb_build_object('changed', true);
END;
$$;

-- -----------------------------------------------------------------------------
-- Honey tools: create / retire
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_honey_tool_create(
    p_org uuid, p_actor uuid, p_agent uuid, p_server text, p_name text, p_description text, p_action text
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_row public.honey_tools%ROWTYPE;
BEGIN
    PERFORM 1 FROM public.agents WHERE id = p_agent AND organization_id = p_org FOR UPDATE;  -- serialises the count
    IF NOT FOUND THEN
        RAISE EXCEPTION 'agent not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF (SELECT count(*) FROM public.honey_tools WHERE agent_id = p_agent AND status = 'active') >= 5 THEN
        RAISE EXCEPTION 'at most 5 active honey tools per agent' USING ERRCODE = 'check_violation';
    END IF;
    INSERT INTO public.honey_tools (organization_id, agent_id, server_slug, name, description, action, created_by)
    VALUES (p_org, p_agent, p_server, p_name, p_description, p_action, p_actor)
    RETURNING * INTO v_row;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'honey_tool.created', 'agent', p_agent, NULL,
            jsonb_build_object('honey_tool_id', v_row.id, 'name', v_row.name, 'server', v_row.server_slug,
                               'action', v_row.action));
    RETURN jsonb_build_object('id', v_row.id, 'agent_id', v_row.agent_id, 'server', v_row.server_slug,
        'name', v_row.name, 'description', v_row.description, 'action', v_row.action, 'status', v_row.status,
        'created_at', v_row.created_at, 'last_tripped_at', v_row.last_tripped_at, 'trip_count', v_row.trip_count);
END;
$$;

CREATE OR REPLACE FUNCTION public.control_honey_tool_retire(p_org uuid, p_actor uuid, p_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_row public.honey_tools%ROWTYPE;
BEGIN
    SELECT * INTO v_row FROM public.honey_tools WHERE id = p_id AND organization_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'honey tool not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF v_row.status = 'retired' THEN
        RETURN jsonb_build_object('changed', false);
    END IF;
    UPDATE public.honey_tools SET status = 'retired', retired_at = now() WHERE id = p_id;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'honey_tool.retired', 'agent', v_row.agent_id, NULL,
            jsonb_build_object('honey_tool_id', p_id, 'name', v_row.name));
    RETURN jsonb_build_object('changed', true);
END;
$$;

-- -----------------------------------------------------------------------------
-- record_trip(): one trip reported by the gateway. Idempotent per trip id. Tenant checks are made here, not
-- trusted from the gateway: the agent and the honeytoken (or honey tool) must belong to p_org. An unknown or
-- retired reference is not an error (the gateway may hold a context a few seconds old): it is just not recorded.
-- Returns what core needs to act: whether this is new, the label, the stored action, and whether to alert
-- (at most one alert per agent, reference and place every 5 minutes; the trip itself is always recorded).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.record_trip(
    p_org uuid, p_trip_id uuid, p_agent uuid, p_kind text, p_ref uuid, p_seen_in text, p_tool text, p_server text
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_agent_name text;
    v_label text;
    v_action text;
    v_recent boolean;
    v_inserted integer;
    c_system CONSTANT uuid := '00000000-0000-0000-0000-000000000000';
BEGIN
    IF p_org IS NULL OR p_trip_id IS NULL OR p_agent IS NULL OR p_ref IS NULL
       OR p_kind NOT IN ('honeytoken', 'honey_tool')
       OR (p_kind = 'honeytoken' AND p_seen_in NOT IN ('arguments', 'result'))
       OR (p_kind = 'honey_tool' AND p_seen_in <> 'call') THEN
        RAISE EXCEPTION 'invalid trip' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT name INTO v_agent_name FROM public.agents WHERE id = p_agent AND organization_id = p_org;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'agent not found' USING ERRCODE = 'no_data_found';
    END IF;

    IF p_kind = 'honeytoken' THEN
        SELECT label, CASE WHEN p_seen_in = 'arguments' THEN action_on_use ELSE action_on_read END
          INTO v_label, v_action
        FROM public.honeytokens WHERE id = p_ref AND organization_id = p_org AND status = 'active';
    ELSE
        SELECT name, action INTO v_label, v_action
        FROM public.honey_tools WHERE id = p_ref AND organization_id = p_org AND agent_id = p_agent AND status = 'active';
    END IF;
    IF v_label IS NULL THEN
        RETURN jsonb_build_object('recorded', false, 'reason', 'unknown_reference');
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM public.honeytrips
        WHERE ref_id = p_ref AND agent_id = p_agent AND seen_in = p_seen_in AND occurred_at > now() - interval '5 minutes'
    ) INTO v_recent;

    INSERT INTO public.honeytrips (id, organization_id, agent_id, kind, ref_id, seen_in, tool_name, server_slug)
    VALUES (p_trip_id, p_org, p_agent, p_kind, p_ref, p_seen_in, left(coalesce(p_tool, ''), 128), left(coalesce(p_server, ''), 128))
    ON CONFLICT (id) DO NOTHING;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted = 0 THEN
        RETURN jsonb_build_object('recorded', false, 'reason', 'duplicate');
    END IF;

    IF p_kind = 'honeytoken' THEN
        UPDATE public.honeytokens SET last_tripped_at = now(), trip_count = trip_count + 1 WHERE id = p_ref;
    ELSE
        UPDATE public.honey_tools SET last_tripped_at = now(), trip_count = trip_count + 1 WHERE id = p_ref;
    END IF;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, c_system,
            CASE WHEN p_kind = 'honeytoken' THEN 'honeytoken.tripped' ELSE 'honey_tool.tripped' END,
            'agent', p_agent, NULL,
            jsonb_build_object('ref_id', p_ref, 'label', v_label, 'seen_in', p_seen_in, 'tool', left(coalesce(p_tool, ''), 128),
                               'server', left(coalesce(p_server, ''), 128), 'action', v_action));
    RETURN jsonb_build_object('recorded', true, 'label', v_label, 'action', v_action,
                              'agent_name', v_agent_name, 'alert', NOT v_recent);
END;
$$;

-- Trips and retired honeytokens are kept 90 days (documented in the Phase 3 plan).
CREATE OR REPLACE FUNCTION public.purge_honey()
RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_trips bigint;
    v_tokens bigint;
    v_tools bigint;
BEGIN
    DELETE FROM public.honeytrips WHERE occurred_at < now() - interval '90 days';
    GET DIAGNOSTICS v_trips = ROW_COUNT;
    DELETE FROM public.honeytokens WHERE status = 'retired' AND retired_at < now() - interval '90 days';
    GET DIAGNOSTICS v_tokens = ROW_COUNT;
    DELETE FROM public.honey_tools WHERE status = 'retired' AND retired_at < now() - interval '90 days';
    GET DIAGNOSTICS v_tools = ROW_COUNT;
    RETURN jsonb_build_object('trips', v_trips, 'honeytokens', v_tokens, 'honey_tools', v_tools);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.control_honeytoken_create(uuid, uuid, text, text, text, text, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_honeytoken_retire(uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_honey_tool_create(uuid, uuid, uuid, text, text, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_honey_tool_retire(uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.record_trip(uuid, uuid, uuid, text, uuid, text, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.purge_honey() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.control_honeytoken_create(uuid, uuid, text, text, text, text, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_honeytoken_retire(uuid, uuid, uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_honey_tool_create(uuid, uuid, uuid, text, text, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_honey_tool_retire(uuid, uuid, uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.record_trip(uuid, uuid, uuid, text, uuid, text, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.purge_honey() TO service_role;

COMMIT;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        PERFORM cron.schedule('redhand-purge-honey', '27 19 * * *', 'SELECT public.purge_honey()');
        RAISE NOTICE 'scheduled redhand-purge-honey';
    ELSE
        RAISE NOTICE 'pg_cron is not available here: schedule purge_honey() yourself (daily)';
    END IF;
END;
$$;

NOTIFY pgrst, 'reload schema';
