-- =============================================================================
-- Atomic control actions: each action and its control_audit_log row commit together.
-- Rollback: supabase/rollbacks/20261102000000_atomic_control_actions.down.sql
-- Plan: docs/plans/atomic-control-actions.md
--
-- redhand-core makes the decisions (state machine, confirmations, scope-expansion check)
-- and calls these functions to APPLY the result and write the audit row in a single
-- transaction. If any statement fails, including the audit insert, nothing is applied.
--
-- Security:
--   * SECURITY INVOKER with a fixed search_path; parameters only, no dynamic SQL.
--   * Callable only by service_role. Supabase exposes public functions to anon and
--     authenticated through /rpc by default, so EXECUTE is revoked from them explicitly.
--   * Every statement is scoped by p_org, so another tenant's rows behave as not found.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. One agent: freeze / unfreeze / revoke / scopes / renew / key rotation
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_agent_change(
    p_org uuid,
    p_agent uuid,
    p_actor uuid,
    p_action text,
    p_expected_status text,        -- compare-and-set guard; NULL skips the check
    p_changes jsonb,               -- subset of: status, status_reason, scopes, expires_at
    p_deactivate_keys boolean,
    p_new_key jsonb,               -- {"key_prefix": ..., "key_hash": ...} or NULL
    p_reason text,
    p_details jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_agent public.agents%ROWTYPE;
    v_column text;
BEGIN
    IF p_action NOT IN (
        'passport.frozen', 'passport.unfrozen', 'passport.revoked',
        'passport.scopes_changed', 'passport.renewed', 'passport.key_rotated'
    ) THEN
        RAISE EXCEPTION 'unsupported control action %', p_action
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    FOR v_column IN SELECT jsonb_object_keys(COALESCE(p_changes, '{}'::jsonb)) LOOP
        IF v_column NOT IN ('status', 'status_reason', 'scopes', 'expires_at') THEN
            RAISE EXCEPTION 'column % cannot be changed by a control action', v_column
                USING ERRCODE = 'invalid_parameter_value';
        END IF;
    END LOOP;

    -- The row lock serialises concurrent actions on the same agent.
    SELECT * INTO v_agent
    FROM public.agents
    WHERE id = p_agent AND organization_id = p_org
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'agent not found' USING ERRCODE = 'no_data_found';
    END IF;

    IF p_expected_status IS NOT NULL AND v_agent.status::text <> p_expected_status THEN
        RETURN jsonb_build_object('conflict', true, 'status', v_agent.status::text);
    END IF;

    -- The agents_passport_rules trigger rejects reactivating a revoked passport and bumps
    -- the version when status, scopes or expiry change.
    UPDATE public.agents SET
        status = COALESCE((p_changes ->> 'status')::public.agent_status, status),
        status_reason = CASE WHEN p_changes ? 'status_reason'
                             THEN p_changes ->> 'status_reason' ELSE status_reason END,
        scopes = CASE WHEN p_changes ? 'scopes' THEN p_changes -> 'scopes' ELSE scopes END,
        expires_at = CASE WHEN p_changes ? 'expires_at'
                          THEN (p_changes ->> 'expires_at')::timestamptz ELSE expires_at END
    WHERE id = p_agent AND organization_id = p_org
    RETURNING * INTO v_agent;

    IF p_deactivate_keys THEN
        UPDATE public.agent_keys
        SET is_active = FALSE, deactivated_at = NOW()
        WHERE agent_id = p_agent AND organization_id = p_org AND is_active;
    END IF;

    IF p_new_key IS NOT NULL THEN
        INSERT INTO public.agent_keys
            (organization_id, agent_id, key_prefix, key_hash, is_active, created_by)
        VALUES
            (p_org, p_agent, p_new_key ->> 'key_prefix', p_new_key ->> 'key_hash', TRUE, p_actor);
    END IF;

    INSERT INTO public.control_audit_log
        (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES
        (p_org, p_actor, p_action, 'agent', p_agent, p_reason, COALESCE(p_details, '{}'::jsonb));

    RETURN jsonb_build_object('conflict', false, 'agent', to_jsonb(v_agent));
END;
$$;

-- -----------------------------------------------------------------------------
-- 2. Kill switch: freeze every active agent of the tenant
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_freeze_all(
    p_org uuid,
    p_actor uuid,
    p_reason text
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_ids jsonb;
BEGIN
    WITH frozen AS (
        UPDATE public.agents
        SET status = 'frozen', status_reason = p_reason
        WHERE organization_id = p_org AND status = 'active'
        RETURNING id
    )
    SELECT COALESCE(jsonb_agg(id), '[]'::jsonb) INTO v_ids FROM frozen;

    INSERT INTO public.control_audit_log
        (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES
        (p_org, p_actor, 'organization.frozen_all', 'organization', p_org, p_reason,
         jsonb_build_object('frozen_count', jsonb_array_length(v_ids), 'frozen_agent_ids', v_ids));

    RETURN jsonb_build_object('frozen_agent_ids', v_ids);
END;
$$;

-- -----------------------------------------------------------------------------
-- 3. Register an agent: passport, first key and audit row
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_create_passport(
    p_org uuid,
    p_actor uuid,
    p_agent jsonb,
    p_key jsonb,
    p_details jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_agent public.agents%ROWTYPE;
BEGIN
    INSERT INTO public.agents
        (id, organization_id, external_agent_id, name, framework, environment, status,
         owner_id, backup_owner_id, scopes, expires_at)
    VALUES
        ((p_agent ->> 'id')::uuid, p_org, p_agent ->> 'external_agent_id', p_agent ->> 'name',
         COALESCE(p_agent ->> 'framework', 'custom'),
         (p_agent ->> 'environment')::public.agent_environment, 'active',
         (p_agent ->> 'owner_id')::uuid, NULLIF(p_agent ->> 'backup_owner_id', '')::uuid,
         COALESCE(p_agent -> 'scopes', '[]'::jsonb), (p_agent ->> 'expires_at')::timestamptz)
    RETURNING * INTO v_agent;

    INSERT INTO public.agent_keys
        (organization_id, agent_id, key_prefix, key_hash, is_active, created_by)
    VALUES
        (p_org, v_agent.id, p_key ->> 'key_prefix', p_key ->> 'key_hash', TRUE, p_actor);

    INSERT INTO public.control_audit_log
        (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES
        (p_org, p_actor, 'passport.created', 'agent', v_agent.id, NULL,
         COALESCE(p_details, '{}'::jsonb));

    RETURN to_jsonb(v_agent);
END;
$$;

-- -----------------------------------------------------------------------------
-- 4. MCP servers: register / deactivate with audit row
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_mcp_server(
    p_org uuid,
    p_actor uuid,
    p_op text,                     -- 'register' or 'deactivate'
    p_server jsonb,                -- register: {"slug", "name", "url"}
    p_server_id uuid               -- deactivate: the server id
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_server public.mcp_servers%ROWTYPE;
BEGIN
    IF p_op = 'register' THEN
        INSERT INTO public.mcp_servers (organization_id, slug, name, url, is_active, created_by)
        VALUES (p_org, p_server ->> 'slug', p_server ->> 'name', p_server ->> 'url', TRUE, p_actor)
        RETURNING * INTO v_server;

        INSERT INTO public.control_audit_log
            (organization_id, actor_user_id, action, target_type, target_id, reason, details)
        VALUES
            (p_org, p_actor, 'mcp_server.registered', 'mcp_server', v_server.id, NULL,
             jsonb_build_object('slug', v_server.slug, 'url', v_server.url));

    ELSIF p_op = 'deactivate' THEN
        UPDATE public.mcp_servers
        SET is_active = FALSE
        WHERE id = p_server_id AND organization_id = p_org
        RETURNING * INTO v_server;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'MCP server not found' USING ERRCODE = 'no_data_found';
        END IF;

        INSERT INTO public.control_audit_log
            (organization_id, actor_user_id, action, target_type, target_id, reason, details)
        VALUES
            (p_org, p_actor, 'mcp_server.deactivated', 'mcp_server', v_server.id, NULL,
             jsonb_build_object('slug', v_server.slug));
    ELSE
        RAISE EXCEPTION 'unsupported MCP server operation %', p_op
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN to_jsonb(v_server);
END;
$$;

-- -----------------------------------------------------------------------------
-- 5. Privileges: service_role only
-- -----------------------------------------------------------------------------
REVOKE ALL ON FUNCTION
    public.control_agent_change(uuid, uuid, uuid, text, text, jsonb, boolean, jsonb, text, jsonb),
    public.control_freeze_all(uuid, uuid, text),
    public.control_create_passport(uuid, uuid, jsonb, jsonb, jsonb),
    public.control_mcp_server(uuid, uuid, text, jsonb, uuid)
FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION
    public.control_agent_change(uuid, uuid, uuid, text, text, jsonb, boolean, jsonb, text, jsonb),
    public.control_freeze_all(uuid, uuid, text),
    public.control_create_passport(uuid, uuid, jsonb, jsonb, jsonb),
    public.control_mcp_server(uuid, uuid, text, jsonb, uuid)
TO service_role;

COMMIT;

-- Ask PostgREST to reload its schema cache so /rpc sees the new functions.
NOTIFY pgrst, 'reload schema';
