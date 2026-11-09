-- Rollback for 20261119000000_canary_kind.sql: DELETES every canary and the trips recorded for it (they cannot exist under the old
-- kind check), restores the old kind check, and restores record_trip() as it was in 20261115000000_honeytokens.sql.
-- control_audit_log is append-only, so the audit rows for canaries (honeytoken.created, honeytoken.tripped) stay.

BEGIN;

DELETE FROM public.honeytrips WHERE kind = 'honeytoken' AND ref_id IN (SELECT id FROM public.honeytokens WHERE kind = 'canary');
DELETE FROM public.honeytokens WHERE kind = 'canary';

ALTER TABLE public.honeytokens DROP CONSTRAINT honeytokens_kind_check;
ALTER TABLE public.honeytokens ADD CONSTRAINT honeytokens_kind_check CHECK (kind IN ('api_key', 'aws_key', 'password'));

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

COMMIT;

NOTIFY pgrst, 'reload schema';
