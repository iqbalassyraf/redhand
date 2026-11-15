-- =============================================================================
-- Phase 4.5 B1: the Risk Engine (docs/plans/phase45-b1-risk-engine.md, ADR 0019).
-- Rollback: supabase/rollbacks/20261122000000_risk_engine.down.sql
--
-- Per agent, redhand-core turns signals RedHand already stores (honeytoken trips, findings, refusals, the budget limit) into a score, and
-- applies the organization's response ladder: alert (on by default at 50), Safe Mode and freeze (both OFF by default, opt-in). This file
-- only adds storage and three functions; the scoring itself is plain Python in core (risk/scoring.py) so it can be read and tested.
--
-- New: organizations.risk_*_threshold, agents.risk_last_alert_at / risk_released_at, a trigger that stamps a human release (unfreeze or
-- Safe Mode turned off), agent_risk_signals(), control_risk_ladder(), risk_mark_alerted(), one index. Changed: the audit action list
-- (every earlier action kept). Additive: an older core keeps working and simply never reads the new columns.
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
    'organization.risk_ladder_changed'
));

-- The ladder. NULL means the rung is off. Alert is on by default (it only notifies); Safe Mode and freeze are off (B-D4: opt-in).
ALTER TABLE public.organizations
    ADD COLUMN risk_alert_threshold INTEGER DEFAULT 50 CHECK (risk_alert_threshold BETWEEN 1 AND 100),
    ADD COLUMN risk_safe_mode_threshold INTEGER CHECK (risk_safe_mode_threshold BETWEEN 1 AND 100),
    ADD COLUMN risk_freeze_threshold INTEGER CHECK (risk_freeze_threshold BETWEEN 1 AND 100);
ALTER TABLE public.organizations ADD CONSTRAINT organizations_risk_ladder_order CHECK (
    (risk_alert_threshold IS NULL OR risk_safe_mode_threshold IS NULL OR risk_alert_threshold <= risk_safe_mode_threshold)
    AND (risk_safe_mode_threshold IS NULL OR risk_freeze_threshold IS NULL OR risk_safe_mode_threshold <= risk_freeze_threshold)
    AND (risk_alert_threshold IS NULL OR risk_freeze_threshold IS NULL OR risk_alert_threshold <= risk_freeze_threshold)
);

ALTER TABLE public.agents
    ADD COLUMN risk_last_alert_at TIMESTAMPTZ,
    ADD COLUMN risk_released_at TIMESTAMPTZ;

CREATE INDEX idx_honeytrips_agent_time ON public.honeytrips(agent_id, occurred_at DESC);

-- -----------------------------------------------------------------------------
-- A human release: an agent is unfrozen, or its Safe Mode is turned off. Only signals AFTER this moment count towards automatic actions,
-- so an agent a person has just released cannot be put back by the signals that person already looked at. Done by a trigger so that
-- every path that releases an agent (core, a future one, a manual fix) stamps it in the same transaction. No automatic path releases.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.risk_stamp_release() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF (OLD.status = 'frozen' AND NEW.status = 'active') OR (OLD.safe_mode AND NOT NEW.safe_mode) THEN
        NEW.risk_released_at := now();
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_agents_risk_release BEFORE UPDATE OF status, safe_mode ON public.agents
    FOR EACH ROW EXECUTE FUNCTION public.risk_stamp_release();

-- -----------------------------------------------------------------------------
-- agent_risk_signals(): per agent and signal, how many signals in the last 24 hours and from day 2 to day 7, and how many of those came
-- after the agent's last release. Read-only. Counts rows, never payloads. One agent, or every agent of the organization (p_agent NULL).
--   trip               honeytrips (honeytoken, canary, honey tool)
--   confirmed_finding  a finding a person marked as real (counted even under a suppression: a person said it is real)
--   destination_open / loop_open / radar_open
--                      an unreviewed finding of that kind, not low confidence, not under a live suppression for its agent and rule
--   refusal            a Black Box BLOCK outside the passport: a tool not in the scopes, or a pinned tool that is not approved (the
--                      gateway's fixed reason wording, agentwall/src/gateway/service.py; a test keeps the two in step)
--   budget_limit       the daily call limit was reached in the last 24 hours
-- A finding is dated by its last_seen_at: a finding that keeps happening after a release counts as new.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.agent_risk_signals(p_org uuid, p_agent uuid, p_now timestamptz)
RETURNS TABLE (agent_id uuid, signal text, recent_all integer, older_all integer, recent_action integer, older_action integer)
LANGUAGE sql
STABLE
SET search_path = public, pg_temp
AS $$
    WITH a AS (
        SELECT g.id, g.risk_released_at FROM public.agents g
        WHERE g.organization_id = p_org AND (p_agent IS NULL OR g.id = p_agent)
    ),
    ev AS (
        SELECT t.agent_id, 'trip'::text AS signal, t.occurred_at AS at
        FROM public.honeytrips t JOIN a ON a.id = t.agent_id
        WHERE t.organization_id = p_org AND t.occurred_at > p_now - interval '7 days' AND t.occurred_at <= p_now
        UNION ALL
        SELECT f.agent_id,
               CASE WHEN f.review_status = 'confirmed' THEN 'confirmed_finding'
                    WHEN f.kind = 'destination' THEN 'destination_open'
                    WHEN f.kind = 'loop' THEN 'loop_open'
                    ELSE 'radar_open' END,
               f.last_seen_at
        FROM public.security_findings f JOIN a ON a.id = f.agent_id
        WHERE f.organization_id = p_org AND f.last_seen_at > p_now - interval '7 days' AND f.last_seen_at <= p_now
          AND (
              f.review_status = 'confirmed'
              OR (f.review_status = 'open' AND f.confidence <> 'low' AND NOT EXISTS (
                  SELECT 1 FROM public.radar_suppressions s
                  WHERE s.agent_id = f.agent_id AND s.rule_id = f.rule_id AND s.revoked_at IS NULL AND s.expires_at > p_now))
          )
        UNION ALL
        SELECT e.agent_id, 'refusal', e.occurred_at
        FROM public.agent_events e JOIN a ON a.id = e.agent_id
        WHERE e.organization_id = p_org AND e.decision = 'BLOCK' AND e.occurred_at > p_now - interval '7 days' AND e.occurred_at <= p_now
          AND EXISTS (SELECT 1 FROM unnest(e.reasons) r
                      WHERE r LIKE '%is not in this agent''s passport scopes.' OR r LIKE '%is not approved: its current version has not been reviewed.')
        UNION ALL
        SELECT b.agent_id, 'budget_limit', b.limit_reached_at
        FROM public.agent_budget_state b JOIN a ON a.id = b.agent_id
        WHERE b.limit_reached_at > p_now - interval '24 hours' AND b.limit_reached_at <= p_now
    )
    SELECT ev.agent_id, ev.signal,
           (count(*) FILTER (WHERE ev.at > p_now - interval '24 hours'))::integer,
           (count(*) FILTER (WHERE ev.at <= p_now - interval '24 hours'))::integer,
           (count(*) FILTER (WHERE ev.at > p_now - interval '24 hours' AND (a.risk_released_at IS NULL OR ev.at > a.risk_released_at)))::integer,
           (count(*) FILTER (WHERE ev.at <= p_now - interval '24 hours' AND (a.risk_released_at IS NULL OR ev.at > a.risk_released_at)))::integer
    FROM ev JOIN a ON a.id = ev.agent_id
    GROUP BY ev.agent_id, ev.signal
$$;

-- -----------------------------------------------------------------------------
-- control_risk_ladder(): an admin changes the ladder (core checks the role and the confirmation). Audited with old and new values; no
-- change, no audit row. The CHECK constraints refuse a threshold outside 1..100 or out of order (check_violation, 409 in core).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.control_risk_ladder(
    p_org uuid, p_actor uuid, p_alert integer, p_safe_mode integer, p_freeze integer, p_reason text
) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_org public.organizations%ROWTYPE;
    v_old jsonb;
    v_new jsonb;
BEGIN
    SELECT * INTO v_org FROM public.organizations WHERE id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'organization not found' USING ERRCODE = 'no_data_found';
    END IF;
    v_old := jsonb_build_object('alert', v_org.risk_alert_threshold, 'safe_mode', v_org.risk_safe_mode_threshold, 'freeze', v_org.risk_freeze_threshold);
    v_new := jsonb_build_object('alert', p_alert, 'safe_mode', p_safe_mode, 'freeze', p_freeze);
    IF v_old = v_new THEN
        RETURN jsonb_build_object('changed', false, 'ladder', v_new);
    END IF;
    UPDATE public.organizations
       SET risk_alert_threshold = p_alert, risk_safe_mode_threshold = p_safe_mode, risk_freeze_threshold = p_freeze
     WHERE id = p_org;
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id, reason, details)
    VALUES (p_org, p_actor, 'organization.risk_ladder_changed', 'organization', p_org, p_reason,
            jsonb_build_object('old', v_old, 'new', v_new));
    RETURN jsonb_build_object('changed', true, 'ladder', v_new);
END $$;

-- -----------------------------------------------------------------------------
-- risk_mark_alerted(): true exactly once per cooldown per agent, even when two core instances evaluate the same agent at once (the
-- UPDATE ... WHERE is the compare-and-set). The caller sends the alert only when this returns true.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.risk_mark_alerted(p_org uuid, p_agent uuid, p_cooldown_seconds integer)
RETURNS boolean
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    UPDATE public.agents SET risk_last_alert_at = now()
     WHERE id = p_agent AND organization_id = p_org
       AND (risk_last_alert_at IS NULL OR risk_last_alert_at <= now() - make_interval(secs => p_cooldown_seconds));
    RETURN FOUND;
END $$;

REVOKE EXECUTE ON FUNCTION public.risk_stamp_release() FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.agent_risk_signals(uuid, uuid, timestamptz) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.control_risk_ladder(uuid, uuid, integer, integer, integer, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.risk_mark_alerted(uuid, uuid, integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.agent_risk_signals(uuid, uuid, timestamptz) TO service_role;
GRANT EXECUTE ON FUNCTION public.control_risk_ladder(uuid, uuid, integer, integer, integer, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.risk_mark_alerted(uuid, uuid, integer) TO service_role;

COMMIT;
