-- SQL tests for supabase/migrations/20261121000000_destination_allowlist.sql (Phase 4 M7).

\set ON_ERROR_STOP on
\set QUIET on

-- The SQL tests share one database, and older tests count audit rows and findings globally. This file writes both, so it runs inside a
-- transaction that is rolled back at the end and leaves nothing behind for them to count.
BEGIN;

CREATE FUNCTION pg_temp.check(p_ok boolean, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN RAISE EXCEPTION 'CHECK FAILED: %', p_msg; END IF;
    RAISE NOTICE 'ok: %', p_msg;
END $$;

CREATE FUNCTION pg_temp.expect_error(p_sql text, p_sqlstate text, p_msg text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE = p_sqlstate THEN RAISE NOTICE 'ok: % (SQLSTATE %)', p_msg, p_sqlstate; RETURN; END IF;
        RAISE EXCEPTION 'CHECK FAILED: % -- expected % but got % (%)', p_msg, p_sqlstate, SQLSTATE, SQLERRM;
    END;
    RAISE EXCEPTION 'CHECK FAILED: % -- expected SQLSTATE % but it succeeded', p_msg, p_sqlstate;
END $$;

INSERT INTO auth.users (id) VALUES ('00000000-0000-0000-0000-0000200a0001');
INSERT INTO public.organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-000020000001', 'Dest Org A', 'dest-org-a'),
    ('00000000-0000-0000-0000-000020000002', 'Dest Org B', 'dest-org-b');
INSERT INTO public.agents (id, organization_id, external_agent_id, name) VALUES
    ('00000000-0000-0000-0000-00002000000a', '00000000-0000-0000-0000-000020000001', 'dest-bot-a', 'Dest Bot A'),
    ('00000000-0000-0000-0000-00002000000c', '00000000-0000-0000-0000-000020000001', 'dest-bot-c', 'Dest Bot C'),
    ('00000000-0000-0000-0000-00002000000d', '00000000-0000-0000-0000-000020000001', 'dest-bot-d', 'Dest Bot D'),
    ('00000000-0000-0000-0000-00002000000b', '00000000-0000-0000-0000-000020000002', 'dest-bot-b', 'Dest Bot B');

CREATE FUNCTION pg_temp.dst_item(p_detail text DEFAULT 'evil.com', p_tool text DEFAULT 'send_report', p_extra jsonb DEFAULT '{}') RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'rule_id', 'RAD-DST-001', 'kind', 'destination', 'family', 'destination', 'severity', 'high', 'confidence', 'high', 'place', 'call',
        'tool_name', p_tool, 'server', 'mail', 'evasion', '[]'::jsonb, 'would_block', false, 'detail', p_detail) || p_extra
$$;

CREATE FUNCTION pg_temp.inj_item() RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'rule_id', 'RAD-INJ-001', 'kind', 'injection', 'family', 'override', 'severity', 'high', 'confidence', 'medium', 'place', 'text',
        'tool_name', 'get_ticket', 'server', 'helpdesk', 'evasion', '[]'::jsonb, 'would_block', false, 'detail', 'should-be-ignored.com')
$$;

CREATE FUNCTION pg_temp.loop_item() RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'rule_id', 'RAD-LOOP-001', 'kind', 'loop', 'family', 'loop', 'severity', 'medium', 'confidence', 'high', 'place', 'call',
        'tool_name', 'get_status', 'server', 'helpdesk', 'evasion', '[]'::jsonb, 'would_block', false)
$$;

-- ---------------------------------------------------------------------------------------------------------------------
-- The list: adding, validating, tenant checks, the cap
-- ---------------------------------------------------------------------------------------------------------------------
DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-000020000001';
    b uuid := '00000000-0000-0000-0000-000020000002';
    ag uuid := '00000000-0000-0000-0000-00002000000a';
    ac uuid := '00000000-0000-0000-0000-00002000000c';
    bg uuid := '00000000-0000-0000-0000-00002000000b';
    actor uuid := '00000000-0000-0000-0000-0000200a0001';
    r jsonb; e1 uuid; e2 uuid; i integer;
BEGIN
    PERFORM pg_temp.check((SELECT destination_mode = 'off' AND destination_mode_changed_at IS NULL FROM public.agents WHERE id = ag), 'an agent starts with the check off');
    r := public.destination_settings(a, ag);
    PERFORM pg_temp.check(r->>'destination_mode' = 'off' AND jsonb_array_length(r->'entries') = 0, 'and an empty list');

    r := public.control_destination_add(a, actor, ag, 'good.com', 'the reporting service');
    PERFORM pg_temp.check((r->>'added')::boolean, 'a host is added');
    e1 := (r->>'id')::uuid;
    r := public.control_destination_add(a, actor, ag, 'good.com', NULL);
    PERFORM pg_temp.check(NOT (r->>'added')::boolean AND (r->>'id')::uuid = e1, 'adding it again is idempotent and returns the same entry');
    PERFORM pg_temp.check((SELECT count(*) = 1 FROM public.control_audit_log WHERE organization_id = a AND action = 'passport.destination_added'), 'the repeat wrote no second audit row');
    PERFORM pg_temp.check((SELECT details->>'host' = 'good.com' AND actor_user_id = actor AND reason = 'the reporting service' FROM public.control_audit_log
                           WHERE organization_id = a AND action = 'passport.destination_added'), 'the audit row has the host, the actor and the reason');
    e2 := (public.control_destination_add(a, actor, ag, 'files.good.com', NULL)->>'id')::uuid;
    PERFORM pg_temp.check((SELECT string_agg(x->>'host', ',' ORDER BY x->>'host') = 'files.good.com,good.com' FROM jsonb_array_elements(public.destination_settings(a, ag)->'entries') x), 'the list is returned sorted');
    PERFORM pg_temp.check((public.control_destination_add(a, actor, ac, 'good.com', NULL)->>'id')::uuid <> e1, 'another agent has its own entry for the same host');

    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_add(%L, %L, %L, %L, NULL)', a, actor, ag, 'Evil.COM'), '22023', 'upper case is not a normalized host');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_add(%L, %L, %L, %L, NULL)', a, actor, ag, 'a/b'), '22023', 'a path is not a host');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_add(%L, %L, %L, %L, NULL)', a, actor, ag, 'http://x.com'), '22023', 'a scheme is not a host');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_add(%L, %L, %L, %L, NULL)', a, actor, ag, ''), '22023', 'an empty host is refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_add(%L, %L, %L, %L, NULL)', a, actor, ag, repeat('a', 254)), '22023', 'a host over 253 characters is refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_add(%L, %L, %L, %L, %L)', a, actor, ag, 'x.com', repeat('r', 301)), '22023', 'the reason is capped');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_add(%L, %L, %L, %L, NULL)', b, actor, ag, 'x.com'), 'P0002', 'organization B cannot add to A''s agent');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_add(%L, %L, %L, %L, NULL)', a, actor, gen_random_uuid(), 'x.com'), 'P0002', 'an unknown agent is refused');
    PERFORM pg_temp.check((SELECT count(*) = 2 FROM public.agent_destinations WHERE agent_id = ag), 'none of the refusals changed the list');
    PERFORM pg_temp.expect_error(format('SELECT public.destination_settings(%L, %L)', b, ag), 'P0002', 'organization B cannot read A''s list');

    -- the cap: 100 per agent
    FOR i IN 1..98 LOOP
        PERFORM public.control_destination_add(a, actor, ag, 'h' || i || '.cap.example', NULL);
    END LOOP;
    PERFORM pg_temp.check((SELECT count(*) = 100 FROM public.agent_destinations WHERE agent_id = ag), 'the list holds 100 entries');
    r := public.control_destination_add(a, actor, ag, 'one-too-many.example', NULL);
    PERFORM pg_temp.check((r->>'limit')::boolean AND NOT (r->>'added')::boolean, 'the 101st is refused');
    PERFORM pg_temp.check((public.control_destination_add(a, actor, ag, 'good.com', NULL)->>'added')::boolean = false, 'a host already on a full list is still an idempotent no-op');
    PERFORM pg_temp.check((SELECT count(*) = 100 FROM public.agent_destinations WHERE agent_id = ag), 'the cap held');
    DELETE FROM public.agent_destinations WHERE agent_id = ag AND host LIKE '%.cap.example';  -- back to good.com and files.good.com for the rest
    PERFORM pg_temp.check((SELECT count(*) = 2 FROM public.agent_destinations WHERE agent_id = ag), 'two entries again');
END $$;

-- ---------------------------------------------------------------------------------------------------------------------
-- Mode: compare and set, idempotent, audited, enforce needs a list; removal
-- ---------------------------------------------------------------------------------------------------------------------
DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-000020000001';
    b uuid := '00000000-0000-0000-0000-000020000002';
    ag uuid := '00000000-0000-0000-0000-00002000000a';
    ac uuid := '00000000-0000-0000-0000-00002000000c';
    ad uuid := '00000000-0000-0000-0000-00002000000d';
    actor uuid := '00000000-0000-0000-0000-0000200a0001';
    r jsonb; e1 uuid; e2 uuid;
BEGIN
    SELECT id INTO e1 FROM public.agent_destinations WHERE agent_id = ag AND host = 'good.com';
    SELECT id INTO e2 FROM public.agent_destinations WHERE agent_id = ag AND host = 'files.good.com';

    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_mode(%L, %L, %L, %L, %L, NULL)', a, actor, ag, 'block', 'off'), '22023', 'block is not a mode');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_mode(%L, %L, %L, NULL, %L, NULL)', a, actor, ag, 'off'), '22023', 'a mode is required');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_mode(%L, %L, %L, %L, %L, %L)', a, actor, ag, 'observe', 'off', repeat('r', 301)), '22023', 'the reason is capped');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_mode(%L, %L, %L, %L, %L, NULL)', b, actor, ag, 'observe', 'off'), 'P0002', 'organization B cannot change A''s agent');

    r := public.control_destination_mode(a, actor, ag, 'observe', 'enforce', NULL);
    PERFORM pg_temp.check((r->>'conflict')::boolean AND r->>'destination_mode' = 'off', 'a stale expectation is a conflict and reports the current mode');
    r := public.control_destination_mode(a, actor, ag, 'off', 'off', NULL);
    PERFORM pg_temp.check(NOT (r->>'conflict')::boolean AND NOT (r->>'changed')::boolean, 'repeating the current mode changes nothing');
    PERFORM pg_temp.check((SELECT count(*) = 0 FROM public.control_audit_log WHERE organization_id = a AND action = 'passport.destination_mode_changed'), 'and writes no audit row');

    -- enforce on an agent with no entries is refused
    r := public.control_destination_mode(a, actor, ad, 'enforce', 'off', NULL);
    PERFORM pg_temp.check(NOT (r->>'changed')::boolean AND (r->>'empty_list')::boolean AND r->>'destination_mode' = 'off', 'enforce with an empty list is refused and the mode stays');
    PERFORM pg_temp.check((SELECT count(*) = 0 FROM public.control_audit_log WHERE organization_id = a AND action = 'passport.destination_mode_changed'), 'and nothing is audited');
    PERFORM public.control_destination_add(a, actor, ac, 'only.good.com', NULL);
    r := public.control_destination_mode(a, actor, ac, 'enforce', 'off', 'night test');
    PERFORM pg_temp.check((r->>'changed')::boolean AND r->>'destination_mode' = 'enforce', 'enforce with one entry is accepted');

    r := public.control_destination_mode(a, actor, ag, 'observe', 'off', NULL);
    PERFORM pg_temp.check((r->>'changed')::boolean, 'observe is accepted with or without a list');
    PERFORM pg_temp.check((SELECT destination_mode = 'observe' AND destination_mode_changed_at IS NOT NULL FROM public.agents WHERE id = ag), 'the mode and the time of the change are stored');
    PERFORM pg_temp.check((SELECT count(*) = 2 FROM public.control_audit_log WHERE organization_id = a AND action = 'passport.destination_mode_changed'
        AND actor_user_id = actor AND details ? 'old_mode' AND details ? 'new_mode'), 'each change is audited once with the actor');
    PERFORM pg_temp.check((SELECT destination_mode = 'off' FROM public.agents WHERE id = '00000000-0000-0000-0000-00002000000b'), 'another organization''s agent is untouched');

    -- removal
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_remove(%L, %L, %L, %L, NULL)', a, actor, ag, gen_random_uuid()), 'P0002', 'an unknown entry is refused');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_remove(%L, %L, %L, %L, NULL)', a, actor, ac, e1), 'P0002', 'an entry of another agent cannot be removed through this one');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_remove(%L, %L, %L, %L, NULL)', b, actor, ag, e1), 'P0002', 'organization B cannot remove A''s entry');
    PERFORM pg_temp.expect_error(format('SELECT public.control_destination_remove(%L, %L, %L, %L, %L)', a, actor, ag, e2, repeat('r', 301)), '22023', 'the reason is capped');
    r := public.control_destination_remove(a, actor, ag, e2, 'no longer used');
    PERFORM pg_temp.check((r->>'removed')::boolean, 'an entry is removed in observe');
    PERFORM pg_temp.check((SELECT count(*) = 1 FROM public.control_audit_log WHERE organization_id = a AND action = 'passport.destination_removed' AND details->>'host' = 'files.good.com'), 'the removal is audited with the host');
    -- agent C is enforcing with two entries (good.com and only.good.com): one can go, the last cannot
    PERFORM pg_temp.check((SELECT count(*) = 2 FROM public.agent_destinations WHERE agent_id = ac) AND (SELECT destination_mode = 'enforce' FROM public.agents WHERE id = ac), 'agent C enforces with two entries');
    r := public.control_destination_remove(a, actor, ac, (SELECT id FROM public.agent_destinations WHERE agent_id = ac AND host = 'good.com'), NULL);
    PERFORM pg_temp.check((r->>'removed')::boolean, 'with two entries one can go while enforcing');
    r := public.control_destination_remove(a, actor, ac, (SELECT id FROM public.agent_destinations WHERE agent_id = ac), NULL);
    PERFORM pg_temp.check(NOT (r->>'removed')::boolean AND (r->>'last_entry_in_enforce')::boolean, 'the last entry cannot be removed while the agent is enforcing');
    PERFORM pg_temp.check((SELECT count(*) = 1 FROM public.agent_destinations WHERE agent_id = ac), 'and it is still there');
    PERFORM pg_temp.check((SELECT count(*) = 1 FROM public.control_audit_log WHERE organization_id = a AND action = 'passport.destination_removed' AND details->>'host' = 'good.com'), 'the refused removal wrote no audit row');
    PERFORM public.control_destination_mode(a, actor, ac, 'observe', 'enforce', NULL);
    r := public.control_destination_remove(a, actor, ac, (SELECT id FROM public.agent_destinations WHERE agent_id = ac), NULL);
    PERFORM pg_temp.check((r->>'removed')::boolean AND (SELECT count(*) = 0 FROM public.agent_destinations WHERE agent_id = ac), 'in observe the last entry can be removed');
END $$;

-- ---------------------------------------------------------------------------------------------------------------------
-- Findings: the agent's mode governs them, a coarse host is kept, cooldowns are separate, kinds stay consistent
-- ---------------------------------------------------------------------------------------------------------------------
DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-000020000001';
    b uuid := '00000000-0000-0000-0000-000020000002';
    ag uuid := '00000000-0000-0000-0000-00002000000a';
    ac uuid := '00000000-0000-0000-0000-00002000000c';
    bg uuid := '00000000-0000-0000-0000-00002000000b';
    actor uuid := '00000000-0000-0000-0000-0000200a0001';
    r jsonb;
BEGIN
    -- agent C is in observe now; agent A is in observe: switch A off to start
    PERFORM public.control_destination_mode(a, actor, ag, 'off', 'observe', NULL);
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.dst_item()));
    PERFORM pg_temp.check((r->>'disabled')::int = 1 AND (r->>'new')::int = 0, 'nothing is stored while the agent''s check is off');
    PERFORM pg_temp.check((SELECT count(*) = 0 FROM public.security_findings WHERE agent_id = ag), 'nothing at all');

    PERFORM public.control_destination_mode(a, actor, ag, 'observe', 'off', NULL);
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.dst_item('evil.com')));
    PERFORM pg_temp.check((r->>'new')::int = 1 AND (r->>'destination_new')::int = 1 AND (r->>'destination_alert')::boolean, 'in observe a finding is stored and raises the destination alert');
    PERFORM pg_temp.check(r->>'destination_tool' = 'send_report' AND r->>'destination_detail' = 'evil.com' AND r->>'destination_mode' = 'observe', 'the result names the tool, the coarse host and the mode');
    PERFORM pg_temp.check(NOT (r->>'alert')::boolean AND NOT (r->>'loop_alert')::boolean AND jsonb_array_length(r->'rules') = 0, 'the injection and loop results are not touched');
    PERFORM pg_temp.check((SELECT detail = 'evil.com' AND kind = 'destination' AND place = 'call' FROM public.security_findings WHERE agent_id = ag AND rule_id = 'RAD-DST-001'), 'the row keeps the coarse host');

    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.dst_item('other.org')));
    PERFORM pg_temp.check((r->>'new')::int = 0 AND (r->>'coalesced')::int = 1 AND NOT (r->>'destination_alert')::boolean, 'a second host in the same window coalesces and does not alert again');
    PERFORM pg_temp.check((SELECT detail = 'evil.com' AND occurrences = 2 FROM public.security_findings WHERE agent_id = ag AND rule_id = 'RAD-DST-001'), 'the first host seen is kept and the count adds up');

    -- the detail is validated: a bad one is dropped, the finding is still stored
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.dst_item('Evil.COM', 'tool_two'), pg_temp.dst_item('a/b', 'tool_three'), pg_temp.dst_item(repeat('x', 65), 'tool_four')));
    PERFORM pg_temp.check((r->>'new')::int = 3 AND (SELECT count(*) = 3 FROM public.security_findings WHERE agent_id = ag AND detail IS NULL AND tool_name IN ('tool_two', 'tool_three', 'tool_four')), 'a bad detail is stored as nothing, not as text');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.inj_item()));
    PERFORM pg_temp.check((r->>'new')::int = 1 AND (SELECT detail IS NULL FROM public.security_findings WHERE agent_id = ag AND rule_id = 'RAD-INJ-001'), 'another kind never keeps a detail');

    -- separate cooldowns: an injection alert after a destination alert, and the other way round
    PERFORM pg_temp.check((r->>'alert')::boolean, 'an injection finding alerts although a destination alert just fired');
    UPDATE public.agents SET destination_last_alert_at = NULL, radar_last_alert_at = now(), loop_last_alert_at = now() WHERE id = ag;
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.dst_item('evil.com', 'tool_five')));
    PERFORM pg_temp.check((r->>'destination_alert')::boolean, 'a destination finding alerts although an injection and a loop alert just fired');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.loop_item()));
    PERFORM pg_temp.check((r->>'loop_alert')::boolean = false AND (r->>'loop_new')::int = 1, 'the loop cooldown is its own (it was just set above)');
    UPDATE public.agents SET destination_last_alert_at = now() - interval '11 minutes' WHERE id = ag;
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.dst_item('evil.com', 'tool_six')));
    PERFORM pg_temp.check((r->>'destination_alert')::boolean, 'the destination alert returns after 10 minutes');

    -- the kind, the rule and the place must agree; the mode of the agent decides, not the organization's
    r := public.record_security_findings(a, ag, jsonb_build_array(
        pg_temp.dst_item('x.com', 'bad1', '{"kind": "loop"}'), pg_temp.dst_item('x.com', 'bad2', '{"kind": "injection"}'),
        pg_temp.dst_item('x.com', 'bad3', '{"place": "text"}'), pg_temp.dst_item('x.com', 'bad4', '{"rule_id": "RAD-LOOP-001"}'),
        pg_temp.dst_item('x.com', 'bad5', '{"rule_id": "RAD-DSX-001"}'), pg_temp.dst_item('x.com', 'bad6', '{"kind": "telepathy"}'),
        pg_temp.inj_item() || '{"place": "call"}', pg_temp.loop_item() || '{"rule_id": "RAD-DST-001"}'));
    PERFORM pg_temp.check((r->>'skipped')::int = 8 AND (r->>'new')::int = 0, 'eight inconsistent or unknown items are skipped');
    PERFORM pg_temp.check((SELECT count(*) = 0 FROM public.security_findings WHERE tool_name LIKE 'bad%'), 'none of them reached the table');

    -- another agent of the same organization is governed by its own mode (C is in observe, A could be off)
    PERFORM public.control_destination_mode(a, actor, ag, 'off', 'observe', NULL);
    r := public.record_security_findings(a, ac, jsonb_build_array(pg_temp.dst_item('evil.com', 'agent_c_tool')));
    PERFORM pg_temp.check((r->>'new')::int = 1, 'agent C (observe) stores a finding while agent A (off) does not');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.dst_item('evil.com', 'agent_a_tool')));
    PERFORM pg_temp.check((r->>'disabled')::int = 1, 'agent A is off');

    -- tenant isolation
    PERFORM pg_temp.expect_error(format('SELECT public.record_security_findings(%L, %L, ''[]'')', b, ag), 'P0002', 'an agent of another organization cannot be reported against');

    -- suppression accepts the destination rule, and the finding is then counted as suppressed
    PERFORM public.control_destination_mode(a, actor, ag, 'observe', 'off', NULL);
    r := public.control_radar_suppression_create(a, actor, ag, 'RAD-DST-001', 30, 'a reporting agent');
    PERFORM pg_temp.check((r->>'created')::boolean, 'a destination suppression can be created');
    PERFORM pg_temp.expect_error(format('SELECT public.control_radar_suppression_create(%L, %L, %L, %L, 30, %L)', a, actor, ag, 'RAD-DSX-001', 'typo'), '22023', 'a mistyped rule is refused');
    r := public.record_security_findings(a, ag, jsonb_build_array(pg_temp.dst_item('evil.com', 'suppressed_tool')));
    PERFORM pg_temp.check((r->>'suppressed')::int = 1 AND (r->>'new')::int = 0, 'a suppressed destination finding is not stored');
END $$;

-- ---------------------------------------------------------------------------------------------------------------------
-- Summaries never mix kinds
-- ---------------------------------------------------------------------------------------------------------------------
DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-000020000001';
    b uuid := '00000000-0000-0000-0000-000020000002';
    ag uuid := '00000000-0000-0000-0000-00002000000a';
    ac uuid := '00000000-0000-0000-0000-00002000000c';
    r jsonb;
BEGIN
    r := public.radar_summary(a);
    PERFORM pg_temp.check((r->'last_7_days'->>'findings')::int = 1, 'radar_summary counts only the injection finding');
    r := public.loop_settings(a);
    PERFORM pg_temp.check((r->'last_7_days'->>'findings')::int = 1, 'loop_settings counts only the loop finding');
    r := public.destination_settings(a, ag);
    PERFORM pg_temp.check((r->'last_7_days'->>'findings')::int = (SELECT count(*) FROM public.security_findings WHERE agent_id = ag AND kind = 'destination'), 'destination_settings counts this agent''s destination findings');
    r := public.destination_settings(a, ac);
    PERFORM pg_temp.check((r->'last_7_days'->>'findings')::int = 1, 'and not another agent''s');
    PERFORM pg_temp.check((public.destination_settings(b, '00000000-0000-0000-0000-00002000000b')->'last_7_days'->>'findings')::int = 0, 'another organization sees none');
END $$;

-- ---------------------------------------------------------------------------------------------------------------------
-- Constraints hold for a caller that bypasses the functions; deletion cascades; privileges
-- ---------------------------------------------------------------------------------------------------------------------
DO $$
DECLARE
    a uuid := '00000000-0000-0000-0000-000020000001';
    ag uuid := '00000000-0000-0000-0000-00002000000a';
    actor uuid := '00000000-0000-0000-0000-0000200a0001';
BEGIN
    PERFORM pg_temp.expect_error(format('INSERT INTO public.agent_destinations (organization_id, agent_id, host, created_by) VALUES (%L, %L, %L, %L)', a, ag, 'UPPER.com', actor), '23514', 'the table refuses a host that is not normalized');
    PERFORM pg_temp.expect_error(format('INSERT INTO public.agent_destinations (organization_id, agent_id, host, created_by) VALUES (%L, %L, %L, %L)', a, ag, 'good.com', actor), '23505', 'the table refuses a duplicate');
    PERFORM pg_temp.expect_error(format('INSERT INTO public.agent_destinations (organization_id, agent_id, host, created_by) VALUES (%L, %L, %L, %L)', a, gen_random_uuid(), 'x.com', actor), '23503', 'the table refuses an unknown agent');
    PERFORM pg_temp.expect_error(format('UPDATE public.agents SET destination_mode = %L WHERE id = %L', 'block', ag), '23514', 'only the three modes exist');
    PERFORM pg_temp.expect_error(format('UPDATE public.security_findings SET detail = %L WHERE agent_id = %L', 'Not Normal', ag), '23514', 'a finding''s detail must be a normalized host');
    PERFORM pg_temp.expect_error(format('UPDATE public.security_findings SET detail = %L WHERE agent_id = %L', repeat('x', 65), ag), '23514', 'and at most 64 characters');
    PERFORM pg_temp.expect_error(format('INSERT INTO public.security_findings (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, window_start) VALUES (%L, %L, %L, %L, %L, %L, %L, %L, now())', a, ag, 'RAD-DST-001', 'destination', 'telepathy', 'low', 'low', 'call'), '23514', 'an unknown kind cannot be stored');
    PERFORM pg_temp.expect_error(format('INSERT INTO public.security_findings (organization_id, agent_id, rule_id, family, kind, severity, confidence, place, window_start) VALUES (%L, %L, %L, %L, %L, %L, %L, %L, now())', a, ag, 'RAD-DST-1', 'destination', 'destination', 'low', 'low', 'call'), '23514', 'a destination rule id must have three digits');
    PERFORM pg_temp.expect_error(format('INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id) VALUES (%L, %L, %L, %L, %L)', a, actor, 'passport.destination_dance', 'agent', ag), '23514', 'an unknown audit action is refused');
    INSERT INTO public.control_audit_log (organization_id, actor_user_id, action, target_type, target_id) VALUES (a, actor, 'organization.loop_settings_changed', 'organization', a);
    PERFORM pg_temp.check(true, 'M6''s audit action is still accepted');

    -- deleting an agent takes its list and findings with it
    PERFORM pg_temp.check((SELECT count(*) > 0 FROM public.agent_destinations WHERE agent_id = ag) AND (SELECT count(*) > 0 FROM public.security_findings WHERE agent_id = ag AND kind = 'destination'), 'agent A has entries and findings before deletion');
    DELETE FROM public.agents WHERE id = ag;
    PERFORM pg_temp.check((SELECT count(*) = 0 FROM public.agent_destinations WHERE agent_id = ag) AND (SELECT count(*) = 0 FROM public.security_findings WHERE agent_id = ag), 'its list and findings go with it');
END $$;

SELECT pg_temp.check((SELECT relrowsecurity FROM pg_class WHERE relname = 'agent_destinations'), 'row level security is on for the list');
SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.control_destination_add(uuid,uuid,uuid,text,text)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.control_destination_remove(uuid,uuid,uuid,uuid,text)', 'EXECUTE')
    AND NOT has_function_privilege('authenticated', 'public.control_destination_mode(uuid,uuid,uuid,text,text,text)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.destination_settings(uuid,uuid)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.control_destination_add(uuid,uuid,uuid,text,text)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.control_destination_remove(uuid,uuid,uuid,uuid,text)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.control_destination_mode(uuid,uuid,uuid,text,text,text)', 'EXECUTE')
    AND has_function_privilege('service_role', 'public.destination_settings(uuid,uuid)', 'EXECUTE'), 'the new functions are service_role only');
SELECT pg_temp.check(NOT has_function_privilege('authenticated', 'public.record_security_findings(uuid,uuid,jsonb)', 'EXECUTE')
    AND NOT has_function_privilege('anon', 'public.control_radar_suppression_create(uuid,uuid,uuid,text,integer,text)', 'EXECUTE'), 'the replaced functions are still service_role only');

\echo ALL SQL TESTS PASSED

ROLLBACK;
