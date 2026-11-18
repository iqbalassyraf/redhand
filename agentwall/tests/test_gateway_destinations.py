"""
The destination allowlist in the gateway (Phase 4 M7, docs/plans/phase4-m7-destination-allowlist.md): observe records an address outside an
agent's list and never refuses; enforce refuses it (and refuses what it could not check) before the loop check and Budget Guard, without echoing
the address; a check error denies in enforce and changes nothing in observe; an agent whose check is off, and the kill switch, skip it entirely;
and the settings from core are required, so an older core makes the call fail closed.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from agentwall.src.gateway import service as service_module
from agentwall.src.gateway.loops import LoopMeter
from agentwall.src.gateway.service import JSONRPC_POLICY_VIOLATION

from test_gateway import INVOICES_READ, Harness, tool

GOOD = ("good.com", "files.good.com")
SECRET = "secret-token-4417"


def wired(mode: str = "enforce", allowed: tuple[str, ...] = GOOD, **kwargs: Any) -> tuple[Harness, str]:
    h = Harness()
    agent = h.add_agent(INVOICES_READ, destination_mode=mode, allowed_destinations=allowed, **kwargs)
    return h, h.token(agent)


def forwarded(h: Harness) -> int:
    return sum(1 for m in h.upstream.received if m["method"] == "tools/call")


async def send(h: Harness, token: str, **args: Any) -> Any:
    return await h.call(token, params=tool("list_invoices", **args))


def refused(response: Any) -> bool:
    return "error" in (response.body or {})


def dst_reports(h: Harness) -> list[dict[str, Any]]:
    return [i for r in h.findings_reporter.reports for i in r.items if i["rule_id"] == "RAD-DST-001"]


def spy(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Records every call to the scanner. (Raising instead would be swallowed: the gateway treats a check error as an error.)"""
    ran: list[int] = []
    real = service_module.scan_arguments

    def recording(value: Any) -> Any:
        ran.append(1)
        return real(value)

    monkeypatch.setattr(service_module, "scan_arguments", recording)
    return ran


# --- observe ----------------------------------------------------------------------------------------------------------

async def test_observe_records_an_address_outside_the_list_and_never_refuses() -> None:
    h, token = wired("observe")
    assert not refused(await send(h, token, url="https://good.com/a"))
    await h.radar.wait_idle()
    assert dst_reports(h) == []  # an allowed address: nothing
    assert not refused(await send(h, token, url="https://evil.com/a"))  # forwarded
    await h.radar.wait_idle()
    assert forwarded(h) == 2
    assert dst_reports(h) == [{
        "rule_id": "RAD-DST-001", "kind": "destination", "family": "destination", "severity": "high", "confidence": "high", "place": "call",
        "evasion": [], "tool_name": "list_invoices", "server": "xero", "would_block": False, "occurrences": 1, "detail": "evil.com",
    }]
    text = h.gateway.metrics.render()
    assert 'redhand_gateway_destination_checks_total{outcome="ok"} 1' in text and 'redhand_gateway_destination_checks_total{outcome="flagged"} 1' in text


async def test_a_repeated_finding_is_reported_once_and_the_rest_are_counted() -> None:
    h, token = wired("observe")
    for _ in range(6):
        await send(h, token, url="https://evil.com/a")
    await h.radar.wait_idle()
    assert len(dst_reports(h)) == 1
    text = h.gateway.metrics.render()
    assert 'outcome="flagged"} 6' in text and 'outcome="report_throttled"} 5' in text


async def test_what_leaves_the_gateway_is_the_coarse_host_never_a_subdomain_or_a_path() -> None:
    h, token = wired("observe")
    await send(h, token, url=f"https://{SECRET}.collector.evil.com/{SECRET}?q={SECRET}", note=SECRET)
    await h.radar.wait_idle()
    assert [r["detail"] for r in dst_reports(h)] == ["evil.com"]
    assert SECRET not in json.dumps([r.items for r in h.findings_reporter.reports]) and SECRET not in h.gateway.metrics.render()


async def test_an_email_address_is_an_address_too() -> None:
    h, token = wired("observe")
    await send(h, token, to="alice@evil.org")
    await h.radar.wait_idle()
    assert [r["detail"] for r in dst_reports(h)] == ["evil.org"]


async def test_a_call_with_no_address_is_not_flagged() -> None:
    h, token = wired("observe")
    for i in range(5):
        await send(h, token, month="2026-10", page=i, query="invoices for March")
    await h.radar.wait_idle()
    assert dst_reports(h) == [] and 'outcome="ok"} 5' in h.gateway.metrics.render()


async def test_observe_with_arguments_past_the_budget_only_counts() -> None:
    h, token = wired("observe")
    assert not refused(await send(h, token, blob="x" * 70_000))
    assert 'redhand_gateway_destination_checks_total{outcome="untracked"} 1' in h.gateway.metrics.render()
    assert forwarded(h) == 1


# --- enforce ----------------------------------------------------------------------------------------------------------

async def test_enforce_allows_a_listed_address_and_refuses_any_other() -> None:
    h, token = wired("enforce")
    assert not refused(await send(h, token, url="https://good.com/a", cc="bob@files.good.com"))
    response = await send(h, token, url="https://evil.com/a")
    assert response.status_code == 200 and response.body["error"]["code"] == JSONRPC_POLICY_VIOLATION
    assert response.body["error"]["message"] == "PolicyViolation: this call contains an address that is not on this agent's allowed list."
    assert response.body["error"]["data"] == {"tool_name": "list_invoices"}
    assert forwarded(h) == 1  # the refused call never reached the tool
    await h.radar.wait_idle()
    assert [r["detail"] for r in dst_reports(h)] == ["evil.com"]  # the owner sees it as a finding too
    text = h.gateway.metrics.render()
    assert 'reason="destination_not_allowed"' in text and 'redhand_gateway_destination_checks_total{outcome="refused"} 1' in text


async def test_the_refusal_echoes_no_part_of_the_call_and_the_ledger_keeps_only_the_coarse_host() -> None:
    h, token = wired("enforce")
    response = await send(h, token, url=f"https://{SECRET}.collector.evil.com/{SECRET}")
    body = json.dumps(response.body)
    assert refused(response) and SECRET not in body and "evil" not in body
    blocks = [r for r in h.full_rows(50) if r["decision"] == "BLOCK"]
    assert len(blocks) == 1 and "evil.com" in json.dumps(blocks[0]["reasons"]) and SECRET not in json.dumps(blocks[0]["reasons"])


@pytest.mark.parametrize(
    "value",
    [
        "https://good.com@evil.com/",  # the part before @ is user info
        "https://evil.com#@good.com",
        "https://evil.com?@good.com",
        "https://good.com\\@evil.com/",  # a browser and a strict parser read this differently
        "https://good.com%40evil.com/",
        "https://a@b@good.com/",  # ambiguous
        "https://good.com.evil.com/",
        "https://evilgood.com/",
        "https://sub.good.com/",  # no wildcards in v1
        "https://good.com:8080@evil.com/",
        "https://аpple.com/",  # a Cyrillic letter
        "http://2130706433/", "http://0x7f.1/", "http://0177.0.0.1/", "http://[::1]/", "http://[::ffff:7f00:1]/",
        "http:///evil.com/x", "http:\\\\evil.com/x",
        "see https://good.com/?next=https://evil.com now",  # a second address inside the first
        "mailto:alice@evil.org", "alice@evil.org",
        "wss://sock.evil.com", "ftp://files.evil.com/a", "sftp://h.evil.com",
    ],
)
async def test_enforce_refuses_every_bypass_class(value: str) -> None:
    h, token = wired("enforce")
    assert refused(await send(h, token, text=value)), value
    assert forwarded(h) == 0


async def test_enforce_refuses_an_address_hidden_in_a_nested_value_or_a_key() -> None:
    h, token = wired("enforce")
    assert refused(await send(h, token, deep={"a": [{"b": "https://evil.com/x"}]}))
    assert refused(await send(h, token, **{"https://evil.com/key": 1}))
    assert forwarded(h) == 0


async def test_enforce_with_an_empty_list_refuses_every_address_and_allows_a_call_with_none() -> None:
    h, token = wired("enforce", allowed=())
    assert refused(await send(h, token, url="https://good.com/"))
    assert not refused(await send(h, token, month="2026-10"))


async def test_enforce_refuses_what_it_could_not_check() -> None:
    h, token = wired("enforce")
    response = await send(h, token, blob="x" * 70_000 + " https://evil.com/")
    assert refused(response) and "too large to check" in response.body["error"]["message"]
    assert 'reason="destination_untracked"' in h.gateway.metrics.render() and forwarded(h) == 0
    many = " ".join(f"https://h{i}.good.com/" for i in range(60))
    assert refused(await send(h, token, links=many))  # more distinct addresses than can be checked


async def test_a_refused_call_uses_no_budget_and_no_loop_count() -> None:
    h, token = wired("enforce", limit=3, loop_mode="throttle", loop_limit=3)
    h.gateway.loops = LoopMeter(clock=h.clock)
    for _ in range(30):
        assert refused(await send(h, token, url="https://evil.com/"))
    assert h.gateway.loops.size == 0  # the loop check never saw them
    for i in range(3):
        assert not refused(await send(h, token, month=str(i)))  # the whole daily limit is still there
    assert refused(await send(h, token, month="x"))  # now the budget's own refusal


async def test_refusals_reach_the_ledger_once_a_minute_and_are_always_counted_with_a_ledger_of_their_own() -> None:
    h, token = wired("enforce", limit=1)
    await send(h, token, month="a")
    assert refused(await send(h, token, month="b"))  # the budget's refusal: its own ledger record
    for _ in range(40):
        assert refused(await send(h, token, url="https://evil.com/"))
    blocks = [r for r in h.full_rows(200) if r["decision"] == "BLOCK"]
    assert len(blocks) == 2  # one for the budget, one for the destination: neither silenced the other
    assert 'reason="destination_not_allowed"} 40' in h.gateway.metrics.render()
    h.gateway._destination_refusal_logged[next(iter(h.gateway._destination_refusal_logged))] -= 61.0
    await send(h, token, url="https://evil.com/")
    assert len([r for r in h.full_rows(200) if r["decision"] == "BLOCK"]) == 3


async def test_calls_refused_earlier_are_not_checked() -> None:
    h, token = wired("enforce")
    for _ in range(5):
        response = await h.call(token, params=tool("delete_invoice", url="https://evil.com/"))
        assert "out of scope" in response.body["error"]["message"]
    await h.radar.wait_idle()
    assert dst_reports(h) == [] and 'destination_checks_total{outcome="refused"}' not in h.gateway.metrics.render()


async def test_other_methods_are_not_checked() -> None:
    h, token = wired("enforce")
    assert not refused(await h.call(token, method="tools/list"))
    assert not refused(await h.call(token, method="ping"))


# --- who skips the check ----------------------------------------------------------------------------------------------

async def test_an_agent_with_the_check_off_is_never_scanned(monkeypatch: pytest.MonkeyPatch) -> None:
    h, token = wired("off")
    ran = spy(monkeypatch)
    for _ in range(10):
        assert not refused(await send(h, token, url="https://evil.com/"))
    assert ran == []


async def test_the_kill_switch_skips_the_check_whatever_core_says(monkeypatch: pytest.MonkeyPatch) -> None:
    h, token = wired("enforce")
    h.gateway.destination_check_enabled = False
    ran = spy(monkeypatch)
    for _ in range(10):
        assert not refused(await send(h, token, url="https://evil.com/"))
    assert ran == [] and forwarded(h) == 10


async def test_each_agent_has_its_own_mode_and_list() -> None:
    h, token = wired("enforce")
    other = h.add_agent(INVOICES_READ, destination_mode="off")
    third = h.add_agent(INVOICES_READ, destination_mode="enforce", allowed_destinations=("evil.com",))
    assert refused(await send(h, token, url="https://evil.com/"))
    assert not refused(await send(h, h.token(other), url="https://evil.com/"))
    assert not refused(await send(h, h.token(third), url="https://evil.com/"))


# --- failure ----------------------------------------------------------------------------------------------------------

def _broken(*_: Any, **__: Any) -> Any:
    raise RuntimeError("scanner failure")


async def test_a_check_error_denies_in_enforce_and_the_call_is_not_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    h, token = wired("enforce")
    monkeypatch.setattr(service_module, "scan_arguments", _broken)
    response = await send(h, token, url="https://good.com/")
    assert response.body["error"]["code"] == JSONRPC_POLICY_VIOLATION and "could not be checked" in response.body["error"]["message"]
    assert forwarded(h) == 0
    text = h.gateway.metrics.render()
    assert 'redhand_gateway_destination_checks_total{outcome="error"} 1' in text and 'reason="destination_check_error"' in text


async def test_a_check_error_changes_nothing_in_observe(monkeypatch: pytest.MonkeyPatch) -> None:
    h, token = wired("observe")
    monkeypatch.setattr(service_module, "scan_arguments", _broken)
    for _ in range(3):
        assert not refused(await send(h, token, url="https://evil.com/"))
    assert forwarded(h) == 3 and 'redhand_gateway_destination_checks_total{outcome="error"} 3' in h.gateway.metrics.render()


async def test_a_failure_to_queue_the_finding_never_affects_the_call(monkeypatch: pytest.MonkeyPatch) -> None:
    h, token = wired("enforce")
    monkeypatch.setattr(h.radar._dispatcher, "submit", _broken)
    assert refused(await send(h, token, url="https://evil.com/"))  # still refused, and no exception reaches the caller
    observe, observe_token = wired("observe")
    monkeypatch.setattr(observe.radar._dispatcher, "submit", _broken)
    assert not refused(await send(observe, observe_token, url="https://evil.com/"))


async def test_the_check_stage_is_timed() -> None:
    h, token = wired("observe")
    await send(h, token, url="https://good.com/")
    assert 'stage="destination_check"' in h.gateway.metrics.render()


# --- the settings from core are required and strict -------------------------------------------------------------------

@pytest.mark.parametrize("missing", ["destination_mode", "allowed_destinations"])
async def test_a_context_without_the_destination_settings_denies(missing: str) -> None:
    h, token = wired("observe")
    del h.core.agents[next(iter(h.core.agents))][missing]  # an older core
    response = await send(h, token, url="https://good.com/")
    assert response.status_code == 503 and forwarded(h) == 0


@pytest.mark.parametrize(
    "bad",
    [
        {"destination_mode": "block"}, {"destination_mode": None}, {"destination_mode": True}, {"destination_mode": "ENFORCE"},
        {"allowed_destinations": "good.com"}, {"allowed_destinations": None}, {"allowed_destinations": [1]},
        {"allowed_destinations": ["GOOD.com"]}, {"allowed_destinations": ["good.com/path"]}, {"allowed_destinations": ["a b"]},
        {"allowed_destinations": [""]}, {"allowed_destinations": ["x" * 254]}, {"allowed_destinations": [f"h{i}.com" for i in range(101)]},
    ],
    ids=["block", "null mode", "bool mode", "upper mode", "string list", "null list", "int entry", "upper entry", "path entry", "space entry",
         "empty entry", "long entry", "101 entries"],
)
async def test_a_malformed_destination_setting_denies(bad: dict[str, Any]) -> None:
    h, token = wired("observe")
    h.core.agents[next(iter(h.core.agents))].update(bad)
    response = await send(h, token, url="https://good.com/")
    assert response.status_code == 503 and forwarded(h) == 0


async def test_a_change_in_core_reaches_the_gateway_within_the_cache_lifetime() -> None:
    h, token = wired("observe")
    assert not refused(await send(h, token, url="https://evil.com/"))
    agent = next(iter(h.core.agents))
    h.core.agents[agent]["destination_mode"] = "enforce"  # an admin turns enforcement on
    h.clock.now += 3.0  # the cached passport expires (2 s)
    assert refused(await send(h, token, url="https://evil.com/"))
    h.core.agents[agent]["allowed_destinations"] = ["evil.com"]
    h.clock.now += 3.0
    assert not refused(await send(h, token, url="https://evil.com/"))
