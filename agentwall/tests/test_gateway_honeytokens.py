"""
Honeytokens and decoy tools in the gateway (Phase 3 M3/M4): the scanner, and what the gateway does when bait is
used, read or called. Planted values here are made-up fixtures, not real credentials.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentwall.src.gateway import honeytokens as scanner
from agentwall.src.gateway.honeytokens import HoneytokenRef, scan
from agentwall.src.gateway.trips import MAX_IN_FLIGHT, Trip, TripDispatcher
from agentwall.src.gateway import service as gateway_service

from test_gateway import Harness, INVOICES_READ, tool

API_KEY = "sk_live_" + "A1b2C3d4" * 4
AWS_KEY = "AKIA" + "ZZ9QX8W7V6U5T4R3"
PASSWORD = "Zx9Qw8Er7Ty6Ui5Op4As3Df2"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _ref(value: str) -> HoneytokenRef:
    return HoneytokenRef(uuid4(), _digest(value))


def _payload(ref: HoneytokenRef) -> dict[str, str]:
    return {"id": str(ref.id), "digest": ref.digest}


# --- scanner -----------------------------------------------------------------------------------------------

def test_with_no_honeytokens_nothing_is_scanned_or_copied() -> None:
    value = {"a": API_KEY}
    result = scan(value, ())
    assert result.matched == () and result.value is value and result.truncated is False


@pytest.mark.parametrize("value", [API_KEY, AWS_KEY, PASSWORD])
def test_each_issued_format_is_found(value: str) -> None:
    ref = _ref(value)
    result = scan({"note": f"use {value} now", "list": [1, {"deep": value}]}, (ref,))
    assert result.matched == (ref.id,)
    assert value not in json.dumps(result.value) and scanner.REDACTED in json.dumps(result.value)


def test_the_bait_is_found_in_keys_and_redacted_there() -> None:
    ref = _ref(API_KEY)
    result = scan({API_KEY: "x" * 3}, (ref,))
    assert result.matched == (ref.id,) and API_KEY not in json.dumps(result.value)


def test_look_alikes_that_are_not_honeytokens_are_left_alone() -> None:
    ref = _ref(API_KEY)
    other = "sk_live_" + "Z9y8X7w6" * 4
    result = scan({"k": other, "p": PASSWORD}, (ref,))
    assert result.matched == () and result.value == {"k": other, "p": PASSWORD}


def test_a_longer_alphanumeric_run_is_not_the_password_format() -> None:
    ref = _ref(PASSWORD)
    assert scan({"v": "x" + PASSWORD}, (ref,)).matched == ()  # 25 characters: a different token
    assert scan({"v": f"pw={PASSWORD};"}, (ref,)).matched == (ref.id,)


def test_two_baits_and_a_repeat_are_reported_once_each() -> None:
    a, b = _ref(API_KEY), _ref(AWS_KEY)
    result = scan([API_KEY, AWS_KEY, API_KEY], (a, b))
    assert result.matched == (a.id, b.id)


def test_text_past_the_budget_is_not_scanned_and_says_so() -> None:
    ref = _ref(API_KEY)
    filler = "lorem ipsum " * 6000  # about 72 KB
    result = scan({"first": filler, "tail": API_KEY}, (ref,))
    assert result.truncated is True and result.matched == ()


def test_one_oversized_string_cannot_hide_bait_inside_the_scan_window() -> None:
    ref = _ref(API_KEY)
    big = f"{API_KEY} " + "lorem ipsum " * 7000  # about 84 KB, bait at the start
    result = scan({"v": big}, (ref,))
    assert result.truncated is True and result.matched == (ref.id,)
    assert API_KEY not in result.value["v"] and len(result.value["v"]) > scanner.MAX_SCAN_CHARS  # the tail is kept
    assert scan({"v": "lorem ipsum " * 7000 + API_KEY}, (ref,)).matched == ()  # past the window: a stated limit


def test_too_many_values_and_too_deep_are_truncated_not_crashed() -> None:
    ref = _ref(API_KEY)
    assert scan([str(i) for i in range(scanner.MAX_NODES + 50)], (ref,)).truncated is True
    deep: Any = API_KEY
    for _ in range(scanner.MAX_DEPTH + 5):
        deep = [deep]
    assert scan(deep, (ref,)).truncated is True


def test_scanning_never_mutates_its_input() -> None:
    ref = _ref(API_KEY)
    value = {"a": [API_KEY]}
    scan(value, (ref,))
    assert value == {"a": [API_KEY]}


# --- the gateway: bait in arguments ------------------------------------------------------------------------

def _wired(honeytokens: list[HoneytokenRef] | None = None, honey_tools: list[dict[str, str]] | None = None,
           scopes: list[dict[str, str]] | None = None, **agent: Any) -> tuple[Harness, UUID, str]:
    h = Harness()
    agent_id = h.add_agent(
        scopes if scopes is not None else INVOICES_READ,
        honeytokens=[_payload(r) for r in honeytokens or []], honey_tools=honey_tools, **agent,
    )
    return h, agent_id, h.token(agent_id)


@pytest.mark.asyncio
async def test_bait_in_arguments_refuses_the_call_before_upstream_and_reports_a_trip() -> None:
    ref = _ref(API_KEY)
    h, agent, token = _wired([ref], payload_capture=True)
    resp = await h.call(token, params=tool("list_invoices", note=f"key is {API_KEY}"))
    assert resp.body["error"]["code"] == -32000
    assert "honeytoken" not in json.dumps(resp.body).lower() and API_KEY not in json.dumps(resp.body)
    assert h.upstream.received == []  # never forwarded
    await h.trips.wait_idle()
    (trip,) = h.trip_reporter.trips
    assert (trip.kind, trip.seen_in, trip.ref_id, trip.agent_id, trip.tool_name) == ("honeytoken", "arguments", ref.id, agent, "list_invoices")
    await h.recorder.flush()
    (event,) = [e for batch in h.event_reporter.batches for e in batch]
    assert event["decision"] == "BLOCK" and event["reasons"] == ["honeytoken"]
    assert event.get("arguments_redacted") is None and API_KEY not in json.dumps(event)  # no payload for a trip


@pytest.mark.asyncio
async def test_bait_is_a_trip_even_when_the_tool_is_out_of_scope() -> None:
    ref = _ref(PASSWORD)
    h, _, token = _wired([ref])
    resp = await h.call(token, params=tool("delete_invoice", secret_note=PASSWORD))
    await h.trips.wait_idle()
    assert resp.body["error"]["code"] == -32000 and len(h.trip_reporter.trips) == 1
    assert h.upstream.received == []


@pytest.mark.asyncio
async def test_calls_without_bait_are_unaffected_and_report_nothing() -> None:
    h, _, token = _wired([_ref(API_KEY)])
    resp = await h.call(token, params=tool("list_invoices", month="2026-10"))
    await h.trips.wait_idle()
    assert "result" in resp.body and h.trip_reporter.trips == [] and len(h.upstream.received) == 1


# --- the gateway: bait in a result -------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bait_in_a_result_is_redacted_and_reported_but_the_result_still_returns() -> None:
    # The password format is used here because the egress firewall already redacts AWS-style keys on its own.
    ref = _ref(PASSWORD)
    h, _, token = _wired([ref], payload_capture=True, scopes=[{"server": "xero", "tool": "*", "access": "read"}])
    original = h.upstream.handler

    def handler(request: Any) -> Any:
        message = json.loads(request.content)
        if message.get("method") == "tools/call":
            import httpx

            return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": {
                "content": [{"type": "text", "text": f"config: note {PASSWORD} end"}]}})
        return original(request)

    h.gateway.forwarder._http = __import__("httpx").AsyncClient(transport=__import__("httpx").MockTransport(handler))
    resp = await h.call(token, params=tool("read_config"))
    assert PASSWORD not in json.dumps(resp.body) and "config: note" in json.dumps(resp.body)
    await h.trips.wait_idle()
    (trip,) = h.trip_reporter.trips
    assert (trip.seen_in, trip.ref_id) == ("result", ref.id)
    await h.recorder.flush()
    (event,) = [e for batch in h.event_reporter.batches for e in batch]
    assert event["decision"] == "ALLOW" and event["reasons"] == ["honeytoken"]
    assert event.get("result_excerpt") is None and PASSWORD not in json.dumps(event)


# --- the gateway: decoy tools ------------------------------------------------------------------------------

DECOY = {"id": str(uuid4()), "name": "export_all_customer_records", "description": "Exports every customer record"}


@pytest.mark.asyncio
async def test_a_decoy_tool_is_listed_for_its_agent_only_and_never_duplicated() -> None:
    h, _, token = _wired(honey_tools=[DECOY, {**DECOY, "id": str(uuid4()), "name": "list_invoices"}])
    names = [t["name"] for t in (await h.call(token, method="tools/list")).body["result"]["tools"]]
    assert names.count("export_all_customer_records") == 1 and names.count("list_invoices") == 1
    other = h.add_agent(INVOICES_READ)  # an agent with no decoys
    other_names = [t["name"] for t in (await h.call(h.token(other), method="tools/list")).body["result"]["tools"]]
    assert "export_all_customer_records" not in other_names


@pytest.mark.asyncio
async def test_a_call_to_a_decoy_is_never_forwarded_and_looks_like_an_ordinary_tool_error() -> None:
    h, agent, token = _wired(honey_tools=[DECOY])
    resp = await h.call(token, params=tool("export_all_customer_records", everything=True))
    assert resp.status_code == 200 and resp.body["result"]["isError"] is True
    assert "decoy" not in json.dumps(resp.body).lower() and "honey" not in json.dumps(resp.body).lower()
    assert h.upstream.received == []
    await h.trips.wait_idle()
    (trip,) = h.trip_reporter.trips
    assert (trip.kind, trip.seen_in, trip.ref_id, trip.agent_id) == ("honey_tool", "call", UUID(DECOY["id"]), agent)
    await h.recorder.flush()
    (event,) = [e for batch in h.event_reporter.batches for e in batch]
    assert event["decision"] == "BLOCK" and event["reasons"] == ["honey_tool"] and event["tool_name"] == "export_all_customer_records"


@pytest.mark.asyncio
async def test_a_decoy_trips_even_for_an_agent_scoped_to_every_tool() -> None:
    h, _, token = _wired(honey_tools=[DECOY], scopes=[{"server": "xero", "tool": "*", "access": "write"}])
    await h.call(token, params=tool("export_all_customer_records"))
    await h.trips.wait_idle()
    assert len(h.trip_reporter.trips) == 1 and h.upstream.received == []


# --- fail closed and never block enforcement ---------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_scanner_failure_on_arguments_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    h, _, token = _wired([_ref(API_KEY)])

    def broken(*_: Any) -> Any:
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(gateway_service, "scan_honeytokens", broken)
    resp = await h.call(token, params=tool("list_invoices"))
    assert resp.body["error"]["code"] == -32000 and h.upstream.received == []


@pytest.mark.asyncio
async def test_a_scanner_failure_on_a_result_withholds_the_result(monkeypatch: pytest.MonkeyPatch) -> None:
    h, _, token = _wired([_ref(API_KEY)])
    real = gateway_service.scan_honeytokens
    calls = {"n": 0}

    def flaky(value: Any, refs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 2:  # the first scan is the arguments, the second the result
            raise RuntimeError("scanner exploded")
        return real(value, refs)

    monkeypatch.setattr(gateway_service, "scan_honeytokens", flaky)
    resp = await h.call(token, params=tool("list_invoices"))
    assert resp.body["error"]["code"] == -32000 and "result" not in resp.body


@pytest.mark.asyncio
async def test_a_core_that_sends_no_bait_fields_is_denied() -> None:
    h = Harness()
    agent = h.add_agent(INVOICES_READ)
    del h.core.agents[str(agent)]["honeytokens"]
    resp = await h.call(h.token(agent), params=tool("list_invoices"))
    assert resp.status_code == 503 and h.upstream.received == []


@pytest.mark.asyncio
async def test_a_broken_trip_reporter_never_changes_the_decision() -> None:
    ref = _ref(API_KEY)
    h, _, token = _wired([ref])

    async def explode(trip: Trip) -> Any:
        raise RuntimeError("reporter exploded")

    h.trip_reporter.send = explode  # type: ignore[method-assign]
    resp = await h.call(token, params=tool("list_invoices", note=API_KEY))
    await h.trips.wait_idle()
    assert resp.body["error"]["code"] == -32000 and h.upstream.received == []


# --- the dispatcher ----------------------------------------------------------------------------------------

def _trip() -> Trip:
    return Trip(uuid4(), uuid4(), uuid4(), "honeytoken", uuid4(), "arguments", "t", "s")


@pytest.mark.asyncio
async def test_a_failed_report_is_retried_then_succeeds() -> None:
    h = Harness()
    h.trip_reporter.outcomes = ["retry", "retry", "ok"]
    dispatcher = TripDispatcher(reporter=h.trip_reporter, retry_delays=(0.0, 0.0, 0.0))
    dispatcher.report(_trip())
    await dispatcher.wait_idle()
    assert len(h.trip_reporter.trips) == 3 and len({t.trip_id for t in h.trip_reporter.trips}) == 1  # same id each time


@pytest.mark.asyncio
async def test_a_refused_report_is_not_retried() -> None:
    h = Harness()
    h.trip_reporter.outcomes = ["drop", "ok"]
    dispatcher = TripDispatcher(reporter=h.trip_reporter, retry_delays=(0.0, 0.0))
    dispatcher.report(_trip())
    await dispatcher.wait_idle()
    assert len(h.trip_reporter.trips) == 1


@pytest.mark.asyncio
async def test_retries_stop_after_the_last_attempt() -> None:
    h = Harness()
    h.trip_reporter.outcomes = ["retry"] * 10
    dispatcher = TripDispatcher(reporter=h.trip_reporter, retry_delays=(0.0, 0.0))
    dispatcher.report(_trip())
    await dispatcher.wait_idle()
    assert len(h.trip_reporter.trips) == 3


@pytest.mark.asyncio
async def test_reports_past_the_in_flight_cap_are_dropped_not_queued(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    h = Harness()
    gate = asyncio.Event()

    async def slow(trip: Trip) -> Any:
        await gate.wait()
        return "ok"

    h.trip_reporter.send = slow  # type: ignore[method-assign]
    dispatcher = TripDispatcher(reporter=h.trip_reporter, retry_delays=())
    for _ in range(MAX_IN_FLIGHT + 10):
        dispatcher.report(_trip())
    assert len(dispatcher._tasks) == MAX_IN_FLIGHT
    gate.set()
    await dispatcher.wait_idle()


# --- bait in a tool name or an argument key must not leak into events, logs or reports ------------------------

@pytest.mark.asyncio
async def test_bait_used_as_a_tool_name_is_a_trip_and_never_reaches_events_or_reports() -> None:
    ref = _ref(API_KEY)
    h, _, token = _wired([ref], scopes=[{"server": "xero", "tool": "*", "access": "write"}], payload_capture=True)
    resp = await h.call(token, params=tool(API_KEY, month="2026-10"))
    await h.trips.wait_idle()
    assert resp.body["error"]["code"] == -32000 and h.upstream.received == []
    (trip,) = h.trip_reporter.trips
    assert (trip.kind, trip.ref_id) == ("honeytoken", ref.id) and API_KEY not in trip.tool_name
    await h.recorder.flush()
    (event,) = [e for batch in h.event_reporter.batches for e in batch]
    assert event["reasons"] == ["honeytoken"] and API_KEY not in json.dumps(event)
    assert API_KEY not in json.dumps([dataclasses.asdict(t) for t in h.trip_reporter.trips], default=str)


@pytest.mark.asyncio
async def test_bait_used_as_an_argument_key_does_not_appear_in_the_recorded_event() -> None:
    ref = _ref(API_KEY)
    h, _, token = _wired([ref])
    await h.call(token, params={"name": "list_invoices", "arguments": {API_KEY: "x", "month": "2026-10"}})
    await h.recorder.flush()
    (event,) = [e for batch in h.event_reporter.batches for e in batch]
    assert event["reasons"] == ["honeytoken"] and API_KEY not in json.dumps(event)
    assert "month" in event["argument_keys"]  # the harmless key is still recorded


@pytest.mark.asyncio
async def test_bait_is_never_written_to_the_gateways_own_logs(capsys: pytest.CaptureFixture[str]) -> None:
    ref = _ref(API_KEY)
    h, _, token = _wired([ref], scopes=[{"server": "xero", "tool": "*", "access": "write"}])
    await h.call(token, params=tool(API_KEY, note=API_KEY))
    await h.trips.wait_idle()
    captured = capsys.readouterr()
    assert API_KEY not in captured.out and API_KEY not in captured.err
    ledger = json.dumps(h.decisions(1)[-1], default=str)  # the gateway's own forensic ledger
    assert API_KEY not in ledger and "[REDACTED:HONEYTOKEN]" in ledger
