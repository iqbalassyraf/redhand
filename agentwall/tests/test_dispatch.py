"""The shared background reporter used by trips and tool observations (and, later, Radar findings)."""

from __future__ import annotations

import asyncio

import pytest

from agentwall.src.gateway.dispatch import Outcome, ReportDispatcher, outcome_for_status


class Counter:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def __call__(self, outcome: str) -> None:
        self.counts[outcome] = self.counts.get(outcome, 0) + 1


def _dispatcher(send, counter, *, delays=(), limit=lambda: 5, on_failed=None) -> ReportDispatcher[str]:  # type: ignore[no-untyped-def]
    return ReportDispatcher(name="test", send=send, count=counter, retry_delays=delays, max_in_flight=limit, on_failed=on_failed)


@pytest.mark.parametrize(
    ("status", "outcome"),
    [(200, "ok"), (201, "retry"), (400, "drop"), (401, "drop"), (403, "drop"), (404, "drop"), (422, "drop"),
     (429, "retry"), (500, "retry"), (502, "retry"), (503, "retry"), (302, "retry")],
)
def test_status_mapping(status: int, outcome: Outcome) -> None:
    assert outcome_for_status(status) == outcome


@pytest.mark.asyncio
async def test_a_successful_report_is_counted_once() -> None:
    sent: list[str] = []
    counter = Counter()

    async def send(item: str) -> Outcome:
        sent.append(item)
        return "ok"

    d = _dispatcher(send, counter)
    assert d.submit("a") is True
    await d.wait_idle()
    assert sent == ["a"] and counter.counts == {"ok": 1}


@pytest.mark.asyncio
async def test_a_refusal_is_not_retried() -> None:
    attempts = 0
    counter = Counter()

    async def send(item: str) -> Outcome:
        nonlocal attempts
        attempts += 1
        return "drop"

    d = _dispatcher(send, counter, delays=(0.0, 0.0, 0.0))
    d.submit("a")
    await d.wait_idle()
    assert attempts == 1 and counter.counts == {"refused": 1}


@pytest.mark.asyncio
async def test_retries_follow_the_delays_then_give_up_and_tell_the_caller() -> None:
    attempts = 0
    counter = Counter()
    failed: list[str] = []

    async def send(item: str) -> Outcome:
        nonlocal attempts
        attempts += 1
        return "retry"

    d = _dispatcher(send, counter, delays=(0.0, 0.0), on_failed=failed.append)
    d.submit("a")
    await d.wait_idle()
    assert attempts == 3 and counter.counts == {"failed": 1} and failed == ["a"]


@pytest.mark.asyncio
async def test_a_retry_that_then_succeeds_is_ok_and_not_failed() -> None:
    answers: list[Outcome] = ["retry", "retry", "ok"]
    counter = Counter()
    failed: list[str] = []

    async def send(item: str) -> Outcome:
        return answers.pop(0)

    d = _dispatcher(send, counter, delays=(0.0, 0.0), on_failed=failed.append)
    d.submit("a")
    await d.wait_idle()
    assert counter.counts == {"ok": 1} and failed == []


@pytest.mark.asyncio
async def test_a_reporter_that_raises_is_treated_as_retry_and_never_escapes() -> None:
    attempts = 0
    counter = Counter()

    async def send(item: str) -> Outcome:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("boom")

    d = _dispatcher(send, counter, delays=(0.0,))
    d.submit("a")
    await d.wait_idle()  # would raise if the error escaped
    assert attempts == 2 and counter.counts == {"failed": 1}


@pytest.mark.asyncio
async def test_past_the_limit_the_newest_report_is_dropped_and_counted_without_blocking() -> None:
    gate = asyncio.Event()
    counter = Counter()

    async def send(item: str) -> Outcome:
        await gate.wait()
        return "ok"

    d = _dispatcher(send, counter, limit=lambda: 2)
    assert [d.submit(x) for x in "abcd"] == [True, True, False, False]
    assert len(d.tasks) == 2 and counter.counts == {"dropped": 2}
    gate.set()
    await d.wait_idle()
    assert counter.counts == {"dropped": 2, "ok": 2}


@pytest.mark.asyncio
async def test_the_limit_is_read_at_each_submit() -> None:
    gate = asyncio.Event()
    limit = {"n": 1}
    counter = Counter()

    async def send(item: str) -> Outcome:
        await gate.wait()
        return "ok"

    d = _dispatcher(send, counter, limit=lambda: limit["n"])
    assert d.submit("a") is True and d.submit("b") is False
    limit["n"] = 2
    assert d.submit("c") is True
    gate.set()
    await d.wait_idle()


def test_submit_without_a_running_loop_drops_instead_of_raising() -> None:
    counter = Counter()

    async def send(item: str) -> Outcome:
        return "ok"

    d = _dispatcher(send, counter)
    assert d.submit("a") is False and counter.counts == {"dropped": 1}


@pytest.mark.asyncio
async def test_aclose_gives_pending_reports_time_then_cancels_the_rest() -> None:
    counter = Counter()

    async def send(item: str) -> Outcome:
        await asyncio.sleep(30)
        return "ok"

    d = _dispatcher(send, counter)
    d.submit("a")
    await d.aclose(timeout=0.05)
    await asyncio.sleep(0)
    assert all(t.cancelled() or t.done() for t in d.tasks) or not d.tasks


@pytest.mark.asyncio
async def test_aclose_with_nothing_pending_returns_at_once() -> None:
    d = _dispatcher(lambda item: asyncio.sleep(0, "ok"), Counter())  # type: ignore[arg-type,return-value]
    await d.aclose(timeout=0.01)
