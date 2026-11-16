"""
The local twin of the model-spend roll-up (Phase 4.5 B4a): it must behave like supabase/migrations/20261125000000_model_spend.sql, which the
SQL suite (supabase/tests/model_spend_test.sql) proves. Core's own tests run against this twin, so a difference here would hide a bug there.
"""

from __future__ import annotations

import asyncio
from datetime import date, datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest
from postgrest.exceptions import APIError

from redhand_core.services.local_store import DEFAULT_ORG_ID, LocalSupabaseAdapter

OTHER_ORG = str(uuid4())
ACTOR = str(uuid4())
NOW = datetime.now(timezone.utc)


def make_store() -> tuple[LocalSupabaseAdapter, str, str]:
    store = LocalSupabaseAdapter()
    store.tables["organizations"].append({"id": OTHER_ORG, "name": "Other", "slug": "other", "utc_offset_minutes": 0})
    a, b = str(uuid4()), str(uuid4())
    store.tables["agents"].extend([
        {"id": a, "organization_id": DEFAULT_ORG_ID, "external_agent_id": "a", "name": "A", "status": "active"},
        {"id": b, "organization_id": OTHER_ORG, "external_agent_id": "b", "name": "B", "status": "active"},
    ])
    return store, a, b


def span(org: str, agent: str, tag: str, at: datetime, provider: str | None, model: str | None, prompt: int, completion: int) -> dict[str, Any]:
    return {"organization_id": org, "agent_id": agent, "session_id": str(uuid4()), "trace_id": f"trace-{tag}", "span_id": f"span-{tag}",
            "step_type": "observation", "model_provider": provider, "model_name": model, "prompt_tokens": prompt, "completion_tokens": completion,
            "occurred_at": at.isoformat()}


def ingest(store: LocalSupabaseAdapter, rows: list[dict[str, Any]]) -> None:
    asyncio.run(store.table("execution_traces").upsert(rows, on_conflict="organization_id,trace_id,span_id").execute())


def usage(store: LocalSupabaseAdapter, org: str, agent: str | None, since: date, until: date) -> list[dict[str, Any]]:
    result = asyncio.run(store.rpc("agent_model_usage", {"p_org": org, "p_agent": agent, "p_since": since.isoformat(), "p_until": until.isoformat()}).execute())
    return list(result.data)


def totals(rows: list[dict[str, Any]]) -> tuple[int, int, int]:
    return sum(r["calls"] for r in rows), sum(r["prompt_tokens"] for r in rows), sum(r["completion_tokens"] for r in rows)


def window() -> tuple[date, date]:
    return NOW.date() - timedelta(days=40), NOW.date() + timedelta(days=2)


def test_spans_with_a_model_and_tokens_are_rolled_up_by_agent_day_provider_and_model() -> None:
    store, a, _ = make_store()
    ingest(store, [
        span(DEFAULT_ORG_ID, a, "1", NOW, "anthropic", "claude-sonnet-5-5", 1000, 200),
        span(DEFAULT_ORG_ID, a, "2", NOW, "Anthropic", "Claude-Sonnet-5-5", 500, 50),
        span(DEFAULT_ORG_ID, a, "3", NOW, "anthropic", "claude-haiku-5-5", 70, 7),
    ])
    rows = usage(store, DEFAULT_ORG_ID, a, *window())
    assert sorted((r["model"], r["calls"], r["prompt_tokens"]) for r in rows) == [("claude-haiku-5-5", 1, 70), ("claude-sonnet-5-5", 2, 1500)]


def test_what_is_not_model_use_is_not_counted() -> None:
    store, a, _ = make_store()
    ingest(store, [
        span(DEFAULT_ORG_ID, a, "1", NOW, None, None, 100, 10),
        span(DEFAULT_ORG_ID, a, "2", NOW, "anthropic", "", 100, 10),
        span(DEFAULT_ORG_ID, a, "3", NOW, "anthropic", "m", 0, 0),
        span(DEFAULT_ORG_ID, a, "4", NOW, "anthropic", "m", -5, -5),
    ])
    assert usage(store, DEFAULT_ORG_ID, a, *window()) == []


def test_output_tokens_alone_count_and_an_impossible_count_is_not_believed() -> None:
    store, a, _ = make_store()
    ingest(store, [span(DEFAULT_ORG_ID, a, "1", NOW, "openai", "x", 0, 40), span(DEFAULT_ORG_ID, a, "2", NOW, "openai", "y", 1_500_000_000, 9)])
    by_model = {r["model"]: (r["calls"], r["prompt_tokens"], r["completion_tokens"]) for r in usage(store, DEFAULT_ORG_ID, a, *window())}
    assert by_model == {"x": (1, 0, 40), "y": (1, 0, 9)}


def test_the_day_follows_the_organizations_offset() -> None:
    store, a, b = make_store()
    base = datetime.combine(NOW.date() - timedelta(days=3), datetime.min.time(), tzinfo=timezone.utc)
    ingest(store, [
        span(DEFAULT_ORG_ID, a, "1", base + timedelta(hours=17), "anthropic", "d", 100, 10),  # UTC+8: next day
        span(DEFAULT_ORG_ID, a, "2", base + timedelta(hours=15, minutes=59, seconds=59), "anthropic", "d", 1, 1),
        span(OTHER_ORG, b, "3", base + timedelta(hours=17), "anthropic", "d", 100, 10),  # UTC: same day
    ])
    day = base.date()
    assert {r["day"]: r["prompt_tokens"] for r in usage(store, DEFAULT_ORG_ID, a, *window())} == {(day + timedelta(days=1)).isoformat(): 100, day.isoformat(): 1}
    assert [r["day"] for r in usage(store, OTHER_ORG, b, *window())] == [day.isoformat()]


def test_a_span_cannot_write_an_arbitrary_day() -> None:
    store, a, _ = make_store()
    ingest(store, [
        span(DEFAULT_ORG_ID, a, "1", NOW - timedelta(days=36), "anthropic", "too-old", 100, 10),
        span(DEFAULT_ORG_ID, a, "2", NOW - timedelta(days=34), "anthropic", "old-ok", 100, 10),
        span(DEFAULT_ORG_ID, a, "3", NOW + timedelta(days=30), "anthropic", "future", 100, 10),
    ])
    rows = {r["model"]: r for r in usage(store, DEFAULT_ORG_ID, a, *window())}
    assert set(rows) == {"old-ok", "future"}
    assert date.fromisoformat(rows["future"]["day"]) <= NOW.date() + timedelta(days=1)


def test_a_span_sent_again_is_not_counted_again() -> None:
    store, a, _ = make_store()
    row = span(DEFAULT_ORG_ID, a, "1", NOW, "anthropic", "m", 100, 10)
    ingest(store, [row])
    ingest(store, [row])
    assert totals(usage(store, DEFAULT_ORG_ID, a, *window())) == (1, 100, 10)


def test_one_agent_and_day_keep_at_most_fifty_models_and_no_call_is_lost() -> None:
    store, a, _ = make_store()
    ingest(store, [span(DEFAULT_ORG_ID, a, str(n), NOW, "x", f"model-{n:03d}", 1, 1) for n in range(80)])
    rows = usage(store, DEFAULT_ORG_ID, a, *window())
    assert len(rows) <= 51 and totals(rows)[0] == 80
    assert any(r["model"] == "(other)" and r["provider"] == "" for r in rows)


def test_an_organization_never_reads_anothers_usage() -> None:
    store, a, b = make_store()
    ingest(store, [span(DEFAULT_ORG_ID, a, "1", NOW, "anthropic", "m", 1, 1), span(OTHER_ORG, b, "2", NOW, "anthropic", "m", 2, 2)])
    assert usage(store, DEFAULT_ORG_ID, b, *window()) == []
    assert {r["agent_id"] for r in usage(store, DEFAULT_ORG_ID, None, *window())} == {a}


def test_the_days_range_is_inclusive_and_sums_are_capped() -> None:
    store, a, _ = make_store()
    ingest(store, [span(DEFAULT_ORG_ID, a, "1", NOW, "anthropic", "m", 5, 5)])
    day = usage(store, DEFAULT_ORG_ID, a, *window())[0]["day"]
    assert len(usage(store, DEFAULT_ORG_ID, a, date.fromisoformat(day), date.fromisoformat(day))) == 1
    store.tables["agent_model_daily"].append({"organization_id": DEFAULT_ORG_ID, "agent_id": a, "day": "2020-01-01", "provider": "x", "model": "huge",
                                              "calls": 1, "prompt_tokens": 9 * 10**18, "completion_tokens": 9 * 10**18})
    assert usage(store, DEFAULT_ORG_ID, a, date(2020, 1, 1), date(2020, 1, 1))[0]["prompt_tokens"] == 10**15


# --- the dollar limit ----------------------------------------------------------------------------------------------------------------

def set_limit(store: LocalSupabaseAdapter, org: str, agent: str, limit: int | None, expected: int | None) -> dict[str, Any]:
    params = {"p_org": org, "p_agent": agent, "p_actor": ACTOR, "p_limit": limit, "p_reason": "test", "p_expected_limit": expected}
    return dict(asyncio.run(store.rpc("control_agent_spend_limit", params).execute()).data)


def test_a_limit_is_set_audited_and_idempotent() -> None:
    store, a, _ = make_store()
    assert set_limit(store, DEFAULT_ORG_ID, a, 5_000_000, None)["changed"] is True
    assert set_limit(store, DEFAULT_ORG_ID, a, 5_000_000, 5_000_000)["changed"] is False
    audits = [r for r in store.tables["control_audit_log"] if r["action"] == "passport.spend_limit_changed"]
    assert len(audits) == 1 and audits[0]["details"] == {"old_limit": None, "new_limit": 5_000_000}


def test_a_caller_that_decided_on_an_old_limit_gets_a_conflict_and_nothing_changes() -> None:
    store, a, _ = make_store()
    set_limit(store, DEFAULT_ORG_ID, a, 5_000_000, None)
    assert set_limit(store, DEFAULT_ORG_ID, a, 9_000_000, 1) == {"conflict": True}
    assert next(r for r in store.tables["agents"] if r["id"] == a)["spend_limit_micro_usd"] == 5_000_000


@pytest.mark.parametrize("bad", [0, -1, 1_000_000_000_001, True, 1.5])
def test_an_out_of_range_limit_is_refused(bad: Any) -> None:
    store, a, _ = make_store()
    with pytest.raises(APIError):
        set_limit(store, DEFAULT_ORG_ID, a, bad, None)


def test_another_organization_cannot_change_an_agents_limit() -> None:
    store, a, _ = make_store()
    with pytest.raises(APIError):
        set_limit(store, OTHER_ORG, a, 1_000_000, None)


def test_a_limit_can_be_removed_and_a_new_agent_has_none() -> None:
    store, a, _ = make_store()
    assert next(r for r in store.tables["agents"] if r["id"] == a).get("spend_limit_micro_usd") is None
    set_limit(store, DEFAULT_ORG_ID, a, 5_000_000, None)
    assert set_limit(store, DEFAULT_ORG_ID, a, None, 5_000_000)["changed"] is True


def mark(store: LocalSupabaseAdapter, org: str, agent: str, day: str) -> bool:
    return bool(asyncio.run(store.rpc("spend_mark_alerted", {"p_org": org, "p_agent": agent, "p_day": day}).execute()).data)


def test_one_alert_per_agent_per_day_and_never_an_earlier_day_after_a_later_one() -> None:
    store, a, _ = make_store()
    assert mark(store, DEFAULT_ORG_ID, a, "2026-11-16") is True
    assert mark(store, DEFAULT_ORG_ID, a, "2026-11-16") is False
    assert mark(store, DEFAULT_ORG_ID, a, "2026-11-15") is False
    assert mark(store, DEFAULT_ORG_ID, a, "2026-11-17") is True
    assert mark(store, OTHER_ORG, a, "2026-11-30") is False


def test_a_changed_limit_clears_the_days_alert() -> None:
    store, a, _ = make_store()
    set_limit(store, DEFAULT_ORG_ID, a, 5_000_000, None)
    mark(store, DEFAULT_ORG_ID, a, "2026-11-16")
    set_limit(store, DEFAULT_ORG_ID, a, 2_000_000, 5_000_000)
    assert next(r for r in store.tables["agents"] if r["id"] == a)["spend_alerted_day"] is None


def test_the_roll_up_also_runs_for_a_plain_insert_statement() -> None:
    store, a, _ = make_store()
    asyncio.run(store.table("execution_traces").insert([span(DEFAULT_ORG_ID, a, "1", NOW, "anthropic", "m", 7, 3)]).execute())
    assert totals(usage(store, DEFAULT_ORG_ID, a, *window())) == (1, 7, 3)
