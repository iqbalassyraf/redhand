"""The latency script's arithmetic: parsing the histogram, the percentile upper bounds, the budget verdict, and that it never prints a secret."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest

_SPEC = importlib.util.spec_from_file_location("latency_baseline", Path(__file__).resolve().parents[2] / "scripts" / "latency_baseline.py")
assert _SPEC and _SPEC.loader
lb = importlib.util.module_from_spec(_SPEC)
sys.modules["latency_baseline"] = lb
_SPEC.loader.exec_module(lb)

BUCKETS = (1, 2, 5, 10, 25, 50, 100, 250, 1000)


def metrics(counts: list[int], total_sum: float) -> str:
    lines = ["# HELP redhand_gateway_overhead_ms Gateway-added latency.", "# TYPE redhand_gateway_overhead_ms histogram"]
    lines += [f'redhand_gateway_overhead_ms_bucket{{le="{b}"}} {c}' for b, c in zip(BUCKETS, counts)]
    lines += [f'redhand_gateway_overhead_ms_bucket{{le="+Inf"}} {counts[-1]}', f"redhand_gateway_overhead_ms_sum {total_sum}", f"redhand_gateway_overhead_ms_count {counts[-1]}"]
    return "\n".join(lines)


def test_parse_reads_buckets_sum_and_count() -> None:
    parsed = lb.parse_overhead(metrics([0, 5, 90, 100, 100, 100, 100, 100, 100], 400.0))
    assert parsed["count"] == 100 and parsed["sum"] == 400.0 and parsed["buckets"][0] == (1.0, 0.0) and parsed["buckets"][-1][0] == float("inf")


def test_parse_refuses_text_without_the_histogram() -> None:
    with pytest.raises(ValueError):
        lb.parse_overhead("# nothing here\nredhand_gateway_requests_total 3")


def test_percentiles_are_bucket_upper_bounds_of_the_difference_between_snapshots() -> None:
    before = lb.parse_overhead(metrics([10, 20, 30, 40, 40, 40, 40, 40, 40], 100.0))
    # 200 new calls: 120 within 2 ms, 190 within 5 ms, 199 within 25 ms, all within 100 ms
    after = lb.parse_overhead(metrics([10 + 60, 20 + 120, 30 + 190, 40 + 195, 40 + 199, 40 + 199, 40 + 200, 40 + 200, 40 + 200], 100.0 + 500.0))
    summary = lb.summarise(before, after)
    assert summary["calls"] == 200 and summary["p50_upper_ms"] == 2.0 and summary["p99_upper_ms"] == 25.0 and summary["mean_ms"] == 2.5


def test_a_run_with_no_new_calls_is_an_error() -> None:
    snap = lb.parse_overhead(metrics([1, 1, 1, 1, 1, 1, 1, 1, 1], 5.0))
    with pytest.raises(ValueError):
        lb.summarise(snap, snap)


@pytest.mark.parametrize(
    ("p50", "p99", "text"),
    [(5.0, 25.0, "PASS"), (10.0, 50.0, "PASS"), (25.0, 25.0, "OVER BUDGET: p50"), (5.0, 100.0, "OVER BUDGET: p99"), (25.0, 100.0, "p50 is at most 25 ms")],
)
def test_the_verdict_follows_the_budget(p50: float, p99: float, text: str) -> None:
    assert text in lb.verdict({"p50_upper_ms": p50, "p99_upper_ms": p99})


def test_the_script_has_no_place_to_print_a_secret() -> None:
    source = (Path(lb.__file__)).read_text(encoding="utf-8")
    for name in ("token", "key"):
        for line in source.splitlines():
            if "print(" in line:
                assert f"({name}" not in line and f"{{{name}" not in line, line
    assert "getpass.getpass" in source  # hidden input when a variable is missing
