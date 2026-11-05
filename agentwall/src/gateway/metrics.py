"""Minimal in-process Prometheus metrics for gateway decisions (no extra dependency)."""

from __future__ import annotations

from collections import Counter
import threading

LATENCY_BUCKETS_MS = (1, 2, 5, 10, 25, 50, 100, 250, 1000)


class GatewayMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._decisions: Counter[tuple[str, str, str]] = Counter()
        self._latency_buckets: Counter[float] = Counter()
        self._latency_count = 0
        self._latency_sum_ms = 0.0
        self._budget_flushes: Counter[str] = Counter()
        self._budget_unreported = 0
        self._event_flushes: Counter[str] = Counter()
        self._events_buffered = 0
        self._events_dropped_total = 0
        self._events_rejected_total = 0

    def record_budget_flush(self, outcome: str, unreported_keys: int) -> None:
        with self._lock:
            self._budget_flushes[outcome] += 1
            self._budget_unreported = unreported_keys

    def record_event_flush(self, outcome: str, buffered: int) -> None:
        with self._lock:
            self._event_flushes[outcome] += 1
            self._events_buffered = buffered

    def record_event_dropped(self, count: int = 1) -> None:
        with self._lock:
            self._events_dropped_total += count

    def record_events_rejected(self, count: int) -> None:
        with self._lock:
            self._events_rejected_total += count

    def record(self, *, method: str, outcome: str, reason: str, overhead_ms: float) -> None:
        with self._lock:
            self._decisions[(method, outcome, reason)] += 1
            self._latency_count += 1
            self._latency_sum_ms += overhead_ms
            for bucket in LATENCY_BUCKETS_MS:
                if overhead_ms <= bucket:
                    self._latency_buckets[bucket] += 1

    def render(self) -> str:
        with self._lock:
            lines = [
                "# HELP redhand_gateway_decisions_total Gateway decisions by method, outcome and reason.",
                "# TYPE redhand_gateway_decisions_total counter",
            ]
            for (method, outcome, reason), count in sorted(self._decisions.items()):
                lines.append(
                    f'redhand_gateway_decisions_total{{method="{method}",outcome="{outcome}",reason="{reason}"}} {count}'
                )
            lines += [
                "# HELP redhand_gateway_budget_reports_total Reports of call counts to core, by outcome.",
                "# TYPE redhand_gateway_budget_reports_total counter",
            ]
            for outcome, count in sorted(self._budget_flushes.items()):
                lines.append(f'redhand_gateway_budget_reports_total{{outcome="{outcome}"}} {count}')
            lines += [
                "# HELP redhand_gateway_budget_unreported_keys Agent/day counters with calls core has not acknowledged.",
                "# TYPE redhand_gateway_budget_unreported_keys gauge",
                f"redhand_gateway_budget_unreported_keys {self._budget_unreported}",
            ]
            lines += [
                "# HELP redhand_gateway_event_reports_total Black Box event batch reports to core, by outcome.",
                "# TYPE redhand_gateway_event_reports_total counter",
            ]
            for outcome, count in sorted(self._event_flushes.items()):
                lines.append(f'redhand_gateway_event_reports_total{{outcome="{outcome}"}} {count}')
            lines += [
                "# HELP redhand_gateway_events_buffered Events recorded but not yet acknowledged by core.",
                "# TYPE redhand_gateway_events_buffered gauge",
                f"redhand_gateway_events_buffered {self._events_buffered}",
                "# HELP redhand_gateway_events_dropped_total Events dropped because the recorder buffer was full.",
                "# TYPE redhand_gateway_events_dropped_total counter",
                f"redhand_gateway_events_dropped_total {self._events_dropped_total}",
                "# HELP redhand_gateway_events_rejected_total Events core acknowledged but refused to store.",
                "# TYPE redhand_gateway_events_rejected_total counter",
                f"redhand_gateway_events_rejected_total {self._events_rejected_total}",
            ]
            lines += [
                "# HELP redhand_gateway_overhead_ms Gateway-added latency, excluding upstream time.",
                "# TYPE redhand_gateway_overhead_ms histogram",
            ]
            for bucket in LATENCY_BUCKETS_MS:
                lines.append(f'redhand_gateway_overhead_ms_bucket{{le="{bucket}"}} {self._latency_buckets[bucket]}')
            lines.append(f'redhand_gateway_overhead_ms_bucket{{le="+Inf"}} {self._latency_count}')
            lines.append(f"redhand_gateway_overhead_ms_sum {self._latency_sum_ms:.3f}")
            lines.append(f"redhand_gateway_overhead_ms_count {self._latency_count}")
            return "\n".join(lines) + "\n"
