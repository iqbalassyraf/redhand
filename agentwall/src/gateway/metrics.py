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
        self._payload_captures: Counter[str] = Counter()
        self._trips: Counter[tuple[str, str]] = Counter()
        self._trip_reports: Counter[str] = Counter()
        self._honeytoken_scans_truncated = 0
        self._pin_reports: Counter[str] = Counter()
        self._pin_events: Counter[str] = Counter()
        self._loops: Counter[str] = Counter()
        self._destination_checks: Counter[str] = Counter()
        self._stage_buckets: dict[str, Counter[float]] = {}
        self._stage_sum: dict[str, float] = {}
        self._stage_count: Counter[str] = Counter()
        self._radar_scans: Counter[str] = Counter()
        self._radar_findings: Counter[str] = Counter()
        self._radar_reports: Counter[str] = Counter()
        self._radar_count_reports: Counter[str] = Counter()
        self._radar_ms_sum = 0.0
        self._radar_ms_count = 0

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

    def record_payload_capture(self, outcome: str) -> None:
        with self._lock:
            self._payload_captures[outcome] += 1

    def record_trip(self, kind: str, seen_in: str) -> None:
        with self._lock:
            self._trips[(kind, seen_in)] += 1

    def record_trip_report(self, outcome: str) -> None:
        with self._lock:
            self._trip_reports[outcome] += 1

    def record_pin_report(self, outcome: str) -> None:
        with self._lock:
            self._pin_reports[outcome] += 1

    def record_stage(self, stage: str, ms: float) -> None:
        """Time spent in one named step of a call (same buckets as the overhead histogram). Stage names are fixed in code."""
        with self._lock:
            buckets = self._stage_buckets.setdefault(stage, Counter())
            self._stage_count[stage] += 1
            self._stage_sum[stage] = self._stage_sum.get(stage, 0.0) + ms
            for bucket in LATENCY_BUCKETS_MS:
                if ms <= bucket:
                    buckets[bucket] += 1

    def record_radar_scan(self, outcome: str) -> None:
        with self._lock:
            self._radar_scans[outcome] += 1

    def record_radar_finding(self, kind: str) -> None:
        with self._lock:
            self._radar_findings[kind] += 1

    def record_radar_report(self, outcome: str) -> None:
        with self._lock:
            self._radar_reports[outcome] += 1

    def record_radar_counts_report(self, outcome: str) -> None:
        with self._lock:
            self._radar_count_reports[outcome] += 1

    def record_radar_duration(self, ms: float) -> None:
        with self._lock:
            self._radar_ms_sum += ms
            self._radar_ms_count += 1

    def record_pin_event(self, event: str, count: int = 1) -> None:
        with self._lock:
            self._pin_events[event] += count

    def record_loop(self, outcome: str, count: int = 1) -> None:
        """Loop detection outcomes (ok, flagged, throttled, untracked, error, evicted, report_throttled). Fixed names, no agent or tool."""
        with self._lock:
            self._loops[outcome] += count

    def record_destination(self, outcome: str, count: int = 1) -> None:
        """Destination checks by outcome (ok, flagged, refused, untracked, error, report_throttled). Fixed names, no agent, tool or host."""
        with self._lock:
            self._destination_checks[outcome] += count

    def record_honeytoken_scan_truncated(self) -> None:
        with self._lock:
            self._honeytoken_scans_truncated += 1

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
                "# HELP redhand_gateway_payload_captures_total Black Box payload excerpts built, by outcome.",
                "# TYPE redhand_gateway_payload_captures_total counter",
            ]
            for outcome, count in sorted(self._payload_captures.items()):
                lines.append(f'redhand_gateway_payload_captures_total{{outcome="{outcome}"}} {count}')
            lines += [
                "# HELP redhand_gateway_trips_total Honeytoken and decoy tool trips, by kind and where seen.",
                "# TYPE redhand_gateway_trips_total counter",
            ]
            for (kind, seen_in), count in sorted(self._trips.items()):
                lines.append(f'redhand_gateway_trips_total{{kind="{kind}",seen_in="{seen_in}"}} {count}')
            lines += [
                "# HELP redhand_gateway_trip_reports_total Trip reports to core, by outcome (ok, refused, failed, dropped).",
                "# TYPE redhand_gateway_trip_reports_total counter",
            ]
            for outcome, count in sorted(self._trip_reports.items()):
                lines.append(f'redhand_gateway_trip_reports_total{{outcome="{outcome}"}} {count}')
            lines += [
                "# HELP redhand_gateway_pin_reports_total Tool version reports to core, by outcome (ok, refused, failed, dropped).",
                "# TYPE redhand_gateway_pin_reports_total counter",
            ]
            for outcome, count in sorted(self._pin_reports.items()):
                lines.append(f'redhand_gateway_pin_reports_total{{outcome="{outcome}"}} {count}')
            lines += [
                "# HELP redhand_gateway_pin_events_total Tool pinning actions by the gateway (hidden, refused, error).",
                "# TYPE redhand_gateway_pin_events_total counter",
            ]
            for event, count in sorted(self._pin_events.items()):
                lines.append(f'redhand_gateway_pin_events_total{{event="{event}"}} {count}')
            lines += [
                "# HELP redhand_gateway_loops_total Loop detection by outcome (ok, flagged, throttled, untracked, error, evicted, report_throttled).",
                "# TYPE redhand_gateway_loops_total counter",
            ]
            for outcome, count in sorted(self._loops.items()):
                lines.append(f'redhand_gateway_loops_total{{outcome="{outcome}"}} {count}')
            lines += [
                "# HELP redhand_gateway_destination_checks_total Destination allowlist checks by outcome (ok, flagged, refused, untracked, error, report_throttled).",
                "# TYPE redhand_gateway_destination_checks_total counter",
            ]
            for outcome, count in sorted(self._destination_checks.items()):
                lines.append(f'redhand_gateway_destination_checks_total{{outcome="{outcome}"}} {count}')
            lines += [
                "# HELP redhand_gateway_radar_scans_total Background Radar scans by outcome (ok, error, dropped, throttled, truncated).",
                "# TYPE redhand_gateway_radar_scans_total counter",
            ]
            for outcome, count in sorted(self._radar_scans.items()):
                lines.append(f'redhand_gateway_radar_scans_total{{outcome="{outcome}"}} {count}')
            lines += [
                "# HELP redhand_gateway_radar_findings_total Radar findings by kind (injection, output), before throttling.",
                "# TYPE redhand_gateway_radar_findings_total counter",
            ]
            for kind, count in sorted(self._radar_findings.items()):
                lines.append(f'redhand_gateway_radar_findings_total{{kind="{kind}"}} {count}')
            lines += [
                "# HELP redhand_gateway_radar_reports_total Findings reports to core, by outcome (ok, refused, failed, dropped).",
                "# TYPE redhand_gateway_radar_reports_total counter",
            ]
            for outcome, count in sorted(self._radar_reports.items()):
                lines.append(f'redhand_gateway_radar_reports_total{{outcome="{outcome}"}} {count}')
            lines += [
                "# HELP redhand_gateway_radar_count_reports_total Evidence-count reports to core, by outcome (ok, refused, failed, dropped).",
                "# TYPE redhand_gateway_radar_count_reports_total counter",
            ]
            for outcome, count in sorted(self._radar_count_reports.items()):
                lines.append(f'redhand_gateway_radar_count_reports_total{{outcome="{outcome}"}} {count}')
            lines += [
                "# HELP redhand_gateway_radar_scan_ms Time spent scanning one result on the background worker (not added to calls).",
                "# TYPE redhand_gateway_radar_scan_ms summary",
                f"redhand_gateway_radar_scan_ms_sum {self._radar_ms_sum}",
                f"redhand_gateway_radar_scan_ms_count {self._radar_ms_count}",
            ]
            lines += [
                "# HELP redhand_gateway_honeytoken_scans_truncated_total Scans that hit the 64 KiB budget; the rest was not scanned.",
                "# TYPE redhand_gateway_honeytoken_scans_truncated_total counter",
                f"redhand_gateway_honeytoken_scans_truncated_total {self._honeytoken_scans_truncated}",
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
            lines += [
                "# HELP redhand_gateway_stage_ms Time in one step of a call, by stage (verify, context_hit, context_wait_refresh, context_miss, honeytoken_scan, guardrails, budget, budget_flush_now, jwks_refresh, context_refresh, context_refresh_failed).",
                "# TYPE redhand_gateway_stage_ms histogram",
            ]
            for stage in sorted(self._stage_buckets):
                for bucket in LATENCY_BUCKETS_MS:
                    lines.append(f'redhand_gateway_stage_ms_bucket{{stage="{stage}",le="{bucket}"}} {self._stage_buckets[stage][bucket]}')
                lines.append(f'redhand_gateway_stage_ms_bucket{{stage="{stage}",le="+Inf"}} {self._stage_count[stage]}')
                lines.append(f'redhand_gateway_stage_ms_sum{{stage="{stage}"}} {self._stage_sum[stage]:.3f}')
                lines.append(f'redhand_gateway_stage_ms_count{{stage="{stage}"}} {self._stage_count[stage]}')
            return "\n".join(lines) + "\n"
