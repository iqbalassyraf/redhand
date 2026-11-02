"""
RedHand Core - Prometheus Observability Metrics Exporter
File: services/redhand-core/src/redhand_core/services/metrics.py

Provides native, high-performance, thread-safe Prometheus metrics formatting
without external C-extension dependencies. Exposes standard OpenMetrics/Prometheus
text format (v0.0.4) for enterprise Prometheus, Datadog Agent, and Grafana Alloy.
"""

from __future__ import annotations

from collections import defaultdict
import threading


class MetricsCollector:
    """Thread-safe in-memory Prometheus metrics registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple[tuple[str, str], ...], float]] = defaultdict(
            lambda: defaultdict(float)
        )
        self._gauges: dict[str, dict[tuple[tuple[str, str], ...], float]] = defaultdict(
            lambda: defaultdict(float)
        )
        self._histograms: dict[
            str, dict[tuple[tuple[str, str], ...], list[float]]
        ] = defaultdict(lambda: defaultdict(list))
        self._histogram_buckets = [0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500]

    def increment_counter(
        self, name: str, value: float = 1.0, labels: dict[str, str] | None = None
    ) -> None:
        label_key = tuple(sorted((labels or {}).items()))
        with self._lock:
            self._counters[name][label_key] += value

    def set_gauge(
        self, name: str, value: float, labels: dict[str, str] | None = None
    ) -> None:
        label_key = tuple(sorted((labels or {}).items()))
        with self._lock:
            self._gauges[name][label_key] = value

    def record_histogram(
        self, name: str, value: float, labels: dict[str, str] | None = None
    ) -> None:
        label_key = tuple(sorted((labels or {}).items()))
        with self._lock:
            self._histograms[name][label_key].append(value)

    def render_prometheus(self) -> str:
        """Renders standard Prometheus text representation."""
        lines: list[str] = []
        with self._lock:
            # Counters
            for name, series in sorted(self._counters.items()):
                lines.append(f"# TYPE {name} counter")
                for label_tuples, val in series.items():
                    lbl_str = self._format_labels(label_tuples)
                    lines.append(f"{name}{lbl_str} {val}")

            # Gauges
            for name, series in sorted(self._gauges.items()):
                lines.append(f"# TYPE {name} gauge")
                for label_tuples, val in series.items():
                    lbl_str = self._format_labels(label_tuples)
                    lines.append(f"{name}{lbl_str} {val}")

            # Histograms
            for name, series in sorted(self._histograms.items()):
                lines.append(f"# TYPE {name} histogram")
                for label_tuples, observations in series.items():
                    total_count = len(observations)
                    total_sum = sum(observations)
                    lbl_dict = dict(label_tuples)

                    for b in self._histogram_buckets:
                        count_in_bucket = sum(1 for o in observations if o <= b)
                        b_labels = self._format_labels(
                            tuple(sorted({**lbl_dict, "le": str(b)}.items()))
                        )
                        lines.append(f"{name}_bucket{b_labels} {count_in_bucket}")

                    inf_labels = self._format_labels(
                        tuple(sorted({**lbl_dict, "le": "+Inf"}.items()))
                    )
                    lines.append(f"{name}_bucket{inf_labels} {total_count}")
                    sum_labels = self._format_labels(label_tuples)
                    lines.append(f"{name}_sum{sum_labels} {total_sum:.6f}")
                    lines.append(f"{name}_count{sum_labels} {total_count}")

        lines.append("")  # Trailing newline required by Prometheus RFC
        return "\n".join(lines)

    @staticmethod
    def _format_labels(label_tuples: tuple[tuple[str, str], ...]) -> str:
        if not label_tuples:
            return ""
        kvs = [f'{k}="{v}"' for k, v in label_tuples]
        return "{" + ",".join(kvs) + "}"


_global_metrics: MetricsCollector | None = None


def get_metrics() -> MetricsCollector:
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = MetricsCollector()
        # Initialize baseline default series
        _global_metrics.increment_counter("redhand_firewall_evaluations_total", 0, {"verdict": "allow"})
        _global_metrics.increment_counter("redhand_firewall_evaluations_total", 0, {"verdict": "blocked"})
        _global_metrics.increment_counter("redhand_iam_tokens_minted_total", 0, {"cloud": "gcp"})
        _global_metrics.increment_counter("redhand_iam_tokens_minted_total", 0, {"cloud": "aws"})
        _global_metrics.set_gauge("redhand_hitl_interventions_active", 0)
    return _global_metrics

