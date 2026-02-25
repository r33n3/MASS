"""Lightweight application metrics.

Provides thread-safe counters, gauges, and histograms that are exposed
via the ``/metrics`` endpoint in Prometheus exposition format.  Does
not require the ``prometheus_client`` package.

Usage:
    from mass.core.metrics import METRICS

    METRICS.inc("mass_api_requests_total", labels={"method": "GET", "endpoint": "/scans"})
    METRICS.observe("mass_api_latency_seconds", 0.042, labels={"endpoint": "/scans"})
    METRICS.set("mass_db_pool_active", 5)
"""

import threading
import time
from collections import defaultdict
from typing import Any


class _Metric:
    """A single metric value with optional labels."""

    __slots__ = ("name", "type", "help", "values", "lock")

    def __init__(self, name: str, metric_type: str, help_text: str = "") -> None:
        self.name = name
        self.type = metric_type
        self.help = help_text
        self.values: dict[str, float] = defaultdict(float)
        self.lock = threading.Lock()


class MetricsRegistry:
    """Thread-safe metrics registry with Prometheus text export."""

    def __init__(self) -> None:
        self._metrics: dict[str, _Metric] = {}
        self._lock = threading.Lock()
        self._created_at = time.time()

    def _get_or_create(
        self, name: str, metric_type: str, help_text: str = ""
    ) -> _Metric:
        if name not in self._metrics:
            with self._lock:
                if name not in self._metrics:
                    self._metrics[name] = _Metric(name, metric_type, help_text)
        return self._metrics[name]

    @staticmethod
    def _label_key(labels: dict[str, str] | None) -> str:
        if not labels:
            return ""
        sorted_items = sorted(labels.items())
        return "{" + ",".join(f'{k}="{v}"' for k, v in sorted_items) + "}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inc(
        self,
        name: str,
        value: float = 1.0,
        labels: dict[str, str] | None = None,
        help_text: str = "",
    ) -> None:
        """Increment a counter."""
        m = self._get_or_create(name, "counter", help_text)
        key = self._label_key(labels)
        with m.lock:
            m.values[key] += value

    def set(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
        help_text: str = "",
    ) -> None:
        """Set a gauge value."""
        m = self._get_or_create(name, "gauge", help_text)
        key = self._label_key(labels)
        with m.lock:
            m.values[key] = value

    def observe(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
        help_text: str = "",
    ) -> None:
        """Observe a value for a histogram (sum + count only)."""
        # Store sum and count as separate keys
        m_sum = self._get_or_create(f"{name}_sum", "gauge", help_text)
        m_count = self._get_or_create(f"{name}_count", "counter", help_text)
        key = self._label_key(labels)
        with m_sum.lock:
            m_sum.values[key] += value
        with m_count.lock:
            m_count.values[key] += 1

    def export(self) -> str:
        """Export all metrics in Prometheus text exposition format."""
        lines: list[str] = []
        seen_help: set[str] = set()

        for name, m in sorted(self._metrics.items()):
            # Skip _sum/_count helpers for histograms — they're embedded
            base = name.removesuffix("_sum").removesuffix("_count")
            if base not in seen_help:
                seen_help.add(base)
                if m.help:
                    lines.append(f"# HELP {base} {m.help}")
                lines.append(f"# TYPE {base} {m.type}")

            with m.lock:
                for label_key, value in sorted(m.values.items()):
                    lines.append(f"{name}{label_key} {value}")

        # Always include uptime
        lines.append("")
        lines.append("# HELP mass_uptime_seconds Time since metrics registry created")
        lines.append("# TYPE mass_uptime_seconds gauge")
        lines.append(f"mass_uptime_seconds {time.time() - self._created_at}")

        return "\n".join(lines) + "\n"


# Singleton
METRICS = MetricsRegistry()
