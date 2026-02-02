"""Historical scan data tracking and learning.

Stores and analyzes past scan results to improve
future scan prioritization and prediction.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from collections import defaultdict

from mass.core.types import Severity, AttackCategory
from mass.orchestration.planner import JobType


@dataclass
class ScanHistoryEntry:
    """A single scan history entry."""

    scan_id: str
    deployment_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Results
    total_findings: int = 0
    by_severity: dict[Severity, int] = field(default_factory=dict)
    by_category: dict[AttackCategory, int] = field(default_factory=dict)
    by_analyzer: dict[JobType, int] = field(default_factory=dict)

    # Performance
    duration_seconds: float = 0.0
    analyzers_run: list[JobType] = field(default_factory=list)

    # Metadata
    scan_profile: str = ""
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "deployment_id": self.deployment_id,
            "timestamp": self.timestamp.isoformat(),
            "total_findings": self.total_findings,
            "by_severity": {k.value: v for k, v in self.by_severity.items()},
            "by_category": {k.value: v for k, v in self.by_category.items()},
            "by_analyzer": {k.value: v for k, v in self.by_analyzer.items()},
            "duration_seconds": self.duration_seconds,
            "analyzers_run": [a.value for a in self.analyzers_run],
            "scan_profile": self.scan_profile,
            "risk_score": self.risk_score,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanHistoryEntry":
        """Create from dictionary."""
        return cls(
            scan_id=data["scan_id"],
            deployment_id=data["deployment_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            total_findings=data.get("total_findings", 0),
            by_severity={
                Severity(k): v for k, v in data.get("by_severity", {}).items()
            },
            by_category={
                AttackCategory(k): v for k, v in data.get("by_category", {}).items()
            },
            by_analyzer={
                JobType(k): v for k, v in data.get("by_analyzer", {}).items()
            },
            duration_seconds=data.get("duration_seconds", 0.0),
            analyzers_run=[JobType(a) for a in data.get("analyzers_run", [])],
            scan_profile=data.get("scan_profile", ""),
            risk_score=data.get("risk_score", 0.0),
        )


class HistoryStore(ABC):
    """Abstract base for history storage."""

    @abstractmethod
    def save(self, entry: ScanHistoryEntry) -> None:
        """Save a history entry."""
        pass

    @abstractmethod
    def get_by_deployment(
        self,
        deployment_id: str,
        limit: int = 100,
    ) -> list[ScanHistoryEntry]:
        """Get entries for a deployment."""
        pass

    @abstractmethod
    def get_recent(
        self,
        days: int = 30,
        limit: int = 1000,
    ) -> list[ScanHistoryEntry]:
        """Get recent entries."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all history."""
        pass


class MemoryHistoryStore(HistoryStore):
    """In-memory history storage for testing."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._entries: list[ScanHistoryEntry] = []

    def save(self, entry: ScanHistoryEntry) -> None:
        """Save a history entry."""
        self._entries.append(entry)

    def get_by_deployment(
        self,
        deployment_id: str,
        limit: int = 100,
    ) -> list[ScanHistoryEntry]:
        """Get entries for a deployment."""
        matching = [e for e in self._entries if e.deployment_id == deployment_id]
        matching.sort(key=lambda e: e.timestamp, reverse=True)
        return matching[:limit]

    def get_recent(
        self,
        days: int = 30,
        limit: int = 1000,
    ) -> list[ScanHistoryEntry]:
        """Get recent entries."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        recent = [e for e in self._entries if e.timestamp >= cutoff]
        recent.sort(key=lambda e: e.timestamp, reverse=True)
        return recent[:limit]

    def clear(self) -> None:
        """Clear all history."""
        self._entries.clear()

    def count(self) -> int:
        """Get total entry count."""
        return len(self._entries)


@dataclass
class DeploymentStats:
    """Aggregated statistics for a deployment."""

    deployment_id: str
    scan_count: int = 0
    total_findings: int = 0
    avg_findings_per_scan: float = 0.0
    finding_trend: str = "stable"  # "increasing", "decreasing", "stable"
    common_categories: list[AttackCategory] = field(default_factory=list)
    productive_analyzers: list[JobType] = field(default_factory=list)
    last_scan: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "deployment_id": self.deployment_id,
            "scan_count": self.scan_count,
            "total_findings": self.total_findings,
            "avg_findings_per_scan": self.avg_findings_per_scan,
            "finding_trend": self.finding_trend,
            "common_categories": [c.value for c in self.common_categories],
            "productive_analyzers": [a.value for a in self.productive_analyzers],
            "last_scan": self.last_scan.isoformat() if self.last_scan else None,
        }


class ScanHistory:
    """Manages scan history and provides insights.

    Tracks scan results over time and provides analytics
    to improve future scan prioritization.
    """

    def __init__(
        self,
        store: HistoryStore | None = None,
    ) -> None:
        """Initialize scan history.

        Args:
            store: History storage backend.
        """
        self.store = store or MemoryHistoryStore()

    def record(self, entry: ScanHistoryEntry) -> None:
        """Record a scan result.

        Args:
            entry: History entry to record.
        """
        self.store.save(entry)

    def record_from_result(
        self,
        scan_id: str,
        deployment_id: str,
        findings: list[Any],  # Finding objects
        duration_seconds: float,
        analyzers_run: list[JobType],
        scan_profile: str = "",
        risk_score: float = 0.0,
    ) -> ScanHistoryEntry:
        """Record a scan from result data.

        Args:
            scan_id: Scan identifier.
            deployment_id: Deployment scanned.
            findings: List of findings.
            duration_seconds: Scan duration.
            analyzers_run: Analyzers that ran.
            scan_profile: Profile used.
            risk_score: Risk assessment score.

        Returns:
            Created history entry.
        """
        by_severity: dict[Severity, int] = defaultdict(int)
        by_category: dict[AttackCategory, int] = defaultdict(int)

        for finding in findings:
            by_severity[finding.severity] += 1
            by_category[finding.category] += 1

        # Count findings by analyzer (approximate based on category)
        by_analyzer: dict[JobType, int] = defaultdict(int)
        for finding in findings:
            analyzer = self._guess_analyzer_from_finding(finding)
            if analyzer:
                by_analyzer[analyzer] += 1

        entry = ScanHistoryEntry(
            scan_id=scan_id,
            deployment_id=deployment_id,
            total_findings=len(findings),
            by_severity=dict(by_severity),
            by_category=dict(by_category),
            by_analyzer=dict(by_analyzer),
            duration_seconds=duration_seconds,
            analyzers_run=analyzers_run,
            scan_profile=scan_profile,
            risk_score=risk_score,
        )

        self.store.save(entry)
        return entry

    def _guess_analyzer_from_finding(self, finding: Any) -> JobType | None:
        """Guess which analyzer produced a finding."""
        # Map categories to likely analyzers
        category_map = {
            AttackCategory.PROMPT_INJECTION: JobType.CONTEXT_ANALYSIS,
            AttackCategory.DATA_LEAKAGE: JobType.SECRET_DETECTION,
            AttackCategory.SECRETS_EXPOSURE: JobType.SECRET_DETECTION,
            AttackCategory.DATA_MODEL_POISONING: JobType.MODEL_FILE_SCAN,
            AttackCategory.SUPPLY_CHAIN: JobType.MODEL_FILE_SCAN,
            AttackCategory.PRIVILEGE_ESCALATION: JobType.INFRASTRUCTURE_SCAN,
        }
        return category_map.get(finding.category)

    def get_deployment_stats(self, deployment_id: str) -> DeploymentStats:
        """Get aggregated stats for a deployment.

        Args:
            deployment_id: Deployment to analyze.

        Returns:
            Aggregated statistics.
        """
        entries = self.store.get_by_deployment(deployment_id)
        if not entries:
            return DeploymentStats(deployment_id=deployment_id)

        stats = DeploymentStats(
            deployment_id=deployment_id,
            scan_count=len(entries),
            last_scan=entries[0].timestamp if entries else None,
        )

        # Aggregate findings
        total_findings = sum(e.total_findings for e in entries)
        stats.total_findings = total_findings
        stats.avg_findings_per_scan = total_findings / len(entries) if entries else 0

        # Calculate trend
        stats.finding_trend = self._calculate_trend(entries)

        # Common categories
        category_counts: dict[AttackCategory, int] = defaultdict(int)
        for entry in entries:
            for cat, count in entry.by_category.items():
                category_counts[cat] += count

        stats.common_categories = sorted(
            category_counts.keys(),
            key=lambda c: category_counts[c],
            reverse=True,
        )[:5]

        # Productive analyzers
        analyzer_counts: dict[JobType, int] = defaultdict(int)
        for entry in entries:
            for analyzer, count in entry.by_analyzer.items():
                analyzer_counts[analyzer] += count

        stats.productive_analyzers = sorted(
            analyzer_counts.keys(),
            key=lambda a: analyzer_counts[a],
            reverse=True,
        )[:5]

        return stats

    def _calculate_trend(self, entries: list[ScanHistoryEntry]) -> str:
        """Calculate finding trend from entries."""
        if len(entries) < 3:
            return "stable"

        # Compare recent vs older
        recent = entries[:len(entries) // 2]
        older = entries[len(entries) // 2:]

        recent_avg = sum(e.total_findings for e in recent) / len(recent)
        older_avg = sum(e.total_findings for e in older) / len(older)

        if recent_avg > older_avg * 1.2:
            return "increasing"
        elif recent_avg < older_avg * 0.8:
            return "decreasing"
        return "stable"

    def get_analyzer_effectiveness(
        self,
        days: int = 30,
    ) -> dict[JobType, float]:
        """Get analyzer effectiveness scores.

        Args:
            days: Days of history to analyze.

        Returns:
            Effectiveness score per analyzer (0-1).
        """
        entries = self.store.get_recent(days=days)
        if not entries:
            return {}

        # Count findings per analyzer and times run
        findings_by_analyzer: dict[JobType, int] = defaultdict(int)
        runs_by_analyzer: dict[JobType, int] = defaultdict(int)

        for entry in entries:
            for analyzer in entry.analyzers_run:
                runs_by_analyzer[analyzer] += 1
            for analyzer, count in entry.by_analyzer.items():
                findings_by_analyzer[analyzer] += count

        # Calculate effectiveness
        effectiveness = {}
        for analyzer in runs_by_analyzer:
            runs = runs_by_analyzer[analyzer]
            findings = findings_by_analyzer.get(analyzer, 0)
            # Normalize to 0-1 scale
            effectiveness[analyzer] = min(findings / max(runs, 1) / 5, 1.0)

        return effectiveness

    def get_historical_findings_by_analyzer(
        self,
        deployment_id: str,
    ) -> dict[JobType, int]:
        """Get historical finding counts by analyzer.

        Args:
            deployment_id: Deployment to query.

        Returns:
            Finding counts per analyzer.
        """
        entries = self.store.get_by_deployment(deployment_id)
        counts: dict[JobType, int] = defaultdict(int)

        for entry in entries:
            for analyzer, count in entry.by_analyzer.items():
                counts[analyzer] += count

        return dict(counts)

    def predict_findings(
        self,
        deployment_id: str,
    ) -> dict[str, Any]:
        """Predict findings for next scan.

        Args:
            deployment_id: Deployment to predict.

        Returns:
            Prediction data.
        """
        stats = self.get_deployment_stats(deployment_id)
        entries = self.store.get_by_deployment(deployment_id, limit=10)

        if not entries:
            return {
                "expected_findings": 0,
                "confidence": 0.0,
                "likely_categories": [],
            }

        # Simple prediction based on history
        recent_avg = sum(e.total_findings for e in entries[:5]) / min(len(entries), 5)

        # Adjust for trend
        trend_multiplier = {
            "increasing": 1.2,
            "decreasing": 0.8,
            "stable": 1.0,
        }

        predicted = recent_avg * trend_multiplier.get(stats.finding_trend, 1.0)

        return {
            "expected_findings": round(predicted),
            "confidence": min(len(entries) / 10, 1.0),  # More history = more confidence
            "likely_categories": [c.value for c in stats.common_categories[:3]],
            "trend": stats.finding_trend,
        }
