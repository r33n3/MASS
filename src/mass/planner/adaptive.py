"""Adaptive scanning based on intermediate results.

Adjusts scan depth and analyzer selection dynamically
based on findings discovered during the scan.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from mass.core.findings import Finding
from mass.core.types import Severity, AttackCategory
from mass.orchestration.planner import JobType


class AdaptiveStrategy(Enum):
    """Strategies for adaptive scanning."""

    NONE = "none"  # No adaptation
    CONSERVATIVE = "conservative"  # Minor adjustments
    BALANCED = "balanced"  # Moderate adaptation
    AGGRESSIVE = "aggressive"  # Maximum adaptation


@dataclass
class ScanAdjustment:
    """An adjustment to the scan plan."""

    action: str  # "add", "remove", "elevate", "defer", "deepen"
    target: JobType | str
    reason: str
    triggered_by: str | None = None  # Finding ID that triggered this

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action": self.action,
            "target": self.target.value if isinstance(self.target, JobType) else self.target,
            "reason": self.reason,
            "triggered_by": self.triggered_by,
        }


@dataclass
class AdaptiveState:
    """Current state of adaptive scanning."""

    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    categories_seen: set[AttackCategory] = field(default_factory=set)
    adjustments: list[ScanAdjustment] = field(default_factory=list)
    completed_analyzers: set[JobType] = field(default_factory=set)
    pending_analyzers: set[JobType] = field(default_factory=set)
    added_analyzers: set[JobType] = field(default_factory=set)
    removed_analyzers: set[JobType] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "categories_seen": [c.value for c in self.categories_seen],
            "adjustments": [a.to_dict() for a in self.adjustments],
            "completed_analyzers": [a.value for a in self.completed_analyzers],
            "pending_analyzers": [a.value for a in self.pending_analyzers],
            "added_analyzers": [a.value for a in self.added_analyzers],
            "removed_analyzers": [a.value for a in self.removed_analyzers],
        }


class AdaptiveScanner:
    """Adapts scan execution based on intermediate findings.

    Monitors findings as they're discovered and adjusts the
    scan plan to focus on areas of concern or skip unnecessary work.
    """

    # Category to analyzer mappings for escalation
    CATEGORY_ANALYZERS: dict[AttackCategory, list[JobType]] = {
        AttackCategory.PROMPT_INJECTION: [
            JobType.CONTEXT_ANALYSIS,
            JobType.MODEL_INTERROGATION,
        ],
        AttackCategory.DATA_LEAKAGE: [
            JobType.SECRET_DETECTION,
            JobType.WORKFLOW_ANALYSIS,
        ],
        AttackCategory.DATA_MODEL_POISONING: [
            JobType.MODEL_FILE_SCAN,
            JobType.MODEL_INTERROGATION,
        ],
        AttackCategory.PRIVILEGE_ESCALATION: [
            JobType.INFRASTRUCTURE_SCAN,
            JobType.WORKFLOW_ANALYSIS,
        ],
        AttackCategory.SUPPLY_CHAIN: [
            JobType.MODEL_FILE_SCAN,
            JobType.DEPLOYMENT_SCAN,
        ],
        AttackCategory.DENIAL_OF_SERVICE: [
            JobType.INFRASTRUCTURE_SCAN,
            JobType.ATTACK_SURFACE,
        ],
        AttackCategory.MODEL_THEFT: [
            JobType.ATTACK_SURFACE,
            JobType.INFRASTRUCTURE_SCAN,
        ],
        AttackCategory.JAILBREAK: [
            JobType.MODEL_INTERROGATION,
            JobType.CONTEXT_ANALYSIS,
        ],
        AttackCategory.SECRETS_EXPOSURE: [
            JobType.SECRET_DETECTION,
            JobType.INFRASTRUCTURE_SCAN,
        ],
    }

    # Thresholds for different strategies
    STRATEGY_THRESHOLDS: dict[AdaptiveStrategy, dict[str, int]] = {
        AdaptiveStrategy.CONSERVATIVE: {
            "add_threshold": 5,  # Findings before adding analyzers
            "remove_threshold": 0,  # Never remove
            "elevate_threshold": 3,  # Critical findings to elevate
        },
        AdaptiveStrategy.BALANCED: {
            "add_threshold": 3,
            "remove_threshold": 0,
            "elevate_threshold": 2,
        },
        AdaptiveStrategy.AGGRESSIVE: {
            "add_threshold": 1,
            "remove_threshold": 10,  # Remove low-priority if many findings
            "elevate_threshold": 1,
        },
    }

    def __init__(
        self,
        strategy: AdaptiveStrategy = AdaptiveStrategy.BALANCED,
        on_adjustment: Callable[[ScanAdjustment], None] | None = None,
    ) -> None:
        """Initialize the adaptive scanner.

        Args:
            strategy: Adaptation strategy to use.
            on_adjustment: Callback when adjustments are made.
        """
        self.strategy = strategy
        self.on_adjustment = on_adjustment
        self.state = AdaptiveState()
        self._thresholds = self.STRATEGY_THRESHOLDS.get(
            strategy,
            self.STRATEGY_THRESHOLDS[AdaptiveStrategy.BALANCED],
        )

    def reset(self) -> None:
        """Reset state for a new scan."""
        self.state = AdaptiveState()

    def set_initial_plan(self, analyzers: list[JobType]) -> None:
        """Set the initial scan plan.

        Args:
            analyzers: Initial list of analyzers.
        """
        self.state.pending_analyzers = set(analyzers)

    def mark_completed(self, analyzer: JobType) -> None:
        """Mark an analyzer as completed.

        Args:
            analyzer: Completed analyzer.
        """
        self.state.completed_analyzers.add(analyzer)
        self.state.pending_analyzers.discard(analyzer)

    def process_findings(self, findings: list[Finding]) -> list[ScanAdjustment]:
        """Process new findings and return adjustments.

        Args:
            findings: New findings discovered.

        Returns:
            List of plan adjustments.
        """
        if self.strategy == AdaptiveStrategy.NONE:
            return []

        adjustments: list[ScanAdjustment] = []

        for finding in findings:
            self.state.findings_count += 1
            self.state.categories_seen.add(finding.category)

            if finding.severity == Severity.CRITICAL:
                self.state.critical_count += 1
            elif finding.severity == Severity.HIGH:
                self.state.high_count += 1

            # Check for category-based escalation
            adj = self._check_category_escalation(finding)
            if adj:
                adjustments.extend(adj)

            # Check for severity-based escalation
            adj = self._check_severity_escalation(finding)
            if adj:
                adjustments.extend(adj)

        # Check for plan optimization
        if self.strategy == AdaptiveStrategy.AGGRESSIVE:
            adj = self._check_plan_optimization()
            if adj:
                adjustments.extend(adj)

        # Record and notify
        for adj in adjustments:
            self.state.adjustments.append(adj)
            if self.on_adjustment:
                self.on_adjustment(adj)

        return adjustments

    def _check_category_escalation(
        self,
        finding: Finding,
    ) -> list[ScanAdjustment]:
        """Check if category should trigger analyzer addition."""
        adjustments = []
        related_analyzers = self.CATEGORY_ANALYZERS.get(finding.category, [])

        for analyzer in related_analyzers:
            # Only add if not already planned and threshold met
            if (
                analyzer not in self.state.pending_analyzers
                and analyzer not in self.state.completed_analyzers
                and analyzer not in self.state.added_analyzers
            ):
                category_count = sum(
                    1 for c in self.state.categories_seen if c == finding.category
                )
                if category_count >= self._thresholds["add_threshold"]:
                    self.state.added_analyzers.add(analyzer)
                    self.state.pending_analyzers.add(analyzer)
                    adjustments.append(ScanAdjustment(
                        action="add",
                        target=analyzer,
                        reason=f"Escalation due to {finding.category.value} findings",
                        triggered_by=finding.id,
                    ))

        return adjustments

    def _check_severity_escalation(
        self,
        finding: Finding,
    ) -> list[ScanAdjustment]:
        """Check if severity should trigger priority elevation."""
        adjustments = []

        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            critical_threshold = self._thresholds["elevate_threshold"]

            if self.state.critical_count >= critical_threshold:
                # Elevate model interrogation if not done
                if (
                    JobType.MODEL_INTERROGATION in self.state.pending_analyzers
                    and JobType.MODEL_INTERROGATION not in self.state.completed_analyzers
                ):
                    adjustments.append(ScanAdjustment(
                        action="elevate",
                        target=JobType.MODEL_INTERROGATION,
                        reason=f"{self.state.critical_count} critical findings detected",
                        triggered_by=finding.id,
                    ))

        return adjustments

    def _check_plan_optimization(self) -> list[ScanAdjustment]:
        """Check if plan should be optimized (aggressive mode)."""
        adjustments = []

        # If many findings, consider removing low-priority analyzers
        # to focus on what we've found
        if self.state.findings_count >= self._thresholds["remove_threshold"]:
            # This is aggressive - we might skip some analyzers
            # Only if we have critical findings and many pending
            if self.state.critical_count > 0 and len(self.state.pending_analyzers) > 3:
                # Consider deferring workflow analysis if we have critical issues
                if JobType.WORKFLOW_ANALYSIS in self.state.pending_analyzers:
                    self.state.removed_analyzers.add(JobType.WORKFLOW_ANALYSIS)
                    self.state.pending_analyzers.discard(JobType.WORKFLOW_ANALYSIS)
                    adjustments.append(ScanAdjustment(
                        action="defer",
                        target=JobType.WORKFLOW_ANALYSIS,
                        reason="Focusing on critical findings",
                    ))

        return adjustments

    def get_current_plan(self) -> list[JobType]:
        """Get current pending analyzers.

        Returns:
            List of pending analyzers.
        """
        return list(self.state.pending_analyzers)

    def should_deepen(self, analyzer: JobType) -> bool:
        """Check if an analyzer should do deeper scanning.

        Args:
            analyzer: Analyzer to check.

        Returns:
            True if deeper scanning recommended.
        """
        # Deepen if we've found related issues
        related_categories = [
            cat for cat, analyzers in self.CATEGORY_ANALYZERS.items()
            if analyzer in analyzers
        ]

        for cat in related_categories:
            if cat in self.state.categories_seen:
                return True

        # Deepen if high severity findings exist
        return self.state.critical_count > 0 or self.state.high_count > 2

    def get_summary(self) -> dict[str, Any]:
        """Get summary of adaptive scanning.

        Returns:
            Summary dictionary.
        """
        return {
            "strategy": self.strategy.value,
            "state": self.state.to_dict(),
            "adjustments_made": len(self.state.adjustments),
            "analyzers_added": len(self.state.added_analyzers),
            "analyzers_removed": len(self.state.removed_analyzers),
        }
