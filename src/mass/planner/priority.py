"""Priority calculation for scan analyzers.

Determines optimal analyzer execution order based on
risk profiles, historical findings, and dependencies.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mass.core.types import Severity
from mass.orchestration.planner import JobType
from mass.planner.risk import DeploymentRiskProfile, RiskFactor


class AnalyzerPriority(Enum):
    """Priority levels for analyzers."""

    CRITICAL = 1  # Run first, essential
    HIGH = 2  # Run early, important
    NORMAL = 3  # Standard priority
    LOW = 4  # Run later, optional
    DEFERRED = 5  # Run only if time permits


@dataclass
class PrioritizedAnalyzer:
    """An analyzer with its calculated priority."""

    job_type: JobType
    priority: AnalyzerPriority
    score: float  # 0.0 to 1.0, higher = more important
    reasons: list[str] = field(default_factory=list)
    estimated_time_seconds: int = 60
    dependencies: list[JobType] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "job_type": self.job_type.value,
            "priority": self.priority.value,
            "score": self.score,
            "reasons": self.reasons,
            "estimated_time_seconds": self.estimated_time_seconds,
            "dependencies": [d.value for d in self.dependencies],
        }


@dataclass
class PrioritizedPlan:
    """A scan plan with prioritized analyzers."""

    deployment_id: str
    analyzers: list[PrioritizedAnalyzer] = field(default_factory=list)
    total_estimated_seconds: int = 0
    risk_profile: DeploymentRiskProfile | None = None

    def get_ordered(self) -> list[PrioritizedAnalyzer]:
        """Get analyzers in execution order."""
        return sorted(self.analyzers, key=lambda a: (a.priority.value, -a.score))

    def get_by_priority(
        self,
        priority: AnalyzerPriority,
    ) -> list[PrioritizedAnalyzer]:
        """Get analyzers with specific priority."""
        return [a for a in self.analyzers if a.priority == priority]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "deployment_id": self.deployment_id,
            "analyzers": [a.to_dict() for a in self.get_ordered()],
            "total_estimated_seconds": self.total_estimated_seconds,
            "risk_level": (
                self.risk_profile.risk_level.value if self.risk_profile else None
            ),
        }


class PriorityCalculator:
    """Calculates analyzer priorities based on risk and history.

    Uses risk profiles, historical finding patterns, and
    analyzer characteristics to determine optimal execution order.
    """

    # Base priority for each analyzer type
    BASE_PRIORITIES: dict[JobType, AnalyzerPriority] = {
        JobType.DEPLOYMENT_SCAN: AnalyzerPriority.CRITICAL,
        JobType.SECRET_DETECTION: AnalyzerPriority.CRITICAL,
        JobType.MODEL_FILE_SCAN: AnalyzerPriority.HIGH,
        JobType.INFRASTRUCTURE_SCAN: AnalyzerPriority.HIGH,
        JobType.CONTEXT_ANALYSIS: AnalyzerPriority.NORMAL,
        JobType.MCP_ANALYSIS: AnalyzerPriority.NORMAL,
        JobType.ATTACK_SURFACE: AnalyzerPriority.NORMAL,
        JobType.WORKFLOW_ANALYSIS: AnalyzerPriority.NORMAL,
        JobType.MODEL_INTERROGATION: AnalyzerPriority.LOW,
    }

    # Estimated time in seconds for each analyzer
    ESTIMATED_TIMES: dict[JobType, int] = {
        JobType.DEPLOYMENT_SCAN: 30,
        JobType.SECRET_DETECTION: 20,
        JobType.MODEL_FILE_SCAN: 60,
        JobType.INFRASTRUCTURE_SCAN: 45,
        JobType.CONTEXT_ANALYSIS: 40,
        JobType.MCP_ANALYSIS: 35,
        JobType.ATTACK_SURFACE: 50,
        JobType.WORKFLOW_ANALYSIS: 45,
        JobType.MODEL_INTERROGATION: 120,
    }

    # Analyzer dependencies
    DEPENDENCIES: dict[JobType, list[JobType]] = {
        JobType.ATTACK_SURFACE: [JobType.DEPLOYMENT_SCAN],
        JobType.WORKFLOW_ANALYSIS: [JobType.CONTEXT_ANALYSIS],
        JobType.MODEL_INTERROGATION: [JobType.MODEL_FILE_SCAN],
    }

    # Risk factors that elevate specific analyzers
    RISK_ELEVATIONS: dict[RiskFactor, list[JobType]] = {
        RiskFactor.MODEL_FORMAT: [JobType.MODEL_FILE_SCAN],
        RiskFactor.MODEL_SOURCE: [JobType.MODEL_FILE_SCAN, JobType.MODEL_INTERROGATION],
        RiskFactor.SECRET_MANAGEMENT: [JobType.SECRET_DETECTION],
        RiskFactor.EXTERNAL_EXPOSURE: [JobType.ATTACK_SURFACE, JobType.INFRASTRUCTURE_SCAN],
        RiskFactor.INPUT_VALIDATION: [JobType.CONTEXT_ANALYSIS, JobType.MCP_ANALYSIS],
        RiskFactor.PERMISSION_SCOPE: [JobType.WORKFLOW_ANALYSIS],
        RiskFactor.CONTAINER_CONFIG: [JobType.INFRASTRUCTURE_SCAN],
        RiskFactor.INTEGRATION_COUNT: [JobType.MCP_ANALYSIS, JobType.WORKFLOW_ANALYSIS],
    }

    def __init__(
        self,
        history_boost: float = 0.2,
        risk_boost: float = 0.3,
    ) -> None:
        """Initialize the priority calculator.

        Args:
            history_boost: Score boost for analyzers with historical findings.
            risk_boost: Score boost for risk-elevated analyzers.
        """
        self.history_boost = history_boost
        self.risk_boost = risk_boost

    def calculate(
        self,
        deployment_id: str,
        risk_profile: DeploymentRiskProfile | None = None,
        historical_findings: dict[JobType, int] | None = None,
        available_analyzers: list[JobType] | None = None,
    ) -> PrioritizedPlan:
        """Calculate priorities for analyzers.

        Args:
            deployment_id: Deployment being scanned.
            risk_profile: Optional risk assessment.
            historical_findings: Past finding counts by analyzer.
            available_analyzers: Analyzers to include (all if None).

        Returns:
            Prioritized execution plan.
        """
        analyzers = available_analyzers or list(JobType)
        historical = historical_findings or {}
        plan = PrioritizedPlan(
            deployment_id=deployment_id,
            risk_profile=risk_profile,
        )

        for job_type in analyzers:
            prioritized = self._calculate_analyzer_priority(
                job_type=job_type,
                risk_profile=risk_profile,
                historical_count=historical.get(job_type, 0),
            )
            plan.analyzers.append(prioritized)
            plan.total_estimated_seconds += prioritized.estimated_time_seconds

        return plan

    def _calculate_analyzer_priority(
        self,
        job_type: JobType,
        risk_profile: DeploymentRiskProfile | None,
        historical_count: int,
    ) -> PrioritizedAnalyzer:
        """Calculate priority for a single analyzer."""
        base_priority = self.BASE_PRIORITIES.get(job_type, AnalyzerPriority.NORMAL)
        base_score = 1.0 - (base_priority.value - 1) / 4  # Convert to 0-1 score
        reasons = []
        score_adjustments = 0.0

        # Apply risk-based elevation
        if risk_profile:
            for risk_score in risk_profile.scores:
                if risk_score.score >= 0.5:
                    elevated_analyzers = self.RISK_ELEVATIONS.get(
                        risk_score.factor, []
                    )
                    if job_type in elevated_analyzers:
                        score_adjustments += self.risk_boost * risk_score.score
                        reasons.append(
                            f"Risk factor: {risk_score.factor.value}"
                        )

        # Apply historical finding boost
        if historical_count > 0:
            # Logarithmic scaling for historical counts
            import math
            hist_boost = self.history_boost * min(math.log2(historical_count + 1) / 5, 1.0)
            score_adjustments += hist_boost
            reasons.append(f"Historical findings: {historical_count}")

        # Calculate final score
        final_score = min(base_score + score_adjustments, 1.0)

        # Determine final priority based on score
        final_priority = self._score_to_priority(final_score, base_priority)

        return PrioritizedAnalyzer(
            job_type=job_type,
            priority=final_priority,
            score=final_score,
            reasons=reasons if reasons else ["Base priority"],
            estimated_time_seconds=self.ESTIMATED_TIMES.get(job_type, 60),
            dependencies=self.DEPENDENCIES.get(job_type, []),
        )

    def _score_to_priority(
        self,
        score: float,
        base_priority: AnalyzerPriority,
    ) -> AnalyzerPriority:
        """Convert score to priority, potentially elevating from base."""
        if score >= 0.9:
            return AnalyzerPriority.CRITICAL
        elif score >= 0.75:
            return AnalyzerPriority.HIGH
        elif score >= 0.5:
            # Return the higher priority (lower value) between base and NORMAL
            if base_priority.value <= AnalyzerPriority.NORMAL.value:
                return base_priority
            return AnalyzerPriority.NORMAL
        elif score >= 0.25:
            # Return the higher priority (lower value) between base and LOW
            if base_priority.value <= AnalyzerPriority.LOW.value:
                return base_priority
            return AnalyzerPriority.LOW
        else:
            return AnalyzerPriority.DEFERRED

    def quick_order(
        self,
        analyzers: list[JobType],
    ) -> list[JobType]:
        """Quick ordering without risk analysis.

        Args:
            analyzers: Analyzers to order.

        Returns:
            Ordered list of analyzers.
        """
        plan = self.calculate("", available_analyzers=analyzers)
        return [a.job_type for a in plan.get_ordered()]
