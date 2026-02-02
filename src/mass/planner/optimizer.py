"""Scan optimizer combining risk, priority, and history.

Main entry point for AI-powered scan optimization that
coordinates all planning components.
"""

from dataclasses import dataclass, field
from typing import Any
from datetime import datetime

from mass.core.findings import Finding
from mass.orchestration.planner import JobType
from mass.planner.risk import RiskAssessor, DeploymentRiskProfile
from mass.planner.priority import PriorityCalculator, PrioritizedPlan, AnalyzerPriority
from mass.planner.adaptive import AdaptiveScanner, AdaptiveStrategy, ScanAdjustment
from mass.planner.history import ScanHistory, HistoryStore, MemoryHistoryStore


@dataclass
class OptimizationConfig:
    """Configuration for scan optimization."""

    # Strategy settings
    adaptive_strategy: AdaptiveStrategy = AdaptiveStrategy.BALANCED
    use_history: bool = True
    use_risk_assessment: bool = True

    # Priority settings
    history_boost: float = 0.2
    risk_boost: float = 0.3

    # Time budget (0 = unlimited)
    max_scan_seconds: int = 0

    # Analyzer limits
    max_analyzers: int = 0  # 0 = no limit
    required_analyzers: list[JobType] = field(default_factory=list)
    excluded_analyzers: list[JobType] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "adaptive_strategy": self.adaptive_strategy.value,
            "use_history": self.use_history,
            "use_risk_assessment": self.use_risk_assessment,
            "history_boost": self.history_boost,
            "risk_boost": self.risk_boost,
            "max_scan_seconds": self.max_scan_seconds,
            "max_analyzers": self.max_analyzers,
            "required_analyzers": [a.value for a in self.required_analyzers],
            "excluded_analyzers": [a.value for a in self.excluded_analyzers],
        }


@dataclass
class OptimizedScan:
    """An optimized scan plan."""

    deployment_id: str
    analyzers: list[JobType] = field(default_factory=list)
    priority_plan: PrioritizedPlan | None = None
    risk_profile: DeploymentRiskProfile | None = None
    estimated_seconds: int = 0
    optimization_notes: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "deployment_id": self.deployment_id,
            "analyzers": [a.value for a in self.analyzers],
            "priority_plan": self.priority_plan.to_dict() if self.priority_plan else None,
            "risk_profile": self.risk_profile.to_dict() if self.risk_profile else None,
            "estimated_seconds": self.estimated_seconds,
            "optimization_notes": self.optimization_notes,
            "created_at": self.created_at.isoformat(),
        }


class ScanOptimizer:
    """AI-powered scan optimizer.

    Combines risk assessment, priority calculation, historical
    learning, and adaptive scanning to produce optimal scan plans.
    """

    def __init__(
        self,
        config: OptimizationConfig | None = None,
        history_store: HistoryStore | None = None,
    ) -> None:
        """Initialize the optimizer.

        Args:
            config: Optimization configuration.
            history_store: History storage backend.
        """
        self.config = config or OptimizationConfig()
        self.risk_assessor = RiskAssessor()
        self.priority_calculator = PriorityCalculator(
            history_boost=self.config.history_boost,
            risk_boost=self.config.risk_boost,
        )
        self.history = ScanHistory(
            store=history_store or MemoryHistoryStore()
        )
        self.adaptive_scanner = AdaptiveScanner(
            strategy=self.config.adaptive_strategy,
        )

    def optimize(
        self,
        deployment_id: str,
        deployment_info: dict[str, Any] | None = None,
        available_analyzers: list[JobType] | None = None,
    ) -> OptimizedScan:
        """Create an optimized scan plan.

        Args:
            deployment_id: Deployment to scan.
            deployment_info: Optional deployment metadata for risk assessment.
            available_analyzers: Analyzers to consider.

        Returns:
            Optimized scan plan.
        """
        notes: list[str] = []
        all_analyzers = available_analyzers or list(JobType)

        # Filter out excluded analyzers
        analyzers = [
            a for a in all_analyzers
            if a not in self.config.excluded_analyzers
        ]

        # Ensure required analyzers are included
        for required in self.config.required_analyzers:
            if required not in analyzers:
                analyzers.append(required)
                notes.append(f"Added required analyzer: {required.value}")

        # Risk assessment
        risk_profile = None
        if self.config.use_risk_assessment and deployment_info:
            risk_profile = self.risk_assessor.assess(deployment_info)
            notes.append(
                f"Risk assessment: {risk_profile.risk_level.value} "
                f"({risk_profile.overall_score:.2f})"
            )

        # Get historical data
        historical_findings = None
        if self.config.use_history:
            historical_findings = self.history.get_historical_findings_by_analyzer(
                deployment_id
            )
            if historical_findings:
                notes.append(
                    f"Using history: {sum(historical_findings.values())} past findings"
                )

        # Calculate priorities
        priority_plan = self.priority_calculator.calculate(
            deployment_id=deployment_id,
            risk_profile=risk_profile,
            historical_findings=historical_findings,
            available_analyzers=analyzers,
        )

        # Get ordered analyzers
        ordered_analyzers = [a.job_type for a in priority_plan.get_ordered()]

        # Apply time budget if set
        if self.config.max_scan_seconds > 0:
            ordered_analyzers, time_notes = self._apply_time_budget(
                priority_plan,
                self.config.max_scan_seconds,
            )
            notes.extend(time_notes)

        # Apply analyzer limit if set
        if self.config.max_analyzers > 0 and len(ordered_analyzers) > self.config.max_analyzers:
            removed = ordered_analyzers[self.config.max_analyzers:]
            ordered_analyzers = ordered_analyzers[:self.config.max_analyzers]
            notes.append(
                f"Limited to {self.config.max_analyzers} analyzers, "
                f"removed: {[a.value for a in removed]}"
            )

        # Calculate estimated time
        estimated_time = sum(
            pa.estimated_time_seconds
            for pa in priority_plan.analyzers
            if pa.job_type in ordered_analyzers
        )

        return OptimizedScan(
            deployment_id=deployment_id,
            analyzers=ordered_analyzers,
            priority_plan=priority_plan,
            risk_profile=risk_profile,
            estimated_seconds=estimated_time,
            optimization_notes=notes,
        )

    def _apply_time_budget(
        self,
        plan: PrioritizedPlan,
        max_seconds: int,
    ) -> tuple[list[JobType], list[str]]:
        """Apply time budget to analyzer selection.

        Args:
            plan: Priority plan.
            max_seconds: Maximum scan time.

        Returns:
            Tuple of (analyzers to run, notes).
        """
        notes = []
        selected = []
        remaining_time = max_seconds

        for pa in plan.get_ordered():
            if pa.estimated_time_seconds <= remaining_time:
                selected.append(pa.job_type)
                remaining_time -= pa.estimated_time_seconds
            elif pa.priority in (AnalyzerPriority.CRITICAL, AnalyzerPriority.HIGH):
                # Always include critical/high priority even if over budget
                selected.append(pa.job_type)
                notes.append(
                    f"Including {pa.job_type.value} despite time budget (priority)"
                )
            else:
                notes.append(
                    f"Excluded {pa.job_type.value} due to time budget"
                )

        notes.insert(0, f"Time budget: {max_seconds}s")
        return selected, notes

    def record_result(
        self,
        scan_id: str,
        deployment_id: str,
        findings: list[Finding],
        duration_seconds: float,
        analyzers_run: list[JobType],
        scan_profile: str = "",
    ) -> None:
        """Record scan results for learning.

        Args:
            scan_id: Scan identifier.
            deployment_id: Deployment scanned.
            findings: Findings discovered.
            duration_seconds: Scan duration.
            analyzers_run: Analyzers that ran.
            scan_profile: Profile used.
        """
        self.history.record_from_result(
            scan_id=scan_id,
            deployment_id=deployment_id,
            findings=findings,
            duration_seconds=duration_seconds,
            analyzers_run=analyzers_run,
            scan_profile=scan_profile,
        )

    def get_adaptive_scanner(self) -> AdaptiveScanner:
        """Get the adaptive scanner for runtime adaptation.

        Returns:
            Adaptive scanner instance.
        """
        self.adaptive_scanner.reset()
        return self.adaptive_scanner

    def process_interim_findings(
        self,
        findings: list[Finding],
    ) -> list[ScanAdjustment]:
        """Process findings during scan for adaptation.

        Args:
            findings: New findings discovered.

        Returns:
            Any plan adjustments.
        """
        return self.adaptive_scanner.process_findings(findings)

    def get_predictions(self, deployment_id: str) -> dict[str, Any]:
        """Get predictions for a deployment.

        Args:
            deployment_id: Deployment to predict.

        Returns:
            Prediction data.
        """
        return self.history.predict_findings(deployment_id)

    def get_stats(self, deployment_id: str) -> dict[str, Any]:
        """Get deployment statistics.

        Args:
            deployment_id: Deployment to analyze.

        Returns:
            Statistics dictionary.
        """
        stats = self.history.get_deployment_stats(deployment_id)
        return stats.to_dict()

    def get_analyzer_effectiveness(self, days: int = 30) -> dict[str, float]:
        """Get analyzer effectiveness scores.

        Args:
            days: Days of history to analyze.

        Returns:
            Effectiveness scores by analyzer.
        """
        effectiveness = self.history.get_analyzer_effectiveness(days)
        return {k.value: v for k, v in effectiveness.items()}


def create_optimizer(
    strategy: str = "balanced",
    use_history: bool = True,
    max_scan_seconds: int = 0,
) -> ScanOptimizer:
    """Create a scan optimizer with common settings.

    Args:
        strategy: Adaptive strategy ("none", "conservative", "balanced", "aggressive").
        use_history: Whether to use historical data.
        max_scan_seconds: Time budget (0 = unlimited).

    Returns:
        Configured optimizer.
    """
    strategy_map = {
        "none": AdaptiveStrategy.NONE,
        "conservative": AdaptiveStrategy.CONSERVATIVE,
        "balanced": AdaptiveStrategy.BALANCED,
        "aggressive": AdaptiveStrategy.AGGRESSIVE,
    }

    config = OptimizationConfig(
        adaptive_strategy=strategy_map.get(strategy, AdaptiveStrategy.BALANCED),
        use_history=use_history,
        max_scan_seconds=max_scan_seconds,
    )

    return ScanOptimizer(config=config)
