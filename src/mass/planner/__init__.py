"""AI-powered scan planning and optimization.

Provides intelligent scan optimization through risk scoring,
priority ordering, adaptive scanning, and historical learning.
"""

from mass.planner.risk import (
    RiskFactor,
    RiskScore,
    RiskAssessor,
    DeploymentRiskProfile,
)
from mass.planner.priority import (
    AnalyzerPriority,
    PriorityCalculator,
    PrioritizedPlan,
)
from mass.planner.adaptive import (
    AdaptiveStrategy,
    AdaptiveScanner,
    ScanAdjustment,
)
from mass.planner.history import (
    ScanHistoryEntry,
    ScanHistory,
    HistoryStore,
    MemoryHistoryStore,
)
from mass.planner.optimizer import (
    OptimizationConfig,
    OptimizedScan,
    ScanOptimizer,
)

__all__ = [
    # Risk assessment
    "RiskFactor",
    "RiskScore",
    "RiskAssessor",
    "DeploymentRiskProfile",
    # Priority calculation
    "AnalyzerPriority",
    "PriorityCalculator",
    "PrioritizedPlan",
    # Adaptive scanning
    "AdaptiveStrategy",
    "AdaptiveScanner",
    "ScanAdjustment",
    # History tracking
    "ScanHistoryEntry",
    "ScanHistory",
    "HistoryStore",
    "MemoryHistoryStore",
    # Optimization
    "OptimizationConfig",
    "OptimizedScan",
    "ScanOptimizer",
]
