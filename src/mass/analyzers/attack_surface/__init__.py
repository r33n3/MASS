"""Attack surface analysis for AI deployments.

Identifies attack vectors and chains across deployment components.
"""

from mass.analyzers.attack_surface.analyzer import (
    AttackSurfaceAnalyzer,
    AttackSurfaceResult,
    AttackVector,
    ComponentInteraction,
    VulnerabilityPath,
    ThreatModel,
)
from mass.analyzers.attack_surface.chains import (
    AttackChain,
    AttackChainDetector,
    ChainStep,
)

__all__ = [
    # Core analyzer
    "AttackSurfaceAnalyzer",
    "AttackSurfaceResult",
    "AttackVector",
    "ComponentInteraction",
    "VulnerabilityPath",
    "ThreatModel",
    # Chain detection
    "AttackChain",
    "AttackChainDetector",
    "ChainStep",
]
