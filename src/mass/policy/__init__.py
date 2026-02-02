"""Policy and Guardrail Recommendation Engine.

Provides policy recommendations, guardrail definitions, and
remediation guidance based on scan findings and risk assessment.
"""

from mass.policy.guardrails import (
    Guardrail,
    GuardrailType,
    GuardrailSeverity,
    GuardrailRegistry,
    get_default_guardrails,
)
from mass.policy.recommendations import (
    Recommendation,
    RecommendationType,
    RecommendationPriority,
    RecommendationEngine,
)
from mass.policy.templates import (
    PolicyTemplate,
    PolicyCategory,
    PolicyRegistry,
    get_policy_templates,
)
from mass.policy.remediation import (
    RemediationAction,
    RemediationPlan,
    RemediationRegistry,
    create_remediation_plan,
)
from mass.policy.engine import (
    PolicyEngine,
    PolicyEngineConfig,
    PolicyReport,
)

__all__ = [
    # Guardrails
    "Guardrail",
    "GuardrailType",
    "GuardrailSeverity",
    "GuardrailRegistry",
    "get_default_guardrails",
    # Recommendations
    "Recommendation",
    "RecommendationType",
    "RecommendationPriority",
    "RecommendationEngine",
    # Policy Templates
    "PolicyTemplate",
    "PolicyCategory",
    "PolicyRegistry",
    "get_policy_templates",
    # Remediation
    "RemediationAction",
    "RemediationPlan",
    "RemediationRegistry",
    "create_remediation_plan",
    # Main Engine
    "PolicyEngine",
    "PolicyEngineConfig",
    "PolicyReport",
]
