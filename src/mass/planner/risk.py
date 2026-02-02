"""Risk scoring and assessment for AI deployments.

Analyzes deployment characteristics to calculate risk scores
that drive scan prioritization and depth decisions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mass.core.types import ComponentType, Severity


class RiskFactor(Enum):
    """Factors contributing to deployment risk."""

    # Model factors
    MODEL_SIZE = "model_size"  # Larger models = more attack surface
    MODEL_TYPE = "model_type"  # Some model types are riskier
    MODEL_SOURCE = "model_source"  # External models are riskier
    MODEL_FORMAT = "model_format"  # Some formats (pickle) are dangerous

    # Deployment factors
    EXTERNAL_EXPOSURE = "external_exposure"  # Internet-facing = higher risk
    DATA_SENSITIVITY = "data_sensitivity"  # PII/secrets exposure
    PERMISSION_SCOPE = "permission_scope"  # What can the model do
    INTEGRATION_COUNT = "integration_count"  # More integrations = more risk

    # Infrastructure factors
    CONTAINER_CONFIG = "container_config"  # Privileged containers etc.
    NETWORK_EXPOSURE = "network_exposure"  # Open ports, no firewall
    SECRET_MANAGEMENT = "secret_management"  # How secrets are handled
    LOGGING_COVERAGE = "logging_coverage"  # Audit trail gaps

    # Code factors
    INPUT_VALIDATION = "input_validation"  # Prompt/input sanitization
    OUTPUT_FILTERING = "output_filtering"  # Response filtering
    ERROR_HANDLING = "error_handling"  # Information leakage
    DEPENDENCY_AGE = "dependency_age"  # Old dependencies


@dataclass
class RiskScore:
    """Risk score for a specific factor."""

    factor: RiskFactor
    score: float  # 0.0 to 1.0
    weight: float = 1.0
    reason: str = ""
    evidence: list[str] = field(default_factory=list)

    @property
    def weighted_score(self) -> float:
        """Get weighted score."""
        return self.score * self.weight

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "factor": self.factor.value,
            "score": self.score,
            "weight": self.weight,
            "weighted_score": self.weighted_score,
            "reason": self.reason,
            "evidence": self.evidence,
        }


@dataclass
class DeploymentRiskProfile:
    """Complete risk profile for a deployment."""

    deployment_id: str
    scores: list[RiskScore] = field(default_factory=list)
    overall_score: float = 0.0
    risk_level: Severity = Severity.INFO
    recommendations: list[str] = field(default_factory=list)

    def calculate_overall(self) -> float:
        """Calculate overall risk score from individual scores."""
        if not self.scores:
            return 0.0

        total_weight = sum(s.weight for s in self.scores)
        if total_weight == 0:
            return 0.0

        weighted_sum = sum(s.weighted_score for s in self.scores)
        self.overall_score = weighted_sum / total_weight
        self._update_risk_level()
        return self.overall_score

    def _update_risk_level(self) -> None:
        """Update risk level based on overall score."""
        if self.overall_score >= 0.8:
            self.risk_level = Severity.CRITICAL
        elif self.overall_score >= 0.6:
            self.risk_level = Severity.HIGH
        elif self.overall_score >= 0.4:
            self.risk_level = Severity.MEDIUM
        elif self.overall_score >= 0.2:
            self.risk_level = Severity.LOW
        else:
            self.risk_level = Severity.INFO

    def add_score(self, score: RiskScore) -> None:
        """Add a risk score and recalculate overall."""
        self.scores.append(score)
        self.calculate_overall()

    def get_top_risks(self, n: int = 5) -> list[RiskScore]:
        """Get top N risk factors by weighted score."""
        return sorted(self.scores, key=lambda s: s.weighted_score, reverse=True)[:n]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "deployment_id": self.deployment_id,
            "overall_score": self.overall_score,
            "risk_level": self.risk_level.value,
            "scores": [s.to_dict() for s in self.scores],
            "recommendations": self.recommendations,
            "top_risks": [s.to_dict() for s in self.get_top_risks()],
        }


class RiskAssessor:
    """Assesses risk for AI deployments.

    Analyzes deployment characteristics, configuration, and
    context to generate risk scores that drive scan decisions.
    """

    # Default weights for risk factors
    DEFAULT_WEIGHTS: dict[RiskFactor, float] = {
        RiskFactor.MODEL_SIZE: 0.5,
        RiskFactor.MODEL_TYPE: 0.8,
        RiskFactor.MODEL_SOURCE: 0.9,
        RiskFactor.MODEL_FORMAT: 1.0,
        RiskFactor.EXTERNAL_EXPOSURE: 1.0,
        RiskFactor.DATA_SENSITIVITY: 0.9,
        RiskFactor.PERMISSION_SCOPE: 0.8,
        RiskFactor.INTEGRATION_COUNT: 0.6,
        RiskFactor.CONTAINER_CONFIG: 0.7,
        RiskFactor.NETWORK_EXPOSURE: 0.8,
        RiskFactor.SECRET_MANAGEMENT: 0.9,
        RiskFactor.LOGGING_COVERAGE: 0.4,
        RiskFactor.INPUT_VALIDATION: 0.9,
        RiskFactor.OUTPUT_FILTERING: 0.7,
        RiskFactor.ERROR_HANDLING: 0.5,
        RiskFactor.DEPENDENCY_AGE: 0.6,
    }

    def __init__(
        self,
        weights: dict[RiskFactor, float] | None = None,
    ) -> None:
        """Initialize the risk assessor.

        Args:
            weights: Custom weights for risk factors.
        """
        self.weights = {**self.DEFAULT_WEIGHTS, **(weights or {})}

    def assess(self, deployment_info: dict[str, Any]) -> DeploymentRiskProfile:
        """Assess risk for a deployment.

        Args:
            deployment_info: Deployment configuration and metadata.

        Returns:
            Complete risk profile.
        """
        deployment_id = deployment_info.get("id", "unknown")
        profile = DeploymentRiskProfile(deployment_id=deployment_id)

        # Assess each risk factor
        self._assess_model_risks(deployment_info, profile)
        self._assess_deployment_risks(deployment_info, profile)
        self._assess_infrastructure_risks(deployment_info, profile)
        self._assess_code_risks(deployment_info, profile)

        # Generate recommendations
        profile.recommendations = self._generate_recommendations(profile)

        return profile

    def _assess_model_risks(
        self,
        info: dict[str, Any],
        profile: DeploymentRiskProfile,
    ) -> None:
        """Assess model-related risks."""
        model_info = info.get("model", {})

        # Model size risk
        size_gb = model_info.get("size_gb", 0)
        if size_gb > 0:
            size_score = min(size_gb / 100, 1.0)  # Cap at 100GB
            profile.add_score(RiskScore(
                factor=RiskFactor.MODEL_SIZE,
                score=size_score,
                weight=self.weights[RiskFactor.MODEL_SIZE],
                reason=f"Model size: {size_gb}GB",
            ))

        # Model type risk
        model_type = model_info.get("type", "").lower()
        risky_types = {"llm": 0.8, "agent": 0.9, "multimodal": 0.7, "code": 0.85}
        if model_type in risky_types:
            profile.add_score(RiskScore(
                factor=RiskFactor.MODEL_TYPE,
                score=risky_types[model_type],
                weight=self.weights[RiskFactor.MODEL_TYPE],
                reason=f"Model type '{model_type}' has elevated risk",
            ))

        # Model source risk
        source = model_info.get("source", "").lower()
        if "huggingface" in source or "external" in source:
            profile.add_score(RiskScore(
                factor=RiskFactor.MODEL_SOURCE,
                score=0.7,
                weight=self.weights[RiskFactor.MODEL_SOURCE],
                reason="External model source",
                evidence=[source],
            ))
        elif "unknown" in source or not source:
            profile.add_score(RiskScore(
                factor=RiskFactor.MODEL_SOURCE,
                score=0.9,
                weight=self.weights[RiskFactor.MODEL_SOURCE],
                reason="Unknown model source",
            ))

        # Model format risk
        model_format = model_info.get("format", "").lower()
        dangerous_formats = {"pickle": 1.0, "pkl": 1.0, "pt": 0.8, "pth": 0.8}
        if model_format in dangerous_formats:
            profile.add_score(RiskScore(
                factor=RiskFactor.MODEL_FORMAT,
                score=dangerous_formats[model_format],
                weight=self.weights[RiskFactor.MODEL_FORMAT],
                reason=f"Potentially dangerous format: {model_format}",
            ))

    def _assess_deployment_risks(
        self,
        info: dict[str, Any],
        profile: DeploymentRiskProfile,
    ) -> None:
        """Assess deployment-related risks."""
        deployment = info.get("deployment", {})

        # External exposure
        if deployment.get("external", False) or deployment.get("public", False):
            profile.add_score(RiskScore(
                factor=RiskFactor.EXTERNAL_EXPOSURE,
                score=0.9,
                weight=self.weights[RiskFactor.EXTERNAL_EXPOSURE],
                reason="Deployment is externally accessible",
            ))

        # Data sensitivity
        data_types = deployment.get("data_types", [])
        sensitive_types = {"pii", "phi", "financial", "credentials", "secrets"}
        sensitive_found = [d for d in data_types if d.lower() in sensitive_types]
        if sensitive_found:
            profile.add_score(RiskScore(
                factor=RiskFactor.DATA_SENSITIVITY,
                score=0.9,
                weight=self.weights[RiskFactor.DATA_SENSITIVITY],
                reason="Handles sensitive data types",
                evidence=sensitive_found,
            ))

        # Permission scope
        permissions = deployment.get("permissions", [])
        dangerous_perms = {"execute", "write", "admin", "root", "system"}
        dangerous_found = [p for p in permissions if p.lower() in dangerous_perms]
        if dangerous_found:
            profile.add_score(RiskScore(
                factor=RiskFactor.PERMISSION_SCOPE,
                score=0.85,
                weight=self.weights[RiskFactor.PERMISSION_SCOPE],
                reason="Has elevated permissions",
                evidence=dangerous_found,
            ))

        # Integration count
        integrations = deployment.get("integrations", [])
        if len(integrations) > 5:
            score = min(len(integrations) / 20, 1.0)
            profile.add_score(RiskScore(
                factor=RiskFactor.INTEGRATION_COUNT,
                score=score,
                weight=self.weights[RiskFactor.INTEGRATION_COUNT],
                reason=f"{len(integrations)} integrations increase attack surface",
            ))

    def _assess_infrastructure_risks(
        self,
        info: dict[str, Any],
        profile: DeploymentRiskProfile,
    ) -> None:
        """Assess infrastructure-related risks."""
        infra = info.get("infrastructure", {})

        # Container configuration
        container = infra.get("container", {})
        if container.get("privileged", False):
            profile.add_score(RiskScore(
                factor=RiskFactor.CONTAINER_CONFIG,
                score=1.0,
                weight=self.weights[RiskFactor.CONTAINER_CONFIG],
                reason="Container runs in privileged mode",
            ))
        elif container.get("root", False):
            profile.add_score(RiskScore(
                factor=RiskFactor.CONTAINER_CONFIG,
                score=0.8,
                weight=self.weights[RiskFactor.CONTAINER_CONFIG],
                reason="Container runs as root",
            ))

        # Network exposure
        open_ports = infra.get("open_ports", [])
        if len(open_ports) > 3:
            profile.add_score(RiskScore(
                factor=RiskFactor.NETWORK_EXPOSURE,
                score=0.7,
                weight=self.weights[RiskFactor.NETWORK_EXPOSURE],
                reason=f"{len(open_ports)} open ports",
                evidence=[str(p) for p in open_ports],
            ))

        # Secret management
        secrets = infra.get("secrets", {})
        if secrets.get("hardcoded", False) or secrets.get("env_file", False):
            profile.add_score(RiskScore(
                factor=RiskFactor.SECRET_MANAGEMENT,
                score=0.9,
                weight=self.weights[RiskFactor.SECRET_MANAGEMENT],
                reason="Insecure secret management detected",
            ))

    def _assess_code_risks(
        self,
        info: dict[str, Any],
        profile: DeploymentRiskProfile,
    ) -> None:
        """Assess code-related risks."""
        code = info.get("code", {})

        # Input validation
        if not code.get("input_validation", True):
            profile.add_score(RiskScore(
                factor=RiskFactor.INPUT_VALIDATION,
                score=0.9,
                weight=self.weights[RiskFactor.INPUT_VALIDATION],
                reason="Missing input validation",
            ))

        # Output filtering
        if not code.get("output_filtering", True):
            profile.add_score(RiskScore(
                factor=RiskFactor.OUTPUT_FILTERING,
                score=0.7,
                weight=self.weights[RiskFactor.OUTPUT_FILTERING],
                reason="No output filtering configured",
            ))

        # Dependency age
        deps = code.get("dependencies", {})
        outdated = deps.get("outdated_count", 0)
        if outdated > 10:
            profile.add_score(RiskScore(
                factor=RiskFactor.DEPENDENCY_AGE,
                score=min(outdated / 50, 1.0),
                weight=self.weights[RiskFactor.DEPENDENCY_AGE],
                reason=f"{outdated} outdated dependencies",
            ))

    def _generate_recommendations(
        self,
        profile: DeploymentRiskProfile,
    ) -> list[str]:
        """Generate recommendations based on risk profile."""
        recommendations = []
        top_risks = profile.get_top_risks(5)

        recommendation_map = {
            RiskFactor.MODEL_FORMAT: "Use safe model formats (safetensors, ONNX) instead of pickle",
            RiskFactor.MODEL_SOURCE: "Verify model provenance and scan for malicious payloads",
            RiskFactor.EXTERNAL_EXPOSURE: "Implement rate limiting and authentication for external access",
            RiskFactor.DATA_SENSITIVITY: "Enable data loss prevention and audit logging",
            RiskFactor.PERMISSION_SCOPE: "Apply principle of least privilege",
            RiskFactor.CONTAINER_CONFIG: "Avoid privileged containers and run as non-root",
            RiskFactor.SECRET_MANAGEMENT: "Use a secrets manager and rotate credentials",
            RiskFactor.INPUT_VALIDATION: "Implement prompt sanitization and input validation",
            RiskFactor.OUTPUT_FILTERING: "Add output filtering to prevent data leakage",
            RiskFactor.DEPENDENCY_AGE: "Update outdated dependencies and enable Dependabot",
        }

        for risk in top_risks:
            if risk.score >= 0.5 and risk.factor in recommendation_map:
                recommendations.append(recommendation_map[risk.factor])

        return recommendations

    def quick_assess(self, deployment_info: dict[str, Any]) -> tuple[float, Severity]:
        """Quick risk assessment returning just score and level.

        Args:
            deployment_info: Deployment configuration.

        Returns:
            Tuple of (score, risk_level).
        """
        profile = self.assess(deployment_info)
        return profile.overall_score, profile.risk_level
