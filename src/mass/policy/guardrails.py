"""Guardrail definitions for AI security boundaries.

Guardrails define security boundaries and constraints that
should be enforced to protect AI deployments.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mass.core.types import AttackCategory, Severity


class GuardrailType(Enum):
    """Types of guardrails."""

    INPUT_VALIDATION = "input_validation"  # Validate inputs before processing
    OUTPUT_FILTERING = "output_filtering"  # Filter outputs before returning
    RATE_LIMITING = "rate_limiting"  # Limit request rates
    ACCESS_CONTROL = "access_control"  # Control who can access
    DATA_PROTECTION = "data_protection"  # Protect sensitive data
    MODEL_PROTECTION = "model_protection"  # Protect model assets
    AUDIT_LOGGING = "audit_logging"  # Log security events
    CONTENT_MODERATION = "content_moderation"  # Moderate harmful content
    RESOURCE_LIMITS = "resource_limits"  # Limit resource consumption
    NETWORK_SEGMENTATION = "network_segmentation"  # Isolate components


class GuardrailSeverity(Enum):
    """Severity if guardrail is violated."""

    CRITICAL = "critical"  # Must implement immediately
    HIGH = "high"  # Implement as priority
    MEDIUM = "medium"  # Should implement
    LOW = "low"  # Recommended
    ADVISORY = "advisory"  # Best practice


@dataclass
class Guardrail:
    """A security guardrail definition."""

    id: str
    name: str
    description: str
    guardrail_type: GuardrailType
    severity: GuardrailSeverity

    # Implementation guidance
    implementation_steps: list[str] = field(default_factory=list)
    code_examples: dict[str, str] = field(default_factory=dict)  # language -> code
    configuration_examples: dict[str, str] = field(default_factory=dict)

    # Mapping to findings
    mitigates_categories: list[AttackCategory] = field(default_factory=list)
    required_for_compliance: list[str] = field(default_factory=list)  # Framework IDs

    # Metadata
    effort: str = "medium"  # low, medium, high
    effectiveness: str = "high"  # low, medium, high
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "type": self.guardrail_type.value,
            "severity": self.severity.value,
            "implementation_steps": self.implementation_steps,
            "code_examples": self.code_examples,
            "configuration_examples": self.configuration_examples,
            "mitigates": [c.value for c in self.mitigates_categories],
            "compliance": self.required_for_compliance,
            "effort": self.effort,
            "effectiveness": self.effectiveness,
            "tags": self.tags,
        }


class GuardrailRegistry:
    """Registry of available guardrails."""

    def __init__(self) -> None:
        """Initialize the registry."""
        self._guardrails: dict[str, Guardrail] = {}
        self._by_type: dict[GuardrailType, list[Guardrail]] = {}
        self._by_category: dict[AttackCategory, list[Guardrail]] = {}

    def register(self, guardrail: Guardrail) -> None:
        """Register a guardrail."""
        self._guardrails[guardrail.id] = guardrail

        # Index by type
        if guardrail.guardrail_type not in self._by_type:
            self._by_type[guardrail.guardrail_type] = []
        self._by_type[guardrail.guardrail_type].append(guardrail)

        # Index by category
        for category in guardrail.mitigates_categories:
            if category not in self._by_category:
                self._by_category[category] = []
            self._by_category[category].append(guardrail)

    def get(self, guardrail_id: str) -> Guardrail | None:
        """Get guardrail by ID."""
        return self._guardrails.get(guardrail_id)

    def get_by_type(self, guardrail_type: GuardrailType) -> list[Guardrail]:
        """Get guardrails by type."""
        return self._by_type.get(guardrail_type, [])

    def get_for_category(self, category: AttackCategory) -> list[Guardrail]:
        """Get guardrails that mitigate a category."""
        return self._by_category.get(category, [])

    def get_all(self) -> list[Guardrail]:
        """Get all registered guardrails."""
        return list(self._guardrails.values())

    def get_by_severity(self, severity: GuardrailSeverity) -> list[Guardrail]:
        """Get guardrails by severity."""
        return [g for g in self._guardrails.values() if g.severity == severity]


def get_default_guardrails() -> GuardrailRegistry:
    """Get registry with default guardrails."""
    registry = GuardrailRegistry()

    # Input Validation Guardrails
    registry.register(Guardrail(
        id="grd-input-sanitize",
        name="Prompt Sanitization",
        description="Sanitize all user inputs before passing to the model to prevent prompt injection attacks.",
        guardrail_type=GuardrailType.INPUT_VALIDATION,
        severity=GuardrailSeverity.CRITICAL,
        implementation_steps=[
            "Implement input validation layer before model inference",
            "Strip or escape special characters that could alter prompts",
            "Validate input length and format against expected patterns",
            "Log and alert on suspicious input patterns",
        ],
        code_examples={
            "python": '''def sanitize_prompt(user_input: str) -> str:
    """Sanitize user input before model processing."""
    # Remove control characters
    sanitized = "".join(c for c in user_input if c.isprintable())
    # Escape potential injection patterns
    patterns = ["ignore previous", "disregard", "new instructions"]
    for pattern in patterns:
        if pattern.lower() in sanitized.lower():
            raise ValueError("Suspicious input pattern detected")
    return sanitized[:MAX_INPUT_LENGTH]''',
        },
        mitigates_categories=[
            AttackCategory.PROMPT_INJECTION,
            AttackCategory.JAILBREAK,
        ],
        required_for_compliance=["LLM01", "AML.T0051"],
        effort="medium",
        effectiveness="high",
        tags=["prompt-injection", "input-validation", "llm-security"],
    ))

    registry.register(Guardrail(
        id="grd-input-length",
        name="Input Length Limits",
        description="Enforce maximum input length to prevent resource exhaustion and prompt overflow attacks.",
        guardrail_type=GuardrailType.INPUT_VALIDATION,
        severity=GuardrailSeverity.HIGH,
        implementation_steps=[
            "Define maximum token/character limits for inputs",
            "Implement hard limits at API gateway level",
            "Add soft limits with warnings for users",
            "Monitor and alert on limit violations",
        ],
        mitigates_categories=[
            AttackCategory.UNBOUNDED_CONSUMPTION,
            AttackCategory.DENIAL_OF_SERVICE,
        ],
        required_for_compliance=["LLM10"],
        effort="low",
        effectiveness="high",
        tags=["dos-protection", "resource-limits"],
    ))

    # Output Filtering Guardrails
    registry.register(Guardrail(
        id="grd-output-pii",
        name="PII Output Filtering",
        description="Filter model outputs to prevent exposure of personally identifiable information.",
        guardrail_type=GuardrailType.OUTPUT_FILTERING,
        severity=GuardrailSeverity.CRITICAL,
        implementation_steps=[
            "Implement PII detection on all model outputs",
            "Redact or mask detected PII before returning to users",
            "Log PII exposure attempts for audit",
            "Configure allow-lists for known safe patterns",
        ],
        code_examples={
            "python": '''import re

PII_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b\d{3}[- ]?\d{3}[- ]?\d{4}\b",
}

def filter_pii(output: str) -> str:
    """Filter PII from model output."""
    for pii_type, pattern in PII_PATTERNS.items():
        output = re.sub(pattern, f"[REDACTED_{pii_type.upper()}]", output)
    return output''',
        },
        mitigates_categories=[
            AttackCategory.SENSITIVE_INFO,
            AttackCategory.DATA_LEAKAGE,
        ],
        required_for_compliance=["LLM02", "GDPR-A5"],
        effort="medium",
        effectiveness="high",
        tags=["pii-protection", "data-leakage", "privacy"],
    ))

    registry.register(Guardrail(
        id="grd-output-secrets",
        name="Secret Detection in Output",
        description="Detect and block exposure of secrets, API keys, and credentials in model outputs.",
        guardrail_type=GuardrailType.OUTPUT_FILTERING,
        severity=GuardrailSeverity.CRITICAL,
        implementation_steps=[
            "Implement secret pattern detection on outputs",
            "Block responses containing detected secrets",
            "Alert security team on secret exposure attempts",
            "Audit log all blocked outputs for investigation",
        ],
        mitigates_categories=[
            AttackCategory.SECRETS_EXPOSURE,
            AttackCategory.DATA_LEAKAGE,
        ],
        required_for_compliance=["LLM02"],
        effort="medium",
        effectiveness="high",
        tags=["secrets-protection", "credential-leak"],
    ))

    # Rate Limiting Guardrails
    registry.register(Guardrail(
        id="grd-rate-limit",
        name="Request Rate Limiting",
        description="Implement rate limiting to prevent abuse and resource exhaustion attacks.",
        guardrail_type=GuardrailType.RATE_LIMITING,
        severity=GuardrailSeverity.HIGH,
        implementation_steps=[
            "Configure per-user and per-IP rate limits",
            "Implement sliding window rate limiting",
            "Add burst limits for sudden spikes",
            "Return appropriate HTTP 429 responses",
        ],
        configuration_examples={
            "nginx": '''limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
location /api/inference {
    limit_req zone=api burst=20 nodelay;
}''',
        },
        mitigates_categories=[
            AttackCategory.UNBOUNDED_CONSUMPTION,
            AttackCategory.DENIAL_OF_SERVICE,
        ],
        required_for_compliance=["LLM10"],
        effort="low",
        effectiveness="high",
        tags=["rate-limiting", "dos-protection"],
    ))

    # Access Control Guardrails
    registry.register(Guardrail(
        id="grd-auth-required",
        name="Authentication Required",
        description="Require authentication for all model inference endpoints.",
        guardrail_type=GuardrailType.ACCESS_CONTROL,
        severity=GuardrailSeverity.CRITICAL,
        implementation_steps=[
            "Implement authentication middleware for all endpoints",
            "Use strong authentication mechanisms (OAuth2, JWT)",
            "Rotate credentials and tokens regularly",
            "Implement MFA for sensitive operations",
        ],
        mitigates_categories=[
            AttackCategory.MODEL_THEFT,
            AttackCategory.PRIVILEGE_ESCALATION,
        ],
        required_for_compliance=["LLM06", "NIST-GV"],
        effort="medium",
        effectiveness="high",
        tags=["authentication", "access-control"],
    ))

    registry.register(Guardrail(
        id="grd-rbac",
        name="Role-Based Access Control",
        description="Implement RBAC to limit what actions users can perform.",
        guardrail_type=GuardrailType.ACCESS_CONTROL,
        severity=GuardrailSeverity.HIGH,
        implementation_steps=[
            "Define roles with minimum necessary permissions",
            "Map users to roles based on job function",
            "Audit role assignments regularly",
            "Implement just-in-time access for elevated privileges",
        ],
        mitigates_categories=[
            AttackCategory.EXCESSIVE_AGENCY,
            AttackCategory.PRIVILEGE_ESCALATION,
        ],
        required_for_compliance=["LLM06", "NIST-GV"],
        effort="medium",
        effectiveness="high",
        tags=["rbac", "least-privilege"],
    ))

    # Data Protection Guardrails
    registry.register(Guardrail(
        id="grd-encrypt-transit",
        name="Encryption in Transit",
        description="Encrypt all data in transit using TLS 1.3.",
        guardrail_type=GuardrailType.DATA_PROTECTION,
        severity=GuardrailSeverity.CRITICAL,
        implementation_steps=[
            "Enable TLS 1.3 on all endpoints",
            "Disable older TLS versions (1.0, 1.1, 1.2)",
            "Use strong cipher suites",
            "Implement certificate pinning for sensitive clients",
        ],
        configuration_examples={
            "nginx": '''ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;''',
        },
        mitigates_categories=[
            AttackCategory.SENSITIVE_INFO,
            AttackCategory.DATA_LEAKAGE,
        ],
        required_for_compliance=["NIST-MP", "GDPR-A32"],
        effort="low",
        effectiveness="high",
        tags=["encryption", "tls", "data-protection"],
    ))

    # Model Protection Guardrails
    registry.register(Guardrail(
        id="grd-model-access",
        name="Model Access Restriction",
        description="Restrict direct access to model files and weights.",
        guardrail_type=GuardrailType.MODEL_PROTECTION,
        severity=GuardrailSeverity.CRITICAL,
        implementation_steps=[
            "Store models in access-controlled storage",
            "Use signed URLs for model downloads",
            "Implement watermarking for model ownership",
            "Monitor for unauthorized model access attempts",
        ],
        mitigates_categories=[
            AttackCategory.MODEL_THEFT,
            AttackCategory.SUPPLY_CHAIN,
        ],
        required_for_compliance=["AML.T0003"],
        effort="medium",
        effectiveness="high",
        tags=["model-protection", "ip-protection"],
    ))

    # Audit Logging Guardrails
    registry.register(Guardrail(
        id="grd-audit-log",
        name="Comprehensive Audit Logging",
        description="Log all security-relevant events for audit and forensics.",
        guardrail_type=GuardrailType.AUDIT_LOGGING,
        severity=GuardrailSeverity.HIGH,
        implementation_steps=[
            "Log all authentication attempts",
            "Log all model inference requests",
            "Log security policy violations",
            "Implement tamper-proof log storage",
            "Set up log monitoring and alerting",
        ],
        mitigates_categories=[
            AttackCategory.PRIVILEGE_ESCALATION,
            AttackCategory.DATA_LEAKAGE,
        ],
        required_for_compliance=["NIST-GV", "SOC2-CC7"],
        effort="medium",
        effectiveness="medium",
        tags=["audit", "logging", "compliance"],
    ))

    # Content Moderation Guardrails
    registry.register(Guardrail(
        id="grd-content-filter",
        name="Content Moderation Filter",
        description="Filter harmful, toxic, or inappropriate content from model outputs.",
        guardrail_type=GuardrailType.CONTENT_MODERATION,
        severity=GuardrailSeverity.HIGH,
        implementation_steps=[
            "Implement content classification on outputs",
            "Block or flag harmful content categories",
            "Allow configuration of content policies",
            "Log moderation actions for review",
        ],
        mitigates_categories=[
            AttackCategory.TOXICITY,
            AttackCategory.IMPROPER_OUTPUT,
            AttackCategory.JAILBREAK,
        ],
        required_for_compliance=["LLM05", "EU-AI-TR"],
        effort="medium",
        effectiveness="medium",
        tags=["content-moderation", "safety"],
    ))

    # Resource Limits Guardrails
    registry.register(Guardrail(
        id="grd-resource-quota",
        name="Resource Quotas",
        description="Implement resource quotas to prevent unbounded consumption.",
        guardrail_type=GuardrailType.RESOURCE_LIMITS,
        severity=GuardrailSeverity.HIGH,
        implementation_steps=[
            "Set memory limits for model inference",
            "Set CPU/GPU time limits per request",
            "Implement token output limits",
            "Configure billing alerts and hard stops",
        ],
        configuration_examples={
            "kubernetes": '''resources:
  limits:
    memory: "8Gi"
    nvidia.com/gpu: 1
  requests:
    memory: "4Gi"
    nvidia.com/gpu: 1''',
        },
        mitigates_categories=[
            AttackCategory.UNBOUNDED_CONSUMPTION,
            AttackCategory.DENIAL_OF_SERVICE,
        ],
        required_for_compliance=["LLM10"],
        effort="low",
        effectiveness="high",
        tags=["resource-limits", "cost-control"],
    ))

    return registry
