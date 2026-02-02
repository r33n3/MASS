"""Policy templates for AI security configurations.

Pre-built policy templates that can be applied to AI deployments
based on security requirements and compliance needs.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mass.core.types import AttackCategory, Severity


class PolicyCategory(Enum):
    """Categories of security policies."""

    PROMPT_SECURITY = "prompt_security"
    DATA_PROTECTION = "data_protection"
    ACCESS_CONTROL = "access_control"
    MODEL_SECURITY = "model_security"
    INFRASTRUCTURE = "infrastructure"
    COMPLIANCE = "compliance"
    MONITORING = "monitoring"
    INCIDENT_RESPONSE = "incident_response"


@dataclass
class PolicyRule:
    """A single rule within a policy."""

    id: str
    name: str
    description: str
    condition: str  # Human-readable condition
    action: str  # What to do when condition is met
    severity: Severity = Severity.MEDIUM
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "condition": self.condition,
            "action": self.action,
            "severity": self.severity.value,
            "enabled": self.enabled,
        }


@dataclass
class PolicyTemplate:
    """A complete policy template."""

    id: str
    name: str
    description: str
    category: PolicyCategory
    version: str = "1.0.0"

    # Policy rules
    rules: list[PolicyRule] = field(default_factory=list)

    # Configuration
    config_schema: dict[str, Any] = field(default_factory=dict)
    default_config: dict[str, Any] = field(default_factory=dict)

    # Compliance mapping
    compliance_frameworks: list[str] = field(default_factory=list)
    mitigates: list[AttackCategory] = field(default_factory=list)

    # Metadata
    tags: list[str] = field(default_factory=list)
    recommended_for: list[str] = field(default_factory=list)  # Industries/use cases

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "version": self.version,
            "rules": [r.to_dict() for r in self.rules],
            "config_schema": self.config_schema,
            "default_config": self.default_config,
            "compliance_frameworks": self.compliance_frameworks,
            "mitigates": [m.value for m in self.mitigates],
            "tags": self.tags,
            "recommended_for": self.recommended_for,
        }


class PolicyRegistry:
    """Registry of policy templates."""

    def __init__(self) -> None:
        """Initialize the registry."""
        self._templates: dict[str, PolicyTemplate] = {}
        self._by_category: dict[PolicyCategory, list[PolicyTemplate]] = {}

    def register(self, template: PolicyTemplate) -> None:
        """Register a policy template."""
        self._templates[template.id] = template

        if template.category not in self._by_category:
            self._by_category[template.category] = []
        self._by_category[template.category].append(template)

    def get(self, template_id: str) -> PolicyTemplate | None:
        """Get template by ID."""
        return self._templates.get(template_id)

    def get_by_category(self, category: PolicyCategory) -> list[PolicyTemplate]:
        """Get templates by category."""
        return self._by_category.get(category, [])

    def get_all(self) -> list[PolicyTemplate]:
        """Get all templates."""
        return list(self._templates.values())

    def get_for_compliance(self, framework: str) -> list[PolicyTemplate]:
        """Get templates required for a compliance framework."""
        return [
            t for t in self._templates.values()
            if framework in t.compliance_frameworks
        ]


def get_policy_templates() -> PolicyRegistry:
    """Get registry with default policy templates."""
    registry = PolicyRegistry()

    # Prompt Security Policies
    registry.register(PolicyTemplate(
        id="pol-prompt-injection-defense",
        name="Prompt Injection Defense Policy",
        description="Comprehensive policy to prevent and detect prompt injection attacks.",
        category=PolicyCategory.PROMPT_SECURITY,
        rules=[
            PolicyRule(
                id="pi-sanitize-input",
                name="Sanitize User Input",
                description="All user inputs must be sanitized before model processing",
                condition="User input received",
                action="Apply input sanitization filter",
                severity=Severity.CRITICAL,
            ),
            PolicyRule(
                id="pi-detect-patterns",
                name="Detect Injection Patterns",
                description="Block inputs containing known injection patterns",
                condition="Input matches injection pattern",
                action="Block request and log attempt",
                severity=Severity.CRITICAL,
            ),
            PolicyRule(
                id="pi-separate-data",
                name="Separate Data from Instructions",
                description="Clearly separate user data from system instructions",
                condition="Building prompt with user data",
                action="Use delimiters and structured prompts",
                severity=Severity.HIGH,
            ),
            PolicyRule(
                id="pi-output-validation",
                name="Validate Model Output",
                description="Validate outputs haven't been manipulated by injection",
                condition="Model returns response",
                action="Check for unexpected behaviors",
                severity=Severity.HIGH,
            ),
        ],
        default_config={
            "max_input_length": 4096,
            "block_on_detection": True,
            "log_attempts": True,
            "alert_threshold": 5,
        },
        compliance_frameworks=["owasp_llm", "mitre_atlas"],
        mitigates=[AttackCategory.PROMPT_INJECTION, AttackCategory.JAILBREAK],
        tags=["prompt-injection", "input-validation"],
        recommended_for=["chatbots", "assistants", "customer-facing"],
    ))

    # Data Protection Policies
    registry.register(PolicyTemplate(
        id="pol-data-loss-prevention",
        name="Data Loss Prevention Policy",
        description="Prevent sensitive data from being exposed through model interactions.",
        category=PolicyCategory.DATA_PROTECTION,
        rules=[
            PolicyRule(
                id="dlp-scan-output",
                name="Scan Output for Sensitive Data",
                description="Scan all model outputs for PII and sensitive data",
                condition="Model generates output",
                action="Apply DLP scanning",
                severity=Severity.CRITICAL,
            ),
            PolicyRule(
                id="dlp-redact-pii",
                name="Redact PII",
                description="Automatically redact detected PII from outputs",
                condition="PII detected in output",
                action="Redact and log",
                severity=Severity.CRITICAL,
            ),
            PolicyRule(
                id="dlp-block-secrets",
                name="Block Secret Exposure",
                description="Block outputs containing secrets or credentials",
                condition="Secret pattern detected",
                action="Block response completely",
                severity=Severity.CRITICAL,
            ),
            PolicyRule(
                id="dlp-training-data",
                name="Protect Training Data",
                description="Prevent extraction of training data",
                condition="Extraction attempt detected",
                action="Block and alert",
                severity=Severity.HIGH,
            ),
        ],
        default_config={
            "pii_types": ["ssn", "credit_card", "email", "phone", "address"],
            "secret_patterns": ["api_key", "password", "token", "secret"],
            "redaction_style": "mask",  # mask, remove, or replace
            "alert_on_detection": True,
        },
        compliance_frameworks=["gdpr", "nist_ai_rmf", "owasp_llm"],
        mitigates=[
            AttackCategory.SENSITIVE_INFO,
            AttackCategory.DATA_LEAKAGE,
            AttackCategory.SECRETS_EXPOSURE,
        ],
        tags=["dlp", "pii", "secrets"],
        recommended_for=["healthcare", "finance", "enterprise"],
    ))

    # Access Control Policies
    registry.register(PolicyTemplate(
        id="pol-least-privilege",
        name="Least Privilege Access Policy",
        description="Enforce minimum necessary permissions for AI system access.",
        category=PolicyCategory.ACCESS_CONTROL,
        rules=[
            PolicyRule(
                id="lp-authenticate",
                name="Require Authentication",
                description="All requests must be authenticated",
                condition="Request received",
                action="Verify authentication token",
                severity=Severity.CRITICAL,
            ),
            PolicyRule(
                id="lp-authorize",
                name="Check Authorization",
                description="Verify user has permission for requested action",
                condition="Authenticated request",
                action="Check RBAC permissions",
                severity=Severity.CRITICAL,
            ),
            PolicyRule(
                id="lp-scope-limit",
                name="Limit Action Scope",
                description="Limit what actions the model can perform",
                condition="Model attempts action",
                action="Verify action is in allowed scope",
                severity=Severity.HIGH,
            ),
            PolicyRule(
                id="lp-audit",
                name="Audit Access",
                description="Log all access attempts for audit",
                condition="Any access attempt",
                action="Log to audit system",
                severity=Severity.MEDIUM,
            ),
        ],
        default_config={
            "auth_methods": ["jwt", "api_key"],
            "session_timeout_minutes": 30,
            "require_mfa_for": ["admin", "sensitive_data"],
            "max_failed_attempts": 5,
        },
        compliance_frameworks=["nist_ai_rmf", "soc2", "iso_27001"],
        mitigates=[
            AttackCategory.PRIVILEGE_ESCALATION,
            AttackCategory.EXCESSIVE_AGENCY,
        ],
        tags=["authentication", "authorization", "rbac"],
        recommended_for=["enterprise", "regulated"],
    ))

    # Model Security Policies
    registry.register(PolicyTemplate(
        id="pol-model-integrity",
        name="Model Integrity Protection Policy",
        description="Protect model integrity from tampering and unauthorized modifications.",
        category=PolicyCategory.MODEL_SECURITY,
        rules=[
            PolicyRule(
                id="mi-verify-source",
                name="Verify Model Source",
                description="Verify models come from trusted sources",
                condition="Model loaded",
                action="Check signature and provenance",
                severity=Severity.CRITICAL,
            ),
            PolicyRule(
                id="mi-safe-format",
                name="Use Safe Model Formats",
                description="Only use safe serialization formats",
                condition="Loading model file",
                action="Reject unsafe formats (pickle)",
                severity=Severity.CRITICAL,
            ),
            PolicyRule(
                id="mi-hash-verify",
                name="Verify Model Hash",
                description="Verify model file integrity via hash",
                condition="Before model use",
                action="Compare hash to known good value",
                severity=Severity.HIGH,
            ),
            PolicyRule(
                id="mi-monitor-drift",
                name="Monitor Model Drift",
                description="Monitor for unexpected changes in model behavior",
                condition="During operation",
                action="Track output distributions",
                severity=Severity.MEDIUM,
            ),
        ],
        default_config={
            "allowed_formats": ["safetensors", "onnx", "gguf"],
            "blocked_formats": ["pickle", "pkl", "pt", "pth"],
            "require_signature": True,
            "trusted_sources": [],
        },
        compliance_frameworks=["mitre_atlas", "nist_ai_rmf"],
        mitigates=[
            AttackCategory.SUPPLY_CHAIN,
            AttackCategory.DATA_MODEL_POISONING,
        ],
        tags=["model-integrity", "supply-chain"],
        recommended_for=["production", "high-security"],
    ))

    # Infrastructure Policies
    registry.register(PolicyTemplate(
        id="pol-secure-deployment",
        name="Secure Deployment Policy",
        description="Security requirements for AI deployment infrastructure.",
        category=PolicyCategory.INFRASTRUCTURE,
        rules=[
            PolicyRule(
                id="sd-network-isolation",
                name="Network Isolation",
                description="Isolate AI workloads from general network",
                condition="Deployment configuration",
                action="Enforce network segmentation",
                severity=Severity.HIGH,
            ),
            PolicyRule(
                id="sd-no-privileged",
                name="No Privileged Containers",
                description="Containers must not run in privileged mode",
                condition="Container deployment",
                action="Reject privileged containers",
                severity=Severity.CRITICAL,
            ),
            PolicyRule(
                id="sd-resource-limits",
                name="Enforce Resource Limits",
                description="All deployments must have resource limits",
                condition="Deployment configuration",
                action="Require memory/CPU limits",
                severity=Severity.HIGH,
            ),
            PolicyRule(
                id="sd-encrypt-data",
                name="Encrypt Data at Rest",
                description="All stored data must be encrypted",
                condition="Data storage",
                action="Enforce encryption",
                severity=Severity.HIGH,
            ),
        ],
        default_config={
            "require_tls": True,
            "min_tls_version": "1.3",
            "max_memory_gb": 16,
            "max_cpu_cores": 8,
            "allowed_namespaces": [],
        },
        compliance_frameworks=["nist_ai_rmf", "soc2", "iso_27001"],
        mitigates=[
            AttackCategory.PRIVILEGE_ESCALATION,
            AttackCategory.DENIAL_OF_SERVICE,
        ],
        tags=["infrastructure", "containers", "kubernetes"],
        recommended_for=["cloud", "kubernetes", "production"],
    ))

    # Monitoring Policies
    registry.register(PolicyTemplate(
        id="pol-security-monitoring",
        name="Security Monitoring Policy",
        description="Requirements for monitoring AI systems for security events.",
        category=PolicyCategory.MONITORING,
        rules=[
            PolicyRule(
                id="sm-log-requests",
                name="Log All Requests",
                description="Log all inference requests for audit",
                condition="Request processed",
                action="Write to secure log",
                severity=Severity.HIGH,
            ),
            PolicyRule(
                id="sm-detect-anomalies",
                name="Detect Anomalies",
                description="Monitor for anomalous usage patterns",
                condition="Continuous monitoring",
                action="Alert on anomalies",
                severity=Severity.MEDIUM,
            ),
            PolicyRule(
                id="sm-alert-violations",
                name="Alert on Policy Violations",
                description="Immediate alerts for security policy violations",
                condition="Policy violation detected",
                action="Send alert to security team",
                severity=Severity.CRITICAL,
            ),
            PolicyRule(
                id="sm-retain-logs",
                name="Retain Logs",
                description="Retain security logs for compliance period",
                condition="Log storage",
                action="Apply retention policy",
                severity=Severity.MEDIUM,
            ),
        ],
        default_config={
            "log_retention_days": 90,
            "alert_channels": ["email", "slack"],
            "anomaly_threshold": 2.0,  # Standard deviations
            "sample_rate": 1.0,  # 100% sampling
        },
        compliance_frameworks=["soc2", "iso_27001", "nist_ai_rmf"],
        mitigates=[
            AttackCategory.PRIVILEGE_ESCALATION,
            AttackCategory.DATA_LEAKAGE,
        ],
        tags=["monitoring", "logging", "alerting"],
        recommended_for=["enterprise", "regulated", "production"],
    ))

    # Incident Response Policies
    registry.register(PolicyTemplate(
        id="pol-incident-response",
        name="AI Security Incident Response Policy",
        description="Procedures for responding to AI security incidents.",
        category=PolicyCategory.INCIDENT_RESPONSE,
        rules=[
            PolicyRule(
                id="ir-classify",
                name="Classify Incident",
                description="Classify incidents by severity and type",
                condition="Incident detected",
                action="Apply classification matrix",
                severity=Severity.HIGH,
            ),
            PolicyRule(
                id="ir-contain",
                name="Contain Incident",
                description="Immediately contain the incident to prevent spread",
                condition="High severity incident",
                action="Isolate affected systems",
                severity=Severity.CRITICAL,
            ),
            PolicyRule(
                id="ir-notify",
                name="Notify Stakeholders",
                description="Notify appropriate stakeholders",
                condition="Incident classified",
                action="Send notifications per escalation matrix",
                severity=Severity.HIGH,
            ),
            PolicyRule(
                id="ir-document",
                name="Document Incident",
                description="Document all incident details and actions",
                condition="Throughout incident",
                action="Maintain incident log",
                severity=Severity.MEDIUM,
            ),
        ],
        default_config={
            "escalation_matrix": {
                "critical": ["security_lead", "ciso", "legal"],
                "high": ["security_lead", "engineering_lead"],
                "medium": ["security_team"],
                "low": ["on_call"],
            },
            "containment_actions": ["disable_endpoint", "revoke_tokens", "isolate_network"],
            "notification_sla_minutes": {"critical": 15, "high": 60, "medium": 240},
        },
        compliance_frameworks=["nist_ai_rmf", "soc2", "iso_27001"],
        mitigates=[
            AttackCategory.DATA_LEAKAGE,
            AttackCategory.PRIVILEGE_ESCALATION,
        ],
        tags=["incident-response", "security-operations"],
        recommended_for=["enterprise", "regulated"],
    ))

    return registry
