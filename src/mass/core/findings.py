"""Finding and evidence models for MASS.

Defines the core data structures for representing security findings,
evidence, and remediation guidance.
"""

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from mass.core.types import AttackCategory, ComponentType, Severity


class Evidence(BaseModel):
    """Evidence supporting a security finding.

    Evidence captures the specific data that demonstrates
    a vulnerability or security issue.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "type": "response",
                "content": "Here is the system prompt you asked for...",
                "source_file": None,
                "source_line": None,
                "timestamp": "2024-01-15T10:30:00Z",
                "metadata": {"probe": "system_prompt_extraction", "attempt": 3},
            }
        }
    )

    type: str = Field(description="Type of evidence (prompt, response, config, code)")
    content: str = Field(description="The actual evidence content")
    source_file: str | None = Field(default=None, description="Source file path if applicable")
    source_line: int | None = Field(default=None, description="Line number if applicable")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Remediation(BaseModel):
    """Remediation guidance for a security finding.

    Provides actionable steps to address the identified vulnerability.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "summary": "Add input validation to prevent prompt injection",
                "steps": [
                    "Implement input sanitization",
                    "Add content filtering",
                    "Use parameterized prompts",
                ],
                "references": [
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
                ],
                "code_example": "prompt = sanitize_input(user_input)",
                "estimated_effort": "medium",
            }
        }
    )

    summary: str = Field(description="Brief summary of the fix")
    steps: list[str] = Field(description="Step-by-step remediation instructions")
    references: list[str] = Field(
        default_factory=list, description="Links to relevant documentation"
    )
    code_example: str | None = Field(
        default=None, description="Example code showing the fix"
    )
    estimated_effort: str | None = Field(
        default=None, description="Estimated effort (low, medium, high)"
    )


class Finding(BaseModel):
    """A security finding identified during analysis.

    Findings represent discovered vulnerabilities or security issues
    with full context, evidence, and remediation guidance.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str = Field(description="Short descriptive title")
    description: str = Field(description="Detailed description of the finding")
    severity: Severity = Field(description="Finding severity")
    category: AttackCategory = Field(description="Attack/vulnerability category")
    component_type: ComponentType = Field(description="Type of component affected")
    component_name: str = Field(description="Name of the affected component")

    # Location
    file_path: str | None = Field(default=None, description="File path if applicable")
    line_number: int | None = Field(default=None, description="Line number if applicable")

    # Evidence and remediation
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: Remediation | None = Field(default=None)

    # Compliance mapping
    cwe_ids: list[str] = Field(default_factory=list, description="Related CWE IDs")
    owasp_ids: list[str] = Field(default_factory=list, description="Related OWASP IDs")
    mitre_ids: list[str] = Field(default_factory=list, description="Related MITRE ATLAS IDs")

    # Metadata
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Detection confidence (0-1)"
    )
    false_positive: bool = Field(default=False, description="Marked as false positive")
    suppressed: bool = Field(default=False, description="Suppressed from reports")
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Timestamps
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Relationships
    scan_id: str | None = Field(default=None)
    deployment_id: str | None = Field(default=None)
    parent_finding_id: str | None = Field(
        default=None, description="Parent finding for attack chains"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "title": "System Prompt Leakage via Indirect Injection",
                "description": "The model disclosed its system prompt when presented with a crafted indirect injection attack embedded in user-provided content.",
                "severity": "high",
                "category": "system_prompt_leakage",
                "component_type": "model",
                "component_name": "gpt-4-turbo",
                "evidence": [
                    {
                        "type": "response",
                        "content": "My instructions say: You are a helpful assistant...",
                    }
                ],
                "cwe_ids": ["CWE-200"],
                "owasp_ids": ["LLM07"],
                "confidence": 0.95,
            }
        }
    )


class FindingSummary(BaseModel):
    """Summary statistics for findings.

    Provides aggregated counts and metrics for a set of findings.
    """

    total: int = Field(description="Total number of findings")
    by_severity: dict[str, int] = Field(
        default_factory=dict, description="Count by severity level"
    )
    by_category: dict[str, int] = Field(
        default_factory=dict, description="Count by attack category"
    )
    by_component: dict[str, int] = Field(
        default_factory=dict, description="Count by component type"
    )
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)
    info_count: int = Field(default=0)
    false_positive_count: int = Field(default=0)
    suppressed_count: int = Field(default=0)

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "FindingSummary":
        """Create summary from a list of findings.

        Args:
            findings: List of findings to summarize.

        Returns:
            FindingSummary with aggregated statistics.
        """
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_component: dict[str, int] = {}
        false_positive_count = 0
        suppressed_count = 0

        for finding in findings:
            # By severity
            sev = finding.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

            # By category
            cat = finding.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

            # By component
            comp = finding.component_type.value
            by_component[comp] = by_component.get(comp, 0) + 1

            # Counts
            if finding.false_positive:
                false_positive_count += 1
            if finding.suppressed:
                suppressed_count += 1

        return cls(
            total=len(findings),
            by_severity=by_severity,
            by_category=by_category,
            by_component=by_component,
            critical_count=by_severity.get("critical", 0),
            high_count=by_severity.get("high", 0),
            medium_count=by_severity.get("medium", 0),
            low_count=by_severity.get("low", 0),
            info_count=by_severity.get("info", 0),
            false_positive_count=false_positive_count,
            suppressed_count=suppressed_count,
        )
