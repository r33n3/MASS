"""Remediation template schemas.

Request and response models for the remediation template CRUD API.
"""

from pydantic import BaseModel, ConfigDict, Field

from mass.api.schemas.common import IDMixin, TimestampMixin, PaginationMeta


class GuardrailExample(BaseModel):
    """A guardrail policy code example."""

    model_config = ConfigDict(extra="forbid")

    framework: str = Field(
        ..., description="Guardrail framework: bedrock, nemo, guardrails_ai, custom"
    )
    title: str = Field(..., description="Example title")
    code: str = Field(..., description="Code/policy snippet")


class CodeExample(BaseModel):
    """A remediation code example."""

    model_config = ConfigDict(extra="forbid")

    language: str = Field(..., description="Programming language")
    title: str = Field(..., description="Example title")
    code: str = Field(..., description="Code snippet")


class ReferenceLink(BaseModel):
    """A reference link."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., description="Reference title")
    url: str = Field(..., description="Reference URL")


class RemediationTemplateCreate(BaseModel):
    """Request to create a remediation template."""

    model_config = ConfigDict(extra="forbid")

    category: str = Field(
        ..., description="Attack category (from AttackCategory enum values)"
    )
    subcategory: str | None = Field(
        default=None,
        description="Optional subcategory for more specific guidance",
    )
    title: str = Field(..., min_length=1, max_length=500, description="Template title")
    summary: str = Field(..., min_length=1, description="Brief remediation summary")
    description: str | None = Field(
        default=None, description="Detailed description of the vulnerability and fix"
    )
    severity_default: str | None = Field(
        default=None, description="Default severity: critical, high, medium, low, info"
    )
    steps: list[str] | None = Field(
        default=None, description="Ordered remediation steps"
    )
    guardrail_examples: list[GuardrailExample] | None = Field(
        default=None, description="Guardrail policy examples"
    )
    code_examples: list[CodeExample] | None = Field(
        default=None, description="Code fix examples"
    )
    cwe_ids: list[str] | None = Field(
        default=None, description="Related CWE IDs"
    )
    owasp_ids: list[str] | None = Field(
        default=None, description="Related OWASP LLM Top 10 IDs"
    )
    mitre_ids: list[str] | None = Field(
        default=None, description="Related MITRE ATLAS IDs"
    )
    references: list[ReferenceLink] | None = Field(
        default=None, description="Reference links"
    )
    estimated_effort: str | None = Field(
        default=None, description="Effort estimate: low, medium, high"
    )


class RemediationTemplateUpdate(BaseModel):
    """Request to update a remediation template."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=500)
    summary: str | None = Field(default=None, min_length=1)
    description: str | None = Field(default=None)
    severity_default: str | None = Field(default=None)
    steps: list[str] | None = Field(default=None)
    guardrail_examples: list[GuardrailExample] | None = Field(default=None)
    code_examples: list[CodeExample] | None = Field(default=None)
    cwe_ids: list[str] | None = Field(default=None)
    owasp_ids: list[str] | None = Field(default=None)
    mitre_ids: list[str] | None = Field(default=None)
    references: list[ReferenceLink] | None = Field(default=None)
    estimated_effort: str | None = Field(default=None)
    is_active: bool | None = Field(default=None)


class RemediationTemplateResponse(IDMixin, TimestampMixin):
    """Remediation template response."""

    model_config = ConfigDict(extra="forbid")

    category: str
    subcategory: str | None = None
    title: str
    summary: str
    description: str | None = None
    severity_default: str | None = None
    steps: list[str] | None = None
    guardrail_examples: list[GuardrailExample] | None = None
    code_examples: list[CodeExample] | None = None
    cwe_ids: list[str] | None = None
    owasp_ids: list[str] | None = None
    mitre_ids: list[str] | None = None
    references: list[ReferenceLink] | None = None
    estimated_effort: str | None = None
    is_active: bool = True
    version: int = 1


class RemediationTemplateListResponse(BaseModel):
    """List of remediation templates."""

    model_config = ConfigDict(extra="forbid")

    items: list[RemediationTemplateResponse]
    pagination: PaginationMeta
