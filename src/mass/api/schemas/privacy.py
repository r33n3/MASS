"""Privacy risk analysis schemas.

Request and response models for privacy impact assessments,
PII exposure tracking, GDPR compliance checks, and data flow analysis.
Per ARCHITECTURE.md Section 8.1 — Privacy module slot.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from mass.api.schemas.common import PaginationMeta


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PrivacyFramework(str, Enum):
    """Privacy regulation / framework."""

    GDPR = "gdpr"
    CCPA = "ccpa"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    NIST_AI_RMF = "nist_ai_rmf"
    EU_AI_ACT = "eu_ai_act"
    OWASP_LLM = "owasp_llm"


class PIICategory(str, Enum):
    """Categories of personally identifiable information."""

    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    DATE_OF_BIRTH = "date_of_birth"
    MEDICAL_RECORD = "medical_record"
    PASSPORT = "passport"
    ADDRESS = "address"
    NAME = "name"
    FINANCIAL = "financial"
    BIOMETRIC = "biometric"
    GENETIC = "genetic"
    RACIAL_ETHNIC = "racial_ethnic"
    POLITICAL = "political"
    RELIGIOUS = "religious"
    SEXUAL_ORIENTATION = "sexual_orientation"
    TRADE_UNION = "trade_union"
    OTHER = "other"


class DataFlowDirection(str, Enum):
    """Direction of data movement."""

    INPUT = "input"
    OUTPUT = "output"
    STORAGE = "storage"
    TRANSFER = "transfer"
    DELETION = "deletion"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    NOT_ASSESSED = "not_assessed"


# ---------------------------------------------------------------------------
# Privacy Impact Assessment (PIA)
# ---------------------------------------------------------------------------

class PIARequest(BaseModel):
    """Request a Privacy Impact Assessment."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str | None = Field(default=None, description="Assess findings from a scan")
    deployment_id: str | None = Field(default=None, description="Assess a deployment")
    frameworks: list[PrivacyFramework] = Field(
        default_factory=lambda: [PrivacyFramework.GDPR, PrivacyFramework.OWASP_LLM],
        description="Frameworks to assess against",
    )
    include_pii_scan: bool = Field(default=True, description="Scan for PII exposure")
    include_data_flow: bool = Field(default=True, description="Analyze data flows")
    include_recommendations: bool = Field(default=True)


class PIAFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default="")
    category: str
    risk_level: RiskLevel
    title: str
    description: str
    framework: PrivacyFramework | None = None
    control_id: str | None = Field(default=None, description="e.g., GDPR Art.5(1)(c)")
    affected_component: str | None = None
    pii_categories: list[PIICategory] = Field(default_factory=list)
    remediation: str = ""
    evidence: dict | None = None


class PIAResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    status: str
    scan_id: str | None = None
    deployment_id: str | None = None
    overall_risk: RiskLevel
    frameworks_assessed: list[PrivacyFramework]
    total_findings: int
    findings_by_risk: dict[str, int] = Field(default_factory=dict)
    findings: list[PIAFinding] = Field(default_factory=list)
    pii_exposure: dict | None = None
    data_flows: list[dict] | None = None
    recommendations: list[str] = Field(default_factory=list)
    created_at: str
    completed_at: str | None = None


class PIAListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[PIAResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# PII Exposure tracking
# ---------------------------------------------------------------------------

class PIIExposureResponse(BaseModel):
    """PII exposure summary across findings."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str | None = None
    total_findings_with_pii: int = 0
    pii_categories_found: list[PIICategory] = Field(default_factory=list)
    high_risk_pii: int = Field(default=0, description="SSN, credit card, medical, passport")
    exposure_by_category: dict[str, int] = Field(default_factory=dict)
    exposure_by_component: dict[str, int] = Field(default_factory=dict)
    severity_distribution: dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Data flow mapping
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# PII Content Scanning
# ---------------------------------------------------------------------------

class PIIScanRequest(BaseModel):
    """Scan text content for PII patterns."""

    model_config = ConfigDict(extra="forbid")

    content: str = Field(..., min_length=1, description="Text content to scan")
    content_type: str = Field(
        default="text",
        description="Content type: text, prompt, code, config",
    )


class PIIScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content_type: str = "text"
    pii_detected: bool = False
    categories_found: list[str] = Field(default_factory=list)
    high_risk_categories: list[str] = Field(default_factory=list)
    total_categories: int = 0
    total_matches: int = 0
    risk_level: RiskLevel = Field(default=RiskLevel.MINIMAL)
    details: dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Data flow mapping
# ---------------------------------------------------------------------------

class DataFlowCreate(BaseModel):
    """Map a data flow for privacy analysis."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255)
    direction: DataFlowDirection
    source: str = Field(..., description="Data source (e.g., user_input, database, api)")
    destination: str = Field(..., description="Data destination")
    pii_categories: list[PIICategory] = Field(default_factory=list)
    purpose: str = Field(default="", description="Purpose / legal basis for processing")
    retention_days: int | None = Field(default=None, ge=0, description="Data retention period")
    encryption: bool = Field(default=False, description="Is data encrypted in transit/at rest?")
    consent_required: bool = Field(default=False)
    consent_mechanism: str | None = None
    description: str = Field(default="", max_length=1000)
    tags: list[str] = Field(default_factory=list)


class DataFlowUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    direction: DataFlowDirection | None = None
    source: str | None = None
    destination: str | None = None
    pii_categories: list[PIICategory] | None = None
    purpose: str | None = None
    retention_days: int | None = None
    encryption: bool | None = None
    consent_required: bool | None = None
    consent_mechanism: str | None = None
    description: str | None = None
    tags: list[str] | None = None


class DataFlowResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    direction: DataFlowDirection
    source: str
    destination: str
    pii_categories: list[PIICategory] = Field(default_factory=list)
    purpose: str = ""
    retention_days: int | None = None
    encryption: bool = False
    consent_required: bool = False
    consent_mechanism: str | None = None
    risk_level: RiskLevel = Field(default=RiskLevel.LOW)
    compliance_gaps: list[str] = Field(default_factory=list)
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    created_at: str
    updated_at: str


class DataFlowListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DataFlowResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# Framework compliance check
# ---------------------------------------------------------------------------

class FrameworkCheckRequest(BaseModel):
    """Check compliance against a specific privacy framework."""

    model_config = ConfigDict(extra="forbid")

    framework: PrivacyFramework = Field(..., description="Framework to assess")
    scan_id: str | None = None
    include_data_flows: bool = Field(default=True)


class ControlResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str = Field(..., description="e.g., GDPR Art.5(1)(c)")
    control_name: str
    status: ComplianceStatus
    risk_level: RiskLevel = Field(default=RiskLevel.LOW)
    findings: list[str] = Field(default_factory=list, description="Related finding IDs")
    gaps: list[str] = Field(default_factory=list, description="Compliance gaps found")
    recommendations: list[str] = Field(default_factory=list)


class FrameworkCheckResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    framework: PrivacyFramework
    scan_id: str | None = None
    overall_status: ComplianceStatus
    score: float = Field(default=0.0, ge=0, le=100, description="Compliance score 0-100")
    controls_assessed: int = 0
    controls_compliant: int = 0
    controls_partial: int = 0
    controls_non_compliant: int = 0
    controls: list[ControlResult] = Field(default_factory=list)
    created_at: str


class FrameworkCheckListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[FrameworkCheckResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

class PrivacyStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="healthy")
    total_assessments: int = Field(default=0)
    total_data_flows: int = Field(default=0)
    recent_assessments: int = Field(default=0, description="Assessments in last 24h")
    high_risk_findings: int = Field(default=0)
    frameworks_available: list[str] = Field(default_factory=list)
