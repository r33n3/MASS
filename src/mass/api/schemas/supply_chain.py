"""Supply chain verification schemas.

Request and response models for verifying model provenance,
scanning dependencies, generating SBOMs, and detecting malicious packages.
Per ARCHITECTURE.md Section 8.1 — Supply Chain module slot.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from mass.api.schemas.common import PaginationMeta


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PackageEcosystem(str, Enum):
    """Package ecosystem / registry."""

    PYPI = "pypi"
    NPM = "npm"
    HUGGINGFACE = "huggingface"
    DOCKER = "docker"
    MAVEN = "maven"
    CARGO = "cargo"
    GO = "go"
    OTHER = "other"


class VerificationStatus(str, Enum):
    """Status of a supply chain verification check."""

    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    ERROR = "error"
    SKIPPED = "skipped"


class LicenseRisk(str, Enum):
    """License risk classification."""

    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    COMMERCIAL = "commercial"
    UNKNOWN = "unknown"
    RESTRICTED = "restricted"


class SBOMFormat(str, Enum):
    """Supported SBOM output formats."""

    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


# ---------------------------------------------------------------------------
# Package / dependency management
# ---------------------------------------------------------------------------

class PackageCreate(BaseModel):
    """Register a package dependency for tracking."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255, description="Package name")
    version: str = Field(..., min_length=1, max_length=100, description="Package version")
    ecosystem: PackageEcosystem = Field(..., description="Package ecosystem")
    source_url: str | None = Field(default=None, description="Registry / repository URL")
    license: str | None = Field(default=None, description="SPDX license identifier")
    description: str = Field(default="", max_length=1000)
    parent_package: str | None = Field(
        default=None,
        description="Parent package name (for transitive dependencies)",
    )
    is_direct: bool = Field(default=True, description="Direct vs transitive dependency")
    tags: list[str] = Field(default_factory=list)


class PackageUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str | None = None
    source_url: str | None = None
    license: str | None = None
    description: str | None = None
    tags: list[str] | None = None


class PackageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    version: str
    ecosystem: PackageEcosystem
    source_url: str | None = None
    license: str | None = None
    license_risk: LicenseRisk = Field(default=LicenseRisk.UNKNOWN)
    description: str = ""
    parent_package: str | None = None
    is_direct: bool = True
    tags: list[str] = Field(default_factory=list)
    vulnerabilities: list[dict] = Field(
        default_factory=list,
        description="Known CVEs / advisories",
    )
    verification_status: VerificationStatus = Field(default=VerificationStatus.PENDING)
    last_checked_at: str | None = None
    created_at: str
    updated_at: str


class PackageListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[PackageResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# SBOM (Software Bill of Materials)
# ---------------------------------------------------------------------------

class SBOMGenerateRequest(BaseModel):
    """Request to generate an SBOM from registered packages."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str | None = Field(default=None, description="Associate with a scan")
    format: SBOMFormat = Field(default=SBOMFormat.CYCLONEDX, description="Output format")
    include_transitive: bool = Field(default=True, description="Include transitive deps")
    include_vulnerabilities: bool = Field(default=True)
    include_licenses: bool = Field(default=True)


class SBOMResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    format: SBOMFormat
    total_packages: int
    direct_packages: int
    transitive_packages: int
    vulnerability_count: int = 0
    license_violations: int = 0
    document: dict = Field(default_factory=dict, description="SBOM document body")
    created_at: str


class SBOMListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[SBOMResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# Model provenance verification
# ---------------------------------------------------------------------------

class ModelVerifyRequest(BaseModel):
    """Verify a model file's supply chain integrity."""

    model_config = ConfigDict(extra="forbid")

    file_path: str = Field(..., description="Path to model file (relative to scan target)")
    expected_hash: str | None = Field(default=None, description="Expected SHA-256 hash")
    source_url: str | None = Field(default=None, description="Expected source URL (e.g. HF hub)")
    model_id: str | None = Field(default=None, description="Model identifier on hub")
    check_provenance: bool = Field(default=True)
    check_signatures: bool = Field(default=True)
    check_format: bool = Field(default=True, description="Run format-specific security checks")


class ModelVerifyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str
    status: str
    file_path: str
    format_detected: str | None = None
    hash_sha256: str | None = None
    hash_match: VerificationStatus = Field(default=VerificationStatus.SKIPPED)
    provenance_status: VerificationStatus = Field(default=VerificationStatus.SKIPPED)
    signature_status: VerificationStatus = Field(default=VerificationStatus.SKIPPED)
    format_status: VerificationStatus = Field(default=VerificationStatus.SKIPPED)
    findings: list[dict] = Field(default_factory=list)
    provenance: dict | None = None
    error: str | None = None
    created_at: str
    completed_at: str | None = None


# ---------------------------------------------------------------------------
# Vulnerability / CVE tracking
# ---------------------------------------------------------------------------

class VulnerabilityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    cve_id: str | None = None
    advisory_id: str | None = None
    title: str
    description: str = ""
    severity: str = "medium"
    cvss_score: float | None = None
    affected_package: str
    affected_versions: str = ""
    fixed_version: str | None = None
    source: str = ""
    source_url: str | None = None
    published_at: str | None = None


class VulnerabilityListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[VulnerabilityResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# Supply chain scan (full scan of all deps + models)
# ---------------------------------------------------------------------------

class SupplyChainScanRequest(BaseModel):
    """Run a full supply chain verification scan."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str | None = Field(default=None, description="Associate with existing scan")
    check_vulnerabilities: bool = Field(default=True)
    check_licenses: bool = Field(default=True)
    check_model_provenance: bool = Field(default=True)
    check_malicious_packages: bool = Field(default=True)
    severity_threshold: str = Field(
        default="medium",
        description="Minimum severity to flag: critical, high, medium, low, info",
    )


class SupplyChainScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str
    status: str
    total_packages: int = 0
    total_models: int = 0
    vulnerabilities_found: int = 0
    license_violations: int = 0
    malicious_detected: int = 0
    provenance_failures: int = 0
    findings: list[dict] = Field(default_factory=list)
    error: str | None = None
    created_at: str
    completed_at: str | None = None


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

class SupplyChainStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="healthy")
    total_packages: int = Field(default=0)
    total_vulnerabilities: int = Field(default=0)
    total_sboms: int = Field(default=0)
    recent_scans: int = Field(default=0, description="Scans in last 24h")
    packages_by_ecosystem: dict[str, int] = Field(default_factory=dict)
