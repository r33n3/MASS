"""Cloud-native ecosystem schemas.

Request and response models for discovering cloud-hosted AI resources,
assessing their security posture, and mapping cloud infrastructure to
MASS's scanning pipeline.
Per ARCHITECTURE.md Section 8.1 — Cloud-Native module slot.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from mass.api.schemas.common import PaginationMeta


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"


class ResourceType(str, Enum):
    """Cloud AI/ML resource types that MASS can discover and assess."""

    # Compute / hosting
    MODEL_ENDPOINT = "model_endpoint"
    INFERENCE_SERVICE = "inference_service"
    TRAINING_JOB = "training_job"
    NOTEBOOK_INSTANCE = "notebook_instance"
    CONTAINER_SERVICE = "container_service"

    # Storage
    MODEL_REGISTRY = "model_registry"
    DATA_STORE = "data_store"
    ARTIFACT_BUCKET = "artifact_bucket"

    # Orchestration
    ML_PIPELINE = "ml_pipeline"
    AGENT_SERVICE = "agent_service"

    # Infrastructure
    VPC_NETWORK = "vpc_network"
    IAM_ROLE = "iam_role"
    SECRET_STORE = "secret_store"
    API_GATEWAY = "api_gateway"


class DiscoveryStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SecurityGrade(str, Enum):
    """Overall security grade for a cloud resource."""
    A = "A"  # Excellent — no issues
    B = "B"  # Good — minor issues only
    C = "C"  # Fair — medium issues
    D = "D"  # Poor — high severity issues
    F = "F"  # Failing — critical issues


class AssessmentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Cloud account / credential configuration
# ---------------------------------------------------------------------------

class CloudAccountCreate(BaseModel):
    """Register a cloud account for resource discovery."""

    model_config = ConfigDict(extra="forbid")

    provider: CloudProvider
    name: str = Field(..., max_length=255, description="Account display name")
    account_id: str = Field(
        default="", max_length=128,
        description="AWS Account ID, Azure Subscription ID, or GCP Project ID",
    )
    region: str = Field(
        default="", max_length=64,
        description="Primary region (e.g. us-east-1, eastus, us-central1)",
    )
    regions: list[str] = Field(
        default_factory=list,
        description="Additional regions to scan (empty = primary only)",
    )
    # Credentials — stored encrypted, never returned in responses
    access_key: str | None = Field(default=None, description="AWS access key / Azure client ID")
    secret_key: str | None = Field(default=None, description="AWS secret key / Azure client secret")
    session_token: str | None = Field(default=None, description="AWS session token")
    tenant_id_cloud: str | None = Field(default=None, description="Azure tenant ID")
    service_account_json: str | None = Field(default=None, description="GCP service account JSON")
    kubeconfig: str | None = Field(default=None, description="Kubernetes kubeconfig YAML")
    tags: dict[str, str] = Field(default_factory=dict, description="Account tags/labels")


class CloudAccountUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    region: str | None = None
    regions: list[str] | None = None
    access_key: str | None = None
    secret_key: str | None = None
    session_token: str | None = None
    tenant_id_cloud: str | None = None
    service_account_json: str | None = None
    kubeconfig: str | None = None
    tags: dict[str, str] | None = None


class CloudAccountResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    provider: CloudProvider
    name: str
    account_id: str = ""
    region: str = ""
    regions: list[str] = Field(default_factory=list)
    has_credentials: bool = Field(default=False, description="Whether credentials are configured")
    tags: dict[str, str] = Field(default_factory=dict)
    resources_count: int = 0
    last_discovery_at: str | None = None
    created_at: str
    updated_at: str | None = None


class CloudAccountListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[CloudAccountResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# Cloud resource discovery
# ---------------------------------------------------------------------------

class DiscoveryRequest(BaseModel):
    """Start resource discovery for a cloud account."""

    model_config = ConfigDict(extra="forbid")

    account_id: str = Field(..., description="Cloud account ID to discover")
    resource_types: list[ResourceType] = Field(
        default_factory=list,
        description="Resource types to discover (empty = all)",
    )
    regions: list[str] = Field(
        default_factory=list,
        description="Regions to scan (empty = account defaults)",
    )
    include_inactive: bool = Field(
        default=False,
        description="Include stopped/terminated resources",
    )


class CloudResourceResponse(BaseModel):
    """A discovered cloud resource."""

    model_config = ConfigDict(extra="forbid")

    id: str
    account_id: str
    provider: CloudProvider
    resource_type: ResourceType
    resource_id: str = Field(default="", description="Cloud-native resource ID (ARN, URI, etc.)")
    name: str = ""
    region: str = ""
    service: str = Field(default="", description="Cloud service name (e.g. SageMaker, AzureML)")
    status: str = Field(default="active", description="Resource status")
    security_grade: SecurityGrade | None = None
    findings_count: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict, description="Cloud-specific metadata")
    tags: dict[str, str] = Field(default_factory=dict)
    last_assessed_at: str | None = None
    discovered_at: str


class CloudResourceListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[CloudResourceResponse]
    pagination: PaginationMeta


class DiscoveryResponse(BaseModel):
    """Discovery job status and results."""

    model_config = ConfigDict(extra="forbid")

    id: str
    account_id: str
    status: DiscoveryStatus
    resource_types: list[str] = Field(default_factory=list)
    resources_found: int = 0
    resources_by_type: dict[str, int] = Field(default_factory=dict)
    resources_by_region: dict[str, int] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    created_at: str
    completed_at: str | None = None


class DiscoveryListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DiscoveryResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# Security assessment
# ---------------------------------------------------------------------------

class AssessmentRequest(BaseModel):
    """Run security assessment on discovered cloud resources."""

    model_config = ConfigDict(extra="forbid")

    account_id: str = Field(..., description="Cloud account to assess")
    resource_ids: list[str] = Field(
        default_factory=list,
        description="Specific resource IDs (empty = all resources in account)",
    )
    checks: list[str] = Field(
        default_factory=list,
        description="Specific check IDs to run (empty = all applicable)",
    )
    include_iac_scan: bool = Field(
        default=True,
        description="Run Terraform/K8s manifest analysis if available",
    )


class SecurityFinding(BaseModel):
    """A security finding from cloud assessment."""

    model_config = ConfigDict(extra="forbid")

    check_id: str
    severity: str
    title: str
    description: str
    resource_id: str = ""
    resource_type: str = ""
    region: str = ""
    remediation: str = ""
    cwe_id: str | None = None
    compliance: list[str] = Field(
        default_factory=list,
        description="Compliance frameworks (CIS, SOC2, HIPAA, etc.)",
    )


class AssessmentResponse(BaseModel):
    """Security assessment job status and results."""

    model_config = ConfigDict(extra="forbid")

    id: str
    account_id: str
    status: AssessmentStatus
    resources_assessed: int = 0
    checks_run: int = 0
    findings_count: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings: list[SecurityFinding] = Field(default_factory=list)
    security_grade: SecurityGrade | None = None
    compliance_summary: dict[str, dict] = Field(
        default_factory=dict,
        description="framework → {total, passed, failed, coverage_pct}",
    )
    duration_seconds: float = 0.0
    error: str | None = None
    created_at: str
    completed_at: str | None = None


class AssessmentListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[AssessmentResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

class CloudStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="healthy")
    total_accounts: int = 0
    total_resources: int = 0
    total_assessments: int = 0
    resources_by_provider: dict[str, int] = Field(default_factory=dict)
    resources_by_type: dict[str, int] = Field(default_factory=dict)
    supported_providers: list[str] = Field(default_factory=list)
    supported_resource_types: list[str] = Field(default_factory=list)
