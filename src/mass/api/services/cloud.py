"""Cloud-native ecosystem service.

Discovers cloud-hosted AI resources across AWS, Azure, GCP, and Kubernetes
environments, assesses their security posture using MASS infrastructure
analyzers, and tracks cloud accounts and resources.
All state Redis-backed via JobStore (Rule 1 compliant).
Per ARCHITECTURE.md Section 8.1 — Cloud-Native module slot.
"""

import logging
import time
from datetime import datetime
from uuid import uuid4

from mass.api.utils.job_store import JobStore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis-backed stores
# ---------------------------------------------------------------------------
_account_store = JobStore("cloud_accounts", ttl=365 * 24 * 3600)
_resource_store = JobStore("cloud_resources", ttl=90 * 24 * 3600)
_discovery_store = JobStore("cloud_discovery", ttl=30 * 24 * 3600)
_assessment_store = JobStore("cloud_assessment", ttl=30 * 24 * 3600)

# Credentials stored separately with shorter TTL prefix
_credential_store = JobStore("cloud_creds", ttl=90 * 24 * 3600)

# Fields that contain secrets — never returned in responses
_SECRET_FIELDS = {
    "access_key", "secret_key", "session_token",
    "service_account_json", "kubeconfig", "tenant_id_cloud",
}

SUPPORTED_PROVIDERS = ["aws", "azure", "gcp", "kubernetes"]

SUPPORTED_RESOURCE_TYPES = [
    "model_endpoint", "inference_service", "training_job",
    "notebook_instance", "container_service", "model_registry",
    "data_store", "artifact_bucket", "ml_pipeline", "agent_service",
    "vpc_network", "iam_role", "secret_store", "api_gateway",
]

# AWS AI/ML service identifiers for discovery
AWS_AI_SERVICES = {
    "sagemaker": {
        "resource_types": ["model_endpoint", "training_job", "notebook_instance", "ml_pipeline"],
        "description": "Amazon SageMaker",
    },
    "bedrock": {
        "resource_types": ["model_endpoint", "inference_service", "agent_service"],
        "description": "Amazon Bedrock",
    },
    "comprehend": {
        "resource_types": ["inference_service"],
        "description": "Amazon Comprehend",
    },
    "rekognition": {
        "resource_types": ["inference_service"],
        "description": "Amazon Rekognition",
    },
    "lambda": {
        "resource_types": ["inference_service", "agent_service"],
        "description": "AWS Lambda (AI workloads)",
    },
    "ecs": {
        "resource_types": ["container_service"],
        "description": "Amazon ECS",
    },
    "eks": {
        "resource_types": ["container_service"],
        "description": "Amazon EKS",
    },
    "s3": {
        "resource_types": ["data_store", "artifact_bucket", "model_registry"],
        "description": "Amazon S3",
    },
    "ecr": {
        "resource_types": ["model_registry"],
        "description": "Amazon ECR",
    },
    "iam": {
        "resource_types": ["iam_role"],
        "description": "AWS IAM",
    },
    "secretsmanager": {
        "resource_types": ["secret_store"],
        "description": "AWS Secrets Manager",
    },
    "apigateway": {
        "resource_types": ["api_gateway"],
        "description": "Amazon API Gateway",
    },
}

# Azure AI/ML service identifiers
AZURE_AI_SERVICES = {
    "machinelearning": {
        "resource_types": ["model_endpoint", "training_job", "notebook_instance", "ml_pipeline"],
        "description": "Azure Machine Learning",
    },
    "cognitiveservices": {
        "resource_types": ["inference_service", "model_endpoint"],
        "description": "Azure Cognitive Services / OpenAI",
    },
    "containerinstances": {
        "resource_types": ["container_service"],
        "description": "Azure Container Instances",
    },
    "aks": {
        "resource_types": ["container_service"],
        "description": "Azure Kubernetes Service",
    },
    "storage": {
        "resource_types": ["data_store", "artifact_bucket", "model_registry"],
        "description": "Azure Storage",
    },
    "containerregistry": {
        "resource_types": ["model_registry"],
        "description": "Azure Container Registry",
    },
    "keyvault": {
        "resource_types": ["secret_store"],
        "description": "Azure Key Vault",
    },
    "apimanagement": {
        "resource_types": ["api_gateway"],
        "description": "Azure API Management",
    },
}

# GCP AI/ML service identifiers
GCP_AI_SERVICES = {
    "aiplatform": {
        "resource_types": ["model_endpoint", "training_job", "notebook_instance", "ml_pipeline"],
        "description": "Vertex AI",
    },
    "run": {
        "resource_types": ["inference_service", "container_service"],
        "description": "Cloud Run",
    },
    "gke": {
        "resource_types": ["container_service"],
        "description": "Google Kubernetes Engine",
    },
    "storage": {
        "resource_types": ["data_store", "artifact_bucket", "model_registry"],
        "description": "Cloud Storage",
    },
    "artifactregistry": {
        "resource_types": ["model_registry"],
        "description": "Artifact Registry",
    },
    "secretmanager": {
        "resource_types": ["secret_store"],
        "description": "Secret Manager",
    },
    "apigateway": {
        "resource_types": ["api_gateway"],
        "description": "API Gateway",
    },
}

# Security checks organized by category
SECURITY_CHECKS: dict[str, dict] = {
    # Encryption
    "CLD001": {
        "title": "Data encryption at rest",
        "severity": "high",
        "description": "AI model data and training artifacts should be encrypted at rest.",
        "remediation": "Enable server-side encryption on storage resources.",
        "cwe_id": "CWE-311",
        "compliance": ["CIS", "SOC2", "HIPAA"],
        "resource_types": ["data_store", "artifact_bucket", "model_registry"],
    },
    "CLD002": {
        "title": "Data encryption in transit",
        "severity": "high",
        "description": "Model endpoints and APIs must enforce TLS for all traffic.",
        "remediation": "Enable TLS/HTTPS on all model-serving endpoints.",
        "cwe_id": "CWE-319",
        "compliance": ["CIS", "SOC2", "HIPAA"],
        "resource_types": ["model_endpoint", "inference_service", "api_gateway"],
    },
    # Access control
    "CLD003": {
        "title": "Public model endpoint exposure",
        "severity": "critical",
        "description": "Model endpoints should not be publicly accessible without authentication.",
        "remediation": "Restrict endpoint access with IAM policies, VPC endpoints, or API keys.",
        "cwe_id": "CWE-284",
        "compliance": ["CIS", "SOC2", "NIST"],
        "resource_types": ["model_endpoint", "inference_service", "api_gateway"],
    },
    "CLD004": {
        "title": "Overly permissive IAM role",
        "severity": "critical",
        "description": "IAM roles for AI services should follow least-privilege principle.",
        "remediation": "Scope IAM policies to specific resources and actions needed.",
        "cwe_id": "CWE-269",
        "compliance": ["CIS", "SOC2", "NIST"],
        "resource_types": ["iam_role"],
    },
    "CLD005": {
        "title": "Missing network isolation",
        "severity": "high",
        "description": "AI workloads should run within private VPCs/subnets with network policies.",
        "remediation": "Deploy in private subnets and configure security groups/network policies.",
        "cwe_id": "CWE-668",
        "compliance": ["CIS", "SOC2"],
        "resource_types": ["model_endpoint", "training_job", "notebook_instance", "container_service"],
    },
    # Secrets & credentials
    "CLD006": {
        "title": "Hardcoded API keys in configuration",
        "severity": "critical",
        "description": "API keys and secrets should be stored in a secrets manager, not hardcoded.",
        "remediation": "Use AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager.",
        "cwe_id": "CWE-798",
        "compliance": ["CIS", "SOC2", "OWASP"],
        "resource_types": ["model_endpoint", "inference_service", "container_service", "agent_service"],
    },
    "CLD007": {
        "title": "Secret store access logging disabled",
        "severity": "medium",
        "description": "Access to secrets should be audited for compliance and incident response.",
        "remediation": "Enable audit logging on secrets manager resources.",
        "cwe_id": "CWE-778",
        "compliance": ["CIS", "SOC2", "HIPAA"],
        "resource_types": ["secret_store"],
    },
    # Container security
    "CLD008": {
        "title": "Container running as root",
        "severity": "high",
        "description": "AI model containers should not run as root user.",
        "remediation": "Set runAsNonRoot: true in container security context.",
        "cwe_id": "CWE-250",
        "compliance": ["CIS", "NIST"],
        "resource_types": ["container_service", "inference_service"],
    },
    "CLD009": {
        "title": "Container image from untrusted registry",
        "severity": "high",
        "description": "ML container images should come from trusted, private registries.",
        "remediation": "Use private container registries (ECR, GCR, ACR) with image signing.",
        "cwe_id": "CWE-829",
        "compliance": ["CIS", "NIST"],
        "resource_types": ["container_service", "model_registry"],
    },
    # Data governance
    "CLD010": {
        "title": "Training data in unencrypted storage",
        "severity": "high",
        "description": "Training datasets may contain sensitive data and must be encrypted.",
        "remediation": "Enable encryption and access logging on training data stores.",
        "cwe_id": "CWE-311",
        "compliance": ["HIPAA", "GDPR", "SOC2"],
        "resource_types": ["data_store", "artifact_bucket"],
    },
    "CLD011": {
        "title": "Model artifacts publicly accessible",
        "severity": "critical",
        "description": "Model weights and artifacts should not be publicly downloadable.",
        "remediation": "Remove public access and require authentication for model downloads.",
        "cwe_id": "CWE-284",
        "compliance": ["CIS", "SOC2"],
        "resource_types": ["model_registry", "artifact_bucket"],
    },
    # Monitoring
    "CLD012": {
        "title": "Missing monitoring on model endpoint",
        "severity": "medium",
        "description": "Model endpoints should have monitoring and alerting configured.",
        "remediation": "Enable CloudWatch/Azure Monitor/Cloud Monitoring with anomaly alerts.",
        "cwe_id": "CWE-778",
        "compliance": ["SOC2", "NIST"],
        "resource_types": ["model_endpoint", "inference_service"],
    },
    "CLD013": {
        "title": "Missing resource limits on AI workload",
        "severity": "medium",
        "description": "AI workloads without resource limits can cause unbounded consumption.",
        "remediation": "Set CPU/memory limits and configure auto-scaling boundaries.",
        "cwe_id": "CWE-770",
        "compliance": ["CIS", "NIST"],
        "resource_types": ["training_job", "container_service", "inference_service"],
    },
    # Pipeline security
    "CLD014": {
        "title": "ML pipeline without input validation",
        "severity": "high",
        "description": "ML pipelines should validate input data to prevent poisoning attacks.",
        "remediation": "Add data validation steps and integrity checks in pipeline stages.",
        "cwe_id": "CWE-20",
        "compliance": ["OWASP", "NIST"],
        "resource_types": ["ml_pipeline", "training_job"],
    },
    "CLD015": {
        "title": "Notebook instance with internet access",
        "severity": "medium",
        "description": "Development notebooks with direct internet access risk data exfiltration.",
        "remediation": "Restrict notebook internet access and use VPC endpoints for services.",
        "cwe_id": "CWE-668",
        "compliance": ["CIS", "SOC2"],
        "resource_types": ["notebook_instance"],
    },
}


# ---------------------------------------------------------------------------
# Account CRUD
# ---------------------------------------------------------------------------

async def create_account(tenant_id: str, data: dict) -> dict:
    """Create a cloud account registration."""
    account_id = str(uuid4())
    now = datetime.utcnow().isoformat()

    # Extract and store credentials separately
    creds = {}
    for field in _SECRET_FIELDS:
        val = data.pop(field, None)
        if val:
            creds[field] = val

    record = {
        "id": account_id,
        "tenant_id": tenant_id,
        "provider": data.get("provider", ""),
        "name": data.get("name", ""),
        "account_id": data.get("account_id", ""),
        "region": data.get("region", ""),
        "regions": data.get("regions", []),
        "has_credentials": bool(creds),
        "tags": data.get("tags", {}),
        "resources_count": 0,
        "last_discovery_at": None,
        "created_at": now,
        "updated_at": now,
    }
    await _account_store.save(account_id, record)

    # Store credentials separately
    if creds:
        await _credential_store.save(account_id, creds)

    return record


async def get_account(account_id: str) -> dict | None:
    return await _account_store.load(account_id)


async def update_account(account_id: str, data: dict) -> dict | None:
    record = await _account_store.load(account_id)
    if not record:
        return None

    # Extract credentials
    creds = {}
    for field in _SECRET_FIELDS:
        val = data.pop(field, None)
        if val:
            creds[field] = val

    for key, val in data.items():
        if val is not None and key in record:
            record[key] = val

    record["updated_at"] = datetime.utcnow().isoformat()

    if creds:
        existing_creds = await _credential_store.load(account_id) or {}
        existing_creds.update(creds)
        await _credential_store.save(account_id, existing_creds)
        record["has_credentials"] = True

    await _account_store.save(account_id, record)
    return record


async def delete_account(account_id: str) -> bool:
    await _credential_store.delete(account_id)
    return await _account_store.delete(account_id)


async def list_accounts(
    tenant_id: str,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    all_items = await _account_store.list_jobs(tenant_id=tenant_id, limit=5000)
    total = len(all_items)
    return all_items[offset:offset + limit], total


# ---------------------------------------------------------------------------
# Resource CRUD
# ---------------------------------------------------------------------------

async def get_resource(resource_id: str) -> dict | None:
    return await _resource_store.load(resource_id)


async def list_resources(
    tenant_id: str,
    account_id: str | None = None,
    provider: str | None = None,
    resource_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    all_items = await _resource_store.list_jobs(tenant_id=tenant_id, limit=5000)

    if account_id:
        all_items = [r for r in all_items if r.get("account_id") == account_id]
    if provider:
        all_items = [r for r in all_items if r.get("provider") == provider]
    if resource_type:
        all_items = [r for r in all_items if r.get("resource_type") == resource_type]

    total = len(all_items)
    return all_items[offset:offset + limit], total


async def delete_resource(resource_id: str) -> bool:
    return await _resource_store.delete(resource_id)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

async def create_discovery(tenant_id: str, data: dict) -> dict:
    """Create a resource discovery job."""
    job_id = str(uuid4())
    now = datetime.utcnow().isoformat()

    record = {
        "id": job_id,
        "tenant_id": tenant_id,
        "account_id": data.get("account_id", ""),
        "status": "pending",
        "resource_types": data.get("resource_types", []),
        "regions": data.get("regions", []),
        "include_inactive": data.get("include_inactive", False),
        "resources_found": 0,
        "resources_by_type": {},
        "resources_by_region": {},
        "errors": [],
        "duration_seconds": 0.0,
        "created_at": now,
        "completed_at": None,
    }
    await _discovery_store.save(job_id, record)
    return record


async def get_discovery(job_id: str) -> dict | None:
    return await _discovery_store.load(job_id)


async def list_discoveries(
    tenant_id: str,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    all_items = await _discovery_store.list_jobs(tenant_id=tenant_id, limit=5000)
    total = len(all_items)
    return all_items[offset:offset + limit], total


async def run_discovery(job_id: str) -> None:
    """Execute resource discovery.  Runs as BackgroundTask."""
    job = await _discovery_store.load(job_id)
    if not job:
        return

    try:
        job["status"] = "running"
        await _discovery_store.save(job_id, job)

        start = time.time()
        account_id = job.get("account_id", "")
        account = await _account_store.load(account_id)
        if not account:
            job["status"] = "failed"
            job["errors"] = ["Account not found"]
            job["completed_at"] = datetime.utcnow().isoformat()
            await _discovery_store.save(job_id, job)
            return

        tenant_id = job.get("tenant_id", "")
        provider = account.get("provider", "")
        creds = await _credential_store.load(account_id) or {}
        requested_types = set(job.get("resource_types", []))
        regions = job.get("regions", []) or account.get("regions", []) or [account.get("region", "")]

        # Select service catalog based on provider
        service_catalog = _get_service_catalog(provider)

        resources_found = 0
        by_type: dict[str, int] = {}
        by_region: dict[str, int] = {}
        errors: list[str] = []

        for region in regions:
            if not region:
                continue

            for svc_name, svc_info in service_catalog.items():
                try:
                    discovered = await _discover_service_resources(
                        provider=provider,
                        service=svc_name,
                        service_info=svc_info,
                        region=region,
                        account=account,
                        creds=creds,
                        requested_types=requested_types,
                        include_inactive=job.get("include_inactive", False),
                    )

                    for res in discovered:
                        res_id = str(uuid4())
                        res_record = {
                            "id": res_id,
                            "tenant_id": tenant_id,
                            "account_id": account_id,
                            "provider": provider,
                            "resource_type": res["resource_type"],
                            "resource_id": res.get("resource_id", ""),
                            "name": res.get("name", ""),
                            "region": region,
                            "service": svc_info["description"],
                            "status": res.get("status", "active"),
                            "security_grade": None,
                            "findings_count": 0,
                            "findings_by_severity": {},
                            "metadata": res.get("metadata", {}),
                            "tags": res.get("tags", {}),
                            "last_assessed_at": None,
                            "discovered_at": datetime.utcnow().isoformat(),
                        }
                        await _resource_store.save(res_id, res_record)
                        resources_found += 1

                        rtype = res["resource_type"]
                        by_type[rtype] = by_type.get(rtype, 0) + 1
                        by_region[region] = by_region.get(region, 0) + 1

                except Exception as e:
                    errors.append(f"{provider}/{svc_name}/{region}: {e}")
                    logger.debug("Discovery error: %s/%s/%s: %s", provider, svc_name, region, e)

        # Update account resource count
        account["resources_count"] = resources_found
        account["last_discovery_at"] = datetime.utcnow().isoformat()
        await _account_store.save(account_id, account)

        job["resources_found"] = resources_found
        job["resources_by_type"] = by_type
        job["resources_by_region"] = by_region
        job["errors"] = errors
        job["status"] = "completed"
        job["duration_seconds"] = round(time.time() - start, 2)
        job["completed_at"] = datetime.utcnow().isoformat()

        # Broadcast event
        try:
            from mass.core.events import Event, EventType, publish_event
            await publish_event(Event(
                type=EventType.CLOUD_DISCOVERY_COMPLETED,
                data={
                    "job_id": job_id,
                    "account_id": account_id,
                    "resources_found": resources_found,
                },
                tenant_id=tenant_id,
            ))
        except Exception:
            pass

    except Exception as exc:
        logger.exception("Cloud discovery %s failed", job_id)
        job["status"] = "failed"
        job["errors"] = [str(exc)]
        job["completed_at"] = datetime.utcnow().isoformat()
        await _discovery_store.move_to_dlq(job_id, str(exc))

    await _discovery_store.save(job_id, job)


def _get_service_catalog(provider: str) -> dict:
    """Get the AI service catalog for a provider."""
    catalogs = {
        "aws": AWS_AI_SERVICES,
        "azure": AZURE_AI_SERVICES,
        "gcp": GCP_AI_SERVICES,
        "kubernetes": {
            "deployments": {
                "resource_types": ["container_service", "inference_service"],
                "description": "Kubernetes Deployments",
            },
            "services": {
                "resource_types": ["model_endpoint", "api_gateway"],
                "description": "Kubernetes Services",
            },
            "namespaces": {
                "resource_types": ["vpc_network"],
                "description": "Kubernetes Namespaces",
            },
            "secrets": {
                "resource_types": ["secret_store"],
                "description": "Kubernetes Secrets",
            },
            "serviceaccounts": {
                "resource_types": ["iam_role"],
                "description": "Kubernetes Service Accounts",
            },
        },
    }
    return catalogs.get(provider, {})


async def _discover_service_resources(
    provider: str,
    service: str,
    service_info: dict,
    region: str,
    account: dict,
    creds: dict,
    requested_types: set[str],
    include_inactive: bool,
) -> list[dict]:
    """Discover resources from a specific cloud service.

    This is the extension point where cloud SDK calls would be added.
    Currently performs configuration-based discovery by scanning for
    IaC files (Terraform, K8s manifests) and inferring resources.
    """
    resource_types = service_info.get("resource_types", [])

    # Filter by requested types if specified
    if requested_types:
        resource_types = [rt for rt in resource_types if rt in requested_types]
    if not resource_types:
        return []

    discovered: list[dict] = []

    # Try Terraform-based discovery
    try:
        tf_resources = await _discover_from_terraform(provider, service, resource_types, region)
        discovered.extend(tf_resources)
    except Exception:
        pass

    # Try Kubernetes manifest discovery (for k8s provider)
    if provider == "kubernetes":
        try:
            k8s_resources = await _discover_from_kubernetes(service, resource_types)
            discovered.extend(k8s_resources)
        except Exception:
            pass

    # If credentials available, attempt API-based discovery
    if creds:
        try:
            api_resources = await _discover_from_api(
                provider, service, resource_types, region, creds,
            )
            discovered.extend(api_resources)
        except ImportError:
            # Cloud SDK not installed — expected in many deployments
            pass
        except Exception as e:
            logger.debug("API discovery failed for %s/%s: %s", provider, service, e)

    return discovered


async def _discover_from_terraform(
    provider: str,
    service: str,
    resource_types: list[str],
    region: str,
) -> list[dict]:
    """Discover resources by parsing Terraform files in scan targets."""
    resources: list[dict] = []

    try:
        from mass.analyzers.infrastructure.terraform import TerraformAnalyzer
        import glob
        from pathlib import Path

        # Check common Terraform locations
        tf_patterns = ["*.tf", "**/*.tf"]
        analyzer = TerraformAnalyzer()

        for pattern in tf_patterns:
            for tf_file in glob.glob(pattern, recursive=True):
                try:
                    result = analyzer.analyze_file(Path(tf_file))
                    for finding in result.findings:
                        # Map Terraform resources to cloud resource types
                        res_type = _terraform_resource_to_type(
                            finding.resource_type, provider,
                        )
                        if res_type and res_type in resource_types:
                            resources.append({
                                "resource_type": res_type,
                                "resource_id": f"tf:{tf_file}:{finding.resource_name}",
                                "name": finding.resource_name or finding.resource_type,
                                "status": "configured",
                                "metadata": {
                                    "source": "terraform",
                                    "file": tf_file,
                                    "resource_type": finding.resource_type,
                                },
                            })
                except Exception:
                    pass

    except ImportError:
        pass

    return resources


async def _discover_from_kubernetes(
    service: str,
    resource_types: list[str],
) -> list[dict]:
    """Discover resources by parsing Kubernetes manifests."""
    resources: list[dict] = []

    try:
        from mass.analyzers.infrastructure.kubernetes import KubernetesAnalyzer
        import glob
        from pathlib import Path

        k8s_patterns = ["*.yaml", "*.yml", "**/*.yaml", "**/*.yml"]
        analyzer = KubernetesAnalyzer()

        for pattern in k8s_patterns:
            for k8s_file in glob.glob(pattern, recursive=True):
                try:
                    result = analyzer.analyze_file(Path(k8s_file))
                    for manifest in result.manifests_analyzed if hasattr(result, "manifests_analyzed") else []:
                        res_type = _k8s_kind_to_type(service)
                        if res_type and res_type in resource_types:
                            resources.append({
                                "resource_type": res_type,
                                "resource_id": f"k8s:{k8s_file}",
                                "name": k8s_file,
                                "status": "configured",
                                "metadata": {"source": "kubernetes_manifest", "file": k8s_file},
                            })
                except Exception:
                    pass

    except ImportError:
        pass

    return resources


async def _discover_from_api(
    provider: str,
    service: str,
    resource_types: list[str],
    region: str,
    creds: dict,
) -> list[dict]:
    """Discover resources via cloud provider APIs.

    This is the extension point for real cloud SDK integration.
    Each provider would use its respective SDK (boto3, azure-mgmt, google-cloud).
    """
    # AWS discovery via boto3
    if provider == "aws":
        return await _discover_aws_api(service, resource_types, region, creds)

    # Azure discovery via azure-mgmt
    if provider == "azure":
        return await _discover_azure_api(service, resource_types, region, creds)

    # GCP discovery via google-cloud
    if provider == "gcp":
        return await _discover_gcp_api(service, resource_types, region, creds)

    return []


async def _discover_aws_api(
    service: str, resource_types: list[str], region: str, creds: dict,
) -> list[dict]:
    """AWS API-based resource discovery."""
    import boto3  # type: ignore[import-untyped]

    session = boto3.Session(
        aws_access_key_id=creds.get("access_key"),
        aws_secret_access_key=creds.get("secret_key"),
        aws_session_token=creds.get("session_token"),
        region_name=region,
    )

    resources: list[dict] = []

    if service == "sagemaker" and "model_endpoint" in resource_types:
        client = session.client("sagemaker")
        endpoints = client.list_endpoints(MaxResults=100)
        for ep in endpoints.get("Endpoints", []):
            resources.append({
                "resource_type": "model_endpoint",
                "resource_id": ep.get("EndpointArn", ""),
                "name": ep.get("EndpointName", ""),
                "status": ep.get("EndpointStatus", "").lower(),
                "metadata": {
                    "arn": ep.get("EndpointArn", ""),
                    "creation_time": str(ep.get("CreationTime", "")),
                },
            })

    if service == "s3" and "data_store" in resource_types:
        client = session.client("s3")
        buckets = client.list_buckets()
        for b in buckets.get("Buckets", []):
            resources.append({
                "resource_type": "data_store",
                "resource_id": f"arn:aws:s3:::{b['Name']}",
                "name": b["Name"],
                "status": "active",
                "metadata": {"creation_date": str(b.get("CreationDate", ""))},
            })

    return resources


async def _discover_azure_api(
    service: str, resource_types: list[str], region: str, creds: dict,
) -> list[dict]:
    """Azure API-based resource discovery."""
    from azure.identity import ClientSecretCredential  # type: ignore[import-untyped]
    from azure.mgmt.resource import ResourceManagementClient  # type: ignore[import-untyped]

    credential = ClientSecretCredential(
        tenant_id=creds.get("tenant_id_cloud", ""),
        client_id=creds.get("access_key", ""),
        client_secret=creds.get("secret_key", ""),
    )

    subscription_id = creds.get("session_token", "")  # Reuse field for subscription
    client = ResourceManagementClient(credential, subscription_id)

    resources: list[dict] = []
    type_filter = f"Microsoft.{service}"

    for res in client.resources.list(filter=f"resourceType eq '{type_filter}'"):
        res_type = _azure_type_to_resource_type(res.type, resource_types)
        if res_type:
            resources.append({
                "resource_type": res_type,
                "resource_id": res.id,
                "name": res.name,
                "status": "active",
                "metadata": {
                    "azure_type": res.type,
                    "location": res.location,
                    "resource_group": res.id.split("/")[4] if "/" in res.id else "",
                },
                "tags": res.tags or {},
            })

    return resources


async def _discover_gcp_api(
    service: str, resource_types: list[str], region: str, creds: dict,
) -> list[dict]:
    """GCP API-based resource discovery."""
    # GCP discovery would use google-cloud-asset or service-specific clients
    # This is the extension point for GCP SDK integration
    return []


def _terraform_resource_to_type(tf_type: str, provider: str) -> str | None:
    """Map Terraform resource types to MASS cloud resource types."""
    mapping = {
        "aws_sagemaker_endpoint": "model_endpoint",
        "aws_sagemaker_notebook_instance": "notebook_instance",
        "aws_sagemaker_training_job": "training_job",
        "aws_s3_bucket": "data_store",
        "aws_ecr_repository": "model_registry",
        "aws_iam_role": "iam_role",
        "aws_secretsmanager_secret": "secret_store",
        "aws_api_gateway_rest_api": "api_gateway",
        "aws_lambda_function": "inference_service",
        "aws_ecs_service": "container_service",
        "aws_eks_cluster": "container_service",
        "aws_security_group": "vpc_network",
        "azurerm_machine_learning_workspace": "ml_pipeline",
        "azurerm_cognitive_account": "inference_service",
        "azurerm_storage_account": "data_store",
        "azurerm_container_registry": "model_registry",
        "azurerm_key_vault": "secret_store",
        "azurerm_kubernetes_cluster": "container_service",
        "azurerm_api_management": "api_gateway",
        "google_vertex_ai_endpoint": "model_endpoint",
        "google_storage_bucket": "data_store",
        "google_artifact_registry_repository": "model_registry",
        "google_secret_manager_secret": "secret_store",
        "google_cloud_run_service": "container_service",
        "google_container_cluster": "container_service",
    }
    return mapping.get(tf_type)


def _k8s_kind_to_type(service: str) -> str | None:
    """Map Kubernetes service to resource type."""
    mapping = {
        "deployments": "container_service",
        "services": "model_endpoint",
        "namespaces": "vpc_network",
        "secrets": "secret_store",
        "serviceaccounts": "iam_role",
    }
    return mapping.get(service)


def _azure_type_to_resource_type(azure_type: str, allowed: list[str]) -> str | None:
    """Map Azure resource types to MASS types."""
    mapping = {
        "Microsoft.MachineLearningServices/workspaces": "ml_pipeline",
        "Microsoft.CognitiveServices/accounts": "inference_service",
        "Microsoft.Storage/storageAccounts": "data_store",
        "Microsoft.ContainerRegistry/registries": "model_registry",
        "Microsoft.KeyVault/vaults": "secret_store",
        "Microsoft.ContainerService/managedClusters": "container_service",
    }
    mapped = mapping.get(azure_type)
    if mapped and mapped in allowed:
        return mapped
    return None


# ---------------------------------------------------------------------------
# Security assessment
# ---------------------------------------------------------------------------

async def create_assessment(tenant_id: str, data: dict) -> dict:
    """Create a security assessment job."""
    job_id = str(uuid4())
    now = datetime.utcnow().isoformat()

    record = {
        "id": job_id,
        "tenant_id": tenant_id,
        "account_id": data.get("account_id", ""),
        "status": "pending",
        "resource_ids": data.get("resource_ids", []),
        "checks": data.get("checks", []),
        "include_iac_scan": data.get("include_iac_scan", True),
        "resources_assessed": 0,
        "checks_run": 0,
        "findings_count": 0,
        "findings_by_severity": {},
        "findings": [],
        "security_grade": None,
        "compliance_summary": {},
        "duration_seconds": 0.0,
        "error": None,
        "created_at": now,
        "completed_at": None,
    }
    await _assessment_store.save(job_id, record)
    return record


async def get_assessment(job_id: str) -> dict | None:
    return await _assessment_store.load(job_id)


async def list_assessments(
    tenant_id: str,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    all_items = await _assessment_store.list_jobs(tenant_id=tenant_id, limit=5000)
    total = len(all_items)
    return all_items[offset:offset + limit], total


async def run_assessment(job_id: str) -> None:
    """Execute security assessment.  Runs as BackgroundTask."""
    job = await _assessment_store.load(job_id)
    if not job:
        return

    try:
        job["status"] = "running"
        await _assessment_store.save(job_id, job)

        start = time.time()
        tenant_id = job.get("tenant_id", "")
        account_id = job.get("account_id", "")
        requested_resource_ids = set(job.get("resource_ids", []))
        requested_checks = set(job.get("checks", []))

        # Load resources for this account
        resources, _ = await list_resources(
            tenant_id=tenant_id,
            account_id=account_id,
            limit=5000,
        )

        if requested_resource_ids:
            resources = [r for r in resources if r.get("id") in requested_resource_ids]

        all_findings: list[dict] = []
        by_severity: dict[str, int] = {}
        compliance_hits: dict[str, dict] = {}
        checks_run = 0

        for resource in resources:
            res_type = resource.get("resource_type", "")
            res_id = resource.get("id", "")

            # Run applicable security checks
            for check_id, check in SECURITY_CHECKS.items():
                if requested_checks and check_id not in requested_checks:
                    continue
                if res_type not in check.get("resource_types", []):
                    continue

                checks_run += 1

                # Evaluate check against resource metadata
                is_vulnerable = _evaluate_check(check_id, resource)
                if is_vulnerable:
                    severity = check["severity"]
                    finding = {
                        "check_id": check_id,
                        "severity": severity,
                        "title": check["title"],
                        "description": check["description"],
                        "resource_id": res_id,
                        "resource_type": res_type,
                        "region": resource.get("region", ""),
                        "remediation": check.get("remediation", ""),
                        "cwe_id": check.get("cwe_id"),
                        "compliance": check.get("compliance", []),
                    }
                    all_findings.append(finding)
                    by_severity[severity] = by_severity.get(severity, 0) + 1

                    # Track compliance hits
                    for framework in check.get("compliance", []):
                        if framework not in compliance_hits:
                            compliance_hits[framework] = {"total": 0, "passed": 0, "failed": 0}
                        compliance_hits[framework]["failed"] += 1

                # Track compliance totals
                for framework in check.get("compliance", []):
                    if framework not in compliance_hits:
                        compliance_hits[framework] = {"total": 0, "passed": 0, "failed": 0}
                    compliance_hits[framework]["total"] += 1
                    if not is_vulnerable:
                        compliance_hits[framework]["passed"] += 1

            # Update resource with findings
            resource_findings = [f for f in all_findings if f.get("resource_id") == res_id]
            if resource_findings:
                resource["findings_count"] = len(resource_findings)
                resource["findings_by_severity"] = {}
                for f in resource_findings:
                    sev = f["severity"]
                    resource["findings_by_severity"][sev] = resource["findings_by_severity"].get(sev, 0) + 1
                resource["security_grade"] = _compute_grade(resource["findings_by_severity"])
                resource["last_assessed_at"] = datetime.utcnow().isoformat()
                await _resource_store.save(res_id, resource)

        # Run IaC scan if requested
        if job.get("include_iac_scan", True):
            iac_findings = await _run_iac_assessment()
            for f in iac_findings:
                all_findings.append(f)
                sev = f["severity"]
                by_severity[sev] = by_severity.get(sev, 0) + 1

        # Compute compliance coverage
        for framework, counts in compliance_hits.items():
            total = counts["total"]
            counts["coverage_pct"] = round(
                counts["passed"] / total * 100, 1,
            ) if total > 0 else 0.0

        job["resources_assessed"] = len(resources)
        job["checks_run"] = checks_run
        job["findings_count"] = len(all_findings)
        job["findings_by_severity"] = by_severity
        job["findings"] = all_findings
        job["security_grade"] = _compute_grade(by_severity)
        job["compliance_summary"] = compliance_hits
        job["status"] = "completed"
        job["duration_seconds"] = round(time.time() - start, 2)
        job["completed_at"] = datetime.utcnow().isoformat()

        # Broadcast event
        try:
            from mass.core.events import Event, EventType, publish_event
            await publish_event(Event(
                type=EventType.CLOUD_ASSESSMENT_COMPLETED,
                data={
                    "job_id": job_id,
                    "account_id": account_id,
                    "resources_assessed": len(resources),
                    "findings_count": len(all_findings),
                    "security_grade": job["security_grade"],
                },
                tenant_id=tenant_id,
            ))
        except Exception:
            pass

    except Exception as exc:
        logger.exception("Cloud assessment %s failed", job_id)
        job["status"] = "failed"
        job["error"] = str(exc)
        job["completed_at"] = datetime.utcnow().isoformat()
        await _assessment_store.move_to_dlq(job_id, str(exc))

    await _assessment_store.save(job_id, job)


def _evaluate_check(check_id: str, resource: dict) -> bool:
    """Evaluate a security check against a resource.

    Uses resource metadata to determine if the check condition is violated.
    Returns True if the resource is vulnerable (check failed).
    """
    metadata = resource.get("metadata", {})
    tags = resource.get("tags", {})
    res_type = resource.get("resource_type", "")

    # Encryption at rest
    if check_id == "CLD001":
        return not metadata.get("encryption_enabled", False)

    # Encryption in transit
    if check_id == "CLD002":
        return not metadata.get("tls_enabled", True)  # Default safe

    # Public exposure
    if check_id == "CLD003":
        return metadata.get("publicly_accessible", False)

    # Overly permissive IAM
    if check_id == "CLD004":
        actions = metadata.get("policy_actions", [])
        return "*" in actions or "arn:aws:iam::*" in str(actions)

    # Missing network isolation
    if check_id == "CLD005":
        return not metadata.get("vpc_id") and not metadata.get("subnet_id")

    # Hardcoded secrets
    if check_id == "CLD006":
        env_vars = metadata.get("environment_variables", {})
        secret_patterns = ["key", "secret", "token", "password", "credential"]
        for key, val in env_vars.items():
            if any(p in key.lower() for p in secret_patterns) and val and not val.startswith("${"):
                return True
        return False

    # Secret store audit logging
    if check_id == "CLD007":
        return not metadata.get("audit_logging_enabled", False)

    # Container running as root
    if check_id == "CLD008":
        return metadata.get("run_as_root", False) or not metadata.get("run_as_non_root", True)

    # Untrusted registry
    if check_id == "CLD009":
        image = metadata.get("container_image", "")
        trusted_registries = metadata.get("trusted_registries", [])
        if image and trusted_registries:
            return not any(image.startswith(reg) for reg in trusted_registries)
        # If no image info, assume uncertain (not vulnerable)
        return False

    # Training data encryption
    if check_id == "CLD010":
        return not metadata.get("encryption_enabled", False)

    # Public model artifacts
    if check_id == "CLD011":
        return metadata.get("public_access", False)

    # Missing monitoring
    if check_id == "CLD012":
        return not metadata.get("monitoring_enabled", False)

    # Missing resource limits
    if check_id == "CLD013":
        return not metadata.get("resource_limits_set", False)

    # Pipeline input validation
    if check_id == "CLD014":
        return not metadata.get("input_validation_enabled", False)

    # Notebook internet access
    if check_id == "CLD015":
        return metadata.get("direct_internet_access", True)

    return False


def _compute_grade(by_severity: dict[str, int]) -> str:
    """Compute security grade from severity counts."""
    critical = by_severity.get("critical", 0)
    high = by_severity.get("high", 0)
    medium = by_severity.get("medium", 0)

    if critical > 0:
        return "F"
    if high >= 3:
        return "D"
    if high > 0:
        return "C"
    if medium >= 3:
        return "C"
    if medium > 0:
        return "B"
    return "A"


async def _run_iac_assessment() -> list[dict]:
    """Run infrastructure-as-code security assessment using existing analyzers."""
    findings: list[dict] = []

    try:
        from mass.analyzers.infrastructure.scanner import InfrastructureScanner
        from pathlib import Path

        scanner = InfrastructureScanner()
        result = scanner.scan_directory(Path("."))

        for finding in result.findings:
            severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            findings.append({
                "check_id": finding.rule_id,
                "severity": severity,
                "title": finding.title,
                "description": finding.description,
                "resource_id": str(finding.file_path or ""),
                "resource_type": finding.resource_type,
                "region": "",
                "remediation": finding.remediation,
                "cwe_id": finding.cwe_id,
                "compliance": ["CIS"],
            })

    except Exception as e:
        logger.debug("IaC assessment failed: %s", e)

    return findings
