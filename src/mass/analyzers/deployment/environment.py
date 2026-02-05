"""Environment detector.

Analyzes a DeploymentManifest to auto-detect the cloud provider, services,
databases, authentication mechanisms, and AI model providers used by a
deployment.  Operates entirely on already-collected manifest data (components,
dependencies, model configs, MCP servers) -- reads no additional files.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CloudServiceInfo:
    """A detected cloud service used by the deployment."""

    provider: str         # "aws", "azure", "gcp", "local"
    service_type: str     # "secrets_manager", "compute", "storage", etc.
    resource_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "provider": self.provider,
            "service_type": self.service_type,
        }
        if self.resource_name:
            d["resource_name"] = self.resource_name
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class EnvironmentProfile:
    """Detected deployment environment."""

    cloud_provider: str = "unknown"  # aws, azure, gcp, local, hybrid
    cloud_services: list[CloudServiceInfo] = field(default_factory=list)
    model_provider: str | None = None
    model_name: str | None = None
    databases: list[str] = field(default_factory=list)
    auth_mechanisms: list[str] = field(default_factory=list)
    connected_apis: list[str] = field(default_factory=list)
    mcp_servers: list[str] = field(default_factory=list)

    # ---- convenience properties ----

    @property
    def secrets_manager_name(self) -> str:
        """Return the appropriate secrets manager for the detected provider."""
        return {
            "aws": "AWS Secrets Manager",
            "azure": "Azure Key Vault",
            "gcp": "Google Cloud Secret Manager",
        }.get(self.cloud_provider, "a secrets manager")

    @property
    def secrets_manager_sdk(self) -> str:
        """Python SDK package for the detected secrets manager."""
        return {
            "aws": "boto3",
            "azure": "azure-keyvault-secrets",
            "gcp": "google-cloud-secret-manager",
        }.get(self.cloud_provider, "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "cloud_provider": self.cloud_provider,
            "cloud_services": [s.to_dict() for s in self.cloud_services],
            "model_provider": self.model_provider,
            "model_name": self.model_name,
            "databases": self.databases,
            "auth_mechanisms": self.auth_mechanisms,
            "connected_apis": self.connected_apis,
            "mcp_servers": self.mcp_servers,
            "secrets_manager": self.secrets_manager_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EnvironmentProfile":
        services = [
            CloudServiceInfo(**s) for s in data.get("cloud_services", [])
        ]
        return cls(
            cloud_provider=data.get("cloud_provider", "unknown"),
            cloud_services=services,
            model_provider=data.get("model_provider"),
            model_name=data.get("model_name"),
            databases=data.get("databases", []),
            auth_mechanisms=data.get("auth_mechanisms", []),
            connected_apis=data.get("connected_apis", []),
            mcp_servers=data.get("mcp_servers", []),
        )


# ---------------------------------------------------------------------------
# Detection maps
# ---------------------------------------------------------------------------

# Python dependency → cloud provider
_PYTHON_CLOUD_DEPS: dict[str, str] = {
    # AWS
    "boto3": "aws", "botocore": "aws", "aws-cdk-lib": "aws",
    "aws-cdk": "aws", "sagemaker": "aws", "awscli": "aws",
    "amazon-bedrock-runtime": "aws",
    # Azure
    "azure-identity": "azure", "azure-keyvault-secrets": "azure",
    "azure-keyvault-keys": "azure", "azure-keyvault-certificates": "azure",
    "azure-storage-blob": "azure", "azure-ai-openai": "azure",
    "azure-ai-formrecognizer": "azure", "azure-ai-textanalytics": "azure",
    "azure-cosmos": "azure", "azure-mgmt-resource": "azure",
    "azure-servicebus": "azure",
    # GCP
    "google-cloud-secret-manager": "gcp", "google-cloud-storage": "gcp",
    "google-cloud-aiplatform": "gcp", "google-cloud-firestore": "gcp",
    "google-cloud-bigquery": "gcp", "google-cloud-pubsub": "gcp",
    "google-auth": "gcp", "google-generativeai": "gcp",
}

# Python dependency → cloud service
_PYTHON_SERVICE_DEPS: dict[str, tuple[str, str]] = {
    # (provider, service_type)
    "boto3": ("aws", "sdk"),
    "amazon-bedrock-runtime": ("aws", "bedrock"),
    "sagemaker": ("aws", "sagemaker"),
    "azure-keyvault-secrets": ("azure", "key_vault"),
    "azure-ai-openai": ("azure", "azure_openai"),
    "azure-cosmos": ("azure", "cosmos_db"),
    "azure-servicebus": ("azure", "service_bus"),
    "google-cloud-secret-manager": ("gcp", "secret_manager"),
    "google-cloud-aiplatform": ("gcp", "vertex_ai"),
    "google-cloud-firestore": ("gcp", "firestore"),
    "google-cloud-pubsub": ("gcp", "pub_sub"),
}

# Python dependency → database
_PYTHON_DB_DEPS: dict[str, str] = {
    "psycopg2": "postgresql", "psycopg2-binary": "postgresql",
    "asyncpg": "postgresql", "sqlalchemy": "sql_database",
    "pymongo": "mongodb", "motor": "mongodb",
    "redis": "redis", "aioredis": "redis",
    "pymysql": "mysql", "aiomysql": "mysql",
    "sqlite3": "sqlite",
    "chromadb": "chromadb", "pinecone-client": "pinecone",
    "qdrant-client": "qdrant", "weaviate-client": "weaviate",
    "faiss-cpu": "faiss", "faiss-gpu": "faiss",
    "pgvector": "pgvector",
    "azure-cosmos": "cosmos_db",
    "google-cloud-firestore": "firestore",
}

# Python dependency → auth mechanism
_PYTHON_AUTH_DEPS: dict[str, str] = {
    "PyJWT": "jwt", "python-jose": "jwt",
    "authlib": "oauth", "oauthlib": "oauth",
    "passlib": "password_hashing",
    "cryptography": "encryption",
    "azure-identity": "azure_ad",
    "google-auth": "gcp_iam",
}

# Terraform resource prefix → cloud provider
_TERRAFORM_PREFIXES: dict[str, str] = {
    "aws_": "aws",
    "azurerm_": "azure",
    "azuread_": "azure",
    "google_": "gcp",
}

# Terraform resource → service mapping
_TERRAFORM_SERVICES: dict[str, tuple[str, str]] = {
    "aws_secretsmanager_secret": ("aws", "secrets_manager"),
    "aws_ssm_parameter": ("aws", "ssm_parameter_store"),
    "aws_lambda_function": ("aws", "lambda"),
    "aws_sagemaker": ("aws", "sagemaker"),
    "aws_bedrock": ("aws", "bedrock"),
    "aws_s3_bucket": ("aws", "s3"),
    "aws_rds": ("aws", "rds"),
    "aws_dynamodb_table": ("aws", "dynamodb"),
    "aws_ecs": ("aws", "ecs"),
    "aws_eks": ("aws", "eks"),
    "azurerm_key_vault": ("azure", "key_vault"),
    "azurerm_cognitive_account": ("azure", "cognitive_services"),
    "azurerm_cosmosdb_account": ("azure", "cosmos_db"),
    "azurerm_storage_account": ("azure", "storage"),
    "azurerm_container": ("azure", "container_apps"),
    "azurerm_kubernetes": ("azure", "aks"),
    "google_secret_manager_secret": ("gcp", "secret_manager"),
    "google_cloud_run": ("gcp", "cloud_run"),
    "google_compute_instance": ("gcp", "compute_engine"),
    "google_sql_database": ("gcp", "cloud_sql"),
    "google_storage_bucket": ("gcp", "cloud_storage"),
}

# Model provider detection
_MODEL_PROVIDER_MAP: dict[str, str] = {
    "openai": "openai",
    "anthropic": "anthropic",
    "bedrock": "aws_bedrock",
    "azure_openai": "azure_openai",
    "vertex_ai": "gcp_vertex_ai",
    "google": "google_ai",
    "ollama": "ollama",
    "local": "local",
    "cohere": "cohere",
    "huggingface": "huggingface",
}


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class EnvironmentDetector:
    """Detects deployment environment from a DeploymentManifest.

    Analyzes dependencies, infrastructure files, model configs, and
    MCP server configs to determine the cloud provider, services,
    databases, and authentication mechanisms.
    """

    def detect(self, manifest: Any) -> EnvironmentProfile:
        """Analyze manifest and produce an EnvironmentProfile.

        Args:
            manifest: A DeploymentManifest instance.

        Returns:
            Detected EnvironmentProfile.
        """
        profile = EnvironmentProfile()
        provider_signals: dict[str, int] = {}

        # 1. Detect from dependencies
        self._detect_from_dependencies(manifest, profile, provider_signals)

        # 2. Detect from infrastructure components (terraform, docker)
        self._detect_from_infrastructure(manifest, profile, provider_signals)

        # 3. Detect model provider
        self._detect_model_provider(manifest, profile)

        # 4. Detect MCP servers
        self._detect_mcp_servers(manifest, profile)

        # 5. Determine primary cloud provider from signals
        profile.cloud_provider = self._resolve_cloud_provider(provider_signals)

        logger.info(
            "Detected environment: provider=%s, services=%d, databases=%d, "
            "model=%s, mcp_servers=%d",
            profile.cloud_provider,
            len(profile.cloud_services),
            len(profile.databases),
            profile.model_provider or "none",
            len(profile.mcp_servers),
        )

        return profile

    # ---- detection methods ----

    def _detect_from_dependencies(
        self,
        manifest: Any,
        profile: EnvironmentProfile,
        provider_signals: dict[str, int],
    ) -> None:
        """Detect cloud, DB, and auth from project dependencies."""
        dep_names = set(manifest.dependencies.keys())

        # Cloud provider signals
        for dep_name, provider in _PYTHON_CLOUD_DEPS.items():
            if dep_name in dep_names:
                provider_signals[provider] = provider_signals.get(provider, 0) + 1

        # Cloud services
        seen_services: set[tuple[str, str]] = set()
        for dep_name, (provider, service) in _PYTHON_SERVICE_DEPS.items():
            if dep_name in dep_names:
                key = (provider, service)
                if key not in seen_services:
                    seen_services.add(key)
                    profile.cloud_services.append(CloudServiceInfo(
                        provider=provider,
                        service_type=service,
                        metadata={"detected_from": f"dependency:{dep_name}"},
                    ))

        # Databases
        seen_dbs: set[str] = set()
        for dep_name, db_type in _PYTHON_DB_DEPS.items():
            if dep_name in dep_names and db_type not in seen_dbs:
                seen_dbs.add(db_type)
                profile.databases.append(db_type)

        # Auth mechanisms
        seen_auth: set[str] = set()
        for dep_name, auth_type in _PYTHON_AUTH_DEPS.items():
            if dep_name in dep_names and auth_type not in seen_auth:
                seen_auth.add(auth_type)
                profile.auth_mechanisms.append(auth_type)

    def _detect_from_infrastructure(
        self,
        manifest: Any,
        profile: EnvironmentProfile,
        provider_signals: dict[str, int],
    ) -> None:
        """Detect cloud provider and services from infrastructure files."""
        from mass.core.types import ComponentType

        infra_components = manifest.components_by_type(ComponentType.INFRASTRUCTURE)

        for component in infra_components:
            content = component.content or ""
            file_name = component.path.name.lower()

            # Terraform files
            if file_name.endswith(".tf"):
                self._detect_from_terraform(content, profile, provider_signals)

            # Docker files
            elif file_name.startswith("dockerfile") or file_name.endswith(
                ("docker-compose.yml", "docker-compose.yaml")
            ):
                self._detect_from_docker(content, profile, provider_signals)

    def _detect_from_terraform(
        self,
        content: str,
        profile: EnvironmentProfile,
        provider_signals: dict[str, int],
    ) -> None:
        """Extract cloud info from Terraform content."""
        # Provider block detection
        for prefix, provider in _TERRAFORM_PREFIXES.items():
            # Count resource definitions
            resource_count = len(re.findall(
                rf'resource\s+"({re.escape(prefix)}\w+)"',
                content,
            ))
            if resource_count > 0:
                provider_signals[provider] = (
                    provider_signals.get(provider, 0) + resource_count
                )

        # Specific service detection
        seen_services: set[tuple[str, str]] = set()
        for resource_prefix, (provider, service) in _TERRAFORM_SERVICES.items():
            if resource_prefix in content:
                key = (provider, service)
                if key not in seen_services:
                    seen_services.add(key)
                    profile.cloud_services.append(CloudServiceInfo(
                        provider=provider,
                        service_type=service,
                        metadata={"detected_from": f"terraform:{resource_prefix}"},
                    ))

    def _detect_from_docker(
        self,
        content: str,
        profile: EnvironmentProfile,
        provider_signals: dict[str, int],
    ) -> None:
        """Extract cloud info from Docker content."""
        # AWS ECR registry
        if ".dkr.ecr." in content or "amazonaws.com" in content:
            provider_signals["aws"] = provider_signals.get("aws", 0) + 1

        # Azure Container Registry
        if ".azurecr.io" in content:
            provider_signals["azure"] = provider_signals.get("azure", 0) + 1

        # Google Container Registry / Artifact Registry
        if "gcr.io" in content or "pkg.dev" in content:
            provider_signals["gcp"] = provider_signals.get("gcp", 0) + 1

    def _detect_model_provider(
        self,
        manifest: Any,
        profile: EnvironmentProfile,
    ) -> None:
        """Detect AI model provider from model configs and dependencies."""
        # From manifest model configs (highest priority)
        if manifest.model_configs:
            config = manifest.model_configs[0]
            raw_provider = config.provider.lower()
            profile.model_provider = _MODEL_PROVIDER_MAP.get(
                raw_provider, raw_provider
            )
            profile.model_name = config.model_name

        # Fallback: detect from dependencies
        if not profile.model_provider:
            dep_names = set(manifest.dependencies.keys())
            if "openai" in dep_names:
                profile.model_provider = "openai"
            elif "anthropic" in dep_names:
                profile.model_provider = "anthropic"
            elif "google-generativeai" in dep_names:
                profile.model_provider = "google_ai"
            elif "transformers" in dep_names:
                profile.model_provider = "huggingface"

    def _detect_mcp_servers(
        self,
        manifest: Any,
        profile: EnvironmentProfile,
    ) -> None:
        """Detect MCP server configurations."""
        for mcp in manifest.mcp_servers:
            server_url = mcp.server_url or "unknown"
            profile.mcp_servers.append(server_url)

            # Detect connected APIs from MCP tools
            for tool in mcp.tools:
                tool_lower = tool.lower()
                if tool_lower not in profile.connected_apis:
                    profile.connected_apis.append(tool_lower)

    def _resolve_cloud_provider(
        self,
        provider_signals: dict[str, int],
    ) -> str:
        """Determine primary cloud provider from weighted signals.

        Returns:
            Cloud provider string: aws, azure, gcp, hybrid, local, unknown.
        """
        if not provider_signals:
            return "local"

        # Sort by signal count
        sorted_providers = sorted(
            provider_signals.items(), key=lambda x: x[1], reverse=True
        )

        if len(sorted_providers) == 1:
            return sorted_providers[0][0]

        # If top two are close (within 2x), it's hybrid
        top_provider, top_count = sorted_providers[0]
        second_provider, second_count = sorted_providers[1]

        if second_count > 0 and top_count / second_count < 3:
            return "hybrid"

        return top_provider
