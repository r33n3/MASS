"""Secret detection patterns.

Comprehensive regex patterns for detecting secrets, credentials, and API keys.
Covers 50+ secret types across major providers and services.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Pattern


class SecretCategory(str, Enum):
    """Categories of secrets."""
    CLOUD_PROVIDER = "cloud_provider"
    AI_PROVIDER = "ai_provider"
    VERSION_CONTROL = "version_control"
    DATABASE = "database"
    MESSAGING = "messaging"
    PAYMENT = "payment"
    AUTHENTICATION = "authentication"
    CERTIFICATE = "certificate"
    GENERIC = "generic"
    INFRASTRUCTURE = "infrastructure"


class Severity(str, Enum):
    """Severity of secret exposure."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SecretPattern:
    """Definition of a secret pattern."""
    name: str
    pattern: str
    category: SecretCategory
    severity: Severity
    description: str
    entropy_threshold: float | None = None
    validators: list[str] = field(default_factory=list)
    false_positive_patterns: list[str] = field(default_factory=list)

    @property
    def compiled_pattern(self) -> Pattern[str]:
        """Get compiled regex pattern."""
        return re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)


# ============================================================================
# AI Provider Keys (Critical - Direct API Access)
# ============================================================================

AI_PROVIDER_PATTERNS = [
    SecretPattern(
        name="openai_api_key",
        pattern=r"sk-[A-Za-z0-9]{48,}",
        category=SecretCategory.AI_PROVIDER,
        severity=Severity.CRITICAL,
        description="OpenAI API Key",
        validators=["openai"],
    ),
    SecretPattern(
        name="openai_project_key",
        pattern=r"sk-proj-[A-Za-z0-9\-_]{80,}",
        category=SecretCategory.AI_PROVIDER,
        severity=Severity.CRITICAL,
        description="OpenAI Project API Key",
        validators=["openai"],
    ),
    SecretPattern(
        name="anthropic_api_key",
        pattern=r"sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{93}",
        category=SecretCategory.AI_PROVIDER,
        severity=Severity.CRITICAL,
        description="Anthropic API Key",
        validators=["anthropic"],
    ),
    SecretPattern(
        name="google_gemini_key",
        pattern=r"AIzaSy[A-Za-z0-9\-_]{33}",
        category=SecretCategory.AI_PROVIDER,
        severity=Severity.CRITICAL,
        description="Google Gemini/AI API Key",
        validators=["google_ai"],
    ),
    SecretPattern(
        name="cohere_api_key",
        pattern=r"(?i)(?:cohere|co[-_]?api)[-_]?(?:key|token)\s*[:=]\s*['\"]?([a-zA-Z0-9]{40})['\"]?",
        category=SecretCategory.AI_PROVIDER,
        severity=Severity.HIGH,
        description="Cohere API Key",
        entropy_threshold=4.5,
        validators=["cohere"],
    ),
    SecretPattern(
        name="huggingface_token",
        pattern=r"hf_[A-Za-z0-9]{34,}",
        category=SecretCategory.AI_PROVIDER,
        severity=Severity.HIGH,
        description="HuggingFace API Token",
        validators=["huggingface"],
    ),
    SecretPattern(
        name="replicate_api_token",
        pattern=r"r8_[A-Za-z0-9]{37}",
        category=SecretCategory.AI_PROVIDER,
        severity=Severity.HIGH,
        description="Replicate API Token",
        validators=["replicate"],
    ),
    SecretPattern(
        name="mistral_api_key",
        pattern=r"(?i)(?:mistral|mist)[-_]?(?:api)?[-_]?(?:key|token)\s*[:=]\s*['\"]?([A-Za-z0-9]{32})['\"]?",
        category=SecretCategory.AI_PROVIDER,
        severity=Severity.HIGH,
        description="Mistral AI API Key",
        entropy_threshold=4.5,
        validators=["mistral"],
    ),
    SecretPattern(
        name="together_api_key",
        pattern=r"(?i)(?:together)[-_]?(?:api)?[-_]?(?:key|token)\s*[:=]\s*['\"]?([a-f0-9]{64})['\"]?",
        category=SecretCategory.AI_PROVIDER,
        severity=Severity.HIGH,
        description="Together AI API Key",
        entropy_threshold=4.0,
        validators=["together"],
    ),
    SecretPattern(
        name="groq_api_key",
        pattern=r"gsk_[A-Za-z0-9]{52}",
        category=SecretCategory.AI_PROVIDER,
        severity=Severity.HIGH,
        description="Groq API Key",
        validators=["groq"],
    ),
]

# ============================================================================
# Cloud Provider Keys (Critical - Infrastructure Access)
# ============================================================================

CLOUD_PROVIDER_PATTERNS = [
    SecretPattern(
        name="aws_access_key",
        pattern=r"AKIA[0-9A-Z]{16}",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        description="AWS Access Key ID",
        validators=["aws"],
    ),
    SecretPattern(
        name="aws_secret_key",
        pattern=r"(?i)(?:aws[_-]?secret[_-]?(?:access[_-]?)?key|secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        description="AWS Secret Access Key",
        entropy_threshold=4.5,
        validators=["aws_secret"],
    ),
    SecretPattern(
        name="aws_session_token",
        pattern=r"FwoGZXIvYXdzE[A-Za-z0-9/+=]{300,}",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        description="AWS Session Token",
    ),
    SecretPattern(
        name="azure_storage_key",
        pattern=r"[A-Za-z0-9+/]{86}==",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        description="Azure Storage Account Key",
        entropy_threshold=5.0,
    ),
    SecretPattern(
        name="azure_client_secret",
        pattern=r"(?i)(?:azure|client)[-_]?secret\s*[:=]\s*['\"]?([A-Za-z0-9~_.\-]{34,40})['\"]?",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        description="Azure Client Secret",
        entropy_threshold=4.0,
    ),
    SecretPattern(
        name="azure_connection_string",
        pattern=r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;?",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        description="Azure Storage Connection String",
    ),
    SecretPattern(
        name="gcp_service_account",
        pattern=r'"type"\s*:\s*"service_account"',
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.CRITICAL,
        description="GCP Service Account Key (JSON)",
    ),
    SecretPattern(
        name="gcp_api_key",
        pattern=r"AIza[0-9A-Za-z\-_]{35}",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        description="Google Cloud API Key",
    ),
    SecretPattern(
        name="digitalocean_token",
        pattern=r"dop_v1_[a-f0-9]{64}",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        description="DigitalOcean Personal Access Token",
    ),
    SecretPattern(
        name="digitalocean_oauth",
        pattern=r"doo_v1_[a-f0-9]{64}",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        description="DigitalOcean OAuth Token",
    ),
    SecretPattern(
        name="linode_token",
        pattern=r"(?i)(?:linode)[-_]?(?:api)?[-_]?(?:key|token)\s*[:=]\s*['\"]?([a-f0-9]{64})['\"]?",
        category=SecretCategory.CLOUD_PROVIDER,
        severity=Severity.HIGH,
        description="Linode Personal Access Token",
        entropy_threshold=4.0,
    ),
]

# ============================================================================
# Version Control Tokens (High - Code Access)
# ============================================================================

VERSION_CONTROL_PATTERNS = [
    SecretPattern(
        name="github_pat",
        pattern=r"ghp_[A-Za-z0-9]{36,}",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        description="GitHub Personal Access Token",
    ),
    SecretPattern(
        name="github_oauth",
        pattern=r"gho_[A-Za-z0-9]{36,}",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        description="GitHub OAuth Token",
    ),
    SecretPattern(
        name="github_app_token",
        pattern=r"ghu_[A-Za-z0-9]{36,}",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        description="GitHub App User Token",
    ),
    SecretPattern(
        name="github_app_install_token",
        pattern=r"ghs_[A-Za-z0-9]{36,}",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        description="GitHub App Installation Token",
    ),
    SecretPattern(
        name="github_refresh_token",
        pattern=r"ghr_[A-Za-z0-9]{36,}",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        description="GitHub Refresh Token",
    ),
    SecretPattern(
        name="gitlab_token",
        pattern=r"glpat-[A-Za-z0-9\-_]{20,}",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        description="GitLab Personal Access Token",
    ),
    SecretPattern(
        name="gitlab_pipeline_token",
        pattern=r"glcbt-[A-Za-z0-9]{20,}",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        description="GitLab Pipeline Trigger Token",
    ),
    SecretPattern(
        name="bitbucket_app_password",
        pattern=r"(?i)(?:bitbucket|bb)[-_]?(?:app)?[-_]?(?:password|pass|pwd|token)\s*[:=]\s*['\"]?([A-Za-z0-9]{24})['\"]?",
        category=SecretCategory.VERSION_CONTROL,
        severity=Severity.HIGH,
        description="Bitbucket App Password",
        entropy_threshold=4.0,
    ),
]

# ============================================================================
# Database Credentials (Critical - Data Access)
# ============================================================================

DATABASE_PATTERNS = [
    SecretPattern(
        name="postgres_uri",
        pattern=r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^\s]+",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        description="PostgreSQL Connection URI",
    ),
    SecretPattern(
        name="mysql_uri",
        pattern=r"mysql://[^:]+:[^@]+@[^/]+/[^\s]+",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        description="MySQL Connection URI",
    ),
    SecretPattern(
        name="mongodb_uri",
        pattern=r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s]+",
        category=SecretCategory.DATABASE,
        severity=Severity.CRITICAL,
        description="MongoDB Connection URI",
    ),
    SecretPattern(
        name="redis_uri",
        pattern=r"redis://[^:]*:[^@]+@[^/]+(?:/\d+)?",
        category=SecretCategory.DATABASE,
        severity=Severity.HIGH,
        description="Redis Connection URI",
    ),
    SecretPattern(
        name="credential_uri",
        pattern=r"https?://[A-Za-z0-9._~%-]+:[A-Za-z0-9._~!$&'()*+,;=%-]+@[A-Za-z0-9.-]+(?::\d{2,5})?(?:/\S*)?",
        category=SecretCategory.DATABASE,
        severity=Severity.HIGH,
        description="URL with Embedded Credentials",
        false_positive_patterns=[
            r"https?://example\.",
            r"https?://user(?:name)?:pass(?:word)?@",
            r"https?://\$\{",
            r"https?://<",
            r"https?://\{\{",
        ],
    ),
]

# ============================================================================
# Messaging & Communication (High - Service Access)
# ============================================================================

MESSAGING_PATTERNS = [
    SecretPattern(
        name="slack_token",
        pattern=r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        category=SecretCategory.MESSAGING,
        severity=Severity.HIGH,
        description="Slack Token",
    ),
    SecretPattern(
        name="slack_webhook",
        pattern=r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        category=SecretCategory.MESSAGING,
        severity=Severity.MEDIUM,
        description="Slack Webhook URL",
    ),
    SecretPattern(
        name="discord_token",
        pattern=r"[MN][A-Za-z0-9]{23,28}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27,}",
        category=SecretCategory.MESSAGING,
        severity=Severity.HIGH,
        description="Discord Bot Token",
    ),
    SecretPattern(
        name="discord_webhook",
        pattern=r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
        category=SecretCategory.MESSAGING,
        severity=Severity.MEDIUM,
        description="Discord Webhook URL",
    ),
    SecretPattern(
        name="twilio_account_sid",
        pattern=r"AC[a-f0-9]{32}",
        category=SecretCategory.MESSAGING,
        severity=Severity.HIGH,
        description="Twilio Account SID",
    ),
    SecretPattern(
        name="twilio_auth_token",
        pattern=r"(?i)(?:twilio)[-_]?(?:auth)?[-_]?(?:token|secret)\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
        category=SecretCategory.MESSAGING,
        severity=Severity.HIGH,
        description="Twilio Auth Token",
        entropy_threshold=4.0,
    ),
    SecretPattern(
        name="sendgrid_api_key",
        pattern=r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        category=SecretCategory.MESSAGING,
        severity=Severity.HIGH,
        description="SendGrid API Key",
    ),
    SecretPattern(
        name="mailchimp_api_key",
        pattern=r"[a-f0-9]{32}-us\d+",
        category=SecretCategory.MESSAGING,
        severity=Severity.MEDIUM,
        description="Mailchimp API Key",
    ),
]

# ============================================================================
# Payment & Financial (Critical - Financial Data)
# ============================================================================

PAYMENT_PATTERNS = [
    SecretPattern(
        name="stripe_secret_key",
        pattern=r"sk_live_[A-Za-z0-9]{24,}",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        description="Stripe Live Secret Key",
    ),
    SecretPattern(
        name="stripe_test_key",
        pattern=r"sk_test_[A-Za-z0-9]{24,}",
        category=SecretCategory.PAYMENT,
        severity=Severity.MEDIUM,
        description="Stripe Test Secret Key",
    ),
    SecretPattern(
        name="stripe_restricted_key",
        pattern=r"rk_live_[A-Za-z0-9]{24,}",
        category=SecretCategory.PAYMENT,
        severity=Severity.HIGH,
        description="Stripe Restricted Key",
    ),
    SecretPattern(
        name="paypal_client_secret",
        pattern=r"(?i)(?:paypal|pp)[-_]?(?:client)?[-_]?(?:secret|key)\s*[:=]\s*['\"]?(E[A-Za-z0-9_-]{71})['\"]?",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        description="PayPal Client Secret",
        entropy_threshold=4.5,
    ),
    SecretPattern(
        name="square_access_token",
        pattern=r"sq0atp-[A-Za-z0-9\-_]{22}",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        description="Square Access Token",
    ),
    SecretPattern(
        name="square_oauth_secret",
        pattern=r"sq0csp-[A-Za-z0-9\-_]{43}",
        category=SecretCategory.PAYMENT,
        severity=Severity.CRITICAL,
        description="Square OAuth Secret",
    ),
]

# ============================================================================
# Authentication Tokens (High - Identity)
# ============================================================================

AUTHENTICATION_PATTERNS = [
    SecretPattern(
        name="jwt_token",
        pattern=r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*",
        category=SecretCategory.AUTHENTICATION,
        severity=Severity.HIGH,
        description="JSON Web Token (JWT)",
    ),
    SecretPattern(
        name="basic_auth_header",
        pattern=r"Basic\s+[A-Za-z0-9+/=]{20,}",
        category=SecretCategory.AUTHENTICATION,
        severity=Severity.HIGH,
        description="HTTP Basic Auth Header",
    ),
    SecretPattern(
        name="bearer_token",
        pattern=r"Bearer\s+[A-Za-z0-9\-_\.]{20,}",
        category=SecretCategory.AUTHENTICATION,
        severity=Severity.HIGH,
        description="Bearer Token",
    ),
    SecretPattern(
        name="okta_token",
        pattern=r"(?i)(?:okta)[-_]?(?:api)?[-_]?(?:token|key)\s*[:=]\s*['\"]?(00[A-Za-z0-9_-]{40})['\"]?",
        category=SecretCategory.AUTHENTICATION,
        severity=Severity.HIGH,
        description="Okta Token",
        entropy_threshold=4.0,
    ),
    SecretPattern(
        name="auth0_client_secret",
        pattern=r"(?i)(?:auth0|client)[-_]?(?:secret|key)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,64})['\"]?",
        category=SecretCategory.AUTHENTICATION,
        severity=Severity.HIGH,
        description="Auth0 Client Secret",
        entropy_threshold=4.5,
    ),
]

# ============================================================================
# Certificates & Private Keys (Critical - Security)
# ============================================================================

CERTIFICATE_PATTERNS = [
    SecretPattern(
        name="private_key_rsa",
        pattern=r"-----BEGIN RSA PRIVATE KEY-----",
        category=SecretCategory.CERTIFICATE,
        severity=Severity.CRITICAL,
        description="RSA Private Key",
    ),
    SecretPattern(
        name="private_key_openssh",
        pattern=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        category=SecretCategory.CERTIFICATE,
        severity=Severity.CRITICAL,
        description="OpenSSH Private Key",
    ),
    SecretPattern(
        name="private_key_ec",
        pattern=r"-----BEGIN EC PRIVATE KEY-----",
        category=SecretCategory.CERTIFICATE,
        severity=Severity.CRITICAL,
        description="EC Private Key",
    ),
    SecretPattern(
        name="private_key_dsa",
        pattern=r"-----BEGIN DSA PRIVATE KEY-----",
        category=SecretCategory.CERTIFICATE,
        severity=Severity.CRITICAL,
        description="DSA Private Key",
    ),
    SecretPattern(
        name="private_key_encrypted",
        pattern=r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        category=SecretCategory.CERTIFICATE,
        severity=Severity.HIGH,
        description="Encrypted Private Key",
    ),
    SecretPattern(
        name="pgp_private_key",
        pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        category=SecretCategory.CERTIFICATE,
        severity=Severity.CRITICAL,
        description="PGP Private Key",
    ),
]

# ============================================================================
# Infrastructure (High - Service Access)
# ============================================================================

INFRASTRUCTURE_PATTERNS = [
    SecretPattern(
        name="npm_token",
        pattern=r"npm_[A-Za-z0-9]{36}",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        description="NPM Access Token",
    ),
    SecretPattern(
        name="pypi_token",
        pattern=r"pypi-[A-Za-z0-9_-]{50,}",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        description="PyPI API Token",
    ),
    SecretPattern(
        name="docker_hub_token",
        pattern=r"dckr_pat_[A-Za-z0-9_-]{27}",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        description="Docker Hub Access Token",
    ),
    SecretPattern(
        name="circleci_token",
        pattern=r"(?i)(?:circle[-_]?ci|circleci)[-_]?(?:api)?[-_]?(?:token|key)\s*[:=]\s*['\"]?([a-f0-9]{40})['\"]?",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        description="CircleCI Personal API Token",
        entropy_threshold=4.0,
    ),
    SecretPattern(
        name="travis_ci_token",
        pattern=r"(?i)(?:travis[-_]?ci|travis)[-_]?(?:api)?[-_]?(?:token|key)\s*[:=]\s*['\"]?([A-Za-z0-9]{22})['\"]?",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        description="Travis CI Token",
        entropy_threshold=4.0,
    ),
    SecretPattern(
        name="sonarqube_token",
        pattern=r"sqp_[A-Za-z0-9]{40}",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        description="SonarQube Token",
    ),
    SecretPattern(
        name="datadog_api_key",
        pattern=r"(?i)(?:datadog|dd)[-_]?(?:api)?[-_]?(?:key|token)\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        description="Datadog API Key",
        entropy_threshold=4.0,
    ),
    SecretPattern(
        name="newrelic_api_key",
        pattern=r"NRAK-[A-Z0-9]{27}",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        description="New Relic API Key",
    ),
    SecretPattern(
        name="sentry_dsn",
        pattern=r"https://[a-f0-9]{32}@[a-z0-9.]+\.sentry\.io/\d+",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        description="Sentry DSN",
    ),
    SecretPattern(
        name="terraform_cloud_token",
        pattern=r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67}",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.HIGH,
        description="Terraform Cloud Token",
    ),
    SecretPattern(
        name="vault_token",
        pattern=r"hvs\.[A-Za-z0-9]{24,}",
        category=SecretCategory.INFRASTRUCTURE,
        severity=Severity.CRITICAL,
        description="HashiCorp Vault Token",
    ),
]

# ============================================================================
# Generic Secrets (Variable Severity)
# ============================================================================

GENERIC_PATTERNS = [
    SecretPattern(
        name="generic_api_key",
        pattern=r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,64})['\"]?",
        category=SecretCategory.GENERIC,
        severity=Severity.MEDIUM,
        description="Generic API Key",
        entropy_threshold=4.0,
    ),
    SecretPattern(
        name="generic_secret",
        pattern=r"(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,64})['\"]?",
        category=SecretCategory.GENERIC,
        severity=Severity.MEDIUM,
        description="Generic Secret/Password",
        entropy_threshold=3.5,
        false_positive_patterns=[
            r"password\s*[:=]\s*['\"]?\$",  # Variable references
            r"password\s*[:=]\s*['\"]?<",   # Placeholder
            r"password\s*[:=]\s*['\"]?\{\{", # Template
        ],
    ),
    SecretPattern(
        name="generic_token",
        pattern=r"(?i)(?:token|auth)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{20,100})['\"]?",
        category=SecretCategory.GENERIC,
        severity=Severity.MEDIUM,
        description="Generic Token",
        entropy_threshold=4.0,
    ),
    SecretPattern(
        name="high_entropy_string",
        pattern=r"[A-Za-z0-9+/=]{32,}",
        category=SecretCategory.GENERIC,
        severity=Severity.LOW,
        description="High Entropy String",
        entropy_threshold=4.5,
    ),
]

# ============================================================================
# Combined Pattern List
# ============================================================================

SECRET_PATTERNS: list[SecretPattern] = [
    *AI_PROVIDER_PATTERNS,
    *CLOUD_PROVIDER_PATTERNS,
    *VERSION_CONTROL_PATTERNS,
    *DATABASE_PATTERNS,
    *MESSAGING_PATTERNS,
    *PAYMENT_PATTERNS,
    *AUTHENTICATION_PATTERNS,
    *CERTIFICATE_PATTERNS,
    *INFRASTRUCTURE_PATTERNS,
    *GENERIC_PATTERNS,
]


def get_patterns_by_category(category: SecretCategory) -> list[SecretPattern]:
    """Get all patterns for a specific category."""
    return [p for p in SECRET_PATTERNS if p.category == category]


def get_patterns_by_severity(severity: Severity) -> list[SecretPattern]:
    """Get all patterns for a specific severity."""
    return [p for p in SECRET_PATTERNS if p.severity == severity]


def get_critical_patterns() -> list[SecretPattern]:
    """Get all critical severity patterns."""
    return get_patterns_by_severity(Severity.CRITICAL)
