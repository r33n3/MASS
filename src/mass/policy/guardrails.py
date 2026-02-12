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

    # ── Prompt Injection / Jailbreak ──

    registry.register(Guardrail(
        id="grd-input-sanitize",
        name="Prompt Injection Blocking",
        description=(
            "Intercept user prompts at the proxy layer and block known injection "
            "patterns before they reach the model. Uses pattern matching, embedding "
            "similarity, and a secondary classifier to catch instruction-override, "
            "role-play, and delimiter-confusion attacks."
        ),
        guardrail_type=GuardrailType.INPUT_VALIDATION,
        severity=GuardrailSeverity.CRITICAL,
        implementation_steps=[
            "Deploy a pre-processing middleware in the API gateway that runs before model inference",
            "Build a deny-list of high-signal injection phrases (e.g. 'ignore previous instructions', "
            "'you are now', 'disregard all prior', '### NEW SYSTEM PROMPT') and reject on match",
            "Add a lightweight classifier (distilbert or regex ensemble) scored 0-1 for injection likelihood; "
            "block requests above the threshold (recommend 0.85) and log borderline cases",
            "Separate the system prompt from user input with a clear delimiter token the proxy enforces "
            "(e.g. <|system|>...<|user|>); strip any user-supplied delimiter tokens",
            "Return a structured 422 response with a violation code so the client can surface a "
            "user-friendly error and the event can be tracked in SIEM",
        ],
        code_examples={
            "python": '''import re
from fastapi import Request, HTTPException

# High-confidence injection patterns (tune for your domain)
INJECTION_PATTERNS = [
    r"(?i)ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions|prompts|rules)",
    r"(?i)you\\s+are\\s+now\\s+(a|an|the|DAN|my)",
    r"(?i)disregard\\s+(all|your|the)\\s+(rules|instructions|guidelines)",
    r"(?i)###\\s*(system|new|override)",
    r"(?i)\\[INST\\]|<\\|im_start\\|>|<\\|system\\|>",
    r"(?i)pretend\\s+(you\\s+are|to\\s+be)\\s+.{0,30}(unrestricted|unfiltered|evil)",
    r"(?i)repeat\\s+(the|your)\\s+(system|initial|original)\\s+prompt",
]
_COMPILED = [re.compile(p) for p in INJECTION_PATTERNS]

async def injection_guard(request: Request):
    """FastAPI dependency — raises 422 if prompt injection detected."""
    body = await request.json()
    user_text = body.get("prompt", "") or body.get("messages", [{}])[-1].get("content", "")

    for i, pattern in enumerate(_COMPILED):
        if pattern.search(user_text):
            raise HTTPException(
                status_code=422,
                detail={
                    "violation": "prompt_injection",
                    "pattern_id": i,
                    "message": "Request blocked: potential prompt injection detected",
                },
            )
    # Strip user-supplied delimiter tokens
    for tok in ("<|system|>", "<|user|>", "[INST]", "### System"):
        user_text = user_text.replace(tok, "")
    body["prompt"] = user_text
    return body''',
            "nginx": '''# Block requests containing common injection markers at the edge
# Place in the location block proxying to the inference API

if ($request_body ~* "ignore\\s+(all\\s+)?previous\\s+instructions") {
    return 422 '{"error":"prompt_injection","message":"Blocked by WAF rule"}';
}
if ($request_body ~* "you\\s+are\\s+now") {
    return 422 '{"error":"prompt_injection","message":"Blocked by WAF rule"}';
}

# Rate-limit suspicious clients that trigger multiple soft blocks
limit_req_zone $binary_remote_addr zone=injection_suspects:10m rate=2r/m;''',
        },
        mitigates_categories=[
            AttackCategory.PROMPT_INJECTION,
            AttackCategory.JAILBREAK,
        ],
        required_for_compliance=["LLM01", "AML.T0051"],
        effort="medium",
        effectiveness="high",
        tags=["prompt-injection", "input-validation", "proxy"],
    ))

    # ── Content Moderation ──

    registry.register(Guardrail(
        id="grd-content-filter",
        name="Content Moderation Filter",
        description=(
            "Classify and block harmful, toxic, or policy-violating content in both "
            "model inputs and outputs. Enforced at the proxy layer so every model "
            "behind the gateway inherits the same content policy."
        ),
        guardrail_type=GuardrailType.CONTENT_MODERATION,
        severity=GuardrailSeverity.HIGH,
        implementation_steps=[
            "Integrate a content-classification model (OpenAI moderation endpoint, Perspective API, "
            "or a self-hosted distilbert fine-tune) as a sidecar or middleware",
            "Define category thresholds: violence > 0.8 block, sexual > 0.7 block, self-harm > 0.6 block; "
            "tune per deployment via env vars or config map",
            "Apply classification to BOTH the incoming prompt (pre-inference) and the model response "
            "(post-inference) to catch multi-turn escalation",
            "On block, return a 451 status with the category and confidence so dashboards can "
            "chart violation trends; log the full event for policy review",
            "Add an allow-list bypass for internal red-team / security-testing user roles "
            "(gated behind RBAC) so authorized testing is not disrupted",
            "Review blocked-content reports weekly and adjust thresholds to reduce false positives",
        ],
        code_examples={
            "python": '''from dataclasses import dataclass
import httpx

MODERATION_URL = "https://api.openai.com/v1/moderations"

@dataclass
class ModerationResult:
    flagged: bool
    categories: dict[str, bool]
    scores: dict[str, float]

async def moderate_text(text: str, api_key: str) -> ModerationResult:
    """Check text against OpenAI moderation endpoint."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            MODERATION_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            json={"input": text},
        )
        resp.raise_for_status()
        result = resp.json()["results"][0]
        return ModerationResult(
            flagged=result["flagged"],
            categories=result["categories"],
            scores=result["category_scores"],
        )

# Proxy middleware usage:
async def content_gate(prompt: str, response: str, api_key: str):
    """Block if either prompt or response is flagged."""
    for label, text in [("input", prompt), ("output", response)]:
        result = await moderate_text(text, api_key)
        if result.flagged:
            violated = [c for c, v in result.categories.items() if v]
            raise ContentPolicyViolation(
                stage=label, categories=violated,
                scores={c: result.scores[c] for c in violated},
            )''',
        },
        mitigates_categories=[
            AttackCategory.TOXICITY,
            AttackCategory.IMPROPER_OUTPUT,
            AttackCategory.JAILBREAK,
        ],
        required_for_compliance=["LLM05", "EU-AI-TR"],
        effort="medium",
        effectiveness="medium",
        tags=["content-moderation", "safety", "proxy"],
    ))

    # ── PII / Sensitive Data Filtering ──

    registry.register(Guardrail(
        id="grd-output-pii",
        name="PII & Sensitive Data Filtering",
        description=(
            "Scan model outputs for personally identifiable information (SSNs, "
            "credit cards, emails, phone numbers) and credentials, then redact "
            "before the response reaches the client. Prevents data leakage even "
            "if the model has memorized training data."
        ),
        guardrail_type=GuardrailType.OUTPUT_FILTERING,
        severity=GuardrailSeverity.CRITICAL,
        implementation_steps=[
            "Implement a post-inference filter in the proxy that regex-scans every model response",
            "Define PII patterns: SSN (\\d{3}-\\d{2}-\\d{4}), credit card (Luhn-valid 13-19 digits), "
            "email, phone, AWS keys (AKIA...), JWT tokens, and custom org patterns",
            "Replace matches with typed redaction tokens like [REDACTED_SSN] so downstream consumers "
            "know what was removed without seeing the value",
            "Ship redaction events to SIEM with the pattern type, model ID, and request context "
            "(but NOT the redacted value) for trend analysis",
            "Maintain an allow-list for known-safe patterns (e.g. support@ company email in boilerplate) "
            "to reduce false positives",
        ],
        code_examples={
            "python": '''import re
from typing import NamedTuple

class RedactionHit(NamedTuple):
    pii_type: str
    start: int
    end: int

# Patterns ordered from most specific to least to avoid double-redaction
PII_RULES: list[tuple[str, re.Pattern]] = [
    ("AWS_KEY",     re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")),
    ("JWT",         re.compile(r"eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]+")),
    ("SSN",         re.compile(r"\\b\\d{3}-\\d{2}-\\d{4}\\b")),
    ("CREDIT_CARD", re.compile(r"\\b(?:\\d[ -]*?){13,19}\\b")),
    ("EMAIL",       re.compile(r"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b")),
    ("PHONE_US",    re.compile(r"\\b(?:\\+1[- ]?)?\\(?\\d{3}\\)?[- ]?\\d{3}[- ]?\\d{4}\\b")),
    ("IP_ADDR",     re.compile(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")),
]

def redact_pii(text: str, allow_list: set[str] | None = None) -> tuple[str, list[RedactionHit]]:
    """Scan and redact PII from model output. Returns cleaned text + hit log."""
    allow_list = allow_list or set()
    hits: list[RedactionHit] = []
    for pii_type, pattern in PII_RULES:
        for m in pattern.finditer(text):
            if m.group() in allow_list:
                continue
            hits.append(RedactionHit(pii_type, m.start(), m.end()))
    # Apply replacements in reverse order to preserve indices
    for hit in sorted(hits, key=lambda h: h.start, reverse=True):
        text = text[:hit.start] + f"[REDACTED_{hit.pii_type}]" + text[hit.end:]
    return text, hits''',
        },
        mitigates_categories=[
            AttackCategory.SENSITIVE_INFO,
            AttackCategory.DATA_LEAKAGE,
        ],
        required_for_compliance=["LLM02", "GDPR-A5"],
        effort="medium",
        effectiveness="high",
        tags=["pii-protection", "data-leakage", "privacy", "proxy"],
    ))

    registry.register(Guardrail(
        id="grd-output-secrets",
        name="Secret & Credential Detection",
        description=(
            "Detect API keys, tokens, passwords, and connection strings in model "
            "responses and block the output before delivery. Prevents the model "
            "from leaking credentials it may have memorized from training data or "
            "retrieved via tool calls."
        ),
        guardrail_type=GuardrailType.OUTPUT_FILTERING,
        severity=GuardrailSeverity.CRITICAL,
        implementation_steps=[
            "Add a post-inference scanning step in the proxy using regex and entropy analysis",
            "Cover common secret formats: AWS (AKIA), GitHub (ghp_/gho_), Slack (xoxb-/xoxp-), "
            "Stripe (sk_live_), generic high-entropy strings (Shannon entropy > 4.5 on 20+ char tokens)",
            "On detection, replace the entire response with a safe error message rather than "
            "attempting partial redaction (secrets often span multiple tokens)",
            "Alert the security team via webhook (PagerDuty/Slack) immediately on credential-class "
            "detections, as this may indicate a training data leak",
        ],
        code_examples={
            "python": '''import math
import re

SECRET_PATTERNS = {
    "aws_access_key":   re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key":   re.compile(r"(?i)aws_secret_access_key\\s*[=:]\\s*[A-Za-z0-9/+=]{40}"),
    "github_token":     re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}"),
    "slack_token":      re.compile(r"xox[bpors]-[A-Za-z0-9-]+"),
    "stripe_key":       re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    "generic_password": re.compile(r"(?i)(password|passwd|pwd)\\s*[=:]\\s*\\S{8,}"),
    "connection_string": re.compile(r"(?i)(mongodb|postgres|mysql|redis)://\\S+"),
    "private_key":      re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
}

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())

def scan_for_secrets(text: str) -> list[dict]:
    """Return list of detected secret types. Empty = clean."""
    findings = []
    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            findings.append({"type": name, "pattern": True})

    # High-entropy token scan (catch unknown secret formats)
    for token in re.findall(r"[A-Za-z0-9/+=_-]{20,}", text):
        if shannon_entropy(token) > 4.5:
            findings.append({"type": "high_entropy_token", "entropy": round(shannon_entropy(token), 2)})
            break  # One is enough to flag
    return findings''',
        },
        mitigates_categories=[
            AttackCategory.SECRETS_EXPOSURE,
            AttackCategory.DATA_LEAKAGE,
        ],
        required_for_compliance=["LLM02"],
        effort="medium",
        effectiveness="high",
        tags=["secrets-protection", "credential-leak", "proxy"],
    ))

    # ── Tool & Function Restriction ──

    registry.register(Guardrail(
        id="grd-tool-restrict",
        name="Tool & Function Call Restriction",
        description=(
            "Restrict which tools, functions, and external APIs the model is allowed "
            "to invoke. Prevents excessive agency by enforcing an allow-list of "
            "permitted tool names and argument patterns at the proxy layer."
        ),
        guardrail_type=GuardrailType.ACCESS_CONTROL,
        severity=GuardrailSeverity.CRITICAL,
        implementation_steps=[
            "Define a tool allow-list in proxy configuration specifying exactly which "
            "function names the model may call (e.g. search, get_weather but NOT execute_code, "
            "send_email, delete_resource)",
            "Validate tool call arguments against JSON schemas before forwarding; reject "
            "calls with unexpected parameters or values outside allowed ranges",
            "Implement call-frequency limits per tool (e.g. max 3 search calls per conversation) "
            "to prevent resource abuse loops",
            "Log every tool invocation with the full arguments, model decision context, and user ID "
            "for audit trail",
            "Require human-in-the-loop confirmation for destructive operations (DELETE, PATCH) "
            "even if the tool is on the allow-list",
        ],
        code_examples={
            "python": '''from typing import Any

# Tool policy: name -> {allowed: bool, max_calls: int, arg_validators: {}}
TOOL_POLICY = {
    "search":         {"allowed": True,  "max_calls": 5},
    "get_weather":    {"allowed": True,  "max_calls": 3},
    "read_file":      {"allowed": True,  "max_calls": 10, "arg_rules": {"path": r"^/data/public/"}},
    "execute_code":   {"allowed": False},
    "send_email":     {"allowed": False},
    "delete_resource": {"allowed": False},
}

class ToolCallTracker:
    """Track and enforce tool call policies per conversation."""

    def __init__(self):
        self._counts: dict[str, int] = {}

    def validate_call(self, tool_name: str, arguments: dict[str, Any]) -> str | None:
        """Return error message if call is blocked, None if allowed."""
        policy = TOOL_POLICY.get(tool_name)
        if policy is None:
            return f"Tool '{tool_name}' is not registered in the policy"
        if not policy.get("allowed", False):
            return f"Tool '{tool_name}' is blocked by security policy"

        # Check call frequency
        self._counts[tool_name] = self._counts.get(tool_name, 0) + 1
        max_calls = policy.get("max_calls", 10)
        if self._counts[tool_name] > max_calls:
            return f"Tool '{tool_name}' exceeded max {max_calls} calls per conversation"

        # Validate arguments against rules
        import re
        for arg_name, pattern in policy.get("arg_rules", {}).items():
            value = str(arguments.get(arg_name, ""))
            if not re.match(pattern, value):
                return f"Tool '{tool_name}' argument '{arg_name}' violates policy"

        return None  # Allowed''',
            "yaml": '''# Proxy tool policy configuration (e.g. for LiteLLM / custom gateway)
tool_policy:
  default_action: deny    # deny tools not explicitly listed
  require_approval:       # tools that need human confirmation
    - delete_resource
    - send_email
    - modify_config
  allowed_tools:
    search:
      max_calls_per_session: 5
      rate_limit: 10/minute
    get_weather:
      max_calls_per_session: 3
    read_file:
      max_calls_per_session: 10
      argument_rules:
        path:
          pattern: "^/data/public/"
          description: "Only public data directory"
  blocked_tools:
    - execute_code
    - shell_command
    - write_file
    - network_request''',
        },
        mitigates_categories=[
            AttackCategory.EXCESSIVE_AGENCY,
            AttackCategory.PRIVILEGE_ESCALATION,
        ],
        required_for_compliance=["LLM06", "LLM08"],
        effort="medium",
        effectiveness="high",
        tags=["tool-restriction", "excessive-agency", "proxy"],
    ))

    # ── Rate Limiting ──

    registry.register(Guardrail(
        id="grd-rate-limit",
        name="Request Rate Limiting",
        description=(
            "Enforce per-user, per-IP, and per-API-key rate limits at the proxy "
            "layer to prevent denial-of-service, cost-runaway, and brute-force "
            "extraction attacks against model endpoints."
        ),
        guardrail_type=GuardrailType.RATE_LIMITING,
        severity=GuardrailSeverity.HIGH,
        implementation_steps=[
            "Configure tiered rate limits: per-IP (100 req/min), per-API-key (1000 req/hr), "
            "per-user (50 req/min) using sliding window counters in Redis",
            "Add separate token-based limits (e.g. 100k output tokens/hr per user) to prevent "
            "cost-runaway from long-response attacks",
            "Return HTTP 429 with Retry-After header and a JSON error body including the limit "
            "name and reset time so clients can back off intelligently",
        ],
        code_examples={
            "python": '''import time
import redis.asyncio as aioredis

class SlidingWindowRateLimiter:
    """Redis-backed sliding window rate limiter."""

    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis = aioredis.from_url(redis_url)

    async def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, dict]:
        """Return (allowed, info). info has remaining, reset_at, retry_after."""
        now = time.time()
        window_start = now - window_seconds
        pipe = self.redis.pipeline()
        # Remove expired entries
        pipe.zremrangebyscore(key, 0, window_start)
        # Add current request
        pipe.zadd(key, {str(now): now})
        # Count requests in window
        pipe.zcard(key)
        # Set TTL on the key
        pipe.expire(key, window_seconds + 1)
        _, _, count, _ = await pipe.execute()

        allowed = count <= limit
        return allowed, {
            "limit": limit,
            "remaining": max(0, limit - count),
            "reset_at": int(now + window_seconds),
            "retry_after": window_seconds if not allowed else 0,
        }

# Usage in FastAPI middleware:
# limiter = SlidingWindowRateLimiter()
# allowed, info = await limiter.check(f"rate:{api_key}", limit=1000, window_seconds=3600)
# if not allowed:
#     raise HTTPException(429, detail={"error": "rate_limit", **info})''',
        },
        configuration_examples={
            "nginx": '''# Tiered rate limiting at the edge
limit_req_zone $binary_remote_addr zone=ip_limit:10m rate=100r/m;
limit_req_zone $http_x_api_key    zone=key_limit:10m rate=1000r/m;

location /v1/chat/completions {
    limit_req zone=ip_limit  burst=20  nodelay;
    limit_req zone=key_limit burst=100 nodelay;

    limit_req_status 429;
    error_page 429 = @rate_limited;

    proxy_pass http://inference_backend;
}

location @rate_limited {
    default_type application/json;
    return 429 \'{"error":"rate_limit_exceeded","retry_after":60}\';
}''',
        },
        mitigates_categories=[
            AttackCategory.UNBOUNDED_CONSUMPTION,
            AttackCategory.DENIAL_OF_SERVICE,
        ],
        required_for_compliance=["LLM10"],
        effort="low",
        effectiveness="high",
        tags=["rate-limiting", "dos-protection", "proxy"],
    ))

    # ── Input Length / Token Limits ──

    registry.register(Guardrail(
        id="grd-input-length",
        name="Input & Output Token Limits",
        description=(
            "Enforce hard limits on input prompt length and output token count "
            "at the proxy layer to prevent context-overflow attacks, cost runaway, "
            "and denial-of-service via oversized payloads."
        ),
        guardrail_type=GuardrailType.RESOURCE_LIMITS,
        severity=GuardrailSeverity.HIGH,
        implementation_steps=[
            "Set max_input_tokens and max_output_tokens in the proxy config based on your "
            "model's context window (e.g. 8k input / 4k output for a 16k context model)",
            "Implement a fast token-counting estimate (tiktoken or character/4 heuristic) in "
            "the proxy to reject oversized inputs before they reach the model",
            "Cap max_tokens in the forwarded API call body even if the client requests more",
        ],
        code_examples={
            "python": '''import tiktoken

# Initialize once at startup
_ENCODER = tiktoken.get_encoding("cl100k_base")
MAX_INPUT_TOKENS = 8192
MAX_OUTPUT_TOKENS = 4096

def enforce_token_limits(body: dict) -> dict:
    """Validate and cap token counts in the request body."""
    # Check input size
    messages = body.get("messages", [])
    total_tokens = sum(len(_ENCODER.encode(m.get("content", ""))) for m in messages)
    if total_tokens > MAX_INPUT_TOKENS:
        raise TokenLimitExceeded(
            f"Input is {total_tokens} tokens, max allowed is {MAX_INPUT_TOKENS}"
        )

    # Cap output tokens
    requested = body.get("max_tokens", MAX_OUTPUT_TOKENS)
    body["max_tokens"] = min(requested, MAX_OUTPUT_TOKENS)
    return body''',
        },
        mitigates_categories=[
            AttackCategory.UNBOUNDED_CONSUMPTION,
            AttackCategory.DENIAL_OF_SERVICE,
        ],
        required_for_compliance=["LLM10"],
        effort="low",
        effectiveness="high",
        tags=["token-limits", "dos-protection", "cost-control", "proxy"],
    ))

    # ── Authentication / Access Control ──

    registry.register(Guardrail(
        id="grd-rbac",
        name="Role-Based Access Control",
        description=(
            "Enforce RBAC at the proxy layer so model access, tool permissions, "
            "and content-policy overrides are scoped to the caller's role. "
            "Prevents privilege escalation and limits blast radius of compromised keys."
        ),
        guardrail_type=GuardrailType.ACCESS_CONTROL,
        severity=GuardrailSeverity.HIGH,
        implementation_steps=[
            "Define roles (viewer, user, power_user, admin, red_team) with explicit permission "
            "sets covering: model access, tool allow-lists, rate-limit tiers, and content-policy overrides",
            "Validate the caller's role from the JWT/session at the proxy before forwarding; "
            "reject requests to models or tools the role does not permit",
            "Gate destructive tool calls (delete, modify, send) behind admin or power_user roles",
            "Allow the red_team role to bypass content-moderation filters for authorized security testing",
            "Log role-based decisions (granted/denied) to the audit trail for compliance reporting",
            "Review role assignments quarterly; auto-revoke unused elevated roles after 90 days",
        ],
        code_examples={
            "python": '''from enum import Enum
from dataclasses import dataclass, field

class Role(Enum):
    VIEWER     = "viewer"       # Read-only, no inference
    USER       = "user"         # Standard inference, limited tools
    POWER_USER = "power_user"   # Extended tools, higher rate limits
    ADMIN      = "admin"        # Full access, destructive tools
    RED_TEAM   = "red_team"     # Bypass content filters for testing

@dataclass
class RolePolicy:
    allowed_models: set[str]         = field(default_factory=lambda: {"*"})
    allowed_tools: set[str]          = field(default_factory=set)
    rate_limit_rpm: int              = 30
    max_output_tokens: int           = 2048
    bypass_content_filter: bool      = False

ROLE_POLICIES: dict[Role, RolePolicy] = {
    Role.VIEWER:     RolePolicy(allowed_models=set(), allowed_tools=set(), rate_limit_rpm=0),
    Role.USER:       RolePolicy(allowed_tools={"search", "get_weather"}, rate_limit_rpm=30),
    Role.POWER_USER: RolePolicy(allowed_tools={"search", "get_weather", "read_file", "analyze"},
                                rate_limit_rpm=100, max_output_tokens=4096),
    Role.ADMIN:      RolePolicy(allowed_tools={"*"}, rate_limit_rpm=500, max_output_tokens=8192),
    Role.RED_TEAM:   RolePolicy(allowed_tools={"*"}, rate_limit_rpm=200,
                                max_output_tokens=8192, bypass_content_filter=True),
}

def check_access(role: Role, model: str, tool: str | None = None) -> str | None:
    """Return error message if access denied, None if allowed."""
    policy = ROLE_POLICIES.get(role)
    if not policy:
        return "Unknown role"
    if policy.rate_limit_rpm == 0:
        return f"Role {role.value} does not have inference access"
    if "*" not in policy.allowed_models and model not in policy.allowed_models:
        return f"Role {role.value} cannot access model {model}"
    if tool and "*" not in policy.allowed_tools and tool not in policy.allowed_tools:
        return f"Role {role.value} cannot use tool {tool}"
    return None''',
        },
        mitigates_categories=[
            AttackCategory.EXCESSIVE_AGENCY,
            AttackCategory.PRIVILEGE_ESCALATION,
        ],
        required_for_compliance=["LLM06", "NIST-GV"],
        effort="medium",
        effectiveness="high",
        tags=["rbac", "access-control", "proxy"],
    ))

    # ── Data Protection / Encryption ──

    registry.register(Guardrail(
        id="grd-encrypt-transit",
        name="Encryption in Transit",
        description=(
            "Enforce TLS 1.3 on all proxy-to-model and client-to-proxy connections. "
            "Terminate TLS at the proxy and re-encrypt to backend inference servers."
        ),
        guardrail_type=GuardrailType.DATA_PROTECTION,
        severity=GuardrailSeverity.CRITICAL,
        implementation_steps=[
            "Configure the proxy to terminate TLS 1.3 with strong cipher suites "
            "(ECDHE-ECDSA-AES256-GCM-SHA384 preferred)",
            "Disable TLS 1.0, 1.1, and 1.2 on all model-serving endpoints",
            "Enable HSTS with a 1-year max-age and includeSubDomains",
        ],
        configuration_examples={
            "nginx": '''# TLS 1.3 only — proxy termination config
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# HSTS (1 year, include subdomains, allow preload)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;''',
        },
        mitigates_categories=[
            AttackCategory.SENSITIVE_INFO,
            AttackCategory.DATA_LEAKAGE,
        ],
        required_for_compliance=["NIST-MP", "GDPR-A32"],
        effort="low",
        effectiveness="high",
        tags=["encryption", "tls", "data-protection", "proxy"],
    ))

    # ── Model Protection ──

    registry.register(Guardrail(
        id="grd-model-access",
        name="Model Access Restriction",
        description=(
            "Prevent direct access to model weights, architecture details, and "
            "inference internals. The proxy should be the only path to the model, "
            "with no direct network access from external clients."
        ),
        guardrail_type=GuardrailType.MODEL_PROTECTION,
        severity=GuardrailSeverity.CRITICAL,
        implementation_steps=[
            "Place model inference servers in a private subnet with no public IP; "
            "only the proxy has network access to the inference port",
            "Block model metadata endpoints (/v1/models, /health with version info) "
            "from external access or strip version/architecture details from responses",
            "Enforce output-only access: clients can send prompts and receive completions "
            "but cannot download weights, access logprobs, or query embeddings unless explicitly enabled",
            "Implement request signing between proxy and inference server to prevent "
            "direct-to-backend bypass if network segmentation is compromised",
            "Monitor for model extraction patterns: high-volume, systematic queries "
            "that suggest distillation or behavioral cloning attempts",
        ],
        configuration_examples={
            "nginx": '''# Block direct model metadata access
location ~* ^/v1/(models|internal|debug) {
    return 403 '{"error":"forbidden","message":"Model metadata not accessible"}';
}

# Strip server version headers from proxied responses
proxy_hide_header X-Model-Version;
proxy_hide_header X-Inference-Server;
proxy_hide_header Server;
add_header Server "ai-proxy" always;

# Only allow POST to inference endpoints
location /v1/chat/completions {
    limit_except POST {
        deny all;
    }
    proxy_pass http://inference_internal;
}''',
        },
        mitigates_categories=[
            AttackCategory.MODEL_THEFT,
            AttackCategory.SUPPLY_CHAIN,
        ],
        required_for_compliance=["AML.T0003"],
        effort="medium",
        effectiveness="high",
        tags=["model-protection", "network-segmentation", "proxy"],
    ))

    # ── Audit Logging ──

    registry.register(Guardrail(
        id="grd-audit-log",
        name="Comprehensive Audit Logging",
        description=(
            "Log every proxy decision — allowed requests, blocked requests, "
            "tool calls, content-filter triggers, rate-limit hits, and auth failures — "
            "in a structured, tamper-evident format for compliance and forensics."
        ),
        guardrail_type=GuardrailType.AUDIT_LOGGING,
        severity=GuardrailSeverity.HIGH,
        implementation_steps=[
            "Emit structured JSON log lines for every request containing: timestamp, request_id, "
            "user_id, model, action (allow/block), reason, latency_ms, input_tokens, output_tokens",
            "Include guardrail decisions: which rules fired, confidence scores, and whether "
            "the request was blocked or flagged for review",
            "Ship logs to an append-only store (S3 with Object Lock, or immutable Elasticsearch indices) "
            "to prevent tampering",
            "Set up real-time alerting on high-severity events: credential exposure, injection blocks, "
            "and anomalous usage patterns (> 3 sigma from baseline)",
            "Retain logs for the compliance-required period (SOC2: 1 year, GDPR: as needed for "
            "legitimate interest) with automated lifecycle policies",
            "Never log the full prompt or response body in production — log hashes and token counts "
            "instead; enable full-body logging only in debug mode behind a feature flag",
        ],
        code_examples={
            "python": '''import hashlib
import json
import logging
import time
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("audit")

@dataclass
class AuditEvent:
    timestamp: float = field(default_factory=time.time)
    request_id: str = ""
    user_id: str = ""
    model: str = ""
    action: str = "allow"            # allow | block | flag
    reason: str = ""                 # e.g. "rate_limit", "injection_detected"
    guardrails_fired: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    input_hash: str = ""             # SHA-256 of input (not the content itself)
    output_hash: str = ""            # SHA-256 of output
    tool_calls: list[str] = field(default_factory=list)

def log_audit_event(event: AuditEvent):
    """Emit structured audit log line."""
    logger.info(json.dumps(asdict(event), default=str))

def content_hash(text: str) -> str:
    """SHA-256 hash of content for audit (never log raw content in prod)."""
    return hashlib.sha256(text.encode()).hexdigest()[:16]''',
        },
        mitigates_categories=[
            AttackCategory.PRIVILEGE_ESCALATION,
            AttackCategory.DATA_LEAKAGE,
        ],
        required_for_compliance=["NIST-GV", "SOC2-CC7"],
        effort="medium",
        effectiveness="medium",
        tags=["audit", "logging", "compliance", "proxy"],
    ))

    return registry
