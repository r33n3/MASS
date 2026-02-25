"""Security pattern definitions for code security audit.

Defines ~35 regex patterns across 11 categories that detect common
application security vulnerabilities in source code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from mass.core.types import AttackCategory, Severity


class SecurityCategory(str, Enum):
    """Categories of code security vulnerabilities."""

    AUTH_BYPASS = "auth_bypass"
    INJECTION_SQL = "injection_sql"
    INJECTION_COMMAND = "injection_command"
    INJECTION_TEMPLATE = "injection_template"
    LLM_PROMPT_INJECTION = "llm_prompt_injection"
    MISSING_VALIDATION = "missing_validation"
    XSS = "xss"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    INSECURE_CORS = "insecure_cors"
    SENSITIVE_DATA_LOGGING = "sensitive_data_logging"
    MISSING_AUTH = "missing_auth"


# Maps SecurityCategory to AttackCategory for Finding conversion
CATEGORY_MAPPING: dict[SecurityCategory, AttackCategory] = {
    SecurityCategory.AUTH_BYPASS: AttackCategory.PRIVILEGE_ESCALATION,
    SecurityCategory.INJECTION_SQL: AttackCategory.SENSITIVE_INFO,
    SecurityCategory.INJECTION_COMMAND: AttackCategory.EXCESSIVE_AGENCY,
    SecurityCategory.INJECTION_TEMPLATE: AttackCategory.PROMPT_INJECTION,
    SecurityCategory.LLM_PROMPT_INJECTION: AttackCategory.PROMPT_INJECTION,
    SecurityCategory.MISSING_VALIDATION: AttackCategory.SENSITIVE_INFO,
    SecurityCategory.XSS: AttackCategory.IMPROPER_OUTPUT,
    SecurityCategory.INSECURE_DESERIALIZATION: AttackCategory.SUPPLY_CHAIN,
    SecurityCategory.INSECURE_CORS: AttackCategory.SENSITIVE_INFO,
    SecurityCategory.SENSITIVE_DATA_LOGGING: AttackCategory.DATA_LEAKAGE,
    SecurityCategory.MISSING_AUTH: AttackCategory.PRIVILEGE_ESCALATION,
}


@dataclass
class SecurityPattern:
    """A single security vulnerability pattern."""

    rule_id: str
    name: str
    category: SecurityCategory
    severity: Severity
    pattern: re.Pattern[str]
    description: str
    languages: list[str]
    cwe_ids: list[str]
    owasp_ids: list[str]
    remediation_hint: str
    false_positive_patterns: list[re.Pattern[str]] = field(default_factory=list)
    context_lines: int = 15
    requires_llm_verification: bool = True


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


def _compile_list(patterns: list[str], flags: int = 0) -> list[re.Pattern[str]]:
    return [re.compile(p, flags) for p in patterns]


# ---------------------------------------------------------------------------
# Pattern definitions (~35 patterns, 11 categories)
# ---------------------------------------------------------------------------

SECURITY_PATTERNS: list[SecurityPattern] = [
    # ── AUTH_BYPASS (5) ──────────────────────────────────────────────
    SecurityPattern(
        rule_id="CS-001",
        name="header_role_no_verify",
        category=SecurityCategory.AUTH_BYPASS,
        severity=Severity.CRITICAL,
        pattern=_compile(
            r"""request\.headers\.get\s*\(\s*["'](?:x-role|x-user-role|role|x-admin|x-is-admin)["']""",
            re.IGNORECASE,
        ),
        description="Role/admin status read from request header without verification",
        languages=["python"],
        cwe_ids=["CWE-287"],
        owasp_ids=["A07:2021"],
        remediation_hint="Derive roles from authenticated session/JWT, not raw headers.",
        false_positive_patterns=_compile_list([
            r"test_|mock_|fixture|assert",
        ], re.IGNORECASE),
    ),
    SecurityPattern(
        rule_id="CS-002",
        name="auth_none_check",
        category=SecurityCategory.AUTH_BYPASS,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""authenticated\s*=\s*.*\bis\s+not\s+None\b""",
            re.IGNORECASE,
        ),
        description="Authentication check based solely on 'is not None' (no credential verification)",
        languages=["python"],
        cwe_ids=["CWE-287"],
        owasp_ids=["A07:2021"],
        remediation_hint="Verify credentials (password hash, token signature) rather than just presence.",
    ),
    SecurityPattern(
        rule_id="CS-003",
        name="jwt_decode_no_verify",
        category=SecurityCategory.AUTH_BYPASS,
        severity=Severity.CRITICAL,
        pattern=_compile(
            r"""jwt\.decode\s*\([^)]*verify\s*=\s*False""",
        ),
        description="JWT decoded with verification disabled",
        languages=["python"],
        cwe_ids=["CWE-347"],
        owasp_ids=["A07:2021"],
        remediation_hint="Always verify JWT signatures: jwt.decode(token, key, algorithms=[...])",
    ),
    SecurityPattern(
        rule_id="CS-004",
        name="basic_auth_plaintext",
        category=SecurityCategory.AUTH_BYPASS,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""(?:password|passwd)\s*==\s*["'][^"']+["']""",
        ),
        description="Plaintext password comparison",
        languages=["python", "javascript"],
        cwe_ids=["CWE-798"],
        owasp_ids=["A07:2021"],
        remediation_hint="Use bcrypt/argon2 for password hashing and comparison.",
    ),
    SecurityPattern(
        rule_id="CS-005",
        name="api_key_header_no_timing",
        category=SecurityCategory.AUTH_BYPASS,
        severity=Severity.MEDIUM,
        pattern=_compile(
            r"""api_key\s*==\s*(?:request|req)\.""",
        ),
        description="API key compared with == (timing attack vulnerable)",
        languages=["python"],
        cwe_ids=["CWE-208"],
        owasp_ids=["A07:2021"],
        remediation_hint="Use hmac.compare_digest() for constant-time comparison.",
    ),

    # ── INJECTION_SQL (4) ────────────────────────────────────────────
    SecurityPattern(
        rule_id="CS-010",
        name="sql_fstring",
        category=SecurityCategory.INJECTION_SQL,
        severity=Severity.CRITICAL,
        pattern=_compile(
            r"""f["'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s.*\{""",
            re.IGNORECASE,
        ),
        description="SQL query built with f-string interpolation",
        languages=["python"],
        cwe_ids=["CWE-89"],
        owasp_ids=["A03:2021"],
        remediation_hint="Use parameterized queries: cursor.execute('SELECT ... WHERE id = ?', (user_id,))",
        false_positive_patterns=_compile_list([
            r"test_|mock_|assert",
            r"#\s*nosec",
        ], re.IGNORECASE),
    ),
    SecurityPattern(
        rule_id="CS-011",
        name="sql_cursor_fstring",
        category=SecurityCategory.INJECTION_SQL,
        severity=Severity.CRITICAL,
        pattern=_compile(
            r"""\.execute\s*\(\s*f["']""",
        ),
        description="Database cursor.execute() with f-string argument",
        languages=["python"],
        cwe_ids=["CWE-89"],
        owasp_ids=["A03:2021"],
        remediation_hint="Use parameterized queries with placeholders.",
        false_positive_patterns=_compile_list([
            r"test_|mock_",
        ], re.IGNORECASE),
    ),
    SecurityPattern(
        rule_id="CS-012",
        name="sql_format_string",
        category=SecurityCategory.INJECTION_SQL,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""\.execute\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\b.*\.format\s*\(""",
            re.IGNORECASE,
        ),
        description="SQL query using .format() string interpolation",
        languages=["python"],
        cwe_ids=["CWE-89"],
        owasp_ids=["A03:2021"],
        remediation_hint="Use parameterized queries instead of string formatting.",
    ),
    SecurityPattern(
        rule_id="CS-013",
        name="sql_percent_format",
        category=SecurityCategory.INJECTION_SQL,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""\.execute\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\b.*%s.*["']\s*%\s""",
            re.IGNORECASE,
        ),
        description="SQL query using %-formatting with string operator",
        languages=["python"],
        cwe_ids=["CWE-89"],
        owasp_ids=["A03:2021"],
        remediation_hint="Use parameterized queries; pass params as second arg to execute().",
    ),

    # ── INJECTION_COMMAND (4) ────────────────────────────────────────
    SecurityPattern(
        rule_id="CS-020",
        name="os_system_call",
        category=SecurityCategory.INJECTION_COMMAND,
        severity=Severity.CRITICAL,
        pattern=_compile(r"""os\.system\s*\("""),
        description="Shell command execution via os.system()",
        languages=["python"],
        cwe_ids=["CWE-78"],
        owasp_ids=["A03:2021"],
        remediation_hint="Use subprocess.run() with shell=False and a list of arguments.",
        requires_llm_verification=False,
    ),
    SecurityPattern(
        rule_id="CS-021",
        name="subprocess_shell_true",
        category=SecurityCategory.INJECTION_COMMAND,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""subprocess\.(?:run|call|Popen)\s*\([^)]*shell\s*=\s*True""",
        ),
        description="Subprocess called with shell=True",
        languages=["python"],
        cwe_ids=["CWE-78"],
        owasp_ids=["A03:2021"],
        remediation_hint="Use shell=False and pass command as a list: subprocess.run(['cmd', 'arg']).",
    ),
    SecurityPattern(
        rule_id="CS-022",
        name="eval_call",
        category=SecurityCategory.INJECTION_COMMAND,
        severity=Severity.CRITICAL,
        pattern=_compile(r"""\beval\s*\(\s*(?!["']\s*\))"""),
        description="Dynamic code execution via eval()",
        languages=["python", "javascript"],
        cwe_ids=["CWE-95"],
        owasp_ids=["A03:2021"],
        remediation_hint="Use ast.literal_eval() for safe parsing, or avoid eval entirely.",
        requires_llm_verification=False,
        false_positive_patterns=_compile_list([
            r"ast\.literal_eval",
        ]),
    ),
    SecurityPattern(
        rule_id="CS-023",
        name="exec_call",
        category=SecurityCategory.INJECTION_COMMAND,
        severity=Severity.CRITICAL,
        pattern=_compile(r"""\bexec\s*\(\s*(?!["']\s*\))"""),
        description="Dynamic code execution via exec()",
        languages=["python"],
        cwe_ids=["CWE-95"],
        owasp_ids=["A03:2021"],
        remediation_hint="Avoid exec(); use a sandboxed execution environment if dynamic code is necessary.",
        requires_llm_verification=False,
    ),

    # ── INJECTION_TEMPLATE (2) ───────────────────────────────────────
    SecurityPattern(
        rule_id="CS-030",
        name="render_template_string",
        category=SecurityCategory.INJECTION_TEMPLATE,
        severity=Severity.HIGH,
        pattern=_compile(r"""render_template_string\s*\("""),
        description="Server-side template injection via render_template_string()",
        languages=["python"],
        cwe_ids=["CWE-1336"],
        owasp_ids=["A03:2021"],
        remediation_hint="Use render_template() with a file path, not render_template_string().",
    ),
    SecurityPattern(
        rule_id="CS-031",
        name="jinja2_safe_filter",
        category=SecurityCategory.INJECTION_TEMPLATE,
        severity=Severity.MEDIUM,
        pattern=_compile(r"""\|\s*safe\b"""),
        description="Jinja2 |safe filter disabling auto-escaping",
        languages=["python"],
        cwe_ids=["CWE-79"],
        owasp_ids=["A03:2021"],
        remediation_hint="Avoid |safe; use Markup() only with trusted, sanitized content.",
    ),

    # ── LLM_PROMPT_INJECTION (5) ─────────────────────────────────────
    SecurityPattern(
        rule_id="CS-040",
        name="llm_fstring_user_input",
        category=SecurityCategory.LLM_PROMPT_INJECTION,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""f["'].*(?:prompt|system|instruction|message).*\{(?:user|input|query|request|body|data|content|text|db_result|document|context)""",
            re.IGNORECASE,
        ),
        description="User/external input interpolated into LLM prompt via f-string",
        languages=["python"],
        cwe_ids=["CWE-77"],
        owasp_ids=["LLM01"],
        remediation_hint="Separate system and user content in the messages array; never interpolate untrusted data into system prompts.",
    ),
    SecurityPattern(
        rule_id="CS-041",
        name="llm_messages_append_var",
        category=SecurityCategory.LLM_PROMPT_INJECTION,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""messages\.append\s*\(\s*\{[^}]*["']content["']\s*:\s*(?!["'])""",
        ),
        description="Variable content appended to LLM messages list (potential injection if from DB/file)",
        languages=["python"],
        cwe_ids=["CWE-77"],
        owasp_ids=["LLM01"],
        remediation_hint="Validate and sanitize content before adding to messages; use role separation.",
    ),
    SecurityPattern(
        rule_id="CS-042",
        name="llm_context_concat",
        category=SecurityCategory.LLM_PROMPT_INJECTION,
        severity=Severity.MEDIUM,
        pattern=_compile(
            r"""(?:context|retrieved|documents?|chunks?|results?)\s*(?:\+|\.join|\.format|%).*(?:prompt|system|message)""",
            re.IGNORECASE,
        ),
        description="Retrieved/external context concatenated into prompt string",
        languages=["python"],
        cwe_ids=["CWE-77"],
        owasp_ids=["LLM01"],
        remediation_hint="Use RAG-specific guardrails; delimit retrieved content from instructions.",
    ),
    SecurityPattern(
        rule_id="CS-043",
        name="langchain_unsafe_prompt",
        category=SecurityCategory.LLM_PROMPT_INJECTION,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""PromptTemplate\s*\([^)]*(?:input_variables|partial_variables)""",
            re.IGNORECASE,
        ),
        description="LangChain PromptTemplate with potentially unsanitized variables",
        languages=["python"],
        cwe_ids=["CWE-77"],
        owasp_ids=["LLM01"],
        remediation_hint="Validate all input_variables before invoking the prompt template.",
    ),
    SecurityPattern(
        rule_id="CS-044",
        name="llm_raw_request_to_prompt",
        category=SecurityCategory.LLM_PROMPT_INJECTION,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""(?:request\.(?:json|body|form|data)|body\[).*(?:prompt|system|content|message)""",
            re.IGNORECASE,
        ),
        description="Raw HTTP request body content passed to LLM prompt construction",
        languages=["python"],
        cwe_ids=["CWE-77"],
        owasp_ids=["LLM01"],
        remediation_hint="Validate and sanitize request data; use Pydantic models for strict input typing.",
    ),

    # ── MISSING_VALIDATION (4) ───────────────────────────────────────
    SecurityPattern(
        rule_id="CS-050",
        name="raw_request_json",
        category=SecurityCategory.MISSING_VALIDATION,
        severity=Severity.MEDIUM,
        pattern=_compile(
            r"""(?:await\s+)?request\.json\s*\(\s*\)""",
        ),
        description="Raw request.json() without Pydantic model validation",
        languages=["python"],
        cwe_ids=["CWE-20"],
        owasp_ids=["A03:2021"],
        remediation_hint="Use a Pydantic model as the route parameter type for automatic validation.",
        false_positive_patterns=_compile_list([
            r"test_|mock_",
        ], re.IGNORECASE),
    ),
    SecurityPattern(
        rule_id="CS-051",
        name="no_auth_dependency",
        category=SecurityCategory.MISSING_AUTH,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""@(?:app|router)\.(?:get|post|put|patch|delete)\s*\([^)]*\)\s*\n\s*(?:async\s+)?def\s+\w+\s*\([^)]*\)""",
        ),
        description="Route handler without authentication dependency",
        languages=["python"],
        cwe_ids=["CWE-306"],
        owasp_ids=["A07:2021"],
        remediation_hint="Add authentication dependency: Depends(get_current_user).",
        false_positive_patterns=_compile_list([
            r"(?:health|ping|readiness|liveness|status|docs|openapi|favicon)",
            r"Depends\s*\(",
        ], re.IGNORECASE),
    ),
    SecurityPattern(
        rule_id="CS-052",
        name="no_rate_limit",
        category=SecurityCategory.MISSING_VALIDATION,
        severity=Severity.LOW,
        pattern=_compile(
            r"""@(?:app|router)\.(?:post|put|patch)\s*\(\s*["']/(?:api|v\d)""",
        ),
        description="API mutation endpoint without rate limiting",
        languages=["python"],
        cwe_ids=["CWE-770"],
        owasp_ids=["A04:2021"],
        remediation_hint="Add rate limiting middleware or dependency.",
    ),
    SecurityPattern(
        rule_id="CS-053",
        name="path_traversal_join",
        category=SecurityCategory.MISSING_VALIDATION,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""(?:os\.path\.join|Path)\s*\([^)]*(?:request|user|input|filename|path_param)""",
            re.IGNORECASE,
        ),
        description="File path constructed from user input without sanitization",
        languages=["python"],
        cwe_ids=["CWE-22"],
        owasp_ids=["A01:2021"],
        remediation_hint="Validate paths with os.path.realpath() and check they remain within the allowed directory.",
    ),

    # ── XSS (3) ──────────────────────────────────────────────────────
    SecurityPattern(
        rule_id="CS-060",
        name="innerhtml_assignment",
        category=SecurityCategory.XSS,
        severity=Severity.HIGH,
        pattern=_compile(r"""\.innerHTML\s*="""),
        description="Direct innerHTML assignment (XSS risk)",
        languages=["javascript"],
        cwe_ids=["CWE-79"],
        owasp_ids=["A03:2021"],
        remediation_hint="Use textContent or a sanitizer like DOMPurify.",
    ),
    SecurityPattern(
        rule_id="CS-061",
        name="dangerously_set_innerhtml",
        category=SecurityCategory.XSS,
        severity=Severity.HIGH,
        pattern=_compile(r"""dangerouslySetInnerHTML"""),
        description="React dangerouslySetInnerHTML with potentially unsanitized content",
        languages=["javascript"],
        cwe_ids=["CWE-79"],
        owasp_ids=["A03:2021"],
        remediation_hint="Sanitize HTML with DOMPurify before passing to dangerouslySetInnerHTML.",
    ),
    SecurityPattern(
        rule_id="CS-062",
        name="document_write",
        category=SecurityCategory.XSS,
        severity=Severity.HIGH,
        pattern=_compile(r"""document\.write\s*\("""),
        description="document.write() with potentially unsanitized content",
        languages=["javascript"],
        cwe_ids=["CWE-79"],
        owasp_ids=["A03:2021"],
        remediation_hint="Avoid document.write(); use DOM APIs with proper escaping.",
    ),

    # ── INSECURE_DESERIALIZATION (3) ─────────────────────────────────
    SecurityPattern(
        rule_id="CS-070",
        name="pickle_loads",
        category=SecurityCategory.INSECURE_DESERIALIZATION,
        severity=Severity.CRITICAL,
        pattern=_compile(r"""pickle\.loads?\s*\("""),
        description="Unsafe deserialization via pickle.load(s)()",
        languages=["python"],
        cwe_ids=["CWE-502"],
        owasp_ids=["A08:2021"],
        remediation_hint="Avoid pickle for untrusted data; use JSON or a safe serializer.",
        requires_llm_verification=False,
    ),
    SecurityPattern(
        rule_id="CS-071",
        name="yaml_unsafe_load",
        category=SecurityCategory.INSECURE_DESERIALIZATION,
        severity=Severity.HIGH,
        pattern=_compile(r"""yaml\.load\s*\([^)]*\)(?!\s*#\s*nosec)"""),
        description="yaml.load() without SafeLoader (arbitrary code execution)",
        languages=["python"],
        cwe_ids=["CWE-502"],
        owasp_ids=["A08:2021"],
        remediation_hint="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
        requires_llm_verification=False,
        false_positive_patterns=_compile_list([
            r"SafeLoader",
            r"safe_load",
        ]),
    ),
    SecurityPattern(
        rule_id="CS-072",
        name="marshal_loads",
        category=SecurityCategory.INSECURE_DESERIALIZATION,
        severity=Severity.HIGH,
        pattern=_compile(r"""marshal\.loads?\s*\("""),
        description="Unsafe deserialization via marshal.load(s)()",
        languages=["python"],
        cwe_ids=["CWE-502"],
        owasp_ids=["A08:2021"],
        remediation_hint="Avoid marshal for untrusted data; use JSON or a safe format.",
        requires_llm_verification=False,
    ),

    # ── INSECURE_CORS (2) ────────────────────────────────────────────
    SecurityPattern(
        rule_id="CS-080",
        name="cors_wildcard_origin",
        category=SecurityCategory.INSECURE_CORS,
        severity=Severity.MEDIUM,
        pattern=_compile(
            r"""(?:origins|allow_origins)\s*=\s*\[?\s*["']\*["']""",
        ),
        description="CORS configured with wildcard origin (*)",
        languages=["python"],
        cwe_ids=["CWE-942"],
        owasp_ids=["A05:2021"],
        remediation_hint="Restrict CORS to specific trusted domains.",
        requires_llm_verification=False,
    ),
    SecurityPattern(
        rule_id="CS-081",
        name="cors_wildcard_header",
        category=SecurityCategory.INSECURE_CORS,
        severity=Severity.MEDIUM,
        pattern=_compile(
            r"""Access-Control-Allow-Origin['"]\s*:\s*["']\*["']""",
        ),
        description="Access-Control-Allow-Origin header set to wildcard",
        languages=["python", "javascript"],
        cwe_ids=["CWE-942"],
        owasp_ids=["A05:2021"],
        remediation_hint="Set Access-Control-Allow-Origin to specific trusted domains.",
        requires_llm_verification=False,
    ),

    # ── SENSITIVE_DATA_LOGGING (3) ───────────────────────────────────
    SecurityPattern(
        rule_id="CS-090",
        name="log_password",
        category=SecurityCategory.SENSITIVE_DATA_LOGGING,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""(?:log(?:ger)?\.(?:info|debug|warning|error)|print)\s*\(.*(?:password|passwd|secret|api_key|api_secret|access_token|refresh_token|private_key)""",
            re.IGNORECASE,
        ),
        description="Sensitive data (password/key/token) passed to logging/print",
        languages=["python"],
        cwe_ids=["CWE-532"],
        owasp_ids=["A09:2021"],
        remediation_hint="Mask or redact sensitive values before logging.",
        false_positive_patterns=_compile_list([
            r"mask|redact|censor|\*\*\*",
        ], re.IGNORECASE),
    ),
    SecurityPattern(
        rule_id="CS-091",
        name="log_credentials_format",
        category=SecurityCategory.SENSITIVE_DATA_LOGGING,
        severity=Severity.HIGH,
        pattern=_compile(
            r"""(?:log(?:ger)?\.(?:info|debug|warning|error)|print)\s*\(\s*f["'].*\{.*(?:password|secret|key|token)""",
            re.IGNORECASE,
        ),
        description="Credentials interpolated into log message via f-string",
        languages=["python"],
        cwe_ids=["CWE-532"],
        owasp_ids=["A09:2021"],
        remediation_hint="Never log credentials; use redaction if logging is necessary.",
    ),
    SecurityPattern(
        rule_id="CS-092",
        name="console_log_sensitive",
        category=SecurityCategory.SENSITIVE_DATA_LOGGING,
        severity=Severity.MEDIUM,
        pattern=_compile(
            r"""console\.log\s*\(.*(?:password|secret|api_key|token|credential)""",
            re.IGNORECASE,
        ),
        description="Sensitive data logged via console.log()",
        languages=["javascript"],
        cwe_ids=["CWE-532"],
        owasp_ids=["A09:2021"],
        remediation_hint="Remove console.log() calls with sensitive data; use a structured logger with redaction.",
    ),
]

# Language → file extension mapping
LANGUAGE_EXTENSIONS: dict[str, set[str]] = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
}
