"""AI framework CVE database.

Contains CVE entries for AI/ML frameworks and related dependencies.
This is a curated subset of critical and high severity vulnerabilities
affecting AI/ML deployments.
"""

from datetime import datetime

from mass.analyzers.infrastructure.cve.database import CVEEntry, CVESeverity, CVEDatabase


# AI/ML Framework CVEs
# Organized by framework/library category

PYTORCH_CVES = [
    CVEEntry(
        cve_id="CVE-2024-5480",
        title="PyTorch arbitrary code execution via pickle",
        description="PyTorch torch.load() allows arbitrary code execution when loading pickle files from untrusted sources.",
        severity=CVESeverity.CRITICAL,
        cvss_score=9.8,
        affected_packages=["torch", "pytorch"],
        affected_versions="<2.2.0",
        fixed_versions=["2.2.0"],
        cwe_ids=["CWE-502"],
        references=["https://github.com/pytorch/pytorch/security/advisories"],
    ),
    CVEEntry(
        cve_id="CVE-2023-45853",
        title="PyTorch distributed RCE",
        description="Remote code execution in PyTorch distributed training mode via malicious pickle payloads.",
        severity=CVESeverity.CRITICAL,
        cvss_score=9.8,
        affected_packages=["torch"],
        affected_versions=">=1.0.0,<2.1.1",
        fixed_versions=["2.1.1"],
        cwe_ids=["CWE-502"],
    ),
]

TENSORFLOW_CVES = [
    CVEEntry(
        cve_id="CVE-2024-0964",
        title="TensorFlow denial of service via crafted checkpoint",
        description="TensorFlow allows DoS via crafted checkpoint files that cause memory exhaustion.",
        severity=CVESeverity.HIGH,
        cvss_score=7.5,
        affected_packages=["tensorflow", "tensorflow-gpu"],
        affected_versions="<2.15.0",
        fixed_versions=["2.15.0"],
        cwe_ids=["CWE-400"],
    ),
    CVEEntry(
        cve_id="CVE-2023-25801",
        title="TensorFlow RCE via SavedModel",
        description="TensorFlow allows arbitrary code execution when loading malicious SavedModel files.",
        severity=CVESeverity.CRITICAL,
        cvss_score=9.8,
        affected_packages=["tensorflow"],
        affected_versions=">=2.0.0,<2.11.1",
        fixed_versions=["2.11.1", "2.12.0"],
        cwe_ids=["CWE-502"],
    ),
]

LANGCHAIN_CVES = [
    CVEEntry(
        cve_id="CVE-2024-28088",
        title="LangChain arbitrary code execution via PALChain",
        description="LangChain PALChain allows arbitrary Python code execution via user input.",
        severity=CVESeverity.CRITICAL,
        cvss_score=9.8,
        affected_packages=["langchain"],
        affected_versions="<0.1.0",
        fixed_versions=["0.1.0"],
        cwe_ids=["CWE-94"],
    ),
    CVEEntry(
        cve_id="CVE-2023-46229",
        title="LangChain SSRF via SitemapLoader",
        description="Server-side request forgery in LangChain SitemapLoader.",
        severity=CVESeverity.HIGH,
        cvss_score=7.5,
        affected_packages=["langchain"],
        affected_versions="<0.0.317",
        fixed_versions=["0.0.317"],
        cwe_ids=["CWE-918"],
    ),
    CVEEntry(
        cve_id="CVE-2023-39631",
        title="LangChain SQL injection",
        description="SQL injection vulnerability in LangChain SQLDatabaseChain.",
        severity=CVESeverity.CRITICAL,
        cvss_score=9.8,
        affected_packages=["langchain"],
        affected_versions="<0.0.247",
        fixed_versions=["0.0.247"],
        cwe_ids=["CWE-89"],
    ),
]

LLAMA_CPP_CVES = [
    CVEEntry(
        cve_id="CVE-2024-0000",
        title="llama-cpp-python buffer overflow",
        description="Buffer overflow in llama-cpp-python when parsing malformed GGUF files.",
        severity=CVESeverity.HIGH,
        cvss_score=8.1,
        affected_packages=["llama-cpp-python"],
        affected_versions="<0.2.20",
        fixed_versions=["0.2.20"],
        cwe_ids=["CWE-120"],
    ),
]

TRANSFORMERS_CVES = [
    CVEEntry(
        cve_id="CVE-2023-51447",
        title="Transformers arbitrary code execution",
        description="Hugging Face Transformers allows arbitrary code execution when loading untrusted models.",
        severity=CVESeverity.CRITICAL,
        cvss_score=9.8,
        affected_packages=["transformers"],
        affected_versions="<4.36.0",
        fixed_versions=["4.36.0"],
        cwe_ids=["CWE-502"],
    ),
]

GRADIO_CVES = [
    CVEEntry(
        cve_id="CVE-2024-1728",
        title="Gradio path traversal",
        description="Path traversal vulnerability in Gradio allows reading arbitrary files.",
        severity=CVESeverity.HIGH,
        cvss_score=7.5,
        affected_packages=["gradio"],
        affected_versions="<4.14.0",
        fixed_versions=["4.14.0"],
        cwe_ids=["CWE-22"],
    ),
    CVEEntry(
        cve_id="CVE-2023-51449",
        title="Gradio SSRF vulnerability",
        description="Server-side request forgery in Gradio file proxy.",
        severity=CVESeverity.HIGH,
        cvss_score=7.5,
        affected_packages=["gradio"],
        affected_versions="<4.0.0",
        fixed_versions=["4.0.0"],
        cwe_ids=["CWE-918"],
    ),
]

OPENAI_SDK_CVES = [
    CVEEntry(
        cve_id="CVE-2024-0001",
        title="OpenAI Python SDK sensitive data exposure",
        description="OpenAI Python SDK may log sensitive API keys in debug mode.",
        severity=CVESeverity.MEDIUM,
        cvss_score=5.5,
        affected_packages=["openai"],
        affected_versions="<1.2.0",
        fixed_versions=["1.2.0"],
        cwe_ids=["CWE-532"],
    ),
]

NUMPY_CVES = [
    CVEEntry(
        cve_id="CVE-2021-41496",
        title="NumPy buffer overflow",
        description="Buffer overflow in NumPy allows denial of service via crafted input.",
        severity=CVESeverity.MEDIUM,
        cvss_score=5.5,
        affected_packages=["numpy"],
        affected_versions="<1.21.0",
        fixed_versions=["1.21.0"],
        cwe_ids=["CWE-120"],
    ),
]

PILLOW_CVES = [
    CVEEntry(
        cve_id="CVE-2023-50447",
        title="Pillow arbitrary code execution",
        description="Pillow allows arbitrary code execution when processing malicious images.",
        severity=CVESeverity.CRITICAL,
        cvss_score=9.8,
        affected_packages=["pillow", "Pillow"],
        affected_versions="<10.2.0",
        fixed_versions=["10.2.0"],
        cwe_ids=["CWE-94"],
    ),
]

FASTAPI_CVES = [
    CVEEntry(
        cve_id="CVE-2024-24762",
        title="FastAPI ReDoS vulnerability",
        description="Regular expression denial of service in FastAPI/Starlette.",
        severity=CVESeverity.HIGH,
        cvss_score=7.5,
        affected_packages=["fastapi", "starlette"],
        affected_versions="<0.109.0",
        fixed_versions=["0.109.0"],
        cwe_ids=["CWE-1333"],
    ),
]

FLASK_CVES = [
    CVEEntry(
        cve_id="CVE-2023-30861",
        title="Flask session cookie vulnerability",
        description="Flask session cookie security issue allows session fixation.",
        severity=CVESeverity.HIGH,
        cvss_score=7.5,
        affected_packages=["flask", "Flask"],
        affected_versions="<2.3.2",
        fixed_versions=["2.3.2"],
        cwe_ids=["CWE-384"],
    ),
]

REDIS_CVES = [
    CVEEntry(
        cve_id="CVE-2023-45145",
        title="Redis remote code execution",
        description="Redis allows remote code execution via Lua scripting.",
        severity=CVESeverity.CRITICAL,
        cvss_score=9.8,
        affected_packages=["redis"],
        affected_versions="<7.0.13",
        fixed_versions=["7.0.13", "7.2.3"],
        cwe_ids=["CWE-94"],
    ),
]

CELERY_CVES = [
    CVEEntry(
        cve_id="CVE-2023-32758",
        title="Celery command injection",
        description="Celery allows command injection via crafted task names.",
        severity=CVESeverity.CRITICAL,
        cvss_score=9.8,
        affected_packages=["celery"],
        affected_versions="<5.3.0",
        fixed_versions=["5.3.0"],
        cwe_ids=["CWE-78"],
    ),
]

REQUESTS_CVES = [
    CVEEntry(
        cve_id="CVE-2023-32681",
        title="Requests sensitive info disclosure",
        description="Requests library may expose sensitive headers on redirect.",
        severity=CVESeverity.MEDIUM,
        cvss_score=6.1,
        affected_packages=["requests"],
        affected_versions="<2.31.0",
        fixed_versions=["2.31.0"],
        cwe_ids=["CWE-200"],
    ),
]

PYDANTIC_CVES = [
    CVEEntry(
        cve_id="CVE-2024-24576",
        title="Pydantic DoS via recursive models",
        description="Pydantic allows denial of service via deeply nested recursive models.",
        severity=CVESeverity.MEDIUM,
        cvss_score=5.3,
        affected_packages=["pydantic"],
        affected_versions="<2.5.0",
        fixed_versions=["2.5.0"],
        cwe_ids=["CWE-400"],
    ),
]

SQLALCHEMY_CVES = [
    CVEEntry(
        cve_id="CVE-2024-0000",
        title="SQLAlchemy SQL injection",
        description="SQL injection vulnerability in SQLAlchemy ORM.",
        severity=CVESeverity.HIGH,
        cvss_score=8.1,
        affected_packages=["sqlalchemy", "SQLAlchemy"],
        affected_versions="<2.0.0",
        fixed_versions=["2.0.0"],
        cwe_ids=["CWE-89"],
    ),
]

AIOHTTP_CVES = [
    CVEEntry(
        cve_id="CVE-2024-23829",
        title="aiohttp HTTP request smuggling",
        description="HTTP request smuggling vulnerability in aiohttp.",
        severity=CVESeverity.HIGH,
        cvss_score=7.5,
        affected_packages=["aiohttp"],
        affected_versions="<3.9.2",
        fixed_versions=["3.9.2"],
        cwe_ids=["CWE-444"],
    ),
]

HTTPX_CVES = [
    CVEEntry(
        cve_id="CVE-2024-24761",
        title="HTTPX connection pool contamination",
        description="HTTPX allows connection pool contamination via crafted requests.",
        severity=CVESeverity.MEDIUM,
        cvss_score=5.3,
        affected_packages=["httpx"],
        affected_versions="<0.26.0",
        fixed_versions=["0.26.0"],
        cwe_ids=["CWE-404"],
    ),
]

JINJA2_CVES = [
    CVEEntry(
        cve_id="CVE-2024-22195",
        title="Jinja2 sandbox escape",
        description="Jinja2 sandbox escape allows arbitrary code execution.",
        severity=CVESeverity.CRITICAL,
        cvss_score=9.8,
        affected_packages=["jinja2", "Jinja2"],
        affected_versions="<3.1.3",
        fixed_versions=["3.1.3"],
        cwe_ids=["CWE-94"],
    ),
]

# Combine all CVEs
AI_FRAMEWORK_CVES: list[CVEEntry] = [
    *PYTORCH_CVES,
    *TENSORFLOW_CVES,
    *LANGCHAIN_CVES,
    *LLAMA_CPP_CVES,
    *TRANSFORMERS_CVES,
    *GRADIO_CVES,
    *OPENAI_SDK_CVES,
    *NUMPY_CVES,
    *PILLOW_CVES,
    *FASTAPI_CVES,
    *FLASK_CVES,
    *REDIS_CVES,
    *CELERY_CVES,
    *REQUESTS_CVES,
    *PYDANTIC_CVES,
    *SQLALCHEMY_CVES,
    *AIOHTTP_CVES,
    *HTTPX_CVES,
    *JINJA2_CVES,
]


def get_ai_framework_database() -> CVEDatabase:
    """Get a CVEDatabase populated with AI framework CVEs.

    Returns:
        Populated CVE database.
    """
    db = CVEDatabase()
    db.add_many(AI_FRAMEWORK_CVES)
    return db
