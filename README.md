# MASS - Model & Application Security Suite

[![CI](https://github.com/r33n3/MASS/actions/workflows/ci.yml/badge.svg)](https://github.com/r33n3/MASS/actions/workflows/ci.yml)
[![CodeQL](https://github.com/r33n3/MASS/actions/workflows/security.yml/badge.svg)](https://github.com/r33n3/MASS/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/r33n3/MASS/branch/PROD/graph/badge.svg)](https://codecov.io/gh/r33n3/MASS)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**Comprehensive AI deployment security platform that discovers, analyzes, tests, and remediates vulnerabilities across models, tools, prompts, infrastructure, and agent workflows.**

MASS is an API-first, cloud-native security platform for end-to-end AI deployment validation. It goes beyond model-only testing to discover, scan, interrogate, and remediate entire deployments — including system prompts, MCP servers, agent workflows, knowledge bases, and infrastructure.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Holistic Deployment Analysis** | Scans entire AI deployments, not just models |
| **Cross-Component Attack Surface** | Identifies attack chains across components |
| **AI-Guided Scan Planning** | Uses LLM to intelligently prioritize tests |
| **MCP Server Security** | Static and dynamic analysis of Model Context Protocol servers |
| **Code Security Audit** | Two-phase static grep + LLM verification for AppSec vulnerabilities |
| **Compliance Mapping** | OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, EU AI Act |
| **Enterprise API-First** | Full REST API with multi-tenant support and RBAC |
| **Cloud-Native** | Deploy on AWS, Azure, GCP, or self-hosted |

---

## Installation

### Docker (Recommended)

```bash
git clone https://github.com/r33n3/MASS.git
cd MASS
cp .env.example .env          # configure your API keys
docker compose up -d
```

The dashboard is available at **http://localhost** and the API at **http://localhost/api/v1**.

For a lightweight single-container setup (SQLite, no workers):

```bash
docker compose -f docker-compose.lite.yml up -d
```

See [DOCKER_SETUP.md](DOCKER_SETUP.md) for full configuration options, profiles, and troubleshooting.

### Python Package

```bash
pip install mass
```

For development:

```bash
git clone https://github.com/r33n3/MASS.git
cd MASS
pip install -e ".[dev]"
pre-commit install
```

---

## Quick Start

### CLI

```bash
# Scan a deployment directory
mass scan ./my-agent --profile comprehensive

# Analyze a specific component
mass analyze model ./model.gguf
mass analyze mcp http://localhost:3000

# Compliance assessment
mass compliance assess --framework owasp:llm --scan scan_abc123

# Export findings as SARIF (for GitHub Code Scanning)
mass report export scan_abc123 --format sarif -o findings.sarif
```

### Python SDK

```python
from mass_sdk import MassClient

client = MassClient(api_key="your-api-key")

# Create a deployment and run a scan
deployment = client.deployments.create(name="my-agent", source="./agent-folder")
scan = client.scans.create(deployment_id=deployment.id, profile="comprehensive")

# Wait for completion and fetch critical findings
result = scan.wait(timeout=300)
findings = client.findings.list(scan_id=scan.id, severity=["critical", "high"])
```

### REST API

```bash
# Start the API server directly
uvicorn mass.api.main:create_app --factory

# Create a scan via API
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer $MASS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"deployment_id": "dep_123", "profile": "comprehensive"}'
```

---

## What MASS Detects

### AI-Specific Vulnerabilities
- **Prompt Injection** — Direct, indirect, and context injection attacks
- **Jailbreaks** — DAN variants, encoding bypasses, roleplay exploits
- **System Prompt Extraction** — Probes that leak confidential instructions
- **Data Exfiltration** — PII and sensitive data leakage via model outputs
- **RAG Poisoning** — Malicious content injected into retrieval pipelines
- **Tool/MCP Abuse** — Privilege escalation and injection via agent tools
- **Model Extraction** — Probing for training data and architecture details
- **Reasoning Exploits** — Attacks targeting chain-of-thought reasoning

### Infrastructure & Code
- **Secrets Detection** — API keys, tokens, and credentials in code and configs
- **Dependency Vulnerabilities** — CVE matching against Python and JS packages
- **Container Misconfigurations** — Docker and Kubernetes security issues
- **Code Security Audit** — SQL/command/template injection, auth bypass, XSS, CORS misconfiguration
- **Deployment Topology** — Attack surface mapping across components

### Compliance Assessment
- OWASP LLM Top 10
- MITRE ATLAS
- NIST AI Risk Management Framework
- EU AI Act
- OWASP API Top 10, GDPR, SOC 2, ISO 27001

---

## Architecture

```
MASS Platform
├── API Layer (FastAPI)
│   ├── REST endpoints with OpenAPI docs
│   ├── Authentication (API keys, JWT)
│   └── Multi-tenant isolation
├── Analysis Engine
│   ├── Deployment Scanner (YAML/env/code discovery)
│   ├── Model Interrogator (probe/detector plugins)
│   ├── Context & System Prompt Analyzer
│   ├── MCP Security Scanner (static + dynamic)
│   ├── Code Security Auditor (grep + LLM verify)
│   ├── RAG Pipeline Analyzer
│   └── Attack Surface Mapper
├── Orchestration
│   ├── Worker System (Redis queue)
│   ├── AI Scan Planner (LLM-guided prioritization)
│   └── Confidence Calibration Engine
├── Compliance & Reporting
│   ├── Framework Assessor
│   ├── Report Generator (HTML, PDF, SARIF, JSON, AI-BOM)
│   └── Web Dashboard
└── Storage
    ├── PostgreSQL (metadata, findings, scans)
    ├── Redis (cache, job queues)
    └── Configurable artifact storage
```

---

## Supported Agentic Frameworks

MASS automatically detects and analyzes deployments built with:

- LangChain / LangGraph
- CrewAI
- AutoGen / AG2
- OpenAI Agents SDK

---

## Security

MASS is a security testing tool — it handles adversarial inputs by design. This section describes both what MASS tests for and how MASS itself is secured.

### Responsible Use

MASS sends real attack probes to AI systems. Before scanning:
- **Obtain authorization** — only scan systems you own or have written permission to test
- Test prompts may trigger model safety filters — this is expected
- Scan reports may contain sensitive vulnerability details — handle with appropriate confidentiality
- Use isolated/sandboxed environments when scanning untrusted MCP servers

### Security Controls in MASS

| Control | Implementation |
|---------|----------------|
| **Authentication** | API key auth with HMAC-SHA256 hashing; optional JWT |
| **Authorization** | Role-based (admin vs. tenant) enforced on all write/admin endpoints |
| **SSRF Prevention** | Outbound requests to user-configured endpoints are validated; private IP ranges and metadata endpoints are blocked |
| **Path Traversal** | All user-supplied file paths validated via allowlist before file operations |
| **Command Injection** | MCP subprocess execution restricted to an allowlist of known runtimes |
| **Input Validation** | Pydantic models enforce types and constraints on all API inputs |
| **Secrets** | API keys never stored in plaintext; environment variable injection for all credentials |
| **Rate Limiting** | Configurable per-tenant request rate limits |
| **Multi-Tenancy** | Full data isolation between tenants at the database level |

### Vulnerability Disclosure

If you discover a security vulnerability in MASS itself:

1. **Do NOT** open a public GitHub issue
2. Use [GitHub's private vulnerability reporting](https://github.com/r33n3/MASS/security/advisories/new)
3. Include: description, steps to reproduce, potential impact, and any suggested fixes

We follow coordinated disclosure and aim to acknowledge reports within 48 hours.

See [SECURITY.md](SECURITY.md) for the full security policy.

---

## Configuration

Copy `.env.example` to `.env` and set your LLM provider credentials:

```bash
# Default LLM provider (ollama, openai, anthropic, google, azure-openai, bedrock)
MASS_DEFAULT_PROVIDER=ollama

# Provider API keys (set the ones you use)
MASS_OPENAI_API_KEY=sk-...
MASS_ANTHROPIC_API_KEY=sk-ant-...
MASS_GOOGLE_API_KEY=...

# Database (PostgreSQL for production, SQLite for local dev)
MASS_DATABASE_URL=postgresql+asyncpg://mass:mass@postgres:5432/mass
```

See [docs/getting-started/configuration.md](docs/getting-started/configuration.md) for full configuration reference.

---

## Documentation

- [Quickstart Guide](docs/getting-started/quickstart.md)
- [Installation](docs/getting-started/installation.md)
- [Configuration Reference](docs/getting-started/configuration.md)
- [Docker Setup](DOCKER_SETUP.md)
- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting issues, feature requests, and pull requests.

---

## Credits & Acknowledgments

MASS builds upon the pioneering work of several excellent open-source projects:

| Project | Inspiration |
|---------|-------------|
| [garak](https://github.com/NVIDIA/garak) (NVIDIA) | Probe/detector plugin architecture |
| [promptfoo](https://github.com/promptfoo/promptfoo) | YAML scan configs, CI/CD integration |
| [AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) (Tencent) | Infrastructure CVE database, MCP analysis |
| [agentic-radar](https://github.com/splx-ai/agentic-radar) | Workflow visualization |
| [agentic_security](https://github.com/msoedov/agentic_security) | Adaptive attack strategies |
| [modelscan](https://github.com/protectai/modelscan) (Protect AI) | Model file security scanning |

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
