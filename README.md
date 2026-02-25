# MASS - Model & Application Security Suite - AI Security Research and capabilities exploration for dealing with autonomous coding.

[![CI](https://github.com/r33n3/MASS/actions/workflows/ci.yml/badge.svg)](https://github.com/r33n3/MASS/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/r33n3/MASS/branch/main/graph/badge.svg)](https://codecov.io/gh/r33n3/MASS)
[![PyPI version](https://badge.fury.io/py/mass.svg)](https://badge.fury.io/py/mass)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**Comprehensive AI deployment security platform that discovers, analyzes, tests, and remediates vulnerabilities across models, tools, prompts, infrastructure, and agent workflows.**

MASS is an API-first, cloud-native security platform for end-to-end AI deployment validation. It goes beyond model-only testing to discover, scan, interrogate, and remediate entire deployments including system prompts, MCP servers, agent workflows, knowledge bases, and infrastructure.

## Key Features

- **Holistic Deployment Analysis** - Scans entire AI deployments, not just models
- **Cross-Component Attack Surface** - Identifies attack chains across components
- **AI-Guided Scan Planning** - Uses LLM to intelligently prioritize tests
- **Enterprise API-First** - Full REST API with multi-tenant support
- **Cloud-Native** - Deploy on AWS, Azure, or GCP
- **Compliance Frameworks** - OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, EU AI Act

## Installation

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

## Quick Start

### CLI

```bash
# Scan a deployment
mass scan ./my-agent --profile comprehensive

# Analyze a specific component
mass analyze model ./model.gguf --profile adversarial
mass analyze mcp http://localhost:3000

# Compliance assessment
mass compliance assess --framework owasp:llm --scan scan_abc123

# Export report
mass report export scan_abc123 --format sarif -o findings.sarif
```

### Python SDK

```python
from mass_sdk import MassClient

client = MassClient(api_key="sk-xxx")

# Create and scan deployment
deployment = client.deployments.create(
    name="my-agent",
    source="./agent-folder"
)

scan = client.scans.create(
    deployment_id=deployment.id,
    profile="comprehensive"
)

# Wait and get results
result = scan.wait(timeout=300)

# Get critical findings
findings = client.findings.list(
    scan_id=scan.id,
    severity=["critical", "high"]
)
```

### API

```bash
# Start the API server
uvicorn mass.api.main:create_app --factory

# Create a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"deployment_id": "dep_123", "profile": "comprehensive"}'
```

## Architecture

```
MASS Platform
├── API Layer (FastAPI)
│   ├── REST endpoints
│   ├── Authentication (API keys, JWT, OAuth2)
│   └── Multi-tenant isolation
├── Analysis Engine
│   ├── Deployment Scanner
│   ├── Model Interrogator (probe/detector plugins)
│   ├── Context Analyzer
│   ├── MCP Security Scanner
│   ├── Workflow Analyzer
│   └── Attack Surface Mapper
├── Orchestration
│   ├── Worker System (Redis/SQS/ServiceBus/Pub/Sub)
│   ├── Scan Service
│   └── AI Scan Planner
├── Compliance & Reporting
│   ├── Framework Assessor
│   ├── Report Generator (HTML, PDF, SARIF, JSON)
│   └── Dashboard
└── Storage
    ├── PostgreSQL (metadata)
    ├── Redis (cache, queues)
    └── S3/Azure/GCS (artifacts)
```

## Supported Frameworks

### Compliance
- OWASP LLM Top 10
- OWASP API Top 10
- MITRE ATLAS
- NIST AI RMF
- EU AI Act
- GDPR
- SOC 2
- ISO 27001

### Agentic Frameworks
- LangChain / LangGraph
- CrewAI
- AutoGen
- OpenAI Agents SDK

## Documentation

- [Getting Started](docs/getting-started/quickstart.md)
- [API Reference](docs/api-reference/)
- [CLI Reference](docs/cli-reference/)
- [Deployment Guide](docs/deployment/)

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

For security issues, please see [SECURITY.md](SECURITY.md).

## License

Apache 2.0 - see [LICENSE](LICENSE) for details.
