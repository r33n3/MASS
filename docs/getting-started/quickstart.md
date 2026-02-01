# Quickstart

This guide will help you run your first AI deployment security scan with MASS.

## Prerequisites

- MASS installed (see [Installation](installation.md))
- An AI deployment to scan (local files or API endpoint)

## CLI Quickstart

### 1. Configure MASS

Set up your API keys and preferences:

```bash
mass config set openai-api-key sk-xxx
mass config set anthropic-api-key sk-ant-xxx
```

### 2. Scan a Local Deployment

Scan a local directory containing your AI agent:

```bash
mass scan ./my-agent --profile standard
```

### 3. View Results

View the scan results:

```bash
mass report list
mass report show scan_abc123
```

### 4. Export Report

Export to SARIF for CI integration:

```bash
mass report export scan_abc123 --format sarif -o findings.sarif
```

## API Quickstart

### 1. Start the Server

```bash
uvicorn mass.api.main:create_app --factory --host 0.0.0.0 --port 8000
```

### 2. Create a Deployment

```bash
curl -X POST http://localhost:8000/api/v1/deployments \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-agent",
    "type": "local",
    "path": "/path/to/agent"
  }'
```

### 3. Start a Scan

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "deployment_id": "dep_xxx",
    "profile": "standard"
  }'
```

### 4. Get Results

```bash
curl http://localhost:8000/api/v1/scans/scan_xxx
```

## Python SDK Quickstart

```python
from mass_sdk import MassClient

client = MassClient(api_key="mass_xxx")

# Create deployment
deployment = client.deployments.create(
    name="my-agent",
    source="./my-agent"
)

# Start scan
scan = client.scans.create(
    deployment_id=deployment.id,
    profile="standard"
)

# Wait for completion
result = scan.wait(timeout=300)

# Print findings
for finding in result.findings:
    print(f"[{finding.severity}] {finding.title}")
```

## Next Steps

- [Configuration Guide](configuration.md)
- [Understanding Scans](../concepts/scans.md)
- [Compliance Frameworks](../concepts/compliance.md)
