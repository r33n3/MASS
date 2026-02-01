# Configuration

MASS is configured through environment variables, configuration files, or CLI options.

## Environment Variables

All configuration can be set via environment variables with the `MASS_` prefix:

```bash
# Application
export MASS_ENVIRONMENT=production
export MASS_DEBUG=false
export MASS_LOG_LEVEL=INFO

# API
export MASS_API_HOST=0.0.0.0
export MASS_API_PORT=8000

# Database
export MASS_DB_URL=postgresql+asyncpg://user:pass@localhost:5432/mass

# Redis
export MASS_REDIS_URL=redis://localhost:6379/0

# Model Providers
export MASS_OPENAI_API_KEY=sk-xxx
export MASS_ANTHROPIC_API_KEY=sk-ant-xxx
```

## Configuration File

Create a `mass.yaml` in your project root:

```yaml
environment: production
debug: false
log_level: INFO

api:
  host: 0.0.0.0
  port: 8000
  rate_limit: 100

database:
  url: postgresql+asyncpg://user:pass@localhost:5432/mass
  pool_size: 20

redis:
  url: redis://localhost:6379/0

scanning:
  timeout: 3600
  max_concurrent: 10

auth:
  token_expire_minutes: 60
```

## CLI Configuration

Configure MASS via CLI:

```bash
# Set configuration values
mass config set api-url https://api.mass.io
mass config set openai-api-key sk-xxx

# View configuration
mass config list

# Clear configuration
mass config clear api-key
```

## Scan Profiles

MASS includes predefined scan profiles:

| Profile | Description |
|---------|-------------|
| `quick` | Fast scan with essential probes |
| `standard` | Balanced coverage (default) |
| `comprehensive` | Full coverage, all probes |
| `adversarial` | Aggressive attack simulation |
| `compliance` | Compliance-focused testing |

## Custom Profiles

Create custom scan profiles in `profiles/`:

```yaml
# profiles/custom.yaml
name: custom
description: My custom profile

probes:
  - direct_injection
  - jailbreak_dan
  - system_prompt_leak

detectors:
  - keyword
  - llm_judge

settings:
  max_prompts_per_probe: 50
  use_mutations: true
```

Use with:

```bash
mass scan ./agent --profile custom
```
