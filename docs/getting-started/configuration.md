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

## LLM Provider Configuration

MASS supports multiple LLM providers for chat, verification, guardrail generation, and interrogation:

| Provider | Default Model | API Key Env | Endpoint |
|----------|--------------|-------------|----------|
| `ollama` | `qwen3:8b` | (none) | `OLLAMA_HOST` |
| `openai` | `gpt-4o` | `MASS_OPENAI_API_KEY` | `https://api.openai.com/v1` |
| `anthropic` | `claude-sonnet-4-6` | `MASS_ANTHROPIC_API_KEY` | `https://api.anthropic.com` |
| `gemini` | `gemini-2.0-flash` | `MASS_GOOGLE_API_KEY` | `https://generativelanguage.googleapis.com/v1beta` |
| `grok` | `grok-3` | `MASS_GROK_API_KEY` | `https://api.x.ai/v1` |

Set your default provider in `.env`:

```bash
MASS_DEFAULT_PROVIDER=openai        # or anthropic, gemini, grok, ollama
MASS_DEFAULT_MODEL=                 # blank = use provider default
MASS_OPENAI_API_KEY=sk-...
MASS_ANTHROPIC_API_KEY=sk-ant-...
```

Any model your provider supports works — just set the model name in Settings. For example:
- OpenAI: `gpt-4o`, `gpt-5`, `o3-pro`, `o4-mini`
- Anthropic: `claude-sonnet-4-6`, `claude-opus-4-6`, `claude-haiku-4-5-20251001`
- Gemini: `gemini-2.0-flash`, `gemini-2.5-pro`

The API payload structure is identical across models within a provider. No code changes are needed when new models are released.

### Ollama Local LLM Architecture

> **If using local-only Ollama models, please read this section carefully.** Understanding the container architecture, GPU contention, and memory requirements is critical for performance, especially with larger models (8B+).

MASS deploys up to **three Ollama containers**, each dedicated to a specific role to prevent model-swap thrashing:

```
                       +-------------------+
                       |   ollama (11434)  |  DESTINATION: target/victim model
                       |   OLLAMA_HOST     |  Used by: interrogation target, sandbox target
                       +-------------------+

                       +-------------------+
                       | ollama-attacker   |  SOURCE: interrogator/attacker model
                       |  (11435)          |  Used by: interrogation attacker, default chat
                       | OLLAMA_ATTACKER_  |
                       |       HOST        |
                       +-------------------+

                       +-------------------+
                       | ollama-chat       |  CHAT: assistant/UI model (optional)
                       |  (11436)          |  Used by: chat, verification, guardrails
                       | OLLAMA_CHAT_HOST  |  Activate: --profile chat-ollama
                       +-------------------+
```

**Why three containers?**

When Ollama loads a model, it occupies GPU VRAM. If the same container handles both a chat request and an interrogation request with different models, it must unload one model and load the other — this "model swap" takes 10-30 seconds and causes timeouts. Dedicated containers eliminate this.

**Default behavior (2 containers):**

By default, MASS runs two Ollama containers:
- `ollama` — target/destination models
- `ollama-attacker` — attacker models AND chat/UI (shared)

This works well when you're not running interrogation and chat simultaneously. But during active interrogation, chat requests compete with the attacker model for the same Ollama instance.

**Recommended: 3 containers (activate `ollama-chat`):**

```bash
# Start with the dedicated chat Ollama instance
docker compose --profile chat-ollama up -d

# Set the chat host in .env
OLLAMA_CHAT_HOST=http://ollama-chat:11434
```

**Even better: Use cloud providers for chat:**

The most performant setup uses cloud LLMs (OpenAI, Anthropic, etc.) for chat/verification/guardrails and reserves both Ollama instances for interrogation:

```bash
MASS_DEFAULT_PROVIDER=openai
MASS_OPENAI_API_KEY=sk-...
# Ollama containers are only used for interrogation target/attacker
```

### GPU and Memory Considerations

| Model Size | VRAM per Instance | RAM per Container | Notes |
|-----------|-------------------|-------------------|-------|
| 1-3B | 2-4 GB | 4 GB | Fast, suitable for chat |
| 7-8B | 6-8 GB | 8 GB | Good balance for interrogation |
| 13B | 10-14 GB | 12 GB | Better quality, needs beefy GPU |
| 30-70B | 20-48 GB | 32-64 GB | Enterprise/research only |

**GPU sharing:** On a single GPU, all Ollama containers share VRAM. Running two 8B models simultaneously requires ~16 GB VRAM. If you exceed VRAM, Ollama falls back to CPU, which is 10-50x slower.

**Scaling options:**
- **Single GPU, limited VRAM:** Use a small model for chat (e.g., `qwen3:1.7b`) and a larger model for interrogation. Or use cloud providers for chat.
- **Multi-GPU:** Set `NVIDIA_VISIBLE_DEVICES` per container to pin each to a different GPU.
- **AWS/Cloud:** Run Ollama instances on separate EC2/GCE instances with dedicated GPUs. Set `OLLAMA_HOST`, `OLLAMA_ATTACKER_HOST`, and `OLLAMA_CHAT_HOST` to the remote URLs.
- **High-memory machines (64-128+ GB RAM):** Can run large models on CPU. Set `OLLAMA_CHAT_NUM_GPU=0` to force CPU-only for the chat instance.

```bash
# Example: Multi-GPU setup
# Container  | GPU  | Model
# ollama     | GPU0 | llama3.1:8b (target)
# ollama-atk | GPU1 | qwen3:8b (attacker)
# ollama-chat| CPU  | qwen3:1.7b (chat, verification)
OLLAMA_CHAT_NUM_GPU=0
```

```bash
# Example: Remote Ollama instances on AWS
OLLAMA_HOST=http://10.0.1.10:11434
OLLAMA_ATTACKER_HOST=http://10.0.1.11:11434
OLLAMA_CHAT_HOST=http://10.0.1.12:11434
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
