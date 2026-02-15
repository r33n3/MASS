# MASS Platform Architecture

> **Version**: 1.0
> **Last Updated**: 2026-02-15
> **Status**: Canonical reference — all new modules must comply

This document is the single source of truth for the MASS (Model & Application Security Suite)
platform architecture. Every new module, feature, and performance change must be validated
against the rules and patterns defined here.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Tier Architecture](#2-tier-architecture)
3. [Performance Architecture](#3-performance-architecture)
4. [Scaling Architecture](#4-scaling-architecture)
5. [Data Architecture](#5-data-architecture)
6. [Module Integration Rules](#6-module-integration-rules)
7. [Observability](#7-observability)
8. [Future Module Slots](#8-future-module-slots)
9. [Known Bottlenecks & Remediation Plan](#9-known-bottlenecks--remediation-plan)

---

## 1. System Overview

### 1.1 Component Diagram

```
                                ┌──────────────┐
                                │   Browser /   │
                                │   CI/CD CLI   │
                                └──────┬───────┘
                                       │ HTTP / WebSocket
                                ┌──────▼───────┐
                       ┌────────│  Nginx Proxy  │────────┐
                       │        │  (port 80)    │        │
                       │        └───────────────┘        │
                       │                                  │
                ┌──────▼───────┐                 ┌───────▼──────┐
                │  FastAPI API │                 │  Nginx UI    │
                │  (port 8000) │                 │  (static)    │
                │  N replicas  │                 └──────────────┘
                └──┬───┬───┬──┘
                   │   │   │
          ┌────────┘   │   └────────┐
          │            │            │
    ┌─────▼────┐ ┌────▼─────┐ ┌───▼────────┐
    │ Redis 7  │ │ Postgres │ │ Workers    │
    │ queue    │ │ 15 async │ │ N replicas │
    │ cache    │ │ pool +30 │ │ ×M concur  │
    │ pub/sub  │ │ overflow │ │ per worker │
    └─────┬────┘ └──────────┘ └───┬────────┘
          │                        │
          └──────────┬─────────────┘
                     │
       ┌─────────────┼─────────────┐
       │             │             │
  ┌────▼────┐  ┌────▼────┐  ┌────▼──────┐
  │ Ollama  │  │ Ollama  │  │ External  │
  │ Target  │  │Attacker │  │ LLM APIs  │
  │ :11434  │  │ :11435  │  │ OAI/Anth/ │
  └─────────┘  └─────────┘  │ Gemini/.. │
                             └───────────┘
```

### 1.2 Service Boundaries

| Service | Responsibility | Stateful? | Scales? |
|---------|---------------|-----------|---------|
| **nginx-proxy** | TLS termination, routing, static caching | No | Horizontally |
| **api** | Request validation, auth, job dispatch, WebSocket | No (session in Redis) | Horizontally |
| **worker** | Scan execution, analysis, LLM calls | No (jobs from Redis) | Horizontally |
| **postgres** | Findings, scans, deployments, tenants | Yes | Vertically, then read replicas |
| **redis** | Job queue, cache, pub/sub, rate limits, job state | Yes | Vertically, then Sentinel |
| **ollama / ollama-attacker** | Local LLM inference | Yes (GPU-bound) | Vertically (GPU) |
| **ui** | Static HTML/JS/CSS serving | No | Horizontally / CDN |

### 1.3 Key Data Flows

**Scan Flow**:
```
POST /api/v1/scans
  → validate request (Pydantic)
  → check concurrent scan limit
  → create Scan record in PostgreSQL (status=pending)
  → enqueue Job to Redis queue ("scans")
  → return 202 Accepted + scan_id

Worker dequeues job
  → ScanExecutionService.execute_scan(scan_id)
  → Orchestrator builds ScanPlan (dependency graph of jobs)
  → Executor runs analyzers (attack_surface, code, context, deployment,
                              infrastructure, mcp, model_file, secrets, workflow)
  → Findings stored incrementally in PostgreSQL
  → Progress broadcast via Redis pub/sub → WebSocket → browser
  → FinalJudge verdict + STRIDE-AI threat model (LLM calls)
  → Scan marked completed
```

**MCP Interrogation Flow**:
```
POST /api/v1/mcp-interrogation
  → create job in Redis (mass:interrogation:jobs:{id})
  → BackgroundTask runs MCPInterrogator
  → MCPClient connects (HTTP / SSE / stdio transport)
  → tool_tester generates test cases per tool parameter type
  → response_analyzer scores each result
  → findings + transcript broadcast via WebSocket
  → job marked completed in Redis
```

**MCP Container Audit Flow**:
```
POST /api/v1/mcp-audit
  → create job in Redis (mass:audit:jobs:{id})
  → BackgroundTask creates Docker container (node:20-slim or python:3.12-slim)
  → install package + start stdio-to-HTTP bridge
  → connect audit container to API's Docker network
  → MCPInterrogator runs against bridge URL
  → optional: sandbox scenario testing
  → container + network cleanup (always, even on error)
  → results stored in Redis
```

### 1.4 Current API Surface (23 Routers)

| Prefix | Router | Purpose |
|--------|--------|---------|
| `/api/v1/auth` | auth | API key management, authentication |
| `/api/v1/deployments` | deployments | AI deployment CRUD |
| `/api/v1/scans` | scans | Security scan lifecycle |
| `/api/v1/analyze` | analyze | Direct analysis (no scan record) |
| `/api/v1/compliance` | compliance | Framework assessments (OWASP, NIST, EU AI Act) |
| `/api/v1/reports` | reports | Report generation (SARIF, HTML, JSON) |
| `/api/v1/remediations` | remediations | Remediation templates |
| `/api/v1/webhooks` | webhooks | Event notification subscriptions |
| `/api/v1/admin` | admin | Admin operations |
| `/api/v1/discover` | discovery | AI component discovery |
| `/api/v1/dashboard` | dashboard | Dashboard stats + WebSocket |
| `/api/v1/targets` | targets | Scan target management |
| `/api/v1/scan-targets` | scan_targets | Scan-target associations |
| `/api/v1/interrogation` | interrogation | LLM model interrogation |
| `/api/v1/mcp-interrogation` | mcp_interrogation | MCP server interrogation |
| `/api/v1/mcp-audit` | mcp_audit | Containerized package auditing |
| `/api/v1/browse` | browse | File/content browsing |
| `/api/v1/chat` | chat | LLM chat with tool calling |
| `/api/v1/ollama` | ollama | Ollama model management |
| `/api/v1/sandbox` | sandbox | Scenario-based sandbox testing |
| `/api/v1/guardrails-policies` | guardrails_policies | Guardrail policy management |
| `/api/v1/docs` | docs | API documentation (dark Swagger UI) |
| `/api/v1/settings` | settings | Platform settings |
| `/health`, `/ready` | health | Health checks |

### 1.5 Analyzer Families (9)

| Analyzer | Location | What It Scans |
|----------|----------|---------------|
| **Attack Surface** | `analyzers/attack_surface/` | Privilege escalation, prompt leak, RAG poisoning, tool chaining |
| **Code** | `analyzers/code/` | LLM-powered source code security analysis |
| **Context** | `analyzers/context/` | System prompts, instructions, persona definitions |
| **Deployment** | `analyzers/deployment/` | Configuration files, environment variables, manifests |
| **Infrastructure** | `analyzers/infrastructure/` | Docker, Kubernetes, Terraform, CVE matching |
| **MCP** | `analyzers/mcp/` | Static MCP server analysis (injection, exfil, privilege, rugpull) |
| **Model File** | `analyzers/model_file/` | GGUF, PyTorch, pickle, safetensors, supply chain |
| **Secrets** | `analyzers/secrets/` | API keys, credentials, entropy-based detection |
| **Workflow** | `analyzers/workflow/` | LangChain, LangGraph, CrewAI, AutoGen, OpenAI Agents |

---

## 2. Tier Architecture

```
TIER 1 — API GATEWAY (Stateless, Horizontally Scalable)
├── Nginx reverse proxy
├── FastAPI application (N uvicorn workers per container)
├── Middleware stack: CORS → RequestLogging → Auth → RateLimit
├── Request validation via Pydantic schemas
└── Job dispatch: Redis queue (primary) or BackgroundTasks (fallback)

TIER 2 — SERVICE LAYER (Business Logic, runs in API + Worker processes)
├── ScanExecutionService — orchestrates full security scans
├── MCPInterrogator — MCP server testing pipeline
├── MCPAuditContainer — Docker container lifecycle for package audits
├── SandboxRuntime — scenario-based testing execution
├── ChatService — LLM chat with function calling
├── FindingVerificationService — LLM-powered finding review
├── OllamaManager — local model lifecycle management
└── CodeAnalysisService — LLM-powered code review

TIER 3 — WORKER LAYER (Stateless, Horizontally Scalable)
├── ScanWorker — polls Redis queue, executes scans
├── BackgroundTasks — in-process fallback for <30s operations
├── Thread pools — configurable per operation type
└── Analyzers — 9 analyzer families

TIER 4 — DATA LAYER
├── PostgreSQL 15 — persistent state (async via asyncpg)
│   ├── Pool: configurable (default 15 core + 30 overflow = 45 connections)
│   └── Tables: tenants, deployments, scans, findings, remediations, reports
├── Redis 7 — ephemeral state
│   ├── Job queues (sorted sets with priority)
│   ├── Job state (JSON strings with TTL)
│   ├── Cache (key-value with configurable TTL)
│   ├── Pub/sub (WebSocket broadcast channel)
│   └── Rate limit counters (INCR with TTL)
└── Filesystem — scan targets, cloned repos, report files, GGUF models

TIER 5 — EXTERNAL SERVICES
├── LLM Providers — OpenAI, Anthropic, Gemini, Grok, Bedrock, Azure OpenAI, Ollama
├── MCP Servers — target servers under test (stdio / HTTP / SSE)
├── Docker Engine — container management via Unix socket (/var/run/docker.sock)
└── GitHub / GitLab — future CI/CD and automated issue generation
```

### Scaling Strategy Per Tier

| Tier | Current | Scaling Method | Scale Trigger | Hard Limit |
|------|---------|---------------|---------------|------------|
| T1 API | 1 container | `docker compose up --scale api=N` | CPU > 70% or p95 latency > 2s | 8 replicas |
| T3 Worker | 2 replicas × 5 concurrent | `docker compose up --scale worker=N` | Queue depth > 20 for > 5 min | 16 replicas |
| T4 Postgres | 1 instance, pool 15+30 | Vertical first (CPU/RAM), then read replicas | Active connections > 80% pool | PgBouncer + 2 read replicas |
| T4 Redis | 1 instance, 256MB | Vertical first (RAM to 2GB), then Sentinel | Memory > 80% or pub/sub lag | 3-node Sentinel |
| T5 LLM | 2 Ollama + external APIs | Per-provider connection pools + rate limiters | 429 errors > 5% of calls | Pool size per provider |

---

## 3. Performance Architecture

### 3.1 LLM Connection Pooling

**Problem**: Every LLM call creates a new `httpx.Client`, causing TCP/TLS overhead.
At 100 concurrent scans × 15 LLM calls each = 1,500+ connection setups.

**Architecture**: Shared singleton `httpx.AsyncClient` per provider with connection limits.

```python
# src/mass/runners/pool.py (NEW)

_pools: dict[str, httpx.AsyncClient] = {}

def get_provider_pool(provider: str, base_url: str = "") -> httpx.AsyncClient:
    """Get or create a shared connection pool for an LLM provider."""
    if provider not in _pools:
        _pools[provider] = httpx.AsyncClient(
            base_url=base_url,
            limits=httpx.Limits(
                max_connections=50,
                max_keepalive_connections=20,
            ),
            timeout=httpx.Timeout(60.0, connect=10.0),
            http2=True,
        )
    return _pools[provider]
```

**Rule**: All LLM runners in `src/mass/runners/api/` MUST use `get_provider_pool()`
instead of creating new clients per request.

**Affected files**:
- `src/mass/runners/api/ollama.py`
- `src/mass/runners/api/openai.py`
- `src/mass/runners/api/anthropic.py`
- `src/mass/runners/api/gemini.py`
- `src/mass/runners/api/grok.py`
- `src/mass/runners/api/bedrock.py`
- `src/mass/runners/api/azure_openai.py`

### 3.2 LLM Provider Rate Limiting

**Problem**: No rate limiting on outbound LLM calls. Will exhaust provider quotas.

**Architecture**: Per-provider async token bucket.

```python
# src/mass/runners/pool.py

class ProviderRateLimiter:
    """Async token bucket rate limiter per LLM provider."""
    DEFAULTS = {
        "openai": 500,       # requests per minute
        "anthropic": 200,
        "gemini": 300,
        "grok": 200,
        "bedrock": 300,
        "azure_openai": 300,
        "ollama": 0,         # unlimited (local)
    }

    async def acquire(self, provider: str) -> None:
        """Block until a token is available for this provider."""
        ...
```

**Rule**: Every outbound LLM call MUST call `await rate_limiter.acquire(provider)`.

### 3.3 API Rate Limiting (Distributed)

**Problem**: `RateLimitMiddleware` uses per-process `TokenBucket` in memory.
With multiple API replicas, effective limit = N × configured limit.

**Architecture**: Redis-backed sliding window counter.

```python
# src/mass/api/middleware/rate_limit.py

async def _check_rate_limit(self, client_key: str) -> bool:
    """Distributed rate check via Redis INCR + EXPIRE."""
    current_minute = int(time.time()) // 60
    redis_key = f"mass:ratelimit:api:{client_key}:{current_minute}"
    count = await self.redis.incr(redis_key)
    if count == 1:
        await self.redis.expire(redis_key, 120)
    return count <= self.requests_per_minute
```

### 3.4 Thread Pool Configuration

**Problem**: Hardcoded `ThreadPoolExecutor(max_workers=20)` for scans.

**Architecture**: All pool sizes configurable via environment variables.

```python
# src/mass/core/config.py additions

scan_thread_pool_size: int = 20           # MASS_SCAN_THREAD_POOL_SIZE
interrogation_thread_pool_size: int = 8   # MASS_INTERROGATION_THREAD_POOL_SIZE
probe_max_concurrent: int = 5             # MASS_PROBE_MAX_CONCURRENT
```

**Sizing Guidance**:

| Environment | Scan Pool | Interrogation Pool | Probe Concurrent | API Workers |
|------------|-----------|-------------------|------------------|-------------|
| Dev / Lite | 10 | 4 | 3 | 1 |
| Staging | 30 | 8 | 5 | 4 |
| Production | 50–100 | 16 | 10 | 4–8 |

### 3.5 Caching Strategy

| Data | Cache Location | TTL | Invalidation Trigger |
|------|---------------|-----|---------------------|
| Dashboard stats | Redis `mass:cache:stats:*` | 60s | `scan.completed` event |
| Deployment metadata | Redis `mass:cache:deploy:*` | 300s | `deployment.updated` event |
| Remediation templates | In-memory (loaded at startup) | Until restart | Admin API call |
| LLM responses (opt.) | Redis `mass:cache:llm:{hash}` | 1800s | Content-hash key (never stale) |
| Finding severity counts | Redis `mass:cache:severity:*` | 30s | `finding.created` event |

### 3.6 Queue Architecture

All queues are Redis-backed sorted sets with priority scoring.

| Queue | Purpose | Executor | Concurrency | Timeout | Priority |
|-------|---------|----------|-------------|---------|----------|
| `scans` | Full security scans | Worker containers | 5 / worker | 1800s | NORMAL |
| `scans:priority` | CI/CD-triggered urgent scans | Worker containers | 2 / worker | 1800s | HIGH |
| `interrogation` | MCP server interrogation | API BackgroundTask | 4 | 600s | NORMAL |
| `audit` | Containerized package audits | API BackgroundTask | 2 | 600s | LOW |
| `sandbox` | Sandbox scenario execution | API BackgroundTask | 4 | 300s | NORMAL |
| `threat_intel` | Feed collection + analysis | Worker (future) | 2 | 300s | LOW |
| `supply_chain` | Package dependency auditing | Worker (future) | 2 | 600s | NORMAL |

**Backpressure Rules**:

| Queue Depth | Action |
|-------------|--------|
| > 50 | Return `X-Queue-Warning` header in API responses |
| > 100 | Return `503 Service Unavailable` |
| Worker stall > 2× timeout | Kill job, move to dead letter queue `mass:dlq:{queue}` |

**Dead Letter Queue**: Failed jobs after 3 retries go to `mass:dlq:{queue_name}` for manual review.

---

## 4. Scaling Architecture

### 4.1 Horizontal Scaling

**API Tier** (current: 1, target: 4–8):
```yaml
api:
  deploy:
    replicas: 4
    resources:
      limits: { cpus: '2.0', memory: 4G }
      reservations: { cpus: '0.5', memory: 1G }
  command: >
    uvicorn mass.api.main:create_app --factory
    --host 0.0.0.0 --port 8000 --workers 1
```

Each container runs 1 uvicorn process. Scale by adding containers, not workers-per-container.
This keeps per-container memory predictable and avoids fork-based issues with async Python.

**Worker Tier** (current: 2 × 5 = 10, target: 8 × 5 = 40):
```yaml
worker:
  deploy:
    replicas: 8
    resources:
      limits: { cpus: '4.0', memory: 8G }
      reservations: { cpus: '1.0', memory: 2G }
  environment:
    MASS_WORKER_CONCURRENCY: "5"
```

### 4.2 Capacity Planning Table

| Concurrent Scans | API Replicas | Worker Replicas | DB Pool (per process) | Redis RAM | Total DB Connections |
|-----------------|-------------|-----------------|----------------------|-----------|---------------------|
| 10 (dev) | 1 | 2 | 15 + 30 | 256 MB | ~135 |
| 25 (small team) | 2 | 4 | 20 + 40 | 512 MB | ~360 |
| 50 (medium) | 4 | 8 | 20 + 30 | 1 GB | ~600 |
| 100 (large) | 8 | 16 | 15 + 20 | 2 GB | ~840 |
| 200+ (enterprise) | 8+ behind LB | 32+ K8s HPA | PgBouncer | Redis Cluster | PgBouncer manages |

**Note**: At 100+ scans, introduce **PgBouncer** as a connection multiplexer in front of
PostgreSQL to avoid exhausting `max_connections`. Each API/worker replica thinks it has its
own pool, but PgBouncer multiplexes to a smaller number of real connections.

### 4.3 Resource Limits

```yaml
services:
  api:
    deploy:
      resources:
        limits: { cpus: '2.0', memory: 4G }
        reservations: { cpus: '0.5', memory: 1G }

  worker:
    deploy:
      resources:
        limits: { cpus: '4.0', memory: 8G }
        reservations: { cpus: '1.0', memory: 2G }

  postgres:
    deploy:
      resources:
        limits: { cpus: '4.0', memory: 8G }
    command: >
      postgres
        -c max_connections=200
        -c shared_buffers=2GB
        -c effective_cache_size=4GB
        -c work_mem=16MB
        -c maintenance_work_mem=512MB

  redis:
    deploy:
      resources:
        limits: { cpus: '2.0', memory: 2G }
    command: >
      redis-server
        --maxmemory 1536mb
        --maxmemory-policy allkeys-lru
        --appendonly yes
        --appendfsync everysec

  ollama:
    deploy:
      resources:
        limits: { memory: 16G }
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
```

### 4.4 Auto-Scaling Triggers

| Metric | Threshold | Action |
|--------|-----------|--------|
| API CPU > 80% for 5 min | Scale up | Add 2 API replicas |
| Queue depth > 20 for 5 min | Scale up | Add 2 worker replicas |
| Queue depth < 5 for 15 min | Scale down | Remove 1 worker replica (min 2) |
| API memory > 90% | Alert | Investigate (possible leak) |
| DB active connections > 80% pool | Scale pool | Increase pool_size by 10 |
| Redis memory > 80% | Alert | Investigate key growth |

---

## 5. Data Architecture

### 5.1 State Management Rules

> **MANDATORY**: No module may store job or session state in Python dicts.
> All state must be in Redis (ephemeral) or PostgreSQL (persistent).

| State Type | Storage | TTL | Why |
|-----------|---------|-----|-----|
| Job status / progress | Redis hash | 24h | Survives restarts, shared across workers |
| Scan results | PostgreSQL | Permanent | Persistent, queryable, indexed |
| Cache data | Redis string | Per-resource | Fast reads, auto-expiration |
| File artifacts | Filesystem / S3 | N/A | Large blobs don't belong in DB |
| Rate limit counters | Redis INCR | 60–120s | Shared across API replicas |
| WebSocket broadcasts | Redis pub/sub | N/A | Cross-process delivery |
| Background job results | Redis string | 7 days | Retrieved via API polling |

**Files that currently violate this rule** (need migration to Redis):

| File | Current Pattern | Migration Target |
|------|----------------|-----------------|
| `src/mass/api/routes/mcp_interrogation.py:32` | `_jobs: dict[str, dict] = {}` | `mass:interrogation:jobs:{id}` |
| `src/mass/api/routes/mcp_audit.py:26` | `_audit_jobs: dict[str, dict] = {}` | `mass:audit:jobs:{id}` |
| `src/mass/api/routes/sandbox.py:47` | `_active_jobs: dict[str, dict] = {}` | `mass:sandbox:jobs:{id}` |

### 5.2 Redis Keyspace Organization

```
mass:                                     # Root prefix (all MASS keys)
│
├── jobs:                                 # Worker queue system
│   ├── queue:{name}                      # Sorted set — priority queue
│   │   Examples: mass:jobs:queue:scans
│   │             mass:jobs:queue:scans:priority
│   └── job:{id}                          # String/JSON — job data (TTL 24h)
│
├── interrogation:                        # MCP interrogation
│   └── jobs:{id}                         # String/JSON — job state (TTL 7d)
│
├── audit:                                # MCP container audits
│   └── jobs:{id}                         # String/JSON — audit state (TTL 7d)
│
├── sandbox:                              # Sandbox testing
│   └── jobs:{id}                         # String/JSON — sandbox state (TTL 7d)
│
├── cache:                                # Application cache
│   ├── stats:{scope}:{id}               # Dashboard statistics (TTL 60s)
│   ├── deploy:{id}                      # Deployment metadata (TTL 300s)
│   ├── severity:{scan_id}              # Finding severity counts (TTL 30s)
│   ├── remediation:templates            # Remediation templates (TTL 3600s)
│   └── llm:{content_hash}              # LLM response cache (TTL 1800s)
│
├── ratelimit:                            # Rate limiting
│   ├── api:{client_key}:{minute}        # API request counters (TTL 120s)
│   └── llm:{provider}:{minute}          # LLM provider counters (TTL 120s)
│
├── ws:                                   # WebSocket
│   └── broadcast                         # Pub/sub channel
│
├── worker:                               # Worker health
│   └── {worker_id}:heartbeat            # Liveness beacon (TTL 60s)
│
├── dlq:                                  # Dead letter queues
│   └── {queue_name}                      # List — failed jobs for review
│
└── [future modules]:                     # Reserved prefixes
    ├── threat_intel:feeds:{id}
    ├── threat_intel:items:{id}
    ├── cicd:configs:{id}
    ├── supply_chain:packages:{id}
    └── integrations:github:{repo}
```

**TTL Enforcement Rule**: Every Redis key MUST have a TTL set. Keys without expiration
will accumulate and eventually exhaust Redis memory. A periodic audit task should scan
for keys missing TTL using `OBJECT IDLETIME`.

### 5.3 PostgreSQL Tables & Indexes

**Current tables**: `tenants`, `deployments`, `scans`, `findings`, `remediations`, `reports`

**Required indexes for query performance at scale**:

```sql
-- Scans: queried by tenant + status (concurrent scan limit check)
CREATE INDEX IF NOT EXISTS idx_scans_tenant_status
    ON scans(tenant_id, status);

-- Scans: queried by deployment + status
CREATE INDEX IF NOT EXISTS idx_scans_deployment_status
    ON scans(deployment_id, status);

-- Scans: ordered listing
CREATE INDEX IF NOT EXISTS idx_scans_created_desc
    ON scans(created_at DESC);

-- Findings: the most queried table — compound indexes for common filters
CREATE INDEX IF NOT EXISTS idx_findings_scan_severity
    ON findings(scan_id, severity);

CREATE INDEX IF NOT EXISTS idx_findings_tenant_status
    ON findings(tenant_id, status);

-- Findings: cross-scan deduplication via fingerprint
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint
    ON findings(fingerprint);

-- Findings: category-based filtering
CREATE INDEX IF NOT EXISTS idx_findings_category
    ON findings(category);

-- Findings: ordered listing
CREATE INDEX IF NOT EXISTS idx_findings_created_desc
    ON findings(created_at DESC);

-- Deployments: tenant lookup
CREATE INDEX IF NOT EXISTS idx_deployments_tenant
    ON deployments(tenant_id);
```

### 5.4 Event System

**Architecture**: In-memory `EventBus` with Redis pub/sub for cross-process delivery.

```
Worker Process                   API Process
     │                                │
     ├─ publish(Event)                │
     │   ├─ Local EventBus handlers   │
     │   └─ Redis pub/sub ──────────► │
     │       channel: mass:ws:broadcast
     │                                ├─ Redis listener receives
     │                                ├─ WebSocket Manager delivers
     │                                └─ → Connected browser clients
```

**Event Types** (from `src/mass/core/events.py`):

| Category | Events | Typical Publisher |
|----------|--------|-------------------|
| Scan | `scan.created`, `.started`, `.progress`, `.completed`, `.failed`, `.cancelled` | Worker |
| Finding | `finding.created`, `.updated`, `.suppressed` | Worker / API |
| Analysis | `analysis.started`, `.completed`, `.failed` | Worker |
| Probe | `probe.started`, `.completed`, `.failed` | Worker |
| Sandbox | `sandbox.started`, `.completed`, `.failed` | API BackgroundTask |
| Report | `report.generated`, `.exported` | API |
| Worker | `worker.started`, `.stopped`, `.error` | Worker |

**Rule**: All background operations MUST publish progress events for observability.

---

## 6. Module Integration Rules

> Every new module MUST comply with these rules. Violations will cause performance
> regressions at scale and architectural drift.

### Rule 1: Job State in Redis, Not Memory

```python
# WRONG — lost on restart, not shared across replicas
_jobs: dict[str, dict] = {}

# RIGHT — survives restarts, shared across all processes
async def _save_job(job_id: str, data: dict, ttl: int = 86400):
    r = aioredis.from_url(settings.redis.url)
    await r.set(
        f"mass:{MODULE_NAME}:jobs:{job_id}",
        json.dumps(data, default=str),
        ex=ttl,
    )

async def _load_job(job_id: str) -> dict | None:
    r = aioredis.from_url(settings.redis.url)
    raw = await r.get(f"mass:{MODULE_NAME}:jobs:{job_id}")
    return json.loads(raw) if raw else None
```

### Rule 2: Use Shared LLM Connection Pools

```python
# WRONG — new TCP connection per request
with httpx.Client(timeout=60) as client:
    response = client.post(url, json=payload)

# RIGHT — reuse pooled connections
from mass.runners.pool import get_provider_pool
client = get_provider_pool("openai")
response = await client.post(url, json=payload)
```

### Rule 3: No Blocking I/O in API Route Handlers

```python
# WRONG — blocks the event loop, starves other requests
@router.post("/analyze")
async def analyze(request: AnalyzeRequest):
    result = heavy_synchronous_computation()  # Blocks!
    return result

# RIGHT — dispatch to background, return immediately
@router.post("/analyze")
async def analyze(request: AnalyzeRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid4())
    await _save_job(job_id, {"status": "pending"})
    background_tasks.add_task(_run_analysis, job_id, request)
    return {"job_id": job_id, "status": "pending"}
```

### Rule 4: Publish Progress Events via WebSocket

```python
from mass.dashboard.websocket import manager

await manager.broadcast({
    "type": f"{module_name}_update",
    "job_id": job_id,
    "status": "running",
    "progress": 0.45,         # 0.0 to 1.0
    "phase": "analyzing",
    "phase_detail": "Running prompt injection tests",
})
```

### Rule 5: All External Calls Must Have Timeouts

```python
# WRONG — will hang indefinitely if remote is unresponsive
response = await client.get(url)

# RIGHT — explicit timeout
response = await client.get(url, timeout=30.0)
```

### Rule 6: Standard Route Pattern

Every new route module MUST follow this endpoint structure:

```python
router = APIRouter()

@router.post("")                    # Start async operation → returns job_id
@router.get("/jobs")                # List jobs (paginated)
@router.get("/jobs/{job_id}")       # Get job status + results
@router.delete("/jobs/{job_id}")    # Cancel + cleanup
@router.get("/status")             # Module health / availability check
```

### Rule 7: Configuration via Environment Variables

```python
# WRONG — hardcoded, can't tune per environment
MAX_CONCURRENT = 5
TIMEOUT = 300

# RIGHT — configurable via env vars, with sensible defaults
# In src/mass/core/config.py:
module_max_concurrent: int = Field(default=5, env="MASS_MODULE_MAX_CONCURRENT")
module_timeout: int = Field(default=300, env="MASS_MODULE_TIMEOUT")
```

### Rule 8: Resource Cleanup in Finally Blocks

```python
# For any module that creates external resources (containers, connections, temp files)
async def _run_job(job_id: str):
    resource = None
    try:
        resource = await create_resource()
        await do_work(resource)
    except Exception as e:
        await _update_job(job_id, {"status": "failed", "error": str(e)})
    finally:
        if resource:
            await resource.cleanup()  # ALWAYS clean up
```

---

## 7. Observability

### 7.1 Metrics

**API Metrics** (per route):

| Metric Name | Type | Labels | Purpose |
|------------|------|--------|---------|
| `mass_api_requests_total` | Counter | method, endpoint, status | Request volume |
| `mass_api_latency_seconds` | Histogram | endpoint | Response time (p50/p95/p99) |
| `mass_api_rate_limit_hits_total` | Counter | client | Rate limit pressure |
| `mass_api_active_connections` | Gauge | — | Current load |

**Queue Metrics**:

| Metric Name | Type | Labels | Purpose |
|------------|------|--------|---------|
| `mass_queue_depth` | Gauge | queue_name | Backlog size |
| `mass_queue_job_duration_seconds` | Histogram | queue_name, job_type | Processing time |
| `mass_queue_job_failures_total` | Counter | queue_name | Failure rate |
| `mass_queue_dlq_size` | Gauge | queue_name | Dead letter accumulation |

**LLM Metrics** (per provider):

| Metric Name | Type | Labels | Purpose |
|------------|------|--------|---------|
| `mass_llm_requests_total` | Counter | provider, model | Call volume |
| `mass_llm_latency_seconds` | Histogram | provider | Response time |
| `mass_llm_tokens_total` | Counter | provider, direction | Token usage (input/output) |
| `mass_llm_rate_limit_hits_total` | Counter | provider | Provider throttling |
| `mass_llm_errors_total` | Counter | provider, error_type | API errors |

**Database Metrics**:

| Metric Name | Type | Labels | Purpose |
|------------|------|--------|---------|
| `mass_db_pool_active` | Gauge | — | Active connections |
| `mass_db_pool_waiting` | Gauge | — | Queued connection requests |
| `mass_db_query_duration_seconds` | Histogram | operation | Query performance |

### 7.2 Health Check Standard

Every service exposes `/health` returning:

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 3600,
  "checks": {
    "database": { "status": "healthy", "latency_ms": 2, "pool_active": 5, "pool_size": 45 },
    "redis": { "status": "healthy", "latency_ms": 1, "memory_used_mb": 128 },
    "queue": { "status": "healthy", "depth": { "scans": 3, "interrogation": 0 } },
    "docker": { "status": "healthy", "socket": "/var/run/docker.sock" },
    "llm_providers": {
      "ollama": { "status": "healthy", "models_loaded": 2 },
      "openai": { "status": "configured" }
    }
  }
}
```

**Status values**:
- `healthy` — all checks passing
- `degraded` — non-critical checks failing (e.g., Ollama down but external LLMs available)
- `unhealthy` — critical checks failing (database or Redis down)

### 7.3 Structured Logging Standard

All log entries MUST use structured JSON format with standard fields:

```python
import structlog
logger = structlog.get_logger()

logger.info(
    "scan_completed",
    scan_id=scan_id,
    tenant_id=tenant_id,
    duration_seconds=duration,
    findings_count=len(findings),
    severity_counts={"critical": 2, "high": 5, "medium": 8, "low": 3},
    worker_id=worker_id,
)
```

**Log Levels**:

| Level | Usage | Example |
|-------|-------|---------|
| DEBUG | Detailed execution flow | "Executing probe injection_001 against tool read_file" |
| INFO | Business events | "Scan completed: 18 findings in 45s" |
| WARNING | Recoverable issues | "LLM rate limit hit for openai, retrying in 5s" |
| ERROR | Unrecoverable failures | "Scan failed: database connection timeout" |
| CRITICAL | System-level failures | "Redis connection lost, queue unavailable" |

---

## 8. Future Module Slots

### 8.1 Module Integration Map

| Module | Route Prefix | Service Layer | Worker Queue | New DB Tables | Reuses From Existing |
|--------|-------------|--------------|-------------|--------------|---------------------|
| **Threat Intel** | `/api/v1/threat-intel` | `services/threat_intel.py` | `threat_intel` (LOW) | `threat_items`, `techniques` | LLM pool, `Payload` corpus, `AttackStrategy` |
| **CI/CD** | `/api/v1/cicd` | `services/cicd.py` | None (sync gate) | `cicd_configs` | SARIF formatter, scan pipeline, webhook events |
| **Supply Chain** | `/api/v1/supply-chain` | `services/supply_chain.py` | `supply_chain` (NORMAL) | `packages`, `sboms` | CVE database, model_file scanners |
| **Privacy** | `/api/v1/privacy` | Integrated into scan | None (scan phase) | Uses `findings` | PII detector, compliance assessor |
| **Explainability** | `/api/v1/explain` | `services/explainability.py` | None (on-demand) | None (Redis cache) | LLM pool, attack_surface chains |
| **Cross-Model** | `/api/v1/cross-model` | `services/cross_model.py` | `cross_model` (NORMAL) | `model_comparisons` | All LLM runners, probe executor |
| **Cloud-Native** | `/api/v1/cloud` | `services/cloud.py` | `cloud` (NORMAL) | `cloud_resources` | Infrastructure analyzer patterns |
| **Issue Generation** | `/api/v1/integrations` | `services/github.py` | `issue_export` (LOW) | `exported_issues` | Finding model, remediation templates |

### 8.2 Module Dependency Graph (Build Order)

```
                    ┌──────────────────────┐
                    │   CI/CD Integration  │ ◄── Build first (highest value,
                    │   (uses SARIF, scan  │     lowest complexity)
                    │    pipeline, webhooks)│
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  Automated Issue     │ ◄── Build second (pairs with CI/CD)
                    │  Generation          │
                    │  (exports findings   │
                    │   as GitHub Issues   │
                    │   for AI dev tools)  │
                    └──────────────────────┘

                    ┌──────────────────────┐
                    │   Threat Intel       │ ◄── Build third (keeps attacks current)
                    │   (uses LLM pool,    │
                    │    payload corpus)    │
                    │   Feeds INTO all     │
                    │   scanners           │
                    └──────────────────────┘

     ┌──────────────────┐    ┌──────────────────┐
     │  Supply Chain    │    │  Privacy Risk    │ ◄── Build fourth (new scan phases)
     │  (uses CVE DB,   │    │  (uses PII       │
     │   model scanners)│    │   detector)      │
     └──────────────────┘    └──────────────────┘

     ┌──────────────────┐    ┌──────────────────┐
     │  Explainability  │    │  Cross-Model     │ ◄── Build fifth (enhance output)
     │  (uses LLM pool, │    │  (uses all       │
     │   attack chains) │    │   runners)       │
     └──────────────────┘    └──────────────────┘

                    ┌──────────────────────┐
                    │   Cloud-Native       │ ◄── Build last (most new infra,
                    │   (needs cloud SDKs, │     enterprise-only)
                    │    new providers)    │
                    └──────────────────────┘

                    ┌──────────────────────┐
                    │   Real-Time Monitor  │ ◄── DEFERRED (needs new real-time
                    │   (needs streaming   │     infrastructure)
                    │    infrastructure)   │
                    └──────────────────────┘
```

### 8.3 Module Performance Budget

Each new module gets a performance budget to prevent degradation:

| Module | Max API Latency (p95) | Max Memory per Job | Max Queue Depth | Max LLM Calls/Job |
|--------|-----------------------|--------------------|-----------------|--------------------|
| Threat Intel | 200ms (trigger) | 256 MB | 20 | 10 (analysis) |
| CI/CD | 500ms (sync gate) | 128 MB | N/A (sync) | 0 (reads only) |
| Supply Chain | 200ms (trigger) | 512 MB | 10 | 5 (provenance) |
| Privacy | Part of scan budget | Part of scan | Part of scan | 5 (PII analysis) |
| Explainability | 2s (on-demand) | 128 MB | N/A (sync) | 3 (explanation) |
| Cross-Model | 200ms (trigger) | 1 GB (N models) | 5 | N × scan budget |
| Cloud-Native | 200ms (trigger) | 512 MB | 10 | 2 (posture check) |
| Issue Generation | 200ms (trigger) | 128 MB | 20 | 3 (issue text) |

---

## 9. Known Bottlenecks & Remediation Plan

Prioritized by impact and effort:

| # | Bottleneck | Impact | Fix | Effort | Files Affected |
|---|-----------|--------|-----|--------|----------------|
| 1 | Single API worker | Medium | Use `--workers 4` in compose or scale replicas | None | `docker-compose.yml` |
| 2 | In-memory job stores | High | Migrate `_jobs` dicts to Redis | Low | `mcp_interrogation.py`, `mcp_audit.py`, `sandbox.py` |
| 3 | Hardcoded thread pools | Medium | Move pool sizes to `config.py` env vars | Low | `scan_execution.py`, `config.py` |
| 4 | Per-process rate limiting | Medium | Redis-backed sliding window | Low | `rate_limit.py` |
| 5 | No LLM connection pooling | High | Create `runners/pool.py`, modify all runners | Medium | 7 runner files |
| 6 | No LLM rate limiting | Medium | Per-provider token bucket | Medium | 1 new file + runner integration |
| 7 | No resource limits | Low | Add `deploy.resources` to all services | None | `docker-compose.yml` |
| 8 | Sequential scan jobs | Low | `asyncio.gather()` for independent jobs | Medium | `service.py` |

**Recommended fix order**: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8

Start with zero-code-change wins (1, 7), then low-effort high-impact (2, 3, 4),
then medium-effort (5, 6, 8).

---

## Appendix A: Configuration Reference

All performance-related environment variables:

```bash
# ── Database ──────────────────────────────────────────
MASS_DB_URL=postgresql+asyncpg://mass:mass@postgres:5432/mass
MASS_DB_POOL_SIZE=15              # Core connection pool
MASS_DB_MAX_OVERFLOW=30           # Additional connections allowed
MASS_DB_POOL_TIMEOUT=30           # Seconds to wait for connection

# ── Redis ─────────────────────────────────────────────
MASS_REDIS_URL=redis://redis:6379/0
MASS_REDIS_MAX_CONNECTIONS=50     # Connection pool size
MASS_REDIS_SOCKET_TIMEOUT=5.0    # Seconds (not used for pub/sub)

# ── API ───────────────────────────────────────────────
MASS_API_WORKERS=4                # Uvicorn worker processes
MASS_API_RATE_LIMIT=100           # Requests per minute per client
MASS_API_CORS_ORIGINS=["*"]       # CORS allowed origins

# ── Scanning ──────────────────────────────────────────
MASS_SCAN_TIMEOUT_SECONDS=3600    # Max seconds per scan
MASS_SCAN_MAX_CONCURRENT=10       # Platform-wide concurrent scan limit
MASS_SCAN_THREAD_POOL_SIZE=20     # Thread pool for scan execution
MASS_PROBE_BATCH_SIZE=50          # Probes per batch

# ── Workers ───────────────────────────────────────────
MASS_WORKER_CONCURRENCY=5         # Jobs per worker process
MASS_WORKER_QUEUES=scans          # Comma-separated queue names

# ── Interrogation ─────────────────────────────────────
MASS_INTERROGATION_THREAD_POOL_SIZE=8
MASS_PROBE_MAX_CONCURRENT=5

# ── LLM Providers ────────────────────────────────────
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=...
XAI_API_KEY=...
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_ATTACKER_BASE_URL=http://ollama-attacker:11434

# ── MCP Audit ─────────────────────────────────────────
MASS_AUDIT_CONTAINER_TIMEOUT=600  # Max seconds per audit container
MASS_AUDIT_CONTAINER_MEMORY=512m  # Container memory limit
MASS_AUDIT_CONTAINER_CPUS=1.0     # Container CPU limit
```

---

## Appendix B: File Structure Reference

```
src/mass/
├── analyzers/              # 9 analyzer families (attack_surface, code, context,
│                           #   deployment, infrastructure, mcp, model_file, secrets, workflow)
├── api/
│   ├── main.py             # App factory, router registration, lifecycle
│   ├── dependencies.py     # DI: sessions, repos, auth, pagination
│   ├── middleware/          # CORS, auth, logging, rate_limit, tenant, errors
│   ├── routes/             # 23 API routers
│   ├── schemas/            # Pydantic request/response models
│   ├── services/           # Business logic services
│   └── utils/              # LLM config resolution
├── cli/                    # CLI entry points
├── compliance/             # Framework assessors (OWASP, NIST, EU AI Act)
├── core/                   # Config, events, types, findings, exceptions
├── dashboard/              # Frontend app, WebSocket manager, static files
├── detectors/              # Detection engines (PII, harm, refusal, keywords)
├── interrogator/           # LLM interrogation strategies (12 attack types)
├── mcp/                    # MCP client, interrogator, container, bridge
├── orchestration/          # Scan orchestration, execution, risk scoring
├── planner/                # Scan planning, priority, optimization
├── policy/                 # Policy engine, guardrails, remediation
├── probes/                 # Security test probes (injection, jailbreak, leakage)
├── reporting/              # Report generation (SARIF, HTML, JSON)
├── runners/                # LLM provider runners (7 providers + base)
├── sandbox/                # Scenario testing (proposer, binder, runtime, scorer)
├── storage/                # PostgreSQL models, repos, migrations, cache
├── threat_model/           # STRIDE-AI threat modeling
└── workers/                # Background job processing (queue, worker, scheduler)
```
