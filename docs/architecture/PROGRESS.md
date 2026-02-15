# Architecture Implementation Progress

## Current Phase: Phase 1 — Performance Bottleneck Fixes
## Current Item: P1.7 — PostgreSQL indexes
## Overall: 6/19 items complete

### Completed Items
- [x] P1.1 — Docker Compose resource limits — Date: 2026-02-15
  - Added `deploy.resources` (limits + reservations) to all 8 services in `docker-compose.yml`
  - Added resource limits to `docker-compose.lite.yml` API service
  - Added PostgreSQL tuning parameters (max_connections=200, shared_buffers, etc.)
  - Verified: containers running with correct memory/CPU limits applied
- [x] P1.2 — In-memory job store migration to Redis — Date: 2026-02-15
  - Created `src/mass/api/utils/job_store.py` — shared Redis-backed `JobStore` class
  - Migrated `mcp_interrogation.py` — replaced `_jobs` dict with `JobStore("interrogation")`
  - Migrated `mcp_audit.py` — replaced `_audit_jobs` dict with `JobStore("audit")`
  - Migrated `sandbox.py` — replaced `_active_jobs` dict with `JobStore("sandbox")`
  - Updated `tool_executor.py` — removed `_active_jobs` import
  - Updated `mcp/stdio_bridge.py` — reads job status from Redis instead of memory
  - Verified: all 3 endpoints return data correctly from Redis
- [x] P1.3 — Configurable thread pools via env vars — Date: 2026-02-15
  - Added 4 new config fields to `src/mass/core/config.py`:
    - `MASS_SCAN_THREAD_POOL_SIZE` (default: 20)
    - `MASS_INTERROGATION_THREAD_POOL_SIZE` (default: 8)
    - `MASS_PROBE_MAX_CONCURRENT` (default: 5)
    - `MASS_PROBE_MAX_CONCURRENT_PROMPTS` (default: 2)
  - Updated `scan_execution.py` — reads pool size from config instead of hardcoded 20
  - Updated `interrogation.py` — reads pool size from config instead of hardcoded 4
  - Updated `executor.py` — reads probe concurrency defaults from config instead of hardcoded 3/2
  - Updated `.env.example` with new env vars and sizing guidance (dev/staging/production)
  - Verified: build, restart, health check, and all endpoints pass
- [x] P1.4 — Distributed rate limiting (Redis-backed) — Date: 2026-02-15
  - Replaced in-memory `TokenBucket` with Redis-backed sliding window counter
  - Key pattern: `mass:ratelimit:api:{client}:{minute}` with 120s TTL
  - Registered `RateLimitMiddleware` in `main.py` (was previously unregistered)
  - Fail-open design: if Redis is unavailable, requests pass through
  - Headers confirmed: `X-RateLimit-Limit: 100`, counter decrements correctly
  - Health/ready/metrics endpoints bypass rate limiting
  - Verified: build, restart, rate limit headers working across multiple requests
- [x] P1.5 — LLM connection pooling (runners/pool.py) — Date: 2026-02-15
  - Created `src/mass/runners/pool.py` — shared httpx connection pools per provider
    - `get_httpx_pool()` — singleton sync httpx.Client (50 max connections, 20 keepalive)
    - `get_httpx_async_pool()` — singleton async httpx.AsyncClient (same limits)
    - `close_all_pools()` — graceful shutdown of all pools
  - Updated `ollama.py` — replaced per-request `httpx.Client()`/`httpx.AsyncClient()` with shared pool
  - Cached async SDK clients in 4 runners (previously recreated per call):
    - `openai.py` — cached `self._async_client` (AsyncOpenAI)
    - `anthropic.py` — cached `self._async_client` (AsyncAnthropic)
    - `grok.py` — cached `self._async_client` (AsyncOpenAI)
    - `azure_openai.py` — cached `self._async_client` (AsyncAzureOpenAI)
  - Registered `close_all_pools()` in app lifespan shutdown handler
  - Verified: build, restart, chat via Ollama pooled connection returns correctly

- [x] P1.6 — LLM provider rate limiting — Date: 2026-02-15
  - Added `ProviderRateLimiter` class to `src/mass/runners/pool.py`
    - Token bucket algorithm with per-provider RPM limits
    - Defaults: OpenAI 500, Anthropic 200, Gemini 300, Grok 200, Ollama unlimited
    - Override via `MASS_LLM_RPM_<PROVIDER>` env vars
    - Both sync (`acquire_sync`) and async (`acquire`) methods
  - Integrated rate limiting into all 7 runners:
    - `ollama.py` — sync + async
    - `openai.py` — sync + async
    - `anthropic.py` — sync + async
    - `gemini.py` — sync + async
    - `grok.py` — sync + async
    - `bedrock.py` — sync only
    - `azure_openai.py` — sync + async
  - Verified: build, restart, health check passes

### In Progress
- [ ] P1.7 — PostgreSQL indexes

### Remaining Items

**Phase 1: Performance Bottleneck Fixes**
- [x] P1.1 — Docker Compose resource limits
- [x] P1.2 — In-memory job store migration to Redis
- [x] P1.3 — Configurable thread pools via env vars
- [x] P1.4 — Distributed rate limiting (Redis-backed)
- [x] P1.5 — LLM connection pooling (runners/pool.py)
- [x] P1.6 — LLM provider rate limiting
- [ ] P1.7 — PostgreSQL indexes
- [ ] P1.8 — Dead letter queue for failed jobs

**Phase 2: Observability**
- [ ] P2.1 — Structured logging (structlog)
- [ ] P2.2 — Health check enhancement
- [ ] P2.3 — Metrics foundation

**Phase 3: Future Modules**
- [ ] P3.1 — CI/CD Integration
- [ ] P3.2 — Issue Generation (GitHub)
- [ ] P3.3 — Threat Intelligence
- [ ] P3.4 — Supply Chain Verification
- [ ] P3.5 — Privacy Risk Analysis
- [ ] P3.6 — Explainability
- [ ] P3.7 — Cross-Model Collaborative Security
- [ ] P3.8 — Cloud-Native Ecosystem

### Compliance Status (after P1.5)
- Rule 1 (No in-memory stores): PARTIAL — 3 target files migrated; `interrogation.py` still has `_active_jobs` (not in original scope, will address)
- Rule 2 (LLM connection pools): COMPLIANT — P1.5 complete. All runners use shared pools or cached SDK clients.
- Rule 3 (No blocking I/O): Not yet audited
- Rule 4 (WebSocket events): Existing modules comply
- Rule 5 (Timeouts): Not yet audited
- Rule 6 (Standard route pattern): Existing modules comply
- Rule 7 (Env var config): COMPLIANT — P1.3 complete.
- Rule 8 (Resource cleanup): COMPLIANT — Pool cleanup registered in lifespan.

### Known Issues
- `src/mass/api/routes/interrogation.py:46` — has `_active_jobs: dict` (same violation pattern, not in original scope)
