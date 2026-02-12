"""Interrogation endpoints.

AI-driven adversarial model interrogation using attacker/target model pairs.
Supports any combination: Ollama vs Ollama, Ollama vs OpenAI, etc.

Jobs are persisted to Redis so results survive API restarts.
"""

import asyncio
import concurrent.futures
import json
import logging
import os
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from pydantic import BaseModel, Field

from mass.api.dependencies import CurrentTenantDep, DBSession
from mass.api.schemas.interrogation import (
    AvailableAgent,
    ConversationResponse,
    ConversationTurnResponse,
    CustomStrategyContent,
    CustomStrategyCreate,
    CustomStrategyFile,
    InterrogationFinding,
    InterrogationRequest,
    InterrogationResponse,
    InterrogationStatusResponse,
    OllamaModel,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Redis key prefix for interrogation jobs
_REDIS_PREFIX = "mass:interrogation:jobs:"

# In-memory cache for active (running) jobs only
_active_jobs: dict[str, dict[str, Any]] = {}

# Thread pool for interrogation execution
_interrogation_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=4,
    thread_name_prefix="mass-interrogate",
)


# ---- Redis helpers ----

async def _get_redis():
    """Get an async Redis connection."""
    try:
        import redis.asyncio as aioredis
    except ImportError:
        import aioredis

    redis_url = os.getenv("MASS_REDIS_URL", "redis://localhost:6379/0")
    return aioredis.from_url(redis_url, decode_responses=True)


async def _save_job_to_redis(job_id: str, data: dict) -> None:
    """Persist a job result to Redis."""
    try:
        r = await _get_redis()
        key = f"{_REDIS_PREFIX}{job_id}"
        await r.set(key, json.dumps(data, default=str))
        # Keep jobs for 7 days
        await r.expire(key, 7 * 24 * 3600)
        await r.close()
    except Exception as e:
        logger.warning("Failed to save job %s to Redis: %s", job_id, e)


async def _load_job_from_redis(job_id: str) -> dict | None:
    """Load a job result from Redis."""
    try:
        r = await _get_redis()
        key = f"{_REDIS_PREFIX}{job_id}"
        data = await r.get(key)
        await r.close()
        if data:
            return json.loads(data)
    except Exception as e:
        logger.warning("Failed to load job %s from Redis: %s", job_id, e)
    return None


async def _list_jobs_from_redis() -> list[dict]:
    """List all job summaries from Redis."""
    try:
        r = await _get_redis()
        keys = []
        async for key in r.scan_iter(match=f"{_REDIS_PREFIX}*"):
            keys.append(key)
        jobs = []
        for key in keys:
            data = await r.get(key)
            if data:
                jobs.append(json.loads(data))
        await r.close()
        return jobs
    except Exception as e:
        logger.warning("Failed to list jobs from Redis: %s", e)
    return []


# ---- Endpoints ----

@router.get(
    "/agents",
    response_model=list[AvailableAgent],
    summary="List available red team agents",
    description="Returns all registered red team agents with their strategies and categories.",
)
async def list_agents(tenant: CurrentTenantDep) -> list[AvailableAgent]:
    """List available interrogation agents."""
    import mass.interrogator.agents.strategies  # noqa: F401
    from mass.interrogator.agents.base import agent_registry

    agents = agent_registry.list_all()
    return [
        AvailableAgent(
            name=a.name,
            category=a.category.value,
            description=a.description,
            strategies=[s.name for s in a.strategies],
            tags=a.tags,
        )
        for a in agents
    ]


@router.get(
    "/models",
    response_model=list[OllamaModel],
    summary="List available Ollama models",
    description=(
        "Lists models from both Ollama instances: "
        "destination (victim) and source (interrogator)."
    ),
)
async def list_ollama_models(tenant: CurrentTenantDep) -> list[OllamaModel]:
    """List models from both Ollama instances."""
    hosts = {
        "destination": os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        "source": os.getenv("OLLAMA_ATTACKER_HOST", ""),
    }

    models: list[OllamaModel] = []

    async with httpx.AsyncClient(timeout=10.0) as client:
        for role, host in hosts.items():
            if not host:
                continue
            try:
                response = await client.get(f"{host}/api/tags")
                response.raise_for_status()
                data = response.json()

                for m in data.get("models", []):
                    size_gb = m.get("size", 0) / (1024 ** 3)
                    models.append(OllamaModel(
                        name=m.get("name", ""),
                        size=f"{size_gb:.1f} GB",
                        modified=m.get("modified_at", ""),
                        instance=role,
                    ))
            except httpx.ConnectError:
                continue
            except Exception as e:
                logger.warning("Failed to list Ollama models from %s (%s): %s", role, host, e)

    return models


@router.post(
    "/jobs",
    response_model=InterrogationStatusResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start an interrogation job",
    description=(
        "Launches an adversarial interrogation of a target model using an "
        "attacker model. The attacker conducts multi-turn conversations "
        "to probe for vulnerabilities. Returns immediately with a job ID; "
        "poll GET /jobs/{id} for results."
    ),
)
async def start_interrogation(
    request: InterrogationRequest,
    background_tasks: BackgroundTasks,
    tenant: CurrentTenantDep,
    db: DBSession,
) -> InterrogationStatusResponse:
    """Start an interrogation job."""
    from mass.interrogator.orchestrator import InterrogationConfig

    job_id = str(uuid4())

    config = InterrogationConfig(
        target_provider=request.target.provider,
        target_model=request.target.model,
        target_endpoint=request.target.endpoint,
        target_api_key=request.target.api_key,
        target_system_prompt=request.target_system_prompt,
        attacker_provider=request.attacker.provider,
        attacker_model=request.attacker.model,
        attacker_endpoint=request.attacker.endpoint,
        attacker_api_key=request.attacker.api_key,
        categories=request.categories,
        agent_names=request.agent_names,
        max_turns=request.max_turns,
        max_strategies_per_agent=request.max_strategies_per_agent,
        mcp_servers=[s.model_dump(exclude_none=True) for s in request.mcp_servers]
            if request.mcp_servers else None,
    )

    attacker_label = f"{request.attacker.provider}/{request.attacker.model}"
    target_label = f"{request.target.provider}/{request.target.model}"

    # Store in-memory for the running job
    _active_jobs[job_id] = {
        "status": "pending",
        "config": config,
        "scan_id": request.scan_id,
        "deployment_id": request.deployment_id,
        "target_id": request.target_id,
        "tenant_id": tenant.tenant_id,
        "attacker_model": attacker_label,
        "target_model": target_label,
    }

    # Also persist the pending state to Redis immediately
    await _save_job_to_redis(job_id, {
        "job_id": job_id,
        "status": "pending",
        "attacker_model": attacker_label,
        "target_model": target_label,
        "deployment_id": request.deployment_id,
        "target_id": getattr(request, 'target_id', None),
        "scan_id": request.scan_id,
        "strategies_run": 0,
        "successful_attacks": 0,
        "duration_seconds": 0.0,
        "message": "Queued",
    })

    # Run in background
    background_tasks.add_task(_execute_interrogation, job_id)

    return InterrogationStatusResponse(
        job_id=job_id,
        status="pending",
        attacker_model=attacker_label,
        target_model=target_label,
        message="Interrogation job queued. Poll GET /interrogation/jobs/{id} for results.",
    )


@router.get(
    "/jobs/{job_id}",
    response_model=InterrogationResponse,
    summary="Get interrogation job results",
    description="Returns full results including conversation transcripts and findings.",
)
async def get_interrogation_job(
    job_id: str,
    tenant: CurrentTenantDep,
) -> InterrogationResponse:
    """Get interrogation job status and results."""
    # Check in-memory first (active/running jobs)
    active = _active_jobs.get(job_id)
    if active and active.get("status") in ("pending", "running"):
        if active.get("tenant_id") and active["tenant_id"] != tenant.tenant_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found")
        return InterrogationResponse(
            job_id=job_id,
            status=active["status"],
            attacker_model=active["attacker_model"],
            target_model=active["target_model"],
            message=active.get("message", "Running..."),
        )

    # Load from Redis (running or completed jobs)
    stored = await _load_job_from_redis(job_id)
    if stored:
        if stored.get("tenant_id") and stored["tenant_id"] != tenant.tenant_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found")
        return InterrogationResponse(**stored)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Job {job_id} not found",
    )


@router.get(
    "/jobs",
    response_model=list[InterrogationStatusResponse],
    summary="List interrogation jobs",
)
async def list_jobs(tenant: CurrentTenantDep) -> list[InterrogationStatusResponse]:
    """List all interrogation jobs (active + historical from Redis)."""
    seen_ids: set[str] = set()
    results: list[InterrogationStatusResponse] = []

    # Active/running jobs from memory (filtered by tenant)
    for job_id, job in _active_jobs.items():
        if job.get("status") in ("pending", "running"):
            if job.get("tenant_id") and job["tenant_id"] != tenant.tenant_id:
                continue
            seen_ids.add(job_id)
            results.append(InterrogationStatusResponse(
                job_id=job_id,
                status=job["status"],
                attacker_model=job["attacker_model"],
                target_model=job["target_model"],
                message=job.get("message", ""),
            ))

    # All jobs from Redis (running or completed, filtered by tenant)
    redis_jobs = await _list_jobs_from_redis()
    for stored in redis_jobs:
        jid = stored.get("job_id", "")
        if jid and jid not in seen_ids:
            if stored.get("tenant_id") and stored["tenant_id"] != tenant.tenant_id:
                continue
            results.append(InterrogationStatusResponse(
                job_id=jid,
                status=stored.get("status", "unknown"),
                attacker_model=stored.get("attacker_model", ""),
                target_model=stored.get("target_model", ""),
                strategies_run=stored.get("strategies_run", 0),
                successful_attacks=stored.get("successful_attacks", 0),
                duration_seconds=stored.get("duration_seconds", 0.0),
                message=stored.get("message", ""),
            ))

    # Sort: running/pending first, then completed/failed
    _STATUS_ORDER = {"running": 0, "pending": 1, "completed": 2, "failed": 3}
    results.sort(key=lambda j: _STATUS_ORDER.get(j.status, 9))

    return results


# ---- Ollama management endpoints ----


class OllamaPullRequest(BaseModel):
    """Request to pull a model on an Ollama instance."""

    model: str = Field(..., description="Model name to pull (e.g. qwen3:8b)")
    instance: str = Field(
        default="source",
        description="Ollama instance: 'source' (attacker) or 'destination' (target)",
    )


class OllamaPullResponse(BaseModel):
    """Response from a model pull request."""

    success: bool
    message: str
    instance: str
    model: str


class OllamaInstanceStatus(BaseModel):
    """Health and model info for one Ollama instance."""

    role: str
    host: str
    healthy: bool
    models: list[dict[str, Any]] = Field(default_factory=list)


class OllamaStatusResponse(BaseModel):
    """Combined status of all Ollama instances."""

    instances: list[OllamaInstanceStatus]


@router.get(
    "/ollama/status",
    response_model=OllamaStatusResponse,
    summary="Ollama instances status",
    description="Returns health and model list for all configured Ollama instances.",
)
async def ollama_status(tenant: CurrentTenantDep) -> OllamaStatusResponse:
    """Check health and models on all Ollama instances."""
    from mass.api.services.ollama_manager import (
        check_health,
        get_ollama_hosts,
        list_models,
    )

    hosts = get_ollama_hosts()
    instances: list[OllamaInstanceStatus] = []

    for role, host in hosts.items():
        if not host:
            continue
        healthy = await check_health(host)
        models = await list_models(host) if healthy else []
        instances.append(OllamaInstanceStatus(
            role=role,
            host=host,
            healthy=healthy,
            models=models,
        ))

    return OllamaStatusResponse(instances=instances)


@router.post(
    "/ollama/pull",
    response_model=OllamaPullResponse,
    summary="Pull a model on an Ollama instance",
    description=(
        "Triggers a model pull on the specified Ollama instance. "
        "This is a blocking call and may take several minutes for large models."
    ),
)
async def ollama_pull(
    request: OllamaPullRequest,
    tenant: CurrentTenantDep,
) -> OllamaPullResponse:
    """Pull a model on an Ollama instance."""
    from mass.api.services.ollama_manager import get_ollama_hosts, pull_model

    hosts = get_ollama_hosts()
    host = hosts.get(request.instance)

    if not host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown Ollama instance: {request.instance}. Use 'source' or 'destination'.",
        )

    ok, message = await pull_model(host, request.model)

    return OllamaPullResponse(
        success=ok,
        message=message,
        instance=request.instance,
        model=request.model,
    )


# ---- Custom strategy directory ----

_STRATEGIES_DIR = Path(os.getenv("MASS_STRATEGIES_DIR", "/app/data/strategies"))


def _ensure_strategies_dir() -> Path:
    """Ensure the custom strategies directory exists."""
    _STRATEGIES_DIR.mkdir(parents=True, exist_ok=True)
    return _STRATEGIES_DIR


def _validate_filename(filename: str) -> str:
    """Validate and sanitize a strategy filename."""
    if not filename.endswith((".yaml", ".yml")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename must end in .yaml or .yml",
        )
    # Prevent path traversal
    safe = re.sub(r"[^\w\-.]", "_", filename)
    if safe != filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename contains invalid characters. Use alphanumeric, hyphens, underscores, and dots.",
        )
    if safe.startswith("_"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filenames starting with _ are reserved for templates.",
        )
    return safe


@router.get(
    "/strategies/custom",
    response_model=list[CustomStrategyFile],
    summary="List custom strategy files",
    description="Returns metadata for all custom YAML strategy files.",
)
async def list_custom_strategies(tenant: CurrentTenantDep) -> list[CustomStrategyFile]:
    """List all custom strategy YAML files with parsed metadata."""
    from mass.interrogator.agents.custom_loader import _parse_agent_file

    directory = _ensure_strategies_dir()
    results: list[CustomStrategyFile] = []

    for path in sorted(directory.glob("*.y*ml")):
        if path.name.startswith("_"):
            continue
        agent = _parse_agent_file(path)
        if agent:
            results.append(CustomStrategyFile(
                filename=path.name,
                name=agent.name,
                category=agent.category.value,
                description=agent.description,
                severity=agent.base_severity.value,
                strategy_count=len(agent.strategies),
                tags=agent.tags,
            ))
        else:
            # Include invalid files so users can see and fix them
            results.append(CustomStrategyFile(
                filename=path.name,
                name=path.stem,
                category="unknown",
                description="(invalid YAML — see logs)",
                severity="info",
                strategy_count=0,
                tags=["custom", "invalid"],
            ))

    return results


@router.post(
    "/strategies/custom",
    response_model=CustomStrategyFile,
    status_code=status.HTTP_201_CREATED,
    summary="Create a custom strategy",
    description="Upload a new YAML strategy file. Validates content before saving.",
)
async def create_custom_strategy(
    request: CustomStrategyCreate,
    tenant: CurrentTenantDep,
) -> CustomStrategyFile:
    """Create a new custom strategy YAML file."""
    from mass.interrogator.agents.custom_loader import (
        reload_custom_strategies,
        validate_yaml_content,
    )

    filename = _validate_filename(request.filename)
    directory = _ensure_strategies_dir()
    filepath = directory / filename

    if filepath.exists():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"File '{filename}' already exists. Use PUT to update.",
        )

    # Validate before writing
    agent, error = validate_yaml_content(request.content)
    if error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Validation failed: {error}",
        )

    filepath.write_text(request.content, encoding="utf-8")

    # Hot-reload custom agents
    reload_custom_strategies(directory)

    return CustomStrategyFile(
        filename=filename,
        name=agent.name,
        category=agent.category.value,
        description=agent.description,
        severity=agent.base_severity.value,
        strategy_count=len(agent.strategies),
        tags=agent.tags,
    )


@router.get(
    "/strategies/custom/{filename}",
    response_model=CustomStrategyContent,
    summary="Get custom strategy YAML content",
    description="Returns the raw YAML content of a custom strategy file for editing.",
)
async def get_custom_strategy(filename: str, tenant: CurrentTenantDep) -> CustomStrategyContent:
    """Get the raw YAML content of a custom strategy file."""
    directory = _ensure_strategies_dir()
    filepath = directory / filename

    if not filepath.exists() or not filepath.name.endswith((".yaml", ".yml")):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Strategy file '{filename}' not found.",
        )

    content = filepath.read_text(encoding="utf-8")
    return CustomStrategyContent(filename=filename, content=content)


@router.put(
    "/strategies/custom/{filename}",
    response_model=CustomStrategyFile,
    summary="Update a custom strategy",
    description="Update an existing YAML strategy file. Validates before saving.",
)
async def update_custom_strategy(
    filename: str,
    request: CustomStrategyCreate,
    tenant: CurrentTenantDep,
) -> CustomStrategyFile:
    """Update an existing custom strategy YAML file."""
    from mass.interrogator.agents.custom_loader import (
        reload_custom_strategies,
        validate_yaml_content,
    )

    directory = _ensure_strategies_dir()
    filepath = directory / filename

    if not filepath.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Strategy file '{filename}' not found.",
        )

    # Validate before writing
    agent, error = validate_yaml_content(request.content)
    if error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Validation failed: {error}",
        )

    filepath.write_text(request.content, encoding="utf-8")

    # Hot-reload custom agents
    reload_custom_strategies(directory)

    return CustomStrategyFile(
        filename=filename,
        name=agent.name,
        category=agent.category.value,
        description=agent.description,
        severity=agent.base_severity.value,
        strategy_count=len(agent.strategies),
        tags=agent.tags,
    )


@router.delete(
    "/strategies/custom/{filename}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a custom strategy",
    description="Remove a custom strategy YAML file and unregister its agents.",
)
async def delete_custom_strategy(filename: str, tenant: CurrentTenantDep) -> None:
    """Delete a custom strategy YAML file."""
    from mass.interrogator.agents.custom_loader import reload_custom_strategies

    directory = _ensure_strategies_dir()
    filepath = directory / filename

    if not filepath.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Strategy file '{filename}' not found.",
        )

    filepath.unlink()

    # Hot-reload to remove the deleted agent
    reload_custom_strategies(directory)


async def _execute_interrogation(job_id: str) -> None:
    """Execute interrogation in background."""
    job = _active_jobs.get(job_id)
    if not job:
        return

    job["status"] = "running"
    job["message"] = "Starting..."

    # Helper to update both in-memory, Redis, AND broadcast via WebSocket
    async def _update_status(message: str) -> None:
        job["message"] = message
        await _save_job_to_redis(job_id, {
            "job_id": job_id,
            "status": "running",
            "attacker_model": job["attacker_model"],
            "target_model": job["target_model"],
            "deployment_id": job.get("deployment_id"),
            "target_id": job.get("target_id"),
            "scan_id": job.get("scan_id"),
            "message": message,
        })
        try:
            from mass.dashboard.websocket import broadcast_interrogation_update
            await broadcast_interrogation_update(
                job_id=job_id,
                status="running",
                message=message,
                attacker_model=job["attacker_model"],
                target_model=job["target_model"],
            )
        except Exception:
            pass

    await _update_status("Starting...")

    try:
        from mass.interrogator.orchestrator import InterrogationOrchestrator
        from mass.api.services.ollama_manager import (
            ensure_model_ready,
            get_ollama_hosts,
        )

        config = job["config"]

        # ---- Ollama model readiness phase ----
        hosts = get_ollama_hosts()

        # Check attacker model if using Ollama
        if config.attacker_provider == "ollama":
            attacker_host = config.attacker_endpoint or hosts["source"]
            attacker_model = config.attacker_model
            await _update_status(f"Preparing attacker model: {attacker_model}...")
            ok, msg, resolved = await ensure_model_ready(attacker_host, attacker_model)
            if not ok:
                raise RuntimeError(f"Attacker model setup failed: {msg}")
            if resolved and resolved != attacker_model:
                logger.info("Attacker model resolved: %s → %s", attacker_model, resolved)
                config.attacker_model = resolved
            logger.info("Attacker model ready: %s on %s", config.attacker_model, attacker_host)

        # Check target model if using Ollama
        if config.target_provider == "ollama":
            target_host = config.target_endpoint or hosts["destination"]
            target_model = config.target_model
            await _update_status(f"Preparing target model: {target_model}...")
            ok, msg, resolved = await ensure_model_ready(target_host, target_model)
            if not ok:
                raise RuntimeError(f"Target model setup failed: {msg}")
            if resolved and resolved != target_model:
                logger.info("Target model resolved: %s → %s", target_model, resolved)
                config.target_model = resolved
            logger.info("Target model ready: %s on %s", config.target_model, target_host)

        await _update_status("Running interrogation...")

        # Create a turn callback that broadcasts each conversation turn
        # via WebSocket. The orchestrator runs in a thread pool (sync),
        # so we capture the event loop and schedule async broadcasts.
        _loop = asyncio.get_running_loop()

        def _turn_callback(**kwargs):
            from mass.dashboard.websocket import broadcast_interrogation_turn
            try:
                asyncio.run_coroutine_threadsafe(
                    broadcast_interrogation_turn(job_id=job_id, **kwargs),
                    _loop,
                )
            except Exception:
                pass

        orchestrator = InterrogationOrchestrator(config, turn_callback=_turn_callback)

        result = await _loop.run_in_executor(
            _interrogation_pool,
            orchestrator.execute,
        )

        job["status"] = "completed"

        # Build the full response and persist to Redis
        response_data = _build_response_dict(job_id, job, result)
        await _save_job_to_redis(job_id, response_data)

        # Clean up active job (it's now in Redis)
        _active_jobs.pop(job_id, None)

        # Store findings in database if linked to a scan
        if job.get("scan_id"):
            try:
                await _store_findings(
                    job["scan_id"],
                    job["tenant_id"],
                    result.findings,
                )
            except Exception as e:
                logger.error("Failed to store interrogation findings: %s", e)

        logger.info(
            "Interrogation %s completed: %d findings, %d conversations",
            job_id, len(result.findings), len(result.conversations),
        )

        # Broadcast via WebSocket
        try:
            from mass.dashboard.websocket import broadcast_interrogation_update
            await broadcast_interrogation_update(
                job_id=job_id,
                status="completed",
                message=f"Completed: {result.successful_attacks} attacks, "
                        f"{result.failed_attacks} defended in {result.duration_seconds:.1f}s",
                strategies_run=result.strategies_run,
                successful_attacks=result.successful_attacks,
                attacker_model=result.attacker_model,
                target_model=result.target_model,
                duration_seconds=result.duration_seconds,
            )
        except Exception:
            pass

    except Exception as e:
        logger.exception("Interrogation %s failed: %s", job_id, e)
        await _save_job_to_redis(job_id, {
            "job_id": job_id,
            "status": "failed",
            "attacker_model": job["attacker_model"],
            "target_model": job["target_model"],
            "deployment_id": job.get("deployment_id"),
            "target_id": job.get("target_id"),
            "scan_id": job.get("scan_id"),
            "message": f"Failed: {e}",
            "errors": [str(e)],
        })
        _active_jobs.pop(job_id, None)

        try:
            from mass.dashboard.websocket import broadcast_interrogation_update
            await broadcast_interrogation_update(
                job_id=job_id,
                status="failed",
                message=f"Failed: {e}",
                attacker_model=job["attacker_model"],
                target_model=job["target_model"],
            )
        except Exception:
            pass


def _build_response_dict(job_id: str, job: dict, result: Any) -> dict:
    """Build a JSON-serializable response dict for Redis storage."""
    findings = [
        {
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value,
            "category": f.category.value,
            "confidence": f.confidence,
            "agent_name": f.metadata.get("agent_name", ""),
            "strategy_name": f.metadata.get("strategy_name", ""),
            "total_turns": f.metadata.get("total_turns", 0),
        }
        for f in result.findings
    ]

    conversations = []
    for conv in result.conversations:
        turns = [
            {
                "turn_number": t.turn_number,
                "role": t.role.value,
                "content": t.content,
                "latency_ms": t.latency_ms,
                "model": t.model,
                "timestamp": t.timestamp.isoformat() if t.timestamp else None,
            }
            for t in conv.turns
        ]
        conversations.append({
            "conversation_id": conv.conversation_id,
            "category": conv.category,
            "strategy": conv.strategy,
            "success": conv.success,
            "confidence": conv.confidence,
            "analysis": conv.analysis,
            "total_turns": conv.total_turns,
            "duration_seconds": conv.duration_seconds,
            "attacker_model": conv.attacker_model,
            "target_model": conv.target_model,
            "turns": turns,
            "success_indicators": getattr(conv, 'success_indicators', []),
            "strategy_description": getattr(conv, 'strategy_description', ''),
        })

    return {
        "job_id": job_id,
        "status": "completed",
        "attacker_model": result.attacker_model,
        "target_model": result.target_model,
        "deployment_id": job.get("deployment_id"),
        "target_id": job.get("target_id"),
        "scan_id": job.get("scan_id"),
        "agents_run": result.agents_run,
        "strategies_run": result.strategies_run,
        "successful_attacks": result.successful_attacks,
        "failed_attacks": result.failed_attacks,
        "duration_seconds": result.duration_seconds,
        "findings": findings,
        "conversations": conversations,
        "errors": result.errors,
        "message": (
            f"Completed: {result.successful_attacks} successful attacks, "
            f"{result.failed_attacks} defended in {result.duration_seconds:.1f}s"
        ),
    }


async def _store_findings(
    scan_id: str,
    tenant_id: str,
    findings: list,
) -> None:
    """Store interrogation findings in the database."""
    from mass.storage.database import get_session
    from mass.storage.models.finding import Finding as DBFinding

    async with get_session() as session:
        for finding in findings:
            evidence_json = json.dumps([
                {
                    "type": e.type,
                    "content": e.content[:3000],
                    "metadata": e.metadata,
                }
                for e in finding.evidence
            ])

            db_finding = DBFinding(
                scan_id=scan_id,
                tenant_id=tenant_id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity.value,
                category=finding.category.value,
                component_type=finding.component_type.value,
                component_name=finding.component_name,
                confidence=finding.confidence,
                evidence=evidence_json,
                remediation=finding.remediation.summary if finding.remediation else None,
                cwe_ids=",".join(finding.cwe_ids),
                owasp_ids=",".join(finding.owasp_ids),
                tags=",".join(finding.tags),
                status="open",
                meta=json.dumps(finding.metadata),
            )
            session.add(db_finding)

        await session.commit()
