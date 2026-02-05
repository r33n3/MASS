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
from typing import Any
from uuid import uuid4

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException, status

from mass.api.dependencies import CurrentTenantDep, DBSession
from mass.api.schemas.interrogation import (
    AvailableAgent,
    ConversationResponse,
    ConversationTurnResponse,
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
    )

    attacker_label = f"{request.attacker.provider}/{request.attacker.model}"
    target_label = f"{request.target.provider}/{request.target.model}"

    # Store in-memory for the running job
    _active_jobs[job_id] = {
        "status": "pending",
        "config": config,
        "scan_id": request.scan_id,
        "deployment_id": request.deployment_id,
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
        return InterrogationResponse(
            job_id=job_id,
            status=active["status"],
            attacker_model=active["attacker_model"],
            target_model=active["target_model"],
            message="Job is still running..." if active["status"] == "running" else "Queued",
        )

    # Load from Redis (completed/historical jobs)
    stored = await _load_job_from_redis(job_id)
    if stored:
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

    # Active/running jobs from memory
    for job_id, job in _active_jobs.items():
        if job.get("status") in ("pending", "running"):
            seen_ids.add(job_id)
            results.append(InterrogationStatusResponse(
                job_id=job_id,
                status=job["status"],
                attacker_model=job["attacker_model"],
                target_model=job["target_model"],
            ))

    # Completed jobs from Redis
    redis_jobs = await _list_jobs_from_redis()
    for stored in redis_jobs:
        jid = stored.get("job_id", "")
        if jid and jid not in seen_ids:
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

    return results


async def _execute_interrogation(job_id: str) -> None:
    """Execute interrogation in background."""
    job = _active_jobs.get(job_id)
    if not job:
        return

    job["status"] = "running"

    # Update Redis with running status
    await _save_job_to_redis(job_id, {
        "job_id": job_id,
        "status": "running",
        "attacker_model": job["attacker_model"],
        "target_model": job["target_model"],
        "message": "Running...",
    })

    try:
        from mass.interrogator.orchestrator import InterrogationOrchestrator

        config = job["config"]
        orchestrator = InterrogationOrchestrator(config)

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
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
            from mass.dashboard.websocket import broadcast_scan_complete
            await broadcast_scan_complete(
                scan_id=job_id,
                status="completed",
                duration_seconds=int(result.duration_seconds),
                findings_count=len(result.findings),
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
            "message": f"Failed: {e}",
            "errors": [str(e)],
        })
        _active_jobs.pop(job_id, None)


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
        })

    return {
        "job_id": job_id,
        "status": "completed",
        "attacker_model": result.attacker_model,
        "target_model": result.target_model,
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
