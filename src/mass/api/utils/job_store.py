"""Redis-backed job state storage.

Replaces in-memory _jobs dicts with Redis for persistence across
restarts and sharing across replicas. Per ARCHITECTURE.md Rule 1.

Usage:
    store = JobStore("interrogation")
    await store.save(job_id, {"status": "pending", ...})
    job = await store.load(job_id)
    jobs = await store.list_jobs(tenant_id="default")
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mass.storage.cache import get_redis

logger = logging.getLogger(__name__)

# Default TTL: 7 days
DEFAULT_TTL = 7 * 24 * 3600


class JobStore:
    """Redis-backed job store for a specific module.

    Keys follow the pattern: mass:{module}:jobs:{job_id}
    """

    def __init__(self, module: str, ttl: int = DEFAULT_TTL) -> None:
        self.module = module
        self.ttl = ttl
        self._prefix = f"mass:{module}:jobs"

    def _key(self, job_id: str) -> str:
        return f"{self._prefix}:{job_id}"

    async def save(self, job_id: str, data: dict[str, Any]) -> None:
        """Save job state to Redis."""
        try:
            redis = await get_redis()
            # Filter out non-serializable keys (prefixed with _)
            clean = {k: v for k, v in data.items() if not k.startswith("_")}
            await redis.setex(self._key(job_id), self.ttl, json.dumps(clean, default=str))
        except Exception as e:
            logger.warning("Failed to save %s job %s to Redis: %s", self.module, job_id, e)

    async def load(self, job_id: str) -> dict[str, Any] | None:
        """Load job state from Redis."""
        try:
            redis = await get_redis()
            raw = await redis.get(self._key(job_id))
            if raw:
                return json.loads(raw)
        except Exception as e:
            logger.warning("Failed to load %s job %s from Redis: %s", self.module, job_id, e)
        return None

    async def list_jobs(
        self,
        tenant_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List all jobs, optionally filtered by tenant."""
        try:
            redis = await get_redis()
            keys: list[str] = []
            async for key in redis.scan_iter(f"{self._prefix}:*"):
                keys.append(key)

            jobs: list[dict[str, Any]] = []
            for key in keys:
                raw = await redis.get(key)
                if raw:
                    data = json.loads(raw)
                    if tenant_id and data.get("tenant_id") != tenant_id:
                        continue
                    jobs.append(data)

            jobs.sort(key=lambda j: j.get("created_at", ""), reverse=True)
            return jobs[:limit]
        except Exception as e:
            logger.warning("Failed to list %s jobs from Redis: %s", self.module, e)
            return []

    async def delete(self, job_id: str) -> bool:
        """Delete a job from Redis."""
        try:
            redis = await get_redis()
            result = await redis.delete(self._key(job_id))
            return result > 0
        except Exception as e:
            logger.warning("Failed to delete %s job %s from Redis: %s", self.module, job_id, e)
            return False
