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

    # ------------------------------------------------------------------
    # Dead-letter queue helpers
    # ------------------------------------------------------------------

    async def move_to_dlq(self, job_id: str, error: str = "") -> bool:
        """Move a failed job to the dead-letter queue.

        Copies the job data to ``mass:dlq:{module}:{job_id}`` with
        failure metadata, then removes the original key.
        """
        try:
            redis = await get_redis()
            raw = await redis.get(self._key(job_id))
            if not raw:
                return False

            data = json.loads(raw)
            data["dlq_reason"] = error
            data["dlq_module"] = self.module
            import datetime
            data["dlq_timestamp"] = datetime.datetime.utcnow().isoformat()

            dlq_key = f"mass:dlq:{self.module}:{job_id}"
            # DLQ entries live for 30 days for review
            await redis.setex(dlq_key, 30 * 24 * 3600, json.dumps(data, default=str))
            await redis.delete(self._key(job_id))
            logger.info("Moved %s job %s to DLQ: %s", self.module, job_id, error[:100])
            return True
        except Exception as e:
            logger.warning("Failed to move %s job %s to DLQ: %s", self.module, job_id, e)
            return False

    async def list_dlq(self, limit: int = 50) -> list[dict[str, Any]]:
        """List dead-letter queue entries for this module."""
        try:
            redis = await get_redis()
            prefix = f"mass:dlq:{self.module}:*"
            keys: list[str] = []
            async for key in redis.scan_iter(prefix):
                keys.append(key)

            items: list[dict[str, Any]] = []
            for key in keys:
                raw = await redis.get(key)
                if raw:
                    items.append(json.loads(raw))

            items.sort(key=lambda j: j.get("dlq_timestamp", ""), reverse=True)
            return items[:limit]
        except Exception as e:
            logger.warning("Failed to list DLQ for %s: %s", self.module, e)
            return []

    async def retry_from_dlq(self, job_id: str) -> dict[str, Any] | None:
        """Move a job from DLQ back to active state for retry."""
        try:
            redis = await get_redis()
            dlq_key = f"mass:dlq:{self.module}:{job_id}"
            raw = await redis.get(dlq_key)
            if not raw:
                return None

            data = json.loads(raw)
            # Remove DLQ metadata
            data.pop("dlq_reason", None)
            data.pop("dlq_module", None)
            data.pop("dlq_timestamp", None)
            data["status"] = "pending"

            await self.save(job_id, data)
            await redis.delete(dlq_key)
            logger.info("Retried %s job %s from DLQ", self.module, job_id)
            return data
        except Exception as e:
            logger.warning("Failed to retry %s job %s from DLQ: %s", self.module, job_id, e)
            return None
