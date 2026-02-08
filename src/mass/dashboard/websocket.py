"""WebSocket support for real-time updates.

Provides WebSocket connections for streaming scan progress
and results to connected clients.

Supports:
- Redis pub/sub for cross-process broadcasting (multi-worker)
- Scan-ID subscription filtering (only send relevant updates)
- Graceful fallback to in-memory when Redis is unavailable
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])

# Redis channel for cross-process WebSocket broadcasting
_REDIS_CHANNEL = "mass:ws:broadcast"


class ConnectionManager:
    """Manages WebSocket connections with subscription filtering.

    Each connection can subscribe to specific scan_ids. Broadcast
    messages that carry a scan_id are only delivered to subscribers
    (or to connections with no subscriptions — they get everything).
    """

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []
        # scan_id subscriptions per connection
        self._subscriptions: dict[WebSocket, set[str]] = {}
        # Redis pub/sub listener task
        self._redis_listener_task: asyncio.Task | None = None
        self._redis = None

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        self._subscriptions[websocket] = set()

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        self._subscriptions.pop(websocket, None)

    def subscribe(self, websocket: WebSocket, scan_id: str) -> None:
        """Subscribe a connection to a specific scan_id."""
        if websocket in self._subscriptions:
            self._subscriptions[websocket].add(scan_id)

    def unsubscribe(self, websocket: WebSocket, scan_id: str) -> None:
        """Unsubscribe a connection from a specific scan_id."""
        if websocket in self._subscriptions:
            self._subscriptions[websocket].discard(scan_id)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast a message, publishing to Redis if available."""
        # Try Redis pub/sub first for cross-process delivery
        if await self._publish_redis(message):
            return  # Redis listener will handle local delivery too
        # Fallback: deliver locally only
        await self._deliver_local(message)

    async def _deliver_local(self, message: dict[str, Any]) -> None:
        """Deliver a message to locally connected WebSocket clients."""
        msg_scan_id = message.get("scan_id")

        for connection in self.active_connections[:]:
            try:
                subs = self._subscriptions.get(connection, set())
                # Send if: client has no subscriptions (gets everything),
                # OR the message has no scan_id (global),
                # OR the scan_id is in the client's subscription set
                if not subs or not msg_scan_id or msg_scan_id in subs:
                    await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

    async def send_to(self, websocket: WebSocket, message: dict[str, Any]) -> None:
        """Send a message to a specific connection."""
        try:
            await websocket.send_json(message)
        except Exception:
            self.disconnect(websocket)

    # ── Redis pub/sub ──

    async def _get_redis(self):
        """Get or create a Redis connection for publishing."""
        if self._redis is not None:
            return self._redis
        try:
            from mass.core.config import get_settings
            import redis.asyncio as aioredis

            settings = get_settings()
            self._redis = aioredis.from_url(
                settings.redis.url,
                decode_responses=True,
                socket_timeout=settings.redis.socket_timeout,
            )
            await self._redis.ping()
            return self._redis
        except Exception:
            self._redis = None
            return None

    async def _publish_redis(self, message: dict[str, Any]) -> bool:
        """Publish a message to Redis. Returns True on success."""
        try:
            r = await self._get_redis()
            if r is None:
                return False
            await r.publish(_REDIS_CHANNEL, json.dumps(message, default=str))
            return True
        except Exception:
            logger.debug("Redis publish failed, using local delivery", exc_info=True)
            self._redis = None
            return False

    async def start_redis_listener(self) -> None:
        """Start the background Redis subscription listener.

        Call once at app startup. Messages published by any process
        (including this one) are delivered to local WebSocket clients.
        """
        if self._redis_listener_task is not None:
            return
        self._redis_listener_task = asyncio.create_task(self._redis_listen_loop())

    async def _redis_listen_loop(self) -> None:
        """Long-running loop: subscribe to Redis channel, deliver locally."""
        while True:
            try:
                r = await self._get_redis()
                if r is None:
                    await asyncio.sleep(5)
                    continue

                pubsub = r.pubsub()
                await pubsub.subscribe(_REDIS_CHANNEL)
                logger.info("WebSocket Redis listener subscribed to %s", _REDIS_CHANNEL)

                async for raw_message in pubsub.listen():
                    if raw_message["type"] != "message":
                        continue
                    try:
                        message = json.loads(raw_message["data"])
                        await self._deliver_local(message)
                    except Exception:
                        logger.debug("Failed to process Redis WS message", exc_info=True)

            except asyncio.CancelledError:
                logger.info("Redis listener cancelled")
                return
            except Exception:
                logger.warning("Redis listener error, reconnecting in 5s", exc_info=True)
                self._redis = None
                await asyncio.sleep(5)

    async def shutdown(self) -> None:
        """Clean up Redis connections on app shutdown."""
        if self._redis_listener_task:
            self._redis_listener_task.cancel()
            try:
                await self._redis_listener_task
            except asyncio.CancelledError:
                pass
        if self._redis:
            try:
                await self._redis.aclose()
            except Exception:
                pass


# Global connection manager
manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)

    try:
        # Send initial connection confirmation
        await manager.send_to(websocket, {
            "type": "connected",
            "timestamp": datetime.utcnow().isoformat(),
        })

        # Keep connection alive and handle incoming messages
        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0  # Heartbeat timeout
                )

                # Handle incoming messages
                try:
                    message = json.loads(data)
                    await _handle_message(websocket, message)
                except json.JSONDecodeError:
                    await manager.send_to(websocket, {
                        "type": "error",
                        "message": "Invalid JSON",
                    })

            except asyncio.TimeoutError:
                # Send heartbeat
                await manager.send_to(websocket, {
                    "type": "heartbeat",
                    "timestamp": datetime.utcnow().isoformat(),
                })

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


async def _handle_message(websocket: WebSocket, message: dict[str, Any]) -> None:
    """Handle an incoming WebSocket message."""
    msg_type = message.get("type")

    if msg_type == "ping":
        await manager.send_to(websocket, {
            "type": "pong",
            "timestamp": datetime.utcnow().isoformat(),
        })

    elif msg_type == "subscribe":
        scan_id = message.get("scan_id")
        if scan_id:
            manager.subscribe(websocket, scan_id)
            await manager.send_to(websocket, {
                "type": "subscribed",
                "scan_id": scan_id,
            })

    elif msg_type == "unsubscribe":
        scan_id = message.get("scan_id")
        if scan_id:
            manager.unsubscribe(websocket, scan_id)
            await manager.send_to(websocket, {
                "type": "unsubscribed",
                "scan_id": scan_id,
            })


async def broadcast_scan_update(
    scan_id: str,
    status: str,
    progress: float = 0.0,
    findings_count: int = 0,
    message: str = "",
    current_phase: str = "",
    jobs_completed: int = 0,
    jobs_total: int = 0,
) -> None:
    """Broadcast a scan update to all connected clients."""
    await manager.broadcast({
        "type": "scan_update",
        "scan_id": scan_id,
        "status": status,
        "progress": progress,
        "findings_count": findings_count,
        "message": message,
        "current_phase": current_phase,
        "jobs_completed": jobs_completed,
        "jobs_total": jobs_total,
        "timestamp": datetime.utcnow().isoformat(),
    })


async def broadcast_finding(
    scan_id: str,
    finding: dict[str, Any],
) -> None:
    """Broadcast a new finding to all connected clients."""
    await manager.broadcast({
        "type": "new_finding",
        "scan_id": scan_id,
        "finding": finding,
        "timestamp": datetime.utcnow().isoformat(),
    })


async def broadcast_scan_complete(
    scan_id: str,
    status: str,
    duration_seconds: float,
    findings_count: int,
) -> None:
    """Broadcast scan completion to all connected clients."""
    await manager.broadcast({
        "type": "scan_complete",
        "scan_id": scan_id,
        "status": status,
        "duration_seconds": duration_seconds,
        "findings_count": findings_count,
        "timestamp": datetime.utcnow().isoformat(),
    })


async def broadcast_verdict_ready(
    scan_id: str,
    risk_level: str,
    overall_assessment: str,
) -> None:
    """Broadcast that a verdict is ready for a scan."""
    await manager.broadcast({
        "type": "verdict_ready",
        "scan_id": scan_id,
        "risk_level": risk_level,
        "overall_assessment": overall_assessment,
        "timestamp": datetime.utcnow().isoformat(),
    })


async def broadcast_threat_model_ready(
    scan_id: str,
    overall_risk_level: str,
    total_threats: int,
    data_classification: str,
) -> None:
    """Broadcast that a threat model is ready for a scan."""
    await manager.broadcast({
        "type": "threat_model_ready",
        "scan_id": scan_id,
        "overall_risk_level": overall_risk_level,
        "total_threats": total_threats,
        "data_classification": data_classification,
        "timestamp": datetime.utcnow().isoformat(),
    })


async def broadcast_interrogation_update(
    job_id: str,
    status: str,
    message: str = "",
    strategies_run: int = 0,
    successful_attacks: int = 0,
    attacker_model: str = "",
    target_model: str = "",
    duration_seconds: float = 0.0,
) -> None:
    """Broadcast an interrogation job update to all connected clients."""
    await manager.broadcast({
        "type": "interrogation_update",
        "job_id": job_id,
        "status": status,
        "message": message,
        "strategies_run": strategies_run,
        "successful_attacks": successful_attacks,
        "attacker_model": attacker_model,
        "target_model": target_model,
        "duration_seconds": duration_seconds,
        "timestamp": datetime.utcnow().isoformat(),
    })
