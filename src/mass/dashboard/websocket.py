"""WebSocket support for real-time updates.

Provides WebSocket connections for streaming scan progress
and results to connected clients.
"""

import asyncio
import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect


router = APIRouter(tags=["websocket"])


class ConnectionManager:
    """Manages WebSocket connections."""

    def __init__(self) -> None:
        """Initialize the connection manager."""
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new connection."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast a message to all connections."""
        for connection in self.active_connections[:]:  # Copy list to avoid mutation
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

    async def send_to(self, websocket: WebSocket, message: dict[str, Any]) -> None:
        """Send a message to a specific connection."""
        try:
            await websocket.send_json(message)
        except Exception:
            self.disconnect(websocket)


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
        # Subscribe to specific scan updates
        scan_id = message.get("scan_id")
        if scan_id:
            await manager.send_to(websocket, {
                "type": "subscribed",
                "scan_id": scan_id,
            })

    elif msg_type == "unsubscribe":
        scan_id = message.get("scan_id")
        if scan_id:
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
) -> None:
    """Broadcast a scan update to all connected clients.

    Args:
        scan_id: ID of the scan.
        status: Current scan status.
        progress: Progress percentage (0-100).
        findings_count: Number of findings so far.
        message: Status message.
    """
    await manager.broadcast({
        "type": "scan_update",
        "scan_id": scan_id,
        "status": status,
        "progress": progress,
        "findings_count": findings_count,
        "message": message,
        "timestamp": datetime.utcnow().isoformat(),
    })


async def broadcast_finding(
    scan_id: str,
    finding: dict[str, Any],
) -> None:
    """Broadcast a new finding to all connected clients.

    Args:
        scan_id: ID of the scan.
        finding: Finding data.
    """
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
    """Broadcast scan completion to all connected clients.

    Args:
        scan_id: ID of the scan.
        status: Final status (completed, failed, cancelled).
        duration_seconds: Total scan duration.
        findings_count: Total findings.
    """
    await manager.broadcast({
        "type": "scan_complete",
        "scan_id": scan_id,
        "status": status,
        "duration_seconds": duration_seconds,
        "findings_count": findings_count,
        "timestamp": datetime.utcnow().isoformat(),
    })
