"""Event system for MASS.

Provides an async event bus for decoupled communication between
components, supporting audit logging and plugin notifications.
"""

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine
from uuid import uuid4


class EventType(str, Enum):
    """Event types for the MASS event system."""

    # Scan events
    SCAN_CREATED = "scan.created"
    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_CANCELLED = "scan.cancelled"

    # Finding events
    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    FINDING_SUPPRESSED = "finding.suppressed"

    # Analysis events
    ANALYSIS_STARTED = "analysis.started"
    ANALYSIS_COMPLETED = "analysis.completed"
    ANALYSIS_FAILED = "analysis.failed"

    # Probe events
    PROBE_STARTED = "probe.started"
    PROBE_COMPLETED = "probe.completed"
    PROBE_FAILED = "probe.failed"

    # Detection events
    DETECTION_TRIGGERED = "detection.triggered"

    # Sandbox events
    SANDBOX_STARTED = "sandbox.started"
    SANDBOX_COMPLETED = "sandbox.completed"
    SANDBOX_FAILED = "sandbox.failed"

    # Report events
    REPORT_GENERATED = "report.generated"
    REPORT_EXPORTED = "report.exported"

    # System events
    WORKER_STARTED = "worker.started"
    WORKER_STOPPED = "worker.stopped"
    WORKER_ERROR = "worker.error"

    # Webhook events
    WEBHOOK_DISPATCHED = "webhook.dispatched"
    WEBHOOK_FAILED = "webhook.failed"

    # CI/CD events
    CICD_WEBHOOK_RECEIVED = "cicd.webhook_received"
    CICD_SCAN_TRIGGERED = "cicd.scan_triggered"
    CICD_GATE_EVALUATED = "cicd.gate_evaluated"

    # Issue generation events
    ISSUE_EXPORTED = "issue.exported"
    ISSUE_EXPORT_FAILED = "issue.export_failed"

    # Threat intelligence events
    THREAT_ITEM_CREATED = "threat.item_created"
    THREAT_ANALYZED = "threat.analyzed"
    THREAT_PAYLOADS_GENERATED = "threat.payloads_generated"

    # Supply chain verification events
    SUPPLY_CHAIN_VERIFIED = "supply_chain.verified"
    SUPPLY_CHAIN_SCAN_COMPLETED = "supply_chain.scan_completed"
    SUPPLY_CHAIN_VULNERABILITY = "supply_chain.vulnerability_found"

    # Privacy risk analysis events
    PRIVACY_ASSESSMENT_COMPLETED = "privacy.assessment_completed"
    PRIVACY_PII_DETECTED = "privacy.pii_detected"
    PRIVACY_COMPLIANCE_CHECK = "privacy.compliance_check"

    # Guardrail events
    GUARDRAIL_GENERATED = "guardrail.generated"

    # Explainability events
    EXPLANATION_GENERATED = "explain.generated"
    REMEDIATION_PLAN_GENERATED = "explain.remediation_plan"

    # Cross-model events
    CROSS_MODEL_COMPLETED = "cross_model.completed"

    # Cloud-native events
    CLOUD_DISCOVERY_COMPLETED = "cloud.discovery_completed"
    CLOUD_ASSESSMENT_COMPLETED = "cloud.assessment_completed"

    # Audit events
    API_REQUEST = "api.request"
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"


@dataclass
class Event:
    """An event in the MASS event system.

    Attributes:
        type: The event type.
        data: Event payload data.
        id: Unique event identifier.
        timestamp: When the event occurred.
        tenant_id: Tenant context (for multi-tenancy).
        user_id: User who triggered the event.
        correlation_id: ID to correlate related events.
    """

    type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    tenant_id: str | None = None
    user_id: str | None = None
    correlation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary.

        Returns:
            Dictionary representation of the event.
        """
        return {
            "id": self.id,
            "type": self.type.value,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "correlation_id": self.correlation_id,
        }


# Type alias for event handlers
EventHandler = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus:
    """Async event bus for publishing and subscribing to events.

    Supports multiple subscribers per event type and wildcard subscriptions.

    Example:
        ```python
        bus = EventBus()

        async def on_scan_completed(event: Event):
            print(f"Scan {event.data['scan_id']} completed")

        bus.subscribe(EventType.SCAN_COMPLETED, on_scan_completed)

        await bus.publish(Event(
            type=EventType.SCAN_COMPLETED,
            data={"scan_id": "123", "findings_count": 5}
        ))
        ```
    """

    def __init__(self) -> None:
        """Initialize EventBus."""
        self._handlers: dict[EventType | str, list[EventHandler]] = defaultdict(list)
        self._lock = asyncio.Lock()

    def subscribe(
        self,
        event_type: EventType | str,
        handler: EventHandler,
    ) -> None:
        """Subscribe to an event type.

        Args:
            event_type: Event type to subscribe to. Use "*" for all events.
            handler: Async function to call when event occurs.
        """
        self._handlers[event_type].append(handler)

    def unsubscribe(
        self,
        event_type: EventType | str,
        handler: EventHandler,
    ) -> None:
        """Unsubscribe from an event type.

        Args:
            event_type: Event type to unsubscribe from.
            handler: Handler to remove.
        """
        if handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)

    async def publish(self, event: Event) -> None:
        """Publish an event to all subscribers.

        Args:
            event: Event to publish.
        """
        handlers: list[EventHandler] = []

        # Get specific handlers
        handlers.extend(self._handlers[event.type])

        # Get wildcard handlers
        handlers.extend(self._handlers["*"])

        # Execute all handlers concurrently
        if handlers:
            await asyncio.gather(
                *[self._safe_call(handler, event) for handler in handlers],
                return_exceptions=True,
            )

    async def _safe_call(self, handler: EventHandler, event: Event) -> None:
        """Safely call an event handler.

        Args:
            handler: Handler to call.
            event: Event to pass to handler.
        """
        try:
            await handler(event)
        except Exception as e:
            # Log error but don't propagate to avoid breaking other handlers
            # In production, this would use proper logging
            print(f"Event handler error: {e}")

    def clear(self) -> None:
        """Remove all subscriptions."""
        self._handlers.clear()


# Global event bus instance
_event_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Get the global event bus instance.

    Returns:
        The global EventBus instance.
    """
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


async def publish_event(event: Event) -> None:
    """Convenience function to publish an event.

    Args:
        event: Event to publish.
    """
    await get_event_bus().publish(event)


def subscribe_event(event_type: EventType | str, handler: EventHandler) -> None:
    """Convenience function to subscribe to events.

    Args:
        event_type: Event type to subscribe to.
        handler: Handler function.
    """
    get_event_bus().subscribe(event_type, handler)
