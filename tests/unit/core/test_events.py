"""Tests for mass.core.events module."""

import asyncio
from datetime import datetime

import pytest

from mass.core.events import (
    Event,
    EventBus,
    EventType,
    get_event_bus,
    publish_event,
    subscribe_event,
)


class TestEventType:
    """Tests for EventType enum."""

    def test_scan_events_exist(self) -> None:
        """Test that scan events are defined."""
        assert EventType.SCAN_CREATED.value == "scan.created"
        assert EventType.SCAN_STARTED.value == "scan.started"
        assert EventType.SCAN_COMPLETED.value == "scan.completed"
        assert EventType.SCAN_FAILED.value == "scan.failed"

    def test_finding_events_exist(self) -> None:
        """Test that finding events are defined."""
        assert EventType.FINDING_CREATED.value == "finding.created"
        assert EventType.FINDING_UPDATED.value == "finding.updated"


class TestEvent:
    """Tests for Event dataclass."""

    def test_basic_event(self) -> None:
        """Test basic event creation."""
        event = Event(type=EventType.SCAN_CREATED)
        assert event.type == EventType.SCAN_CREATED
        assert event.data == {}
        assert event.id is not None
        assert isinstance(event.timestamp, datetime)

    def test_event_with_data(self) -> None:
        """Test event with data payload."""
        event = Event(
            type=EventType.SCAN_COMPLETED,
            data={"scan_id": "123", "findings_count": 5},
        )
        assert event.data["scan_id"] == "123"
        assert event.data["findings_count"] == 5

    def test_event_with_context(self) -> None:
        """Test event with tenant and user context."""
        event = Event(
            type=EventType.API_REQUEST,
            tenant_id="tenant_123",
            user_id="user_456",
            correlation_id="corr_789",
        )
        assert event.tenant_id == "tenant_123"
        assert event.user_id == "user_456"
        assert event.correlation_id == "corr_789"

    def test_to_dict(self) -> None:
        """Test event dictionary conversion."""
        event = Event(
            type=EventType.FINDING_CREATED,
            data={"finding_id": "f123"},
        )
        result = event.to_dict()
        assert result["type"] == "finding.created"
        assert result["data"]["finding_id"] == "f123"
        assert "id" in result
        assert "timestamp" in result


class TestEventBus:
    """Tests for EventBus."""

    @pytest.fixture
    def event_bus(self) -> EventBus:
        """Create a fresh event bus for each test."""
        return EventBus()

    @pytest.mark.asyncio
    async def test_subscribe_and_publish(self, event_bus: EventBus) -> None:
        """Test basic subscribe and publish."""
        received_events: list[Event] = []

        async def handler(event: Event) -> None:
            received_events.append(event)

        event_bus.subscribe(EventType.SCAN_CREATED, handler)
        event = Event(type=EventType.SCAN_CREATED, data={"test": True})
        await event_bus.publish(event)

        assert len(received_events) == 1
        assert received_events[0].data["test"] is True

    @pytest.mark.asyncio
    async def test_multiple_handlers(self, event_bus: EventBus) -> None:
        """Test multiple handlers for same event."""
        counter = {"count": 0}

        async def handler1(event: Event) -> None:
            counter["count"] += 1

        async def handler2(event: Event) -> None:
            counter["count"] += 10

        event_bus.subscribe(EventType.SCAN_STARTED, handler1)
        event_bus.subscribe(EventType.SCAN_STARTED, handler2)
        await event_bus.publish(Event(type=EventType.SCAN_STARTED))

        assert counter["count"] == 11

    @pytest.mark.asyncio
    async def test_wildcard_subscription(self, event_bus: EventBus) -> None:
        """Test wildcard handler receives all events."""
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        event_bus.subscribe("*", handler)
        await event_bus.publish(Event(type=EventType.SCAN_CREATED))
        await event_bus.publish(Event(type=EventType.FINDING_CREATED))

        assert len(received) == 2

    @pytest.mark.asyncio
    async def test_unsubscribe(self, event_bus: EventBus) -> None:
        """Test unsubscribing from events."""
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        event_bus.subscribe(EventType.SCAN_COMPLETED, handler)
        event_bus.unsubscribe(EventType.SCAN_COMPLETED, handler)
        await event_bus.publish(Event(type=EventType.SCAN_COMPLETED))

        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_handler_error_doesnt_break_others(
        self, event_bus: EventBus
    ) -> None:
        """Test that handler errors don't affect other handlers."""
        received: list[Event] = []

        async def bad_handler(event: Event) -> None:
            raise ValueError("Handler error")

        async def good_handler(event: Event) -> None:
            received.append(event)

        event_bus.subscribe(EventType.SCAN_FAILED, bad_handler)
        event_bus.subscribe(EventType.SCAN_FAILED, good_handler)
        await event_bus.publish(Event(type=EventType.SCAN_FAILED))

        # Good handler should still receive event
        assert len(received) == 1

    def test_clear(self, event_bus: EventBus) -> None:
        """Test clearing all subscriptions."""

        async def handler(event: Event) -> None:
            pass

        event_bus.subscribe(EventType.SCAN_CREATED, handler)
        event_bus.subscribe(EventType.SCAN_COMPLETED, handler)
        event_bus.clear()

        assert len(event_bus._handlers) == 0


class TestGlobalEventBus:
    """Tests for global event bus functions."""

    def test_get_event_bus_returns_same_instance(self) -> None:
        """Test that get_event_bus returns singleton."""
        bus1 = get_event_bus()
        bus2 = get_event_bus()
        assert bus1 is bus2

    @pytest.mark.asyncio
    async def test_publish_event_convenience(self) -> None:
        """Test publish_event convenience function."""
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        bus = get_event_bus()
        bus.subscribe(EventType.WORKER_STARTED, handler)

        await publish_event(Event(type=EventType.WORKER_STARTED))
        assert len(received) >= 1

    def test_subscribe_event_convenience(self) -> None:
        """Test subscribe_event convenience function."""
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        subscribe_event(EventType.WORKER_STOPPED, handler)
        # Handler should be registered
        bus = get_event_bus()
        assert handler in bus._handlers[EventType.WORKER_STOPPED]
