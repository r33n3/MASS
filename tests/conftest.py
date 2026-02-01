"""Pytest configuration and fixtures for MASS tests."""

import asyncio
from collections.abc import Generator
from typing import Any

import pytest


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_finding_data() -> dict[str, Any]:
    """Sample finding data for tests."""
    return {
        "title": "Test Finding",
        "description": "A test finding for unit tests",
        "severity": "high",
        "category": "prompt_injection",
        "component_type": "model",
        "component_name": "test-model",
    }


@pytest.fixture
def sample_evidence_data() -> dict[str, Any]:
    """Sample evidence data for tests."""
    return {
        "type": "response",
        "content": "Test evidence content",
        "source_file": "test.py",
        "source_line": 42,
    }


@pytest.fixture
def sample_scan_config() -> dict[str, Any]:
    """Sample scan configuration for tests."""
    return {
        "profile": "standard",
        "timeout": 300,
        "max_prompts": 100,
    }
