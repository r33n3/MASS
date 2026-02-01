"""Tests for health endpoints."""

from typing import TYPE_CHECKING

import pytest

from mass.api.main import create_app

if TYPE_CHECKING:
    from starlette.testclient import TestClient


@pytest.fixture
def app():
    """Create test app."""
    return create_app()


@pytest.fixture
def client(app):
    """Create test client."""
    try:
        from starlette.testclient import TestClient
        with TestClient(app) as c:
            yield c
    except TypeError:
        # Skip if httpx/starlette versions are incompatible
        pytest.skip("httpx/starlette version incompatibility")


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_check(self, client: "TestClient") -> None:
        """Test basic health check."""
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "uptime_seconds" in data

    def test_readiness_check(self, client: "TestClient") -> None:
        """Test readiness check."""
        response = client.get("/ready")
        assert response.status_code == 200

        data = response.json()
        assert "ready" in data
        assert "checks" in data
        assert isinstance(data["checks"], dict)

    def test_detailed_health_check(self, client: "TestClient") -> None:
        """Test detailed health check."""
        response = client.get("/health/detailed")
        assert response.status_code == 200

        data = response.json()
        assert "status" in data
        assert "version" in data
        assert "uptime_seconds" in data
        assert "components" in data
        assert isinstance(data["components"], list)

    def test_metrics_endpoint(self, client: "TestClient") -> None:
        """Test Prometheus metrics endpoint."""
        response = client.get("/metrics")
        assert response.status_code == 200

        # Check content type
        assert "text/plain" in response.headers["content-type"]

        # Check content contains expected metrics
        content = response.text
        assert "mass_uptime_seconds" in content
        assert "mass_requests_total" in content


class TestOpenAPISpec:
    """Tests for OpenAPI specification."""

    def test_openapi_json(self, client: "TestClient") -> None:
        """Test OpenAPI JSON endpoint."""
        response = client.get("/api/v1/openapi.json")
        assert response.status_code == 200

        data = response.json()
        assert "openapi" in data
        assert "info" in data
        assert data["info"]["title"] == "MASS API"
        assert "paths" in data

    def test_docs_endpoint(self, client: "TestClient") -> None:
        """Test Swagger UI docs endpoint."""
        response = client.get("/docs")
        assert response.status_code == 200

    def test_redoc_endpoint(self, client: "TestClient") -> None:
        """Test ReDoc endpoint."""
        response = client.get("/redoc")
        assert response.status_code == 200
