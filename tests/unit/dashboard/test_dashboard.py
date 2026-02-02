"""Tests for MASS Dashboard."""

import pytest
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.testclient import TestClient

from mass.dashboard.app import create_app, DashboardConfig
from mass.dashboard.api import (
    ScanRequest,
    ScanResponse,
    FindingResponse,
    ScanResultResponse,
    StatsResponse,
)


@pytest.fixture
def app():
    """Create test app."""
    config = DashboardConfig(
        enable_api=True,
        enable_ui=True,
        enable_websocket=False,  # Disable for simpler testing
    )
    return create_app(config)


@pytest.fixture
def client(app):
    """Create test client."""
    try:
        from starlette.testclient import TestClient
        with TestClient(app) as c:
            yield c
    except TypeError:
        pytest.skip("httpx/starlette version incompatibility")


class TestDashboardConfig:
    """Tests for DashboardConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = DashboardConfig()
        assert config.host == "127.0.0.1"
        assert config.port == 8080
        assert config.debug is False

    def test_custom_config(self):
        """Test custom configuration."""
        config = DashboardConfig(
            host="0.0.0.0",
            port=3000,
            debug=True,
        )
        assert config.host == "0.0.0.0"
        assert config.port == 3000
        assert config.debug is True

    def test_to_dict(self):
        """Test serialization."""
        config = DashboardConfig(port=9000)
        data = config.to_dict()
        assert data["port"] == 9000
        assert "host" in data


class TestAppCreation:
    """Tests for app creation."""

    def test_create_default_app(self):
        """Test creating default app."""
        app = create_app()
        assert app.title == "MASS Dashboard"

    def test_create_app_with_config(self):
        """Test creating app with custom config."""
        config = DashboardConfig(enable_api=True)
        app = create_app(config)
        assert app.state.config == config

    def test_create_app_without_api(self):
        """Test creating app without API."""
        config = DashboardConfig(enable_api=False)
        app = create_app(config)
        assert app.docs_url is None


class TestHealthEndpoint:
    """Tests for health endpoint."""

    def test_health_check(self, client):
        """Test health check returns healthy."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "mass-dashboard"


class TestStatsEndpoint:
    """Tests for stats endpoint."""

    def test_empty_stats(self, client):
        """Test stats with no scans."""
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_scans"] == 0
        assert data["active_scans"] == 0
        assert data["total_findings"] == 0

    def test_stats_with_scans(self, app, client):
        """Test stats with scan data."""
        # Add test scan to store
        app.state.scan_store["test-1"] = {
            "scan_id": "test-1",
            "status": "completed",
            "started_at": datetime.utcnow(),
            "completed_at": datetime.utcnow(),
            "duration_seconds": 30.0,
            "findings": [
                {"severity": "critical"},
                {"severity": "high"},
            ],
        }

        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_scans"] == 1
        assert data["total_findings"] == 2
        assert data["critical_findings"] == 1


class TestScansEndpoint:
    """Tests for scans endpoints."""

    def test_list_scans_empty(self, client):
        """Test listing scans when empty."""
        response = client.get("/api/scans")
        assert response.status_code == 200
        data = response.json()
        assert data == []

    def test_list_scans_with_data(self, app, client):
        """Test listing scans with data."""
        app.state.scan_store["scan-1"] = {
            "scan_id": "scan-1",
            "status": "completed",
            "target": "/test/path",
            "profile": "standard",
            "started_at": datetime.utcnow(),
            "findings": [],
        }

        response = client.get("/api/scans")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["scan_id"] == "scan-1"

    def test_list_scans_filter_by_status(self, app, client):
        """Test filtering scans by status."""
        app.state.scan_store["scan-1"] = {
            "scan_id": "scan-1",
            "status": "completed",
            "target": "/test",
            "profile": "standard",
            "started_at": datetime.utcnow(),
            "findings": [],
        }
        app.state.scan_store["scan-2"] = {
            "scan_id": "scan-2",
            "status": "running",
            "target": "/test2",
            "profile": "standard",
            "started_at": datetime.utcnow(),
            "findings": [],
        }

        response = client.get("/api/scans?status=completed")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["status"] == "completed"

    def test_get_scan_not_found(self, client):
        """Test getting non-existent scan."""
        response = client.get("/api/scans/nonexistent")
        assert response.status_code == 404

    def test_get_scan_by_id(self, app, client):
        """Test getting scan by ID."""
        app.state.scan_store["scan-123"] = {
            "scan_id": "scan-123",
            "status": "completed",
            "target": "/test",
            "profile": "quick",
            "started_at": datetime.utcnow(),
            "findings": [],
        }

        response = client.get("/api/scans/scan-123")
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == "scan-123"
        assert data["profile"] == "quick"

    def test_start_scan_invalid_target(self, client):
        """Test starting scan with invalid target."""
        response = client.post("/api/scans", json={
            "target": "/nonexistent/path",
            "profile": "quick",
        })
        assert response.status_code == 400

    def test_start_scan_valid_target(self, client, tmp_path):
        """Test starting scan with valid target."""
        target = tmp_path / "deployment"
        target.mkdir()

        response = client.post("/api/scans", json={
            "target": str(target),
            "profile": "quick",
        })
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "pending"

    def test_cancel_scan_not_found(self, client):
        """Test cancelling non-existent scan."""
        response = client.delete("/api/scans/nonexistent")
        assert response.status_code == 404

    def test_cancel_scan_already_completed(self, app, client):
        """Test cancelling completed scan."""
        app.state.scan_store["scan-done"] = {
            "scan_id": "scan-done",
            "status": "completed",
            "target": "/test",
            "profile": "standard",
            "started_at": datetime.utcnow(),
            "findings": [],
        }

        response = client.delete("/api/scans/scan-done")
        assert response.status_code == 400

    def test_cancel_running_scan(self, app, client):
        """Test cancelling running scan."""
        app.state.scan_store["scan-running"] = {
            "scan_id": "scan-running",
            "status": "running",
            "target": "/test",
            "profile": "standard",
            "started_at": datetime.utcnow(),
            "findings": [],
        }

        response = client.delete("/api/scans/scan-running")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "cancelled"


class TestFindingsEndpoint:
    """Tests for findings endpoints."""

    def test_get_findings_scan_not_found(self, client):
        """Test getting findings for non-existent scan."""
        response = client.get("/api/scans/nonexistent/findings")
        assert response.status_code == 404

    def test_get_findings_empty(self, app, client):
        """Test getting empty findings."""
        app.state.scan_store["scan-1"] = {
            "scan_id": "scan-1",
            "status": "completed",
            "target": "/test",
            "profile": "standard",
            "started_at": datetime.utcnow(),
            "findings": [],
        }

        response = client.get("/api/scans/scan-1/findings")
        assert response.status_code == 200
        data = response.json()
        assert data == []

    def test_get_findings_with_data(self, app, client):
        """Test getting findings with data."""
        app.state.scan_store["scan-1"] = {
            "scan_id": "scan-1",
            "status": "completed",
            "target": "/test",
            "profile": "standard",
            "started_at": datetime.utcnow(),
            "findings": [
                {
                    "id": "f-1",
                    "title": "Test Finding",
                    "severity": "high",
                    "category": "secrets",
                    "component": "test",
                },
                {
                    "id": "f-2",
                    "title": "Another Finding",
                    "severity": "low",
                    "category": "model",
                    "component": "test",
                },
            ],
        }

        response = client.get("/api/scans/scan-1/findings")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    def test_get_findings_filter_severity(self, app, client):
        """Test filtering findings by severity."""
        app.state.scan_store["scan-1"] = {
            "scan_id": "scan-1",
            "status": "completed",
            "target": "/test",
            "profile": "standard",
            "started_at": datetime.utcnow(),
            "findings": [
                {"id": "1", "title": "F1", "severity": "high", "category": "a", "component": "c"},
                {"id": "2", "title": "F2", "severity": "low", "category": "a", "component": "c"},
            ],
        }

        response = client.get("/api/scans/scan-1/findings?severity=high")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["severity"] == "high"

    def test_get_findings_filter_category(self, app, client):
        """Test filtering findings by category."""
        app.state.scan_store["scan-1"] = {
            "scan_id": "scan-1",
            "status": "completed",
            "target": "/test",
            "profile": "standard",
            "started_at": datetime.utcnow(),
            "findings": [
                {"id": "1", "title": "F1", "severity": "high", "category": "secrets", "component": "c"},
                {"id": "2", "title": "F2", "severity": "low", "category": "model", "component": "c"},
            ],
        }

        response = client.get("/api/scans/scan-1/findings?category=secrets")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["category"] == "secrets"


class TestUIEndpoints:
    """Tests for UI endpoints."""

    def test_dashboard_home(self, client):
        """Test dashboard home page."""
        response = client.get("/")
        assert response.status_code == 200
        assert "MASS Dashboard" in response.text
        assert "<!DOCTYPE html>" in response.text

    def test_scan_detail_page(self, client):
        """Test scan detail page."""
        response = client.get("/scan/test-scan-id")
        assert response.status_code == 200
        assert "<!DOCTYPE html>" in response.text


class TestResponseModels:
    """Tests for response models."""

    def test_scan_request(self):
        """Test ScanRequest model."""
        request = ScanRequest(
            target="/path/to/target",
            profile="quick",
        )
        assert request.target == "/path/to/target"
        assert request.profile == "quick"

    def test_scan_response(self):
        """Test ScanResponse model."""
        response = ScanResponse(
            scan_id="scan-1",
            status="pending",
            message="Scan started",
        )
        assert response.scan_id == "scan-1"

    def test_finding_response(self):
        """Test FindingResponse model."""
        response = FindingResponse(
            id="f-1",
            title="Test Finding",
            severity="high",
            category="secrets",
            component="test",
        )
        assert response.id == "f-1"
        assert response.severity == "high"

    def test_scan_result_response(self):
        """Test ScanResultResponse model."""
        response = ScanResultResponse(
            scan_id="scan-1",
            status="completed",
            target="/test",
            profile="standard",
            started_at="2024-01-01T00:00:00",
            findings_count=5,
            critical_count=1,
        )
        assert response.scan_id == "scan-1"
        assert response.findings_count == 5

    def test_stats_response(self):
        """Test StatsResponse model."""
        response = StatsResponse(
            total_scans=10,
            active_scans=2,
            total_findings=50,
            critical_findings=5,
        )
        assert response.total_scans == 10
        assert response.critical_findings == 5


class TestIntegration:
    """Integration tests for dashboard."""

    def test_complete_workflow(self, client, tmp_path):
        """Test complete scan workflow through dashboard."""
        # Create target
        target = tmp_path / "deployment"
        target.mkdir()
        (target / "test.py").write_text("# test")

        # Check initial stats
        stats = client.get("/api/stats").json()
        initial_scans = stats["total_scans"]

        # Start scan
        response = client.post("/api/scans", json={
            "target": str(target),
            "profile": "quick",
        })
        assert response.status_code == 200
        scan_id = response.json()["scan_id"]

        # Verify scan appears in list
        scans = client.get("/api/scans").json()
        assert any(s["scan_id"] == scan_id for s in scans)

        # Get scan details
        scan = client.get(f"/api/scans/{scan_id}").json()
        assert scan["scan_id"] == scan_id
        assert scan["target"] == str(target)

    def test_stats_update_on_scan(self, app, client):
        """Test that stats update correctly."""
        # Initial stats
        stats1 = client.get("/api/stats").json()

        # Add a scan
        app.state.scan_store["new-scan"] = {
            "scan_id": "new-scan",
            "status": "completed",
            "target": "/test",
            "profile": "standard",
            "started_at": datetime.utcnow(),
            "duration_seconds": 10.0,
            "findings": [
                {"severity": "critical"},
            ],
        }

        # Check stats updated
        stats2 = client.get("/api/stats").json()
        assert stats2["total_scans"] == stats1["total_scans"] + 1
        assert stats2["total_findings"] == stats1["total_findings"] + 1
        assert stats2["critical_findings"] == stats1["critical_findings"] + 1

    def test_dashboard_loads_and_shows_content(self, client):
        """Test that dashboard page loads correctly."""
        response = client.get("/")
        assert response.status_code == 200

        # Check key elements are present
        content = response.text
        assert "MASS" in content
        assert "Dashboard" in content
        assert "New Scan" in content
        assert "Recent Scans" in content
        assert "Total Scans" in content
        assert "Critical Findings" in content
