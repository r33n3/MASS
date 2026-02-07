"""Integration tests for API endpoints.

Tests the full API stack with auth overrides and real database.
"""

import json
import os

from starlette.testclient import TestClient

from mass.api.main import create_app
from mass.api.dependencies import get_current_tenant, get_api_key, CurrentTenant


def _make_client():
    """Create a test client with auth overrides."""
    app = create_app()
    test_tenant = CurrentTenant(tenant_id="test-tenant-001")

    async def mock_tenant():
        return test_tenant

    async def mock_key():
        return "test-key-123"

    app.dependency_overrides[get_current_tenant] = mock_tenant
    app.dependency_overrides[get_api_key] = mock_key
    return TestClient(app), app


def test_health_endpoints():
    client, _ = _make_client()
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200


def test_list_endpoints():
    client, _ = _make_client()
    assert client.get("/api/v1/scans").status_code == 200
    assert client.get("/api/v1/reports").status_code == 200
    assert client.get("/api/v1/targets").status_code == 200
    assert client.get("/api/v1/dashboard/stats").status_code == 200
    assert client.get("/api/v1/dashboard/scans").status_code == 200
    assert client.get("/api/v1/interrogation/jobs").status_code == 200


def test_verdict_missing_scan():
    client, _ = _make_client()
    resp = client.get("/api/v1/scans/nonexistent/verdict")
    assert resp.status_code == 404


def test_threat_model_missing_scan():
    client, _ = _make_client()
    resp = client.get("/api/v1/scans/nonexistent/threat-model")
    assert resp.status_code == 404


def test_target_detail_missing():
    client, _ = _make_client()
    resp = client.get("/api/v1/targets/nonexistent")
    assert resp.status_code == 404


def test_report_validation():
    client, _ = _make_client()

    # Missing scan_id
    resp = client.post(
        "/api/v1/reports",
        content=json.dumps({"format": "html"}),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422

    # Extra field rejected
    resp = client.post(
        "/api/v1/reports",
        content=json.dumps({"scan_id": "test", "bogus": True}),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422


def test_report_include_threat_model_flag():
    client, _ = _make_client()

    # With include_threat_model=True (scan doesn't exist -> 404)
    resp = client.post(
        "/api/v1/reports",
        content=json.dumps({
            "scan_id": "nonexistent",
            "format": "html",
            "include_threat_model": True,
        }),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 404

    # With include_threat_model=False (scan doesn't exist -> 404)
    resp = client.post(
        "/api/v1/reports",
        content=json.dumps({
            "scan_id": "nonexistent",
            "format": "json",
            "include_threat_model": False,
        }),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 404


def test_create_target_and_scan():
    client, _ = _make_client()
    cwd = os.getcwd()

    # Create target
    resp = client.post(
        "/api/v1/scan-targets",
        content=json.dumps({
            "target_type": "deployment",
            "source_path": cwd,
            "name": "test-e2e",
            "auto_scan": False,
        }),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 201
    deployment_id = resp.json()["deployment_id"]

    # Get target detail - verify topology field exists
    resp = client.get(f"/api/v1/targets/{deployment_id}")
    assert resp.status_code == 200
    detail = resp.json()
    assert "topology" in detail

    # Create scan
    resp = client.post(
        "/api/v1/scans",
        content=json.dumps({
            "deployment_id": deployment_id,
            "profile": "quick",
        }),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 201
    scan_id = resp.json()["id"]

    # Verdict not yet available
    assert client.get(f"/api/v1/scans/{scan_id}/verdict").status_code == 404
    assert client.get(f"/api/v1/scans/{scan_id}/threat-model").status_code == 404

    # Generate reports
    resp = client.post(
        "/api/v1/reports",
        content=json.dumps({
            "scan_id": scan_id,
            "format": "html",
            "include_threat_model": True,
        }),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 201
    assert resp.json()["status"] == "completed"

    resp = client.post(
        "/api/v1/reports",
        content=json.dumps({
            "scan_id": scan_id,
            "format": "json",
            "include_threat_model": False,
        }),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 201


def test_auth_blocks_unauthenticated():
    """Without auth override, protected endpoints should return 401."""
    app = create_app()
    client = TestClient(app)
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 401


def test_auth_allows_public_paths():
    """Public paths should work without authentication."""
    app = create_app()
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    assert client.get("/docs").status_code == 200
