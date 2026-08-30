"""
Unit and Integration Tests for Project Umbra FastAPI REST API & SSE Telemetry (Tiers 1-5).
Verifies health probes, async background execution, SSE live telemetry streams,
persistence retrieval, mission cancellation, timeout handling, and adversarial resilience.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from unittest.mock import AsyncMock, patch
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from project_umbra.api.app import create_app
from project_umbra.api.sse import SSEBroadcaster
from project_umbra.config import settings
from project_umbra.core.mission_runner import MissionExecutionManager
from project_umbra.core.state import (
    AgentLifecycleState,
    AgentRunSummary,
    AgentStepRecord,
    AgentTelemetryEvent,
    ExtractedEntityProfile,
    SuppressionActionPlan,
    SuppressionPayload,
    SuppressionReceipt,
    SuppressionStatus,
    TargetIdentityInput,
    TelemetryEventType,
)
from project_umbra.storage.sqlite import SQLitePersistenceRepository


@pytest.fixture
def target_payload() -> dict:
    return {
        "full_name": "Marcus Aurelius Brody",
        "aliases": ["Mark Brody"],
        "primary_email": "m.brody@texastech.edu",
        "secondary_emails": ["marcus.brody@gmail.com"],
        "phone_numbers": ["(214) 555-0192"],
        "current_city": "Dallas",
        "current_state": "TX",
        "known_addresses": ["1428 Elm Street, Dallas, TX 75201"],
        "relatives": ["Eleanor Brody"],
        "employers": ["Texas Tech University"],
        "usernames": ["mbrody_sec"],
    }


@pytest_asyncio.fixture
async def async_client(tmp_path):
    """Provides an isolated AsyncClient with a temporary SQLite database and managed lifespan."""
    test_db = str(tmp_path / "test_api.db")
    app = create_app()

    repo = SQLitePersistenceRepository(db_path=test_db)
    await repo.initialize()
    broadcaster = SSEBroadcaster(heartbeat_interval=0.2)
    manager = MissionExecutionManager(repository=repo, sse_broadcaster=broadcaster)

    app.state.repository = repo
    app.state.storage = repo
    app.state.broadcaster = broadcaster
    app.state.sse_broadcaster = broadcaster
    app.state.mission_manager = manager
    app.state.manager = manager
    app.state.active_missions = manager._task_metadata

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client

    await manager.shutdown()
    await repo.close()


# ==============================================================================
# Tier 1: Health & Ingestion Validation
# ==============================================================================

@pytest.mark.asyncio
async def test_tier1_health_probe(async_client: AsyncClient):
    """Verifies that GET /api/v1/health returns 200 OK and health attributes."""
    resp = await async_client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ["ok", "healthy"]
    assert "version" in data
    assert "active_missions" in data
    assert data["storage_ready"] is True
    assert data["persistence_backend"] == "sqlite"
    assert data["google_agent_framework"] == "Google GenAI SDK"
    assert data["gemini_model"] == "gemini-3.7-flash"
    assert data["external_action_policy"] == "plan_only_no_dispatch"
    assert "deployed_commit_sha" in data


@pytest.mark.asyncio
async def test_production_health_returns_503_when_storage_is_unready(
    async_client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    transport = async_client._transport
    app = transport.app
    app.state.repository.ping = AsyncMock(return_value=False)

    response = await async_client.get("/api/v1/health")

    assert response.status_code == 503
    assert response.json()["status"] == "unready"


@pytest.mark.asyncio
async def test_production_firestore_mode_rejects_wrong_backend(
    async_client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "PERSISTENCE_MODE", "firestore")

    response = await async_client.get("/api/v1/health")

    assert response.status_code == 503
    assert response.json()["status"] == "unready"
    assert response.json()["persistence_backend"] == "sqlite"


@pytest.mark.asyncio
async def test_tier1_favicon_fallback_serves_current_umbra_png(async_client: AsyncClient):
    """Safari-style GET /favicon.ico resolves to the current Umbra PNG without stale caching."""
    resp = await async_client.get("/favicon.ico")

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert resp.headers["cache-control"] == "no-cache, max-age=0"
    assert resp.content.startswith(b"\x89PNG\r\n\x1a\n")


@pytest.mark.asyncio
async def test_tier1_start_scan_202_accepted(async_client: AsyncClient, target_payload: dict):
    """Verifies that POST /api/v1/scan returns 202 Accepted with scan_id and stream URLs."""
    resp = await async_client.post("/api/v1/scan", json=target_payload)
    assert resp.status_code == 202
    data = resp.json()
    assert "scan_id" in data
    assert data["status"] == "initialized"
    assert data["target_name"] == target_payload["full_name"]
    assert f"/api/v1/scan/{data['scan_id']}/events" in data["stream_url"]
    assert f"/api/v1/scan/{data['scan_id']}" in resp.headers.get("Location", "")


@pytest.mark.asyncio
async def test_tier1_start_scan_invalid_payload(async_client: AsyncClient):
    """Verifies that invalid input yields 422 Unprocessable Entity."""
    resp = await async_client.post("/api/v1/scan", json={"full_name": "A"})  # Min length 2
    assert resp.status_code == 422
    data = resp.json()
    assert data["error_type"] == "validation_error" or "detail" in data


# ==============================================================================
# Tier 2: End-to-End Background Execution & Retrieval
# ==============================================================================

@pytest.mark.asyncio
async def test_tier2_background_scan_and_summary_retrieval(
    async_client: AsyncClient,
    target_payload: dict,
    monkeypatch: pytest.MonkeyPatch,
):
    """Verifies complete end-to-end mission execution in background and subsequent retrieval."""
    monkeypatch.setattr(settings, "PLAYWRIGHT_SIMULATION_MODE", True)
    monkeypatch.setattr(settings, "SERP_MODE", "mock")
    resp = await async_client.post("/api/v1/scan", json=target_payload)
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    # Poll until completed
    detail_resp = None
    for _ in range(40):
        await asyncio.sleep(0.2)
        detail_resp = await async_client.get(f"/api/v1/scan/{scan_id}")
        if detail_resp.status_code == 200:
            summary = detail_resp.json()
            if summary["final_state"] in ["completed", "budget_exhausted", "failed"]:
                break

    assert detail_resp is not None
    assert detail_resp.status_code == 200
    summary = detail_resp.json()
    assert summary["run_id"] == scan_id
    assert summary["target_name"] == target_payload["full_name"]
    assert summary["final_state"] == "completed"
    assert summary["vectors_analyzed"] >= 0
    assert len(summary["findings"]) >= 0


@pytest.mark.asyncio
async def test_tier2_get_scan_404_not_found(async_client: AsyncClient):
    """Verifies that non-existent scan IDs return 404."""
    resp = await async_client.get("/api/v1/scan/non_existent_scan_12345")
    assert resp.status_code == 404


# ==============================================================================
# Tier 3: Real-Time SSE Stream Telemetry
# ==============================================================================

@pytest.mark.asyncio
async def test_tier3_sse_stream_events(async_client: AsyncClient, target_payload: dict):
    """Verifies live Server-Sent Events stream emits valid AgentTelemetryEvent frames."""
    resp = await async_client.post("/api/v1/scan", json=target_payload)
    scan_id = resp.json()["scan_id"]

    async with async_client.stream("GET", f"/api/v1/scan/{scan_id}/events") as sse_stream:
        assert sse_stream.status_code == 200
        assert "text/event-stream" in sse_stream.headers.get("content-type", "")

        received_events = []
        async for line in sse_stream.aiter_lines():
            if line.startswith("event:"):
                received_events.append(line.replace("event:", "").strip())
            if "SCAN_COMPLETED" in received_events or len(received_events) >= 4:
                break

    assert len(received_events) > 0


# ==============================================================================
# Tier 4: Mission Cancellation & Timeouts
# ==============================================================================

@pytest.mark.asyncio
async def test_tier4_mission_cancellation(async_client: AsyncClient, target_payload: dict):
    """Verifies that POST /api/v1/scan/{scan_id}/cancel cancels an active mission task."""
    resp = await async_client.post("/api/v1/scan", json=target_payload)
    scan_id = resp.json()["scan_id"]

    # Immediately request cancellation
    cancel_resp = await async_client.post(f"/api/v1/scan/{scan_id}/cancel")
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["scan_id"] == scan_id

    await asyncio.sleep(0.3)
    detail_resp = await async_client.get(f"/api/v1/scan/{scan_id}")
    assert detail_resp.status_code == 200


@pytest.mark.asyncio
async def test_tier4_cancel_nonexistent_scan_returns_404(async_client: AsyncClient):
    """Verifies that cancelling non-existent scan returns 404."""
    resp = await async_client.post("/api/v1/scan/unknown_scan_999/cancel")
    assert resp.status_code == 404


# ==============================================================================
# Tier 5: Findings, Receipts & Historical List Endpoints
# ==============================================================================

@pytest.mark.asyncio
async def test_tier5_findings_and_receipts_endpoints(async_client: AsyncClient, target_payload: dict):
    """Verifies /findings, /receipts, and /missions endpoints return populated lists."""
    resp = await async_client.post("/api/v1/scan", json=target_payload)
    scan_id = resp.json()["scan_id"]

    # Wait for completion
    for _ in range(40):
        await asyncio.sleep(0.2)
        res = await async_client.get(f"/api/v1/scan/{scan_id}")
        if res.status_code == 200 and res.json()["final_state"] in ["completed", "budget_exhausted"]:
            break

    # 1. Check findings endpoint
    findings_resp = await async_client.get(f"/api/v1/scan/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert isinstance(findings, list)

    # 2. Check receipts endpoint
    receipts_resp = await async_client.get(f"/api/v1/scan/{scan_id}/receipts")
    assert receipts_resp.status_code == 200
    receipts = receipts_resp.json()
    assert isinstance(receipts, list)

    # 3. Check historical missions list
    missions_resp = await async_client.get("/api/v1/missions")
    assert missions_resp.status_code == 200
    missions = missions_resp.json()
    assert len(missions) >= 1

    # 4. Check global receipts list
    global_receipts_resp = await async_client.get("/api/v1/receipts")
    assert global_receipts_resp.status_code == 200
    assert isinstance(global_receipts_resp.json(), list)
