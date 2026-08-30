"""
Project Umbra REST & Telemetry Streaming API Router (v1).
Exposes endpoints for initiating scans, polling mission status, streaming SSE telemetry,
listing historical missions, retrieving suppression receipts, cancelling runs, and health probing.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Literal
from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sse_starlette.sse import EventSourceResponse

from project_umbra.api.access import (
    issue_mission_token,
    redact_summary_for_response,
    require_operator_access,
    require_mission_access,
    require_scan_access,
)
from project_umbra.api.sse import SSEBroadcaster
from project_umbra.config import settings
from project_umbra.core.mission_runner import MissionExecutionManager
from project_umbra.core.state import (
    AgentLifecycleState,
    AgentRunSummary,
    ExtractedEntityProfile,
    SuppressionReceipt,
    TargetIdentityInput,
)
from project_umbra.storage.base import BasePersistenceRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Project Umbra Recon"])
api_router = router  # Alias for compatibility


# ==============================================================================
# Helper State Accessors
# ==============================================================================

def _get_manager(request: Request) -> MissionExecutionManager:
    mgr = getattr(request.app.state, "mission_manager", None) or getattr(request.app.state, "manager", None)
    if mgr is None:
        raise HTTPException(status_code=503, detail="MissionExecutionManager not initialized.")
    return mgr


def _get_broadcaster(request: Request) -> SSEBroadcaster:
    broadcaster = getattr(request.app.state, "broadcaster", None) or getattr(request.app.state, "sse_broadcaster", None)
    if broadcaster is None:
        broadcaster = SSEBroadcaster()
        request.app.state.broadcaster = broadcaster
        request.app.state.sse_broadcaster = broadcaster
    return broadcaster


def _get_repository(request: Request) -> BasePersistenceRepository:
    repo = getattr(request.app.state, "repository", None) or getattr(request.app.state, "storage", None)
    if repo is None:
        raise HTTPException(status_code=503, detail="Persistence repository not initialized.")
    return repo


# ==============================================================================
# Endpoints
# ==============================================================================

@router.get("/health")
async def health_check(request: Request, response: Response) -> dict[str, Any]:
    """Readiness and liveness probe for Cloud Run and local monitoring."""
    manager = getattr(request.app.state, "mission_manager", None) or getattr(request.app.state, "manager", None)
    active_count = manager.active_mission_count if manager else 0
    repo = getattr(request.app.state, "repository", None) or getattr(request.app.state, "storage", None)
    storage_healthy = await repo.ping() if repo else False
    persistence_backend = repo.backend_type if repo else "uninitialized"
    backend_policy_satisfied = not (
        settings.ENVIRONMENT == "production"
        and settings.PERSISTENCE_MODE == "firestore"
        and persistence_backend != "firestore"
    )
    storage_ready = bool(repo and storage_healthy and backend_policy_satisfied)
    if settings.ENVIRONMENT == "production" and not storage_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ok" if storage_ready else ("unready" if settings.ENVIRONMENT == "production" else "degraded"),
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "persistence_mode": settings.PERSISTENCE_MODE,
        "persistence_backend": persistence_backend,
        "persistence_policy_satisfied": backend_policy_satisfied,
        "active_missions": active_count,
        "storage_ready": storage_ready,
        "simulation_mode": settings.PLAYWRIGHT_SIMULATION_MODE,
        "serp_mode": settings.SERP_MODE,
        "pii_classifier_mode": settings.PII_CLASSIFIER_MODE,
        "api_key_configured": bool(settings.GEMINI_API_KEY),
        "google_agent_framework": "Google GenAI SDK",
        "gemini_model": settings.GEMINI_MODEL,
        "deployed_commit_sha": settings.APP_COMMIT_SHA,
        "cloud_run_revision": os.environ.get("K_REVISION", "local"),
        "external_action_policy": "plan_only_no_dispatch",
        "public_demo_policy": {
            "scan_scope": "operator_token_required",
            "mission_access": "capability_required",
            "public_enumeration": False,
            "redaction_maps_exposed": False,
        },
    }


@router.post(
    "/scan",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start an autonomous investigation and action-planning mission",
)
async def start_scan(
    target: TargetIdentityInput,
    request: Request,
    response: Response,
    max_budget: int = Query(default=25, ge=1, le=100),
    timeout_seconds: float = Query(default=300.0, ge=10.0, le=900.0),
) -> dict[str, Any]:
    """Initiates an autonomous background OSINT scan, returning HTTP 202 Accepted."""
    require_scan_access(request, target)
    manager = _get_manager(request)
    scan_id = await manager.start_mission(
        target_input=target,
        timeout_seconds=timeout_seconds,
        max_budget=max_budget,
        api_key=getattr(request.state, "gemini_api_key", None),
    )
    access_token = issue_mission_token(request, scan_id)
    status_url = f"/api/v1/scan/{scan_id}"
    events_url = f"/api/v1/scan/{scan_id}/events"
    response.set_cookie(
        key="umbra_mission_access",
        value=access_token,
        max_age=settings.MISSION_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="strict",
        path=f"/api/v1/scan/{scan_id}",
    )
    response.headers["Location"] = status_url

    return {
        "scan_id": scan_id,
        "mission_id": scan_id,
        "status": "initialized",
        "target_name": target.full_name,
        "message": "Scan mission accepted and running in background.",
        "stream_url": events_url,
        "events_url": events_url,
        "detail_url": status_url,
        "status_url": status_url,
        "mission_access_token": access_token,
        "access_policy": "mission_capability_required",
        "execution_contract": "investigation_and_action_plan_only",
        "external_actions_dispatched": 0,
    }


@router.get(
    "/scan/{scan_id}",
    response_model=AgentRunSummary,
    summary="Get status and summary of a scan mission",
)
async def get_scan_details(scan_id: str, request: Request) -> AgentRunSummary:
    """Retrieves status and run summary for a specific scan_id."""
    require_mission_access(request, scan_id)
    manager = _get_manager(request)
    summary = await manager.get_mission(scan_id)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan mission '{scan_id}' not found.",
        )
    return redact_summary_for_response(summary)


@router.post(
    "/scan/{scan_id}/cancel",
    summary="Cancel an active scan mission",
)
async def cancel_scan(scan_id: str, request: Request) -> dict[str, Any]:
    """Cancels an ongoing background mission task."""
    require_mission_access(request, scan_id)
    manager = _get_manager(request)
    cancelled = await manager.cancel_mission(scan_id)
    if not cancelled:
        summary = await manager.get_mission(scan_id)
        if not summary:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan mission '{scan_id}' not found.",
            )
        return {"scan_id": scan_id, "cancelled": False, "message": "Scan already completed or terminated."}
    return {"scan_id": scan_id, "cancelled": True, "message": "Scan execution cancelled successfully."}


@router.get(
    "/scan/{scan_id}/events",
    summary="Subscribe to live SSE telemetry stream for a scan mission",
)
async def stream_scan_events(scan_id: str, request: Request) -> EventSourceResponse:
    """Streams live Server-Sent Events (SSE) telemetry for a scan mission."""
    require_mission_access(request, scan_id)
    broadcaster = _get_broadcaster(request)
    generator = broadcaster.event_generator(
        request=request,
        mission_id=scan_id,
        heartbeat_interval=15.0,
        replay_history=True,
    )
    return EventSourceResponse(
        generator,
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/scan/{scan_id}/findings",
    response_model=list[ExtractedEntityProfile],
    summary="Get extracted entity findings for a scan mission",
)
async def get_scan_findings(scan_id: str, request: Request) -> list[ExtractedEntityProfile]:
    """Retrieves extracted entity findings for a scan."""
    require_mission_access(request, scan_id)
    repo = _get_repository(request)
    return await repo.get_findings(scan_id)


@router.get(
    "/scan/{scan_id}/receipts",
    response_model=list[SuppressionReceipt],
    summary="Get external-action receipts (empty for plan-only missions)",
)
async def get_scan_receipts(scan_id: str, request: Request) -> list[SuppressionReceipt]:
    """Retrieves suppression receipts generated for a scan."""
    require_mission_access(request, scan_id)
    repo = _get_repository(request)
    return await repo.get_receipts(scan_id)


@router.get(
    "/missions",
    response_model=list[AgentRunSummary],
    summary="List historical and active scan missions",
)
async def list_missions(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[AgentRunSummary]:
    """Lists historical and active scan missions."""
    require_operator_access(request)
    repo = _get_repository(request)
    return [
        redact_summary_for_response(summary)
        for summary in await repo.list_scans(limit=limit, offset=offset)
    ]


@router.get(
    "/receipts",
    response_model=list[SuppressionReceipt],
    summary="List external-action receipts",
)
async def list_all_receipts(
    request: Request,
    mission_id: str | None = Query(default=None, description="Optional filter by mission/scan ID"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[SuppressionReceipt]:
    """Lists verifiable suppression receipts across remediation actions."""
    require_operator_access(request)
    repo = _get_repository(request)
    if mission_id:
        return await repo.get_receipts(mission_id)
    return await repo.list_receipts(limit=limit)
