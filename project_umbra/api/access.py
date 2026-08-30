"""Production-safe operator access and mission capability policy."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from fastapi import HTTPException, Request, status

from project_umbra.config import settings
from project_umbra.core.state import AgentRunSummary, TargetIdentityInput


def production_access_enabled() -> bool:
    return settings.ENVIRONMENT == "production"


def has_operator_access(request: Request) -> bool:
    configured = settings.UMBRA_OPERATOR_TOKEN or settings.JUDGE_ACCESS_TOKEN
    supplied = (
        request.headers.get("X-Umbra-Operator-Token", "")
        or request.headers.get("X-Umbra-Judge-Token", "")
    )
    return bool(configured and supplied and hmac.compare_digest(configured, supplied))


def require_scan_access(request: Request, target: TargetIdentityInput) -> None:
    if not production_access_enabled():
        return
    if has_operator_access(request):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Production scans require the configured operator token. The public synthetic walkthrough is available through the controlled demo stream.",
    )


def _access_secret(request: Request) -> bytes:
    configured = settings.UMBRA_ACCESS_SECRET
    if configured:
        return configured.encode("utf-8")
    if production_access_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent mission access secret is not configured.",
        )
    secret = getattr(request.app.state, "umbra_access_secret", None)
    if secret is None:
        secret = secrets.token_bytes(48)
        request.app.state.umbra_access_secret = secret
    return secret if isinstance(secret, bytes) else str(secret).encode("utf-8")


def issue_mission_token(request: Request, scan_id: str) -> str:
    issued_at = int(time.time())
    message = f"{scan_id}:{issued_at}".encode("utf-8")
    signature = hmac.new(_access_secret(request), message, hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"v1.{issued_at}.{encoded}"


def _mission_token_valid(request: Request, scan_id: str, token: str) -> bool:
    try:
        version, issued_raw, supplied_signature = token.split(".", 2)
        issued_at = int(issued_raw)
    except (TypeError, ValueError):
        return False
    now = int(time.time())
    if version != "v1" or issued_at > now + 60 or now - issued_at > settings.MISSION_TOKEN_TTL_SECONDS:
        return False
    message = f"{scan_id}:{issued_at}".encode("utf-8")
    expected = base64.urlsafe_b64encode(
        hmac.new(_access_secret(request), message, hashlib.sha256).digest()
    ).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(expected, supplied_signature)


def require_mission_access(request: Request, scan_id: str) -> None:
    if not production_access_enabled() or has_operator_access(request):
        return
    supplied = (
        request.headers.get("X-Umbra-Mission-Token", "")
        or request.cookies.get("umbra_mission_access", "")
    )
    if supplied and _mission_token_valid(request, scan_id, supplied):
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Mission capability required.")


def require_operator_access(request: Request) -> None:
    if not production_access_enabled() or has_operator_access(request):
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operator access token required.")


def redact_summary_for_response(summary: AgentRunSummary) -> AgentRunSummary:
    """Remove reversible PII secrets from API output while preserving the risk report."""
    redacted = summary.model_copy(deep=True)
    if redacted.sanitization_result is not None:
        redacted.sanitization_result.redaction_map = {}
        for entity in redacted.sanitization_result.detected_entities:
            entity.original_value = "[REDACTED]"
    return redacted


__all__ = [
    "has_operator_access",
    "issue_mission_token",
    "production_access_enabled",
    "redact_summary_for_response",
    "require_operator_access",
    "require_mission_access",
    "require_scan_access",
]
