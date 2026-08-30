"""Production access-policy and privacy regression tests."""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from project_umbra.api.app import create_app
from project_umbra.api.sse import SSEBroadcaster
from project_umbra.classifiers.gemma_classifier import GemmaSanitizerClassifier
from project_umbra.config import settings
from project_umbra.core.agent import ProjectUmbraAgent
from project_umbra.core.mission_runner import MissionExecutionManager
from project_umbra.storage.sqlite import SQLitePersistenceRepository
from project_umbra.tools.browser_scanner import PlaywrightStealthScanner
from project_umbra.tools.serp_scanner import SERPScanner
from project_umbra.tools.structured_extractor import StructuredExtractor
from project_umbra.tools.suppression_engine import SuppressionEngine


AVERY_TARGET = {
    "full_name": "Avery Mercer",
    "aliases": ["Avery J. Mercer", "A. Mercer", "ave_mercer"],
    "primary_email": "avery@helio.example",
    "secondary_emails": ["avery.mercer@relay.example"],
    "phone_numbers": ["+1 (202) 555-0142"],
    "current_city": "Oakland",
    "current_state": "California",
    "employers": ["Helio Civic Lab"],
    "usernames": ["@averymercer", "@heliocivic"],
}


@pytest_asyncio.fixture
async def production_client(tmp_path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "UMBRA_OPERATOR_TOKEN", "operator-secret-token")
    monkeypatch.setattr(settings, "JUDGE_ACCESS_TOKEN", "")
    monkeypatch.setattr(settings, "UMBRA_ACCESS_SECRET", "mission-signing-secret-with-enough-entropy")

    repo = SQLitePersistenceRepository(db_path=str(tmp_path / "production_access.db"))
    await repo.initialize()
    broadcaster = SSEBroadcaster(heartbeat_interval=0.05)

    def controlled_factory(*, max_budget: int, api_key: str | None) -> ProjectUmbraAgent:
        return ProjectUmbraAgent(
            serp_scanner=SERPScanner(mode="mock"),
            browser_scanner=PlaywrightStealthScanner(simulation_mode=True),
            extractor=StructuredExtractor(offline_mode=True),
            gemma_sanitizer=GemmaSanitizerClassifier(mode="heuristic"),
            suppression_engine=SuppressionEngine(simulation_mode=True),
            max_budget=max_budget,
        )

    manager = MissionExecutionManager(
        repository=repo,
        sse_broadcaster=broadcaster,
        agent_factory=controlled_factory,
    )
    app = create_app()
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        AVERY_TARGET,
        {"full_name": "Real Person", "primary_email": "real@example.com"},
    ],
)
async def test_production_rejects_every_public_scan_without_operator_token(
    production_client: AsyncClient,
    payload: dict,
) -> None:
    response = await production_client.post(
        "/api/v1/scan",
        json=payload,
    )

    assert response.status_code == 403
    assert "operator token" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_production_allows_canonical_synthetic_target_with_operator_token(
    production_client: AsyncClient,
) -> None:
    response = await production_client.post(
        "/api/v1/scan",
        json=AVERY_TARGET,
        headers={"X-Umbra-Operator-Token": "operator-secret-token"},
    )

    assert response.status_code == 202
    body = response.json()
    assert body["mission_access_token"]
    assert "access_token=" not in body["events_url"]
    assert "umbra_mission_access=" in response.headers["set-cookie"]
    assert "HttpOnly" in response.headers["set-cookie"]
    assert response.headers["cache-control"] == "no-store"
    assert body["access_policy"] == "mission_capability_required"


@pytest.mark.asyncio
async def test_operator_token_allows_non_synthetic_target(
    production_client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = await production_client.post(
        "/api/v1/scan",
        json={"full_name": "Authorized Operator Target"},
        headers={"X-Umbra-Operator-Token": "operator-secret-token"},
    )

    assert response.status_code == 202


@pytest.mark.asyncio
async def test_legacy_judge_token_allows_non_synthetic_target(
    production_client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "UMBRA_OPERATOR_TOKEN", "")
    monkeypatch.setattr(settings, "JUDGE_ACCESS_TOKEN", "legacy-secret-token")
    response = await production_client.post(
        "/api/v1/scan",
        json={"full_name": "Authorized Legacy Target"},
        headers={"X-Umbra-Judge-Token": "legacy-secret-token"},
    )

    assert response.status_code == 202


@pytest.mark.asyncio
async def test_mission_reads_require_matching_capability(production_client: AsyncClient) -> None:
    start = await production_client.post(
        "/api/v1/scan",
        json=AVERY_TARGET,
        headers={"X-Umbra-Operator-Token": "operator-secret-token"},
    )
    scan_id = start.json()["scan_id"]
    access_token = start.json()["mission_access_token"]
    production_client.cookies.clear()

    assert (await production_client.get(f"/api/v1/scan/{scan_id}")).status_code == 403
    assert (
        await production_client.get(
            f"/api/v1/scan/{scan_id}",
            headers={"X-Umbra-Mission-Token": "wrong-token"},
        )
    ).status_code == 403
    assert (
        await production_client.get(
            "/api/v1/scan/unguessable-does-not-exist",
            headers={"X-Umbra-Mission-Token": access_token},
        )
    ).status_code == 403
    assert (
        await production_client.get(
            f"/api/v1/scan/{scan_id}",
            params={"access_token": access_token},
        )
    ).status_code == 403

    authorized = await production_client.get(
        f"/api/v1/scan/{scan_id}",
        headers={"X-Umbra-Mission-Token": access_token},
    )
    assert authorized.status_code == 200


@pytest.mark.asyncio
async def test_all_mission_subresources_require_capability(production_client: AsyncClient) -> None:
    start = await production_client.post(
        "/api/v1/scan",
        json=AVERY_TARGET,
        headers={"X-Umbra-Operator-Token": "operator-secret-token"},
    )
    scan_id = start.json()["scan_id"]
    production_client.cookies.clear()

    assert (await production_client.get(f"/api/v1/scan/{scan_id}/findings")).status_code == 403
    assert (await production_client.get(f"/api/v1/scan/{scan_id}/receipts")).status_code == 403
    assert (await production_client.get(f"/api/v1/scan/{scan_id}/events")).status_code == 403
    assert (await production_client.post(f"/api/v1/scan/{scan_id}/cancel")).status_code == 403


@pytest.mark.asyncio
async def test_public_cannot_enumerate_missions_or_global_receipts(
    production_client: AsyncClient,
) -> None:
    assert (await production_client.get("/api/v1/missions")).status_code == 403
    assert (await production_client.get("/api/v1/receipts")).status_code == 403

    headers = {"X-Umbra-Operator-Token": "operator-secret-token"}
    assert (await production_client.get("/api/v1/missions", headers=headers)).status_code == 200
    assert (await production_client.get("/api/v1/receipts", headers=headers)).status_code == 200


@pytest.mark.asyncio
async def test_mission_summary_never_exposes_redaction_map(production_client: AsyncClient) -> None:
    start = await production_client.post(
        "/api/v1/scan",
        json=AVERY_TARGET,
        headers={"X-Umbra-Operator-Token": "operator-secret-token"},
    )
    scan_id = start.json()["scan_id"]
    headers = {"X-Umbra-Mission-Token": start.json()["mission_access_token"]}

    summary = None
    for _ in range(60):
        await asyncio.sleep(0.05)
        response = await production_client.get(f"/api/v1/scan/{scan_id}", headers=headers)
        summary = response.json()
        if summary["final_state"] in {"completed", "budget_exhausted", "failed"}:
            break

    assert summary is not None
    assert summary["sanitization_result"] is not None
    assert summary["sanitization_result"]["redaction_map"] == {}


@pytest.mark.asyncio
async def test_health_advertises_safe_public_demo_policy(production_client: AsyncClient) -> None:
    response = await production_client.get("/api/v1/health")

    assert response.status_code == 200
    policy = response.json()["public_demo_policy"]
    assert policy == {
        "scan_scope": "operator_token_required",
        "mission_access": "capability_required",
        "public_enumeration": False,
        "redaction_maps_exposed": False,
    }


@pytest.mark.asyncio
async def test_production_cors_does_not_allow_arbitrary_credentialed_origins(
    production_client: AsyncClient,
) -> None:
    response = await production_client.options(
        "/api/v1/scan",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-umbra-operator-token",
        },
    )

    assert response.headers.get("access-control-allow-origin") is None
    assert response.headers.get("access-control-allow-credentials") != "true"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
async def test_production_schema_and_interactive_docs_are_not_public(
    production_client: AsyncClient,
    path: str,
) -> None:
    response = await production_client.get(path)

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_production_startup_requires_persistent_access_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "UMBRA_ACCESS_SECRET", "")
    monkeypatch.setattr(settings, "UMBRA_OPERATOR_TOKEN", "operator-token")
    app = create_app()

    with pytest.raises(RuntimeError, match="UMBRA_ACCESS_SECRET"):
        async with app.router.lifespan_context(app):
            pass


@pytest.mark.asyncio
async def test_production_startup_requires_operator_access_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "UMBRA_ACCESS_SECRET", "persistent-secret")
    monkeypatch.setattr(settings, "UMBRA_OPERATOR_TOKEN", "")
    monkeypatch.setattr(settings, "JUDGE_ACCESS_TOKEN", "")
    app = create_app()

    with pytest.raises(RuntimeError, match="UMBRA_OPERATOR_TOKEN"):
        async with app.router.lifespan_context(app):
            pass
