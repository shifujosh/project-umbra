"""Regression contracts for the production investigation composition."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from project_umbra.api.sse import SSEBroadcaster
from project_umbra.classifiers.gemma_classifier import GemmaSanitizerClassifier
from project_umbra.core.agent import ProjectUmbraAgent
from project_umbra.core.mission_runner import MissionExecutionManager
from project_umbra.core.production import build_production_agent
from project_umbra.core.production import _build_genai_client
from project_umbra.core.state import (
    AgentLifecycleState,
    AgentRunSummary,
    DorkCategory,
    DorkQuery,
    ExecutionProvenance,
    ExtractedEntityProfile,
    PriorityLevel,
    TargetIdentityInput,
)
from project_umbra.storage.sqlite import SQLitePersistenceRepository
from project_umbra.tools.browser_scanner import PlaywrightStealthScanner
from project_umbra.tools.serp_scanner import SERPScanner
from project_umbra.tools.structured_extractor import StructuredExtractor
from project_umbra.tools.suppression_engine import SuppressionEngine


def test_production_factory_wires_every_investigation_component(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel_client = object()
    monkeypatch.setattr(
        "project_umbra.core.production._build_genai_client",
        lambda _api_key: sentinel_client,
    )

    agent = build_production_agent(max_budget=37, api_key="test-key")

    assert agent.max_budget == 37
    assert isinstance(agent.serp_scanner, SERPScanner)
    assert agent.serp_scanner.gemini_client is sentinel_client
    assert isinstance(agent.browser_scanner, PlaywrightStealthScanner)
    assert isinstance(agent.extractor, StructuredExtractor)
    assert agent.extractor.gemini_extractor._client is sentinel_client
    assert agent.extractor.gemini_extractor.model_name == "gemini-3.7-flash"
    assert isinstance(agent.gemma_sanitizer, GemmaSanitizerClassifier)
    assert agent.gemma_sanitizer.mode == "heuristic"
    assert isinstance(agent.suppression_engine, SuppressionEngine)


@pytest.mark.asyncio
async def test_request_budget_and_byok_key_do_not_bypass_agent_factory(tmp_path) -> None:
    repo = SQLitePersistenceRepository(db_path=str(tmp_path / "factory.db"))
    await repo.initialize()
    broadcaster = SSEBroadcaster()
    captured: dict[str, object] = {}

    def factory(*, max_budget: int, api_key: str | None) -> ProjectUmbraAgent:
        captured.update(max_budget=max_budget, api_key=api_key)
        return ProjectUmbraAgent(max_budget=max_budget)

    manager = MissionExecutionManager(repo, broadcaster, agent_factory=factory)
    scan_id = await manager.start_mission(
        TargetIdentityInput(full_name="Avery Mercer"),
        max_budget=13,
        api_key="request-scoped-key",
    )

    assert captured == {"max_budget": 13, "api_key": "request-scoped-key"}
    assert manager._active_agents[scan_id].max_budget == 13

    await manager.shutdown()
    await repo.close()


def test_byok_clients_are_mission_scoped_and_do_not_mutate_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_keys: list[str] = []

    def build_client(api_key: str | None):
        created_keys.append(api_key or "")
        return SimpleNamespace(client_number=len(created_keys))

    monkeypatch.setenv("GEMINI_API_KEY", "service-key-remains-unchanged")
    monkeypatch.setattr("project_umbra.core.production._build_genai_client", build_client)

    first = build_production_agent(api_key="judge-byok-one")
    second = build_production_agent(api_key="judge-byok-two")

    assert created_keys == ["judge-byok-one", "judge-byok-two"]
    assert first.client is not second.client
    assert first.extractor.gemini_extractor._client is first.client
    assert second.extractor.gemini_extractor._client is second.client
    assert os.environ["GEMINI_API_KEY"] == "service-key-remains-unchanged"


@pytest.mark.asyncio
async def test_controlled_pipeline_reports_provenance_and_never_dispatches(tmp_path) -> None:
    repo = SQLitePersistenceRepository(db_path=str(tmp_path / "controlled.db"))
    await repo.initialize()
    broadcaster = SSEBroadcaster()

    def factory(*, max_budget: int, api_key: str | None) -> ProjectUmbraAgent:
        return ProjectUmbraAgent(
            serp_scanner=SERPScanner(mode="mock"),
            browser_scanner=PlaywrightStealthScanner(simulation_mode=True),
            extractor=StructuredExtractor(offline_mode=True),
            gemma_sanitizer=GemmaSanitizerClassifier(mode="heuristic"),
            suppression_engine=SuppressionEngine(simulation_mode=True),
            max_budget=max_budget,
        )

    manager = MissionExecutionManager(repo, broadcaster, agent_factory=factory)
    scan_id = await manager.start_mission(
        TargetIdentityInput(
            full_name="Avery Mercer",
            primary_email="avery@helio.example",
            phone_numbers=["+1 (202) 555-0142"],
            current_city="Oakland",
            current_state="CA",
        ),
        max_budget=25,
    )
    task = manager._active_tasks[scan_id]
    summary = await task

    assert summary.final_state == AgentLifecycleState.COMPLETED
    assert summary.external_actions_dispatched == 0
    assert summary.remediation_plan is not None
    assert all(action.status.value == "pending" for action in summary.remediation_plan.actions)
    assert ExecutionProvenance.CONTROLLED_FIXTURE in summary.tool_provenance.values()
    assert ExecutionProvenance.FALLBACK in summary.tool_provenance.values()
    assert await repo.get_receipts(scan_id) == []

    await asyncio.sleep(0)
    await manager.shutdown()
    await repo.close()


@pytest.mark.asyncio
async def test_gemini_metadata_is_correlated_into_mission_summary() -> None:
    response_profile = ExtractedEntityProfile(
        target_id="tgt_model_proof",
        source_url="https://fixture.example/profile/avery",
        source_broker="fixture",
        matched_names=["Avery Mercer"],
        email_addresses=["avery@helio.example"],
        confidence_score=0.97,
    )
    response = SimpleNamespace(
        text=response_profile.model_dump_json(),
        parsed=None,
        response_id="resp_proof_123",
        model_version="gemini-3.7-flash-001",
        usage_metadata={"prompt_token_count": 120, "candidates_token_count": 45},
    )
    mock_client = MagicMock()
    mock_client.aio.models.generate_content = AsyncMock(return_value=response)

    agent = ProjectUmbraAgent(
        browser_scanner=PlaywrightStealthScanner(simulation_mode=True),
        extractor=StructuredExtractor(
            api_key="test-key",
            model_name="gemini-3.7-flash",
            client=mock_client,
        ),
        gemma_sanitizer=GemmaSanitizerClassifier(mode="heuristic"),
        max_budget=25,
    )
    summary = await agent.run_mission(
        TargetIdentityInput(
            full_name="Avery Mercer",
            primary_email="avery@helio.example",
        ),
        scan_id="scan_model_proof",
    )

    assert summary.final_state == AgentLifecycleState.COMPLETED
    assert summary.models_used == ["gemini-3.7-flash"]
    assert summary.model_invocations
    assert {item["response_id"] for item in summary.model_invocations} == {"resp_proof_123"}
    assert {item["model_version"] for item in summary.model_invocations} == {"gemini-3.7-flash-001"}
    assert all(item["usage"]["prompt_token_count"] == 120 for item in summary.model_invocations)
    assert summary.external_actions_dispatched == 0


@pytest.mark.asyncio
async def test_shared_genai_client_is_closed_once() -> None:
    client = MagicMock()
    client.aio.aclose = AsyncMock()
    client.close = MagicMock()
    agent = ProjectUmbraAgent(gemini_client=client)

    await agent.close()
    await agent.close()

    client.aio.aclose.assert_awaited_once()
    client.close.assert_called_once()


@pytest.mark.asyncio
async def test_genai_client_closes_even_when_another_dependency_close_fails() -> None:
    client = MagicMock()
    client.aio.aclose = AsyncMock()
    client.close = MagicMock()
    browser = MagicMock()
    browser.close = AsyncMock(side_effect=RuntimeError("browser close failed"))
    agent = ProjectUmbraAgent(browser_scanner=browser, gemini_client=client)

    with pytest.raises(RuntimeError, match="browser close failed"):
        await agent.close()

    browser.close.assert_awaited_once()
    client.aio.aclose.assert_awaited_once()
    client.close.assert_called_once()


@pytest.mark.asyncio
async def test_agent_closes_when_initial_mission_persistence_fails(tmp_path) -> None:
    repo = SQLitePersistenceRepository(db_path=str(tmp_path / "initial-save.db"))
    await repo.initialize()
    repo.save_scan = AsyncMock(side_effect=RuntimeError("initial save failed"))
    agent = ProjectUmbraAgent(max_budget=25)
    agent.close = AsyncMock()
    manager = MissionExecutionManager(
        repository=repo,
        sse_broadcaster=SSEBroadcaster(),
        agent_factory=lambda **_kwargs: agent,
    )

    with pytest.raises(RuntimeError, match="initial save failed"):
        await manager.start_mission(TargetIdentityInput(full_name="Avery Mercer"))

    agent.close.assert_awaited_once()
    await repo.close()


@pytest.mark.asyncio
async def test_initial_persistence_error_is_preserved_when_cleanup_also_fails(tmp_path) -> None:
    repo = SQLitePersistenceRepository(db_path=str(tmp_path / "initial-save-cleanup.db"))
    await repo.initialize()
    repo.save_scan = AsyncMock(side_effect=RuntimeError("initial save failed"))
    agent = ProjectUmbraAgent(max_budget=25)
    agent.close = AsyncMock(side_effect=RuntimeError("cleanup failed"))
    manager = MissionExecutionManager(
        repository=repo,
        sse_broadcaster=SSEBroadcaster(),
        agent_factory=lambda **_kwargs: agent,
    )

    with pytest.raises(RuntimeError, match="initial save failed"):
        await manager.start_mission(TargetIdentityInput(full_name="Avery Mercer"))

    agent.close.assert_awaited_once()
    await repo.close()


@pytest.mark.asyncio
async def test_sensitive_identity_and_redaction_map_are_not_emitted_in_telemetry() -> None:
    events = []
    agent = ProjectUmbraAgent(max_budget=25)
    summary = await agent.run_mission(
        TargetIdentityInput(
            full_name="Private Example",
            aliases=["Private Alias"],
            primary_email="private-person@example.com",
            phone_numbers=["+1 202 555 0199"],
            known_addresses=["141 Private Lane, Oakland, CA"],
            usernames=["@private-example"],
        ),
        event_callback=events.append,
    )

    initiated = next(event for event in events if event.event_type.value == "SCAN_INITIATED")
    sanitized = next(event for event in events if event.event_type.value == "PII_SANITIZED")
    assert "private-person@example.com" not in initiated.model_dump_json()
    assert "redaction_map" not in sanitized.model_dump_json()
    assert "private-person@example.com" not in sanitized.model_dump_json()

    serialized_events = json.dumps([event.model_dump(mode="json") for event in events])
    serialized_steps = json.dumps(
        [step.model_dump(mode="json") for step in agent._execution_log]
    )
    for sensitive_value in (
        "Private Example",
        "Private Alias",
        "private-person@example.com",
        "+1 202 555 0199",
        "141 Private Lane, Oakland, CA",
        "@private-example",
    ):
        assert sensitive_value.casefold() not in serialized_events.casefold()
        assert sensitive_value.casefold() not in serialized_steps.casefold()

    assert summary.sanitization_result is not None
    assert summary.sanitization_result.redaction_map == {}
    assert all(
        entity.original_value == "[REDACTED]"
        for entity in summary.sanitization_result.detected_entities
    )


@pytest.mark.asyncio
async def test_missing_returned_model_version_is_not_fabricated() -> None:
    response_profile = ExtractedEntityProfile(
        target_id="tgt_model_null",
        source_url="https://fixture.example/profile/avery",
        source_broker="fixture",
        matched_names=["Avery Mercer"],
    )
    response = SimpleNamespace(
        text=response_profile.model_dump_json(),
        parsed=None,
        response_id="resp-null-version",
        model_version=None,
        usage_metadata={},
    )
    client = MagicMock()
    client.aio.models.generate_content = AsyncMock(return_value=response)
    extractor = StructuredExtractor(
        api_key="test-key",
        model_name="gemini-3.7-flash",
        client=client,
    )

    profile = await extractor.extract_entities(
        "Avery Mercer avery@helio.example",
        source_url="https://fixture.example/profile/avery",
        target_id="tgt_model_null",
    )

    assert profile.extraction_model == "gemini-3.7-flash"
    assert profile.model_version is None


def _completed_summary(scan_id: str) -> AgentRunSummary:
    now = datetime.now(timezone.utc)
    return AgentRunSummary(
        run_id=scan_id,
        target_id=f"tgt_{scan_id}",
        target_name="Avery Mercer",
        started_at=now,
        completed_at=now,
        final_state=AgentLifecycleState.COMPLETED,
        total_steps_executed=1,
        budget_allocated=25,
        budget_remaining=24,
        vectors_analyzed=1,
        dorks_executed=0,
        brokers_scanned=0,
        exposures_found=0,
        pii_entities_sanitized=0,
        remediations_generated=0,
    )


@pytest.mark.asyncio
async def test_agent_closes_after_successful_worker_run(tmp_path) -> None:
    repo = SQLitePersistenceRepository(db_path=str(tmp_path / "close-success.db"))
    await repo.initialize()
    agent = ProjectUmbraAgent(max_budget=25)
    agent.run_mission = AsyncMock(return_value=_completed_summary("scan_success"))
    agent.close = AsyncMock()
    manager = MissionExecutionManager(repo, SSEBroadcaster(), agent_factory=lambda **_kwargs: agent)

    result = await manager._run_mission_worker(
        "scan_success",
        TargetIdentityInput(full_name="Avery Mercer"),
        agent,
        1.0,
        datetime.now(timezone.utc),
    )

    assert result.final_state == AgentLifecycleState.COMPLETED
    agent.close.assert_awaited_once()
    await repo.close()


@pytest.mark.asyncio
async def test_agent_closes_after_worker_timeout(tmp_path) -> None:
    repo = SQLitePersistenceRepository(db_path=str(tmp_path / "close-timeout.db"))
    await repo.initialize()
    agent = ProjectUmbraAgent(max_budget=25)

    async def never_finishes(*_args, **_kwargs):
        await asyncio.sleep(60)

    agent.run_mission = AsyncMock(side_effect=never_finishes)
    agent.close = AsyncMock()
    manager = MissionExecutionManager(repo, SSEBroadcaster(), agent_factory=lambda **_kwargs: agent)

    result = await manager._run_mission_worker(
        "scan_timeout",
        TargetIdentityInput(full_name="Avery Mercer"),
        agent,
        0.01,
        datetime.now(timezone.utc),
    )

    assert result.final_state == AgentLifecycleState.FAILED
    agent.close.assert_awaited_once()
    await repo.close()


@pytest.mark.asyncio
async def test_agent_closes_after_worker_cancellation(tmp_path) -> None:
    repo = SQLitePersistenceRepository(db_path=str(tmp_path / "close-cancel.db"))
    await repo.initialize()
    agent = ProjectUmbraAgent(max_budget=25)
    started = asyncio.Event()

    async def waits_for_cancellation(*_args, **_kwargs):
        started.set()
        await asyncio.sleep(60)

    agent.run_mission = AsyncMock(side_effect=waits_for_cancellation)
    agent.close = AsyncMock()
    manager = MissionExecutionManager(repo, SSEBroadcaster(), agent_factory=lambda **_kwargs: agent)
    task = asyncio.create_task(
        manager._run_mission_worker(
            "scan_cancel",
            TargetIdentityInput(full_name="Avery Mercer"),
            agent,
            30.0,
            datetime.now(timezone.utc),
        )
    )
    await started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    agent.close.assert_awaited_once()
    await repo.close()


@pytest.mark.asyncio
async def test_failure_details_do_not_leak_into_logs_or_sse(tmp_path, caplog) -> None:
    repo = SQLitePersistenceRepository(db_path=str(tmp_path / "close-failure.db"))
    await repo.initialize()
    agent = ProjectUmbraAgent(max_budget=25)
    sensitive_error = "provider rejected private-person@example.com using byok-secret-value"
    agent.run_mission = AsyncMock(side_effect=RuntimeError(sensitive_error))
    agent.close = AsyncMock()
    broadcaster = SSEBroadcaster()
    manager = MissionExecutionManager(repo, broadcaster, agent_factory=lambda **_kwargs: agent)

    with caplog.at_level("ERROR"):
        result = await manager._run_mission_worker(
            "scan_failure",
            TargetIdentityInput(full_name="Avery Mercer"),
            agent,
            1.0,
            datetime.now(timezone.utc),
        )

    serialized_events = json.dumps(
        [event.model_dump(mode="json") for event in broadcaster.get_history("scan_failure")]
    )
    assert result.final_state == AgentLifecycleState.FAILED
    assert sensitive_error not in caplog.text
    assert sensitive_error not in serialized_events
    assert "private-person@example.com" not in serialized_events
    assert "byok-secret-value" not in serialized_events
    agent.close.assert_awaited_once()
    await repo.close()


@pytest.mark.asyncio
async def test_caught_provider_and_cleanup_errors_do_not_log_sensitive_values(
    tmp_path,
    caplog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive_error = "private@example.com byok-secret-value"

    monkeypatch.setattr(
        "google.genai.Client",
        MagicMock(side_effect=RuntimeError(sensitive_error)),
    )
    with caplog.at_level("WARNING"):
        assert _build_genai_client("byok-secret-value") is None

        structured_client = MagicMock()
        structured_client.aio.models.generate_content = AsyncMock(
            side_effect=RuntimeError(sensitive_error)
        )
        extractor = StructuredExtractor(
            api_key="byok-secret-value",
            model_name="gemini-3.7-flash",
            client=structured_client,
        )
        await extractor.extract_entities(
            "Private Example private@example.com",
            source_url="https://example.test/profile",
            target_id="tgt_private",
        )

        serp_client = MagicMock()
        serp_client.models.generate_content.side_effect = RuntimeError(sensitive_error)
        scanner = SERPScanner(
            mode="google_genai",
            gemini_client=serp_client,
            jitter_min_ms=0,
            jitter_max_ms=0,
        )
        await scanner.execute_dork(
            DorkQuery(
                dork_id="drk_private",
                category=DorkCategory.DATA_BROKER_PROFILES,
                raw_query='"Private Example"',
                encoded_url="https://google.example/search",
                target_vector_id="vec_private",
                expected_signal="profile",
                risk_level=PriorityLevel.HIGH,
            )
        )

        browser = PlaywrightStealthScanner(simulation_mode=False)
        browser._is_initialized = True
        browser._browser = MagicMock()
        browser._browser.new_context = AsyncMock(side_effect=RuntimeError(sensitive_error))
        await browser.scan_broker(
            ProjectUmbraAgent.DEFAULT_BROKER_TARGETS[0],
            TargetIdentityInput(full_name="Private Example"),
        )

        repo = SQLitePersistenceRepository(db_path=str(tmp_path / "cleanup-log.db"))
        await repo.initialize()
        closing_agent = ProjectUmbraAgent(max_budget=25)
        closing_agent.run_mission = AsyncMock(return_value=_completed_summary("scan_close_log"))
        closing_agent.close = AsyncMock(side_effect=RuntimeError(sensitive_error))
        manager = MissionExecutionManager(repo, SSEBroadcaster())
        await manager._run_mission_worker(
            "scan_close_log",
            TargetIdentityInput(full_name="Avery Mercer"),
            closing_agent,
            1.0,
            datetime.now(timezone.utc),
        )
        await repo.close()

    assert "private@example.com" not in caplog.text
    assert "byok-secret-value" not in caplog.text
