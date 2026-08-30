"""
Unit and Integration Tests for Project Umbra Dual-Mode Persistence (Tiers 1-5).
Covers SQLite WAL mode, migrations, CRUD operations, Firestore async repository (mocked),
dynamic storage resolver fallback, and high-concurrency stress testing.
"""

from __future__ import annotations

import json
from pathlib import Path
import asyncio
from datetime import datetime, timezone
import os
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import pytest_asyncio

from project_umbra.core.state import (
    AgentLifecycleState,
    AgentRunSummary,
    AgentStepRecord,
    AgentTelemetryEvent,
    ExtractedEntityProfile,
    PIISanitizationResult,
    SuppressionActionPlan,
    SuppressionPayload,
    SuppressionReceipt,
    SuppressionStatus,
    TelemetryEventType,
)
from project_umbra.storage.firestore import FirestorePersistenceRepository
from project_umbra.storage.resolver import (
    get_default_repository,
    get_persistence_repository,
    get_storage_repository,
    reset_default_repository,
)
from project_umbra.storage.sqlite import SQLitePersistenceRepository


@pytest.fixture
def sample_summary() -> AgentRunSummary:
    now = datetime.now(timezone.utc)
    return AgentRunSummary(
        run_id="scan_test123",
        target_id="tgt_test123",
        target_name="Marcus Brody",
        started_at=now,
        completed_at=now,
        final_state=AgentLifecycleState.COMPLETED,
        total_steps_executed=5,
        budget_allocated=25,
        budget_remaining=20,
        vectors_analyzed=4,
        dorks_executed=3,
        brokers_scanned=2,
        exposures_found=2,
        pii_entities_sanitized=1,
        remediations_generated=1,
        findings=[
            ExtractedEntityProfile(
                target_id="tgt_test123",
                source_url="https://mockbroker.com/p/mbrody",
                source_broker="mockbroker.com",
                matched_names=["Marcus Brody"],
                age="42",
                phone_numbers=["(555) 123-4567"],
                email_addresses=["mbrody@example.com"],
                confidence_score=0.95,
            )
        ],
        sanitization_result=PIISanitizationResult(
            sanitized_text="<PERSON_1> lives at <LOCATION_1>",
            detected_entities=[],
            redaction_map={"<PERSON_1>": "Marcus Brody", "<LOCATION_1>": "123 Elm St"},
            critical_pii_count=0,
            total_pii_count=2,
            overall_risk_score=25.0,
        ),
        remediation_plan=SuppressionActionPlan(
            target_id="tgt_test123",
            actions=[
                SuppressionPayload(
                    remediation_id="rem_001",
                    broker_id="mockbroker",
                    broker_name="MockBroker",
                    opt_out_type="automated_form",
                    submission_url="https://mockbroker.com/optout",
                    status=SuppressionStatus.SUBMITTED,
                )
            ],
            total_actions=1,
        ),
        execution_state_log=[
            AgentStepRecord(
                step_number=1,
                state=AgentLifecycleState.SCANNING_SERP,
                thought="Searching for exposures",
                tool_name="serp_scanner",
                step_duration_ms=120.0,
                budget_remaining=24,
            )
        ],
    )


@pytest.fixture
def sample_receipt() -> SuppressionReceipt:
    now = datetime.now(timezone.utc)
    return SuppressionReceipt(
        receipt_id="rcpt_test_001",
        remediation_id="rem_001",
        broker_name="MockBroker",
        notice_type="automated_form",
        status="CONFIRMED",
        submission_timestamp=now,
        compliance_deadline=now,
        tracking_reference="TRK-MOCK-001",
        response_code=200,
        confirmation_message="Opt-out request submitted successfully.",
    )


@pytest.fixture
def sample_telemetry() -> AgentTelemetryEvent:
    return AgentTelemetryEvent(
        event_id="evt_test_001",
        scan_id="scan_test123",
        timestamp=datetime.now(timezone.utc),
        event_type=TelemetryEventType.SCAN_INITIATED,
        state=AgentLifecycleState.INITIALIZED,
        message="Scan initiated for target Marcus Brody",
        step_number=0,
        budget_remaining=25,
        payload={"target": "Marcus Brody"},
    )


# ==============================================================================
# Tier 1: SQLite Persistence Repository Lifecycle & Migration
# ==============================================================================

@pytest.mark.asyncio
async def test_sqlite_wal_mode_and_migration_v1(tmp_path):
    db_path = str(tmp_path / "test_lifecycle.db")
    repo = SQLitePersistenceRepository(db_path=db_path)
    assert repo.backend_type == "sqlite"

    await repo.initialize()
    assert await repo.ping() is True

    # Verify WAL mode on connection
    async with repo._db.execute("PRAGMA journal_mode;") as cursor:
        row = await cursor.fetchone()
        assert row[0].lower() == "wal"

    # Verify tables created
    async with repo._db.execute("SELECT name FROM sqlite_master WHERE type='table';") as cursor:
        tables = [r[0] for r in await cursor.fetchall()]
        assert "schema_migrations" in tables
        assert "missions" in tables
        assert "receipts" in tables
        assert "telemetry_events" in tables
        assert "findings" in tables

    # Verify migration recorded
    async with repo._db.execute("SELECT version FROM schema_migrations;") as cursor:
        row = await cursor.fetchone()
        assert row[0] == 1

    await repo.close()


@pytest.mark.asyncio
async def test_sqlite_context_manager_lifecycle(tmp_path):
    db_path = str(tmp_path / "test_ctx.db")
    async with SQLitePersistenceRepository(db_path=db_path) as repo:
        assert await repo.ping() is True
    assert repo._db is None


# ==============================================================================
# Tier 2: SQLite CRUD & Pydantic Data Integrity
# ==============================================================================

@pytest.mark.asyncio
async def test_sqlite_save_and_get_mission(tmp_path, sample_summary: AgentRunSummary):
    db_path = str(tmp_path / "test_crud.db")
    async with SQLitePersistenceRepository(db_path=db_path) as repo:
        await repo.save_mission(sample_summary)

        fetched = await repo.get_mission(sample_summary.run_id)
        assert fetched is not None
        assert fetched.run_id == sample_summary.run_id
        assert fetched.target_name == sample_summary.target_name
        assert fetched.final_state == sample_summary.final_state
        assert len(fetched.findings) == 1
        assert fetched.findings[0].source_broker == "mockbroker.com"
        assert fetched.sanitization_result is not None
        assert fetched.sanitization_result.total_pii_count == 2
        assert fetched.remediation_plan is not None
        assert len(fetched.execution_state_log) == 1

        # Also verify scan aliases
        fetched_alias = await repo.get_scan(sample_summary.run_id)
        assert fetched_alias is not None
        assert fetched_alias.run_id == sample_summary.run_id


@pytest.mark.asyncio
async def test_sqlite_mission_upsert_overwrite(tmp_path, sample_summary: AgentRunSummary):
    db_path = str(tmp_path / "test_upsert.db")
    async with SQLitePersistenceRepository(db_path=db_path) as repo:
        await repo.save_mission(sample_summary)

        # Modify summary and re-save
        sample_summary.total_steps_executed = 15
        sample_summary.budget_remaining = 10
        await repo.save_mission(sample_summary)

        updated = await repo.get_mission(sample_summary.run_id)
        assert updated is not None
        assert updated.total_steps_executed == 15
        assert updated.budget_remaining == 10

        # Verify only 1 row exists
        missions = await repo.list_missions()
        assert len(missions) == 1


@pytest.mark.asyncio
async def test_sqlite_list_missions_sorting_and_pagination(tmp_path, sample_summary: AgentRunSummary):
    db_path = str(tmp_path / "test_list.db")
    async with SQLitePersistenceRepository(db_path=db_path) as repo:
        # Save 5 missions with increasing timestamps
        for i in range(5):
            m = sample_summary.model_copy(deep=True)
            m.run_id = f"scan_{i}"
            m.started_at = datetime.fromtimestamp(1700000000 + i * 100, timezone.utc)
            await repo.save_mission(m)

        # List with limit 3
        page1 = await repo.list_missions(limit=3, offset=0)
        assert len(page1) == 3
        assert page1[0].run_id == "scan_4"  # Descending order
        assert page1[1].run_id == "scan_3"
        assert page1[2].run_id == "scan_2"

        # List next page
        page2 = await repo.list_missions(limit=3, offset=3)
        assert len(page2) == 2
        assert page2[0].run_id == "scan_1"
        assert page2[1].run_id == "scan_0"


@pytest.mark.asyncio
async def test_sqlite_save_and_list_receipts(tmp_path, sample_receipt: SuppressionReceipt):
    db_path = str(tmp_path / "test_receipts.db")
    async with SQLitePersistenceRepository(db_path=db_path) as repo:
        r1 = sample_receipt.model_copy(deep=True)
        r1.receipt_id = "rcpt_1"
        r2 = sample_receipt.model_copy(deep=True)
        r2.receipt_id = "rcpt_2"

        await repo.save_receipt("scan_alpha", r1)
        await repo.save_receipt(r2, mission_id="scan_beta")

        fetched_r1 = await repo.get_receipt("rcpt_1")
        assert fetched_r1 is not None
        assert fetched_r1.receipt_id == "rcpt_1"

        alpha_receipts = await repo.list_receipts(mission_id="scan_alpha")
        assert len(alpha_receipts) == 1
        assert alpha_receipts[0].receipt_id == "rcpt_1"

        all_receipts = await repo.list_receipts()
        assert len(all_receipts) == 2


@pytest.mark.asyncio
async def test_sqlite_save_and_list_telemetry_events(tmp_path, sample_telemetry: AgentTelemetryEvent):
    db_path = str(tmp_path / "test_telemetry.db")
    async with SQLitePersistenceRepository(db_path=db_path) as repo:
        for i in range(3):
            evt = sample_telemetry.model_copy(deep=True)
            evt.event_id = f"evt_{i}"
            evt.step_number = i
            evt.timestamp = datetime.fromtimestamp(1700000000 + i * 10, timezone.utc)
            await repo.save_telemetry_event(evt)

        events = await repo.list_telemetry_events("scan_test123")
        assert len(events) == 3
        assert events[0].event_id == "evt_0"
        assert events[2].event_id == "evt_2"


@pytest.mark.asyncio
async def test_sqlite_save_and_get_findings(tmp_path):
    db_path = str(tmp_path / "test_findings.db")
    async with SQLitePersistenceRepository(db_path=db_path) as repo:
        f1 = ExtractedEntityProfile(
            target_id="tgt_1",
            source_url="https://broker1.com/p/1",
            source_broker="broker1",
            matched_names=["Target One"],
        )
        f2 = ExtractedEntityProfile(
            target_id="tgt_1",
            source_url="https://broker2.com/p/1",
            source_broker="broker2",
            matched_names=["Target One"],
        )
        await repo.save_finding("scan_fnd_1", f1)
        await repo.save_finding("scan_fnd_1", f2)

        findings = await repo.get_findings("scan_fnd_1")
        assert len(findings) == 2
        sources = {f.source_broker for f in findings}
        assert sources == {"broker1", "broker2"}


@pytest.mark.asyncio
async def test_sqlite_get_nonexistent_returns_none(tmp_path):
    db_path = str(tmp_path / "test_empty.db")
    async with SQLitePersistenceRepository(db_path=db_path) as repo:
        assert await repo.get_mission("nonexistent") is None
        assert await repo.get_receipt("nonexistent") is None
        assert await repo.get_findings("nonexistent") == []
        assert await repo.list_telemetry_events("nonexistent") == []


@pytest.mark.asyncio
async def test_sqlite_delete_mission(tmp_path, sample_summary: AgentRunSummary, sample_receipt: SuppressionReceipt):
    db_path = str(tmp_path / "test_delete.db")
    async with SQLitePersistenceRepository(db_path=db_path) as repo:
        await repo.save_mission(sample_summary)
        await repo.save_receipt("scan_test123", sample_receipt)

        assert await repo.get_mission("scan_test123") is not None
        deleted = await repo.delete_mission("scan_test123")
        assert deleted is True
        assert await repo.get_mission("scan_test123") is None
        assert await repo.list_receipts("scan_test123") == []


# ==============================================================================
# Tier 3: Firestore Persistence Repository (Mocked AsyncClient)
# ==============================================================================

@pytest.mark.asyncio
async def test_firestore_save_and_get_mission_mocked(sample_summary: AgentRunSummary):
    mock_client = MagicMock()
    mock_doc_ref = MagicMock()
    mock_doc_ref.set = AsyncMock()

    mock_doc = MagicMock()
    mock_doc.exists = True
    mock_doc.to_dict.return_value = sample_summary.model_dump(mode="json")
    mock_doc_ref.get = AsyncMock(return_value=mock_doc)

    mock_collection = MagicMock()
    mock_collection.document.return_value = mock_doc_ref
    mock_client.collection.return_value = mock_collection

    repo = FirestorePersistenceRepository(client=mock_client)
    assert repo.backend_type == "firestore"

    await repo.save_mission(sample_summary)
    mock_doc_ref.set.assert_awaited()

    fetched = await repo.get_mission(sample_summary.run_id)
    assert fetched is not None
    assert fetched.run_id == sample_summary.run_id
    assert fetched.target_name == sample_summary.target_name


@pytest.mark.asyncio
async def test_firestore_save_and_get_receipt_mocked(sample_receipt: SuppressionReceipt):
    mock_client = MagicMock()
    mock_doc_ref = MagicMock()
    mock_doc_ref.set = AsyncMock()

    mock_doc = MagicMock()
    mock_doc.exists = True
    mock_doc.to_dict.return_value = sample_receipt.model_dump(mode="json")
    mock_doc_ref.get = AsyncMock(return_value=mock_doc)

    mock_client.collection.return_value.document.return_value = mock_doc_ref

    repo = FirestorePersistenceRepository(client=mock_client)
    await repo.save_receipt("scan_test", sample_receipt)
    mock_doc_ref.set.assert_awaited()

    fetched = await repo.get_receipt("rcpt_test_001")
    assert fetched is not None
    assert fetched.receipt_id == "rcpt_test_001"


@pytest.mark.asyncio
async def test_firestore_ping_and_close():
    mock_client = MagicMock()
    mock_client.close = AsyncMock()

    async def async_iter():
        yield MagicMock()

    mock_stream = MagicMock()
    mock_stream.__aiter__ = lambda s: async_iter()
    mock_client.collection.return_value.limit.return_value.stream.return_value = mock_stream

    repo = FirestorePersistenceRepository(client=mock_client)
    assert await repo.ping() is True

    await repo.close()
    mock_client.close.assert_awaited()
    assert repo._client is None


@pytest.mark.asyncio
async def test_firestore_initialize_performs_rpc_probe(monkeypatch: pytest.MonkeyPatch):
    mock_client = MagicMock()

    async def async_iter():
        yield MagicMock()

    mock_stream = MagicMock()
    mock_stream.__aiter__ = lambda _self: async_iter()
    mock_client.collection.return_value.limit.return_value.stream.return_value = mock_stream
    monkeypatch.setattr("google.cloud.firestore.AsyncClient", MagicMock(return_value=mock_client))

    repo = FirestorePersistenceRepository(project_id="test-project")
    await repo.initialize()

    mock_client.collection.assert_called_with("missions")
    mock_client.collection.return_value.limit.assert_called_with(1)
    assert repo._initialized is True


@pytest.mark.asyncio
async def test_firestore_initialize_fails_hard_when_rpc_probe_fails(monkeypatch: pytest.MonkeyPatch):
    mock_client = MagicMock()

    async def failing_iter():
        raise ConnectionError("Firestore unavailable")
        yield  # pragma: no cover

    mock_stream = MagicMock()
    mock_stream.__aiter__ = lambda _self: failing_iter()
    mock_client.collection.return_value.limit.return_value.stream.return_value = mock_stream
    mock_client.close = AsyncMock()
    monkeypatch.setattr("google.cloud.firestore.AsyncClient", MagicMock(return_value=mock_client))

    repo = FirestorePersistenceRepository(project_id="test-project")
    with pytest.raises(ConnectionError, match="Firestore unavailable"):
        await repo.initialize()

    assert repo._initialized is False
    assert repo._client is None


def test_firestore_compound_indexes_are_declared() -> None:
    config_path = Path(__file__).resolve().parents[1] / "firestore.indexes.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    declared = {
        (
            entry["collectionGroup"],
            tuple((field["fieldPath"], field["order"]) for field in entry["fields"]),
        )
        for entry in config["indexes"]
    }

    assert (
        "receipts",
        (("mission_id", "ASCENDING"), ("submission_timestamp", "DESCENDING")),
    ) in declared
    assert (
        "telemetry",
        (("scan_id", "ASCENDING"), ("timestamp", "ASCENDING")),
    ) in declared


# ==============================================================================
# Tier 4: Dynamic Resolver & Fallback Logic
# ==============================================================================

def test_resolver_explicit_sqlite_mode():
    repo = get_persistence_repository(mode="sqlite", db_path=":memory:")
    assert isinstance(repo, SQLitePersistenceRepository)
    assert repo.backend_type == "sqlite"


def test_resolver_explicit_firestore_mode():
    repo = get_persistence_repository(mode="firestore", project_id="test-proj")
    assert isinstance(repo, FirestorePersistenceRepository)
    assert repo.backend_type == "firestore"


def test_resolver_auto_mode_fallback_when_unauthenticated(monkeypatch):
    # Ensure no GCP credentials in environment
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)

    repo = get_persistence_repository(mode="auto")
    assert isinstance(repo, SQLitePersistenceRepository)
    assert repo.backend_type == "sqlite"


@pytest.mark.asyncio
async def test_resolver_singleton_lifecycle():
    await reset_default_repository()
    repo1 = await get_default_repository()
    repo2 = await get_default_repository()
    assert repo1 is repo2
    await reset_default_repository()


# ==============================================================================
# Tier 5: Concurrency, Performance & Resilience
# ==============================================================================

@pytest.mark.asyncio
async def test_sqlite_concurrent_async_writes_wal(tmp_path):
    db_path = str(tmp_path / "test_concurrent.db")
    async with SQLitePersistenceRepository(db_path=db_path) as repo:
        now = datetime.now(timezone.utc)

        async def write_event(idx: int):
            evt = AgentTelemetryEvent(
                event_id=f"evt_conc_{idx}",
                scan_id="scan_concurrent",
                timestamp=now,
                event_type=TelemetryEventType.TOOL_COMPLETE,
                state=AgentLifecycleState.SCANNING_SERP,
                message=f"Concurrent event {idx}",
                step_number=idx,
                budget_remaining=25 - idx,
            )
            await repo.save_telemetry_event(evt)

        # Dispatch 50 concurrent writes
        tasks = [write_event(i) for i in range(50)]
        await asyncio.gather(*tasks)

        events = await repo.list_telemetry_events("scan_concurrent", limit=100)
        assert len(events) == 50


@pytest.mark.asyncio
async def test_sqlite_auto_creates_missing_nested_directories(tmp_path):
    nested_path = str(tmp_path / "deeply" / "nested" / "dir" / "ghost.db")
    repo = SQLitePersistenceRepository(db_path=nested_path)
    await repo.initialize()
    assert os.path.exists(nested_path)
    assert await repo.ping() is True
    await repo.close()
