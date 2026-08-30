"""
Local SQLite persistence repository implementation using aiosqlite,
WAL mode, automated schema migration, and Pydantic v2 JSON serialization.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import os
from pathlib import Path
from typing import Any
import uuid
import aiosqlite

from project_umbra.config import settings
from project_umbra.core.state import (
    AgentRunSummary,
    AgentTelemetryEvent,
    ExtractedEntityProfile,
    SuppressionReceipt,
)
from project_umbra.storage.base import BasePersistenceRepository

logger = logging.getLogger(__name__)


class SQLitePersistenceRepository(BasePersistenceRepository):
    """
    Asynchronous SQLite repository with WAL mode, indexing, and schema auto-migration.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or settings.SQLITE_DB_PATH
        self._db: aiosqlite.Connection | None = None
        self._initialized = False

    @property
    def backend_type(self) -> str:
        return "sqlite"

    async def _get_conn(self) -> aiosqlite.Connection:
        if self._db is None:
            await self.initialize()
        assert self._db is not None
        return self._db

    async def initialize(self) -> None:
        if self._initialized and self._db is not None:
            return

        if self.db_path != ":memory:":
            db_dir = os.path.dirname(os.path.abspath(self.db_path))
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)

        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row

        # Concurrency & Performance PRAGMAs
        await self._db.execute("PRAGMA journal_mode = WAL;")
        await self._db.execute("PRAGMA synchronous = NORMAL;")
        await self._db.execute("PRAGMA foreign_keys = ON;")
        await self._db.execute("PRAGMA busy_timeout = 5000;")
        await self._db.commit()

        await self._apply_migrations()
        self._initialized = True
        logger.info(f"SQLite repository initialized at {self.db_path} (WAL mode enabled)")

    async def _apply_migrations(self) -> None:
        assert self._db is not None
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL,
                description TEXT
            );
        """)
        await self._db.commit()

        async with self._db.execute("SELECT version FROM schema_migrations WHERE version = 1") as cursor:
            row = await cursor.fetchone()
            if not row:
                logger.info("Applying SQLite persistence schema migration v1...")
                # Create tables & indexes
                await self._db.execute("""
                    CREATE TABLE IF NOT EXISTS missions (
                        mission_id TEXT PRIMARY KEY,
                        target_id TEXT NOT NULL,
                        target_name TEXT NOT NULL,
                        started_at TEXT NOT NULL,
                        completed_at TEXT,
                        final_state TEXT NOT NULL,
                        total_steps_executed INTEGER DEFAULT 0,
                        budget_allocated INTEGER DEFAULT 25,
                        budget_remaining INTEGER DEFAULT 0,
                        vectors_analyzed INTEGER DEFAULT 0,
                        dorks_executed INTEGER DEFAULT 0,
                        brokers_scanned INTEGER DEFAULT 0,
                        exposures_found INTEGER DEFAULT 0,
                        pii_entities_sanitized INTEGER DEFAULT 0,
                        remediations_generated INTEGER DEFAULT 0,
                        raw_data TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                """)
                await self._db.execute("CREATE INDEX IF NOT EXISTS idx_missions_target_id ON missions(target_id);")
                await self._db.execute("CREATE INDEX IF NOT EXISTS idx_missions_started_at ON missions(started_at DESC);")

                await self._db.execute("""
                    CREATE TABLE IF NOT EXISTS receipts (
                        receipt_id TEXT PRIMARY KEY,
                        mission_id TEXT,
                        remediation_id TEXT NOT NULL,
                        broker_name TEXT NOT NULL,
                        notice_type TEXT NOT NULL,
                        status TEXT NOT NULL,
                        submission_timestamp TEXT NOT NULL,
                        compliance_deadline TEXT NOT NULL,
                        tracking_reference TEXT NOT NULL,
                        response_code INTEGER DEFAULT 200,
                        confirmation_message TEXT,
                        raw_data TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                """)
                await self._db.execute("CREATE INDEX IF NOT EXISTS idx_receipts_mission_id ON receipts(mission_id);")
                await self._db.execute("CREATE INDEX IF NOT EXISTS idx_receipts_submission_timestamp ON receipts(submission_timestamp DESC);")

                await self._db.execute("""
                    CREATE TABLE IF NOT EXISTS telemetry_events (
                        event_id TEXT PRIMARY KEY,
                        mission_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        state TEXT NOT NULL,
                        message TEXT NOT NULL,
                        step_number INTEGER NOT NULL,
                        budget_remaining INTEGER NOT NULL,
                        raw_data TEXT NOT NULL
                    );
                """)
                await self._db.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_mission_id_timestamp ON telemetry_events(mission_id, timestamp ASC);")

                await self._db.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        finding_id TEXT PRIMARY KEY,
                        mission_id TEXT NOT NULL,
                        target_id TEXT NOT NULL,
                        source_broker TEXT,
                        source_url TEXT NOT NULL,
                        confidence_score REAL DEFAULT 0.9,
                        raw_data TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                """)
                await self._db.execute("CREATE INDEX IF NOT EXISTS idx_findings_mission_id ON findings(mission_id);")

                now_iso = datetime.now(timezone.utc).isoformat()
                await self._db.execute(
                    "INSERT INTO schema_migrations (version, applied_at, description) VALUES (?, ?, ?)",
                    (1, now_iso, "Initial dual-mode persistence tables and indexes"),
                )
                await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None
            self._initialized = False

    async def ping(self) -> bool:
        if not self._initialized or self._db is None:
            await self.initialize()
        try:
            assert self._db is not None
            async with self._db.execute("SELECT 1") as cursor:
                row = await cursor.fetchone()
                return row is not None and row[0] == 1
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # Mission / Scan Management
    # -------------------------------------------------------------------------

    async def save_mission(self, mission: AgentRunSummary) -> None:
        db = await self._get_conn()

        now_iso = datetime.now(timezone.utc).isoformat()
        started_iso = mission.started_at.isoformat() if mission.started_at else now_iso
        completed_iso = mission.completed_at.isoformat() if mission.completed_at else None
        raw_json = mission.model_dump_json()

        query = """
            INSERT INTO missions (
                mission_id, target_id, target_name, started_at, completed_at,
                final_state, total_steps_executed, budget_allocated, budget_remaining,
                vectors_analyzed, dorks_executed, brokers_scanned, exposures_found,
                pii_entities_sanitized, remediations_generated, raw_data, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mission_id) DO UPDATE SET
                target_id = excluded.target_id,
                target_name = excluded.target_name,
                completed_at = excluded.completed_at,
                final_state = excluded.final_state,
                total_steps_executed = excluded.total_steps_executed,
                budget_remaining = excluded.budget_remaining,
                vectors_analyzed = excluded.vectors_analyzed,
                dorks_executed = excluded.dorks_executed,
                brokers_scanned = excluded.brokers_scanned,
                exposures_found = excluded.exposures_found,
                pii_entities_sanitized = excluded.pii_entities_sanitized,
                remediations_generated = excluded.remediations_generated,
                raw_data = excluded.raw_data,
                updated_at = excluded.updated_at;
        """
        await db.execute(
            query,
            (
                mission.run_id,
                mission.target_id,
                mission.target_name,
                started_iso,
                completed_iso,
                mission.final_state.value if hasattr(mission.final_state, "value") else str(mission.final_state),
                mission.total_steps_executed,
                mission.budget_allocated,
                mission.budget_remaining,
                mission.vectors_analyzed,
                mission.dorks_executed,
                mission.brokers_scanned,
                mission.exposures_found,
                mission.pii_entities_sanitized,
                mission.remediations_generated,
                raw_json,
                now_iso,
                now_iso,
            ),
        )

        for finding in mission.findings:
            await self.save_finding(mission.run_id, finding)

        await db.commit()

    async def get_mission(self, mission_id: str) -> AgentRunSummary | None:
        db = await self._get_conn()

        async with db.execute("SELECT raw_data FROM missions WHERE mission_id = ?", (mission_id,)) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            return AgentRunSummary.model_validate_json(row["raw_data"])

    async def list_missions(self, limit: int = 50, offset: int = 0) -> list[AgentRunSummary]:
        db = await self._get_conn()

        async with db.execute(
            "SELECT raw_data FROM missions ORDER BY started_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()
            return [AgentRunSummary.model_validate_json(r["raw_data"]) for r in rows]

    async def delete_mission(self, mission_id: str) -> bool:
        db = await self._get_conn()
        await db.execute("DELETE FROM findings WHERE mission_id = ?", (mission_id,))
        await db.execute("DELETE FROM receipts WHERE mission_id = ?", (mission_id,))
        await db.execute("DELETE FROM telemetry_events WHERE mission_id = ?", (mission_id,))
        cursor = await db.execute("DELETE FROM missions WHERE mission_id = ?", (mission_id,))
        await db.commit()
        return cursor.rowcount > 0

    # -------------------------------------------------------------------------
    # Suppression Receipts
    # -------------------------------------------------------------------------

    async def save_receipt(
        self,
        receipt_or_scan_id: SuppressionReceipt | str,
        receipt: SuppressionReceipt | None = None,
        mission_id: str | None = None,
    ) -> None:
        db = await self._get_conn()

        if isinstance(receipt_or_scan_id, SuppressionReceipt):
            target_receipt = receipt_or_scan_id
            target_mission_id = mission_id or (receipt if isinstance(receipt, str) else None)
        elif isinstance(receipt, SuppressionReceipt):
            target_receipt = receipt
            target_mission_id = str(receipt_or_scan_id)
        else:
            raise ValueError("Invalid parameters for save_receipt: must provide SuppressionReceipt")

        now_iso = datetime.now(timezone.utc).isoformat()
        sub_iso = target_receipt.submission_timestamp.isoformat()
        dead_iso = target_receipt.compliance_deadline.isoformat()
        raw_json = target_receipt.model_dump_json()

        query = """
            INSERT INTO receipts (
                receipt_id, mission_id, remediation_id, broker_name, notice_type,
                status, submission_timestamp, compliance_deadline, tracking_reference,
                response_code, confirmation_message, raw_data, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO UPDATE SET
                mission_id = COALESCE(excluded.mission_id, receipts.mission_id),
                status = excluded.status,
                response_code = excluded.response_code,
                confirmation_message = excluded.confirmation_message,
                raw_data = excluded.raw_data;
        """
        await db.execute(
            query,
            (
                target_receipt.receipt_id,
                target_mission_id,
                target_receipt.remediation_id,
                target_receipt.broker_name,
                target_receipt.notice_type,
                target_receipt.status,
                sub_iso,
                dead_iso,
                target_receipt.tracking_reference,
                target_receipt.response_code,
                target_receipt.confirmation_message,
                raw_json,
                now_iso,
            ),
        )
        await db.commit()

    async def get_receipt(self, receipt_id: str) -> SuppressionReceipt | None:
        db = await self._get_conn()

        async with db.execute("SELECT raw_data FROM receipts WHERE receipt_id = ?", (receipt_id,)) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            return SuppressionReceipt.model_validate_json(row["raw_data"])

    async def list_receipts(self, mission_id: str | None = None, limit: int = 50) -> list[SuppressionReceipt]:
        db = await self._get_conn()

        if mission_id:
            query = "SELECT raw_data FROM receipts WHERE mission_id = ? ORDER BY submission_timestamp DESC LIMIT ?"
            params = (mission_id, limit)
        else:
            query = "SELECT raw_data FROM receipts ORDER BY submission_timestamp DESC LIMIT ?"
            params = (limit,)

        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [SuppressionReceipt.model_validate_json(r["raw_data"]) for r in rows]

    # -------------------------------------------------------------------------
    # SSE Telemetry Events
    # -------------------------------------------------------------------------

    async def save_telemetry_event(
        self,
        scan_id_or_event: str | AgentTelemetryEvent,
        event: AgentTelemetryEvent | None = None,
    ) -> None:
        db = await self._get_conn()

        if isinstance(scan_id_or_event, AgentTelemetryEvent):
            target_event = scan_id_or_event
            target_mission_id = target_event.scan_id
        elif isinstance(event, AgentTelemetryEvent):
            target_event = event
            target_mission_id = str(scan_id_or_event)
        else:
            raise ValueError("Invalid parameters for save_telemetry_event: must provide AgentTelemetryEvent")

        ts_iso = target_event.timestamp.isoformat()
        raw_json = target_event.model_dump_json()

        query = """
            INSERT INTO telemetry_events (
                event_id, mission_id, timestamp, event_type, state,
                message, step_number, budget_remaining, raw_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO NOTHING;
        """
        await db.execute(
            query,
            (
                target_event.event_id,
                target_mission_id,
                ts_iso,
                target_event.event_type.value if hasattr(target_event.event_type, "value") else str(target_event.event_type),
                target_event.state.value if hasattr(target_event.state, "value") else str(target_event.state),
                target_event.message,
                target_event.step_number,
                target_event.budget_remaining,
                raw_json,
            ),
        )
        await db.commit()

    async def list_telemetry_events(self, mission_id: str, limit: int = 100) -> list[AgentTelemetryEvent]:
        db = await self._get_conn()

        async with db.execute(
            "SELECT raw_data FROM telemetry_events WHERE mission_id = ? ORDER BY timestamp ASC LIMIT ?",
            (mission_id, limit),
        ) as cursor:
            rows = await cursor.fetchall()
            return [AgentTelemetryEvent.model_validate_json(r["raw_data"]) for r in rows]

    # -------------------------------------------------------------------------
    # Entity Profile Findings
    # -------------------------------------------------------------------------

    async def save_finding(self, mission_id: str, finding: ExtractedEntityProfile) -> None:
        db = await self._get_conn()

        finding_id = f"fnd_{uuid.uuid5(uuid.NAMESPACE_URL, f'{mission_id}:{finding.source_url}').hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        raw_json = finding.model_dump_json()

        query = """
            INSERT INTO findings (
                finding_id, mission_id, target_id, source_broker,
                source_url, confidence_score, raw_data, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
                confidence_score = excluded.confidence_score,
                raw_data = excluded.raw_data;
        """
        await db.execute(
            query,
            (
                finding_id,
                mission_id,
                finding.target_id,
                finding.source_broker,
                finding.source_url,
                finding.confidence_score,
                raw_json,
                now_iso,
            ),
        )
        await db.commit()

    async def get_findings(self, mission_id: str) -> list[ExtractedEntityProfile]:
        db = await self._get_conn()

        async with db.execute("SELECT raw_data FROM findings WHERE mission_id = ?", (mission_id,)) as cursor:
            rows = await cursor.fetchall()
            return [ExtractedEntityProfile.model_validate_json(r["raw_data"]) for r in rows]
