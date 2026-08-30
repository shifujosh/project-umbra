"""
Abstract base persistence repository interface for Project Umbra.
Defines async persistence operations for missions/scans, receipts, telemetry, and findings.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from project_umbra.core.state import (
    AgentRunSummary,
    AgentTelemetryEvent,
    ExtractedEntityProfile,
    SuppressionReceipt,
)


class BasePersistenceRepository(ABC):
    """
    Abstract asynchronous persistence repository.
    Subclasses implement backend-specific persistence (e.g. SQLite, Cloud Firestore).
    """

    @property
    @abstractmethod
    def backend_type(self) -> str:
        """Return the name of the storage backend (e.g., 'sqlite', 'firestore')."""
        ...

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage engine, verify schema/indexes, and open connections."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Cleanly close database connections or client sessions."""
        ...

    async def __aenter__(self) -> BasePersistenceRepository:
        await self.initialize()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    @abstractmethod
    async def ping(self) -> bool:
        """Health check verifying storage backend connectivity."""
        ...

    # -------------------------------------------------------------------------
    # Mission / Scan Management
    # -------------------------------------------------------------------------

    @abstractmethod
    async def save_mission(self, mission: AgentRunSummary) -> None:
        """Persist or upsert an AgentRunSummary mission record."""
        ...

    @abstractmethod
    async def get_mission(self, mission_id: str) -> AgentRunSummary | None:
        """Retrieve an AgentRunSummary mission record by mission_id/run_id."""
        ...

    @abstractmethod
    async def list_missions(self, limit: int = 50, offset: int = 0) -> list[AgentRunSummary]:
        """List historical missions ordered by started_at descending."""
        ...

    @abstractmethod
    async def delete_mission(self, mission_id: str) -> bool:
        """Delete a mission record and its associated data."""
        ...

    # Aliases for scan terminology compatibility
    async def save_scan(self, scan: AgentRunSummary) -> None:
        await self.save_mission(scan)

    async def get_scan(self, scan_id: str) -> AgentRunSummary | None:
        return await self.get_mission(scan_id)

    async def list_scans(self, limit: int = 50, offset: int = 0) -> list[AgentRunSummary]:
        return await self.list_missions(limit=limit, offset=offset)

    async def delete_scan(self, scan_id: str) -> bool:
        return await self.delete_mission(scan_id)

    # -------------------------------------------------------------------------
    # Suppression Receipts
    # -------------------------------------------------------------------------

    @abstractmethod
    async def save_receipt(
        self,
        receipt_or_scan_id: SuppressionReceipt | str,
        receipt: SuppressionReceipt | None = None,
        mission_id: str | None = None,
    ) -> None:
        """Persist a SuppressionReceipt issued during remediation."""
        ...

    @abstractmethod
    async def get_receipt(self, receipt_id: str) -> SuppressionReceipt | None:
        """Retrieve a SuppressionReceipt by receipt_id."""
        ...

    @abstractmethod
    async def list_receipts(self, mission_id: str | None = None, limit: int = 50) -> list[SuppressionReceipt]:
        """List receipts, optionally filtered by mission_id."""
        ...

    async def get_receipts(self, scan_id: str | None = None) -> list[SuppressionReceipt]:
        return await self.list_receipts(mission_id=scan_id)

    # -------------------------------------------------------------------------
    # SSE Telemetry Events
    # -------------------------------------------------------------------------

    @abstractmethod
    async def save_telemetry_event(
        self,
        scan_id_or_event: str | AgentTelemetryEvent,
        event: AgentTelemetryEvent | None = None,
    ) -> None:
        """Persist an SSE telemetry event."""
        ...

    @abstractmethod
    async def list_telemetry_events(self, mission_id: str, limit: int = 100) -> list[AgentTelemetryEvent]:
        """List telemetry events for a mission/scan in chronological order."""
        ...

    async def get_telemetry_events(self, scan_id: str) -> list[AgentTelemetryEvent]:
        return await self.list_telemetry_events(mission_id=scan_id)

    # -------------------------------------------------------------------------
    # Entity Profile Findings
    # -------------------------------------------------------------------------

    @abstractmethod
    async def save_finding(self, mission_id: str, finding: ExtractedEntityProfile) -> None:
        """Persist an individual extracted entity profile finding."""
        ...

    @abstractmethod
    async def get_findings(self, mission_id: str) -> list[ExtractedEntityProfile]:
        """Retrieve all entity profile findings associated with a mission_id."""
        ...
