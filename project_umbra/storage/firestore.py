"""
Google Cloud Firestore asynchronous persistence repository implementation.
Uses google-cloud-firestore AsyncClient with collection indexing for Cloud Run execution.
"""

from __future__ import annotations

import logging
from typing import Any
import uuid

from project_umbra.config import settings
from project_umbra.core.state import (
    AgentRunSummary,
    AgentTelemetryEvent,
    ExtractedEntityProfile,
    SuppressionReceipt,
)
from project_umbra.storage.base import BasePersistenceRepository

logger = logging.getLogger(__name__)


class FirestorePersistenceRepository(BasePersistenceRepository):
    """
    Asynchronous Google Cloud Firestore repository using AsyncClient.
    """

    def __init__(
        self,
        project_id: str | None = None,
        database: str | None = None,
        credentials: Any | None = None,
        client: Any | None = None,
    ) -> None:
        self.project_id = project_id or settings.GCP_PROJECT_ID
        self.database = database or settings.FIRESTORE_DATABASE
        self.credentials = credentials
        self._client = client
        self._initialized = client is not None

    @property
    def backend_type(self) -> str:
        return "firestore"

    async def initialize(self) -> None:
        try:
            if self._client is None:
                from google.cloud.firestore import AsyncClient
                self._client = AsyncClient(
                    project=self.project_id,
                    database=self.database,
                    credentials=self.credentials,
                )
            await self._probe()
            self._initialized = True
            logger.info(f"Firestore repository initialized (project={self.project_id}, database={self.database})")
        except Exception as e:
            await self._close_client()
            logger.error(
                "Failed to initialize Firestore AsyncClient (%s)",
                type(e).__name__,
            )
            raise

    async def _probe(self) -> None:
        """Perform a real Firestore RPC, consuming the stream to surface failures."""
        if self._client is None:
            raise RuntimeError("Firestore client is not initialized")
        docs = self._client.collection("missions").limit(1).stream()
        async for _ in docs:
            break

    async def _close_client(self) -> None:
        client = self._client
        self._client = None
        self._initialized = False
        if client is not None and hasattr(client, "close"):
            result = client.close()
            if hasattr(result, "__await__"):
                await result

    async def close(self) -> None:
        await self._close_client()

    async def ping(self) -> bool:
        if not self._initialized or self._client is None:
            try:
                await self.initialize()
            except Exception:
                return False
        try:
            await self._probe()
            return True
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # Missions
    # -------------------------------------------------------------------------

    async def save_mission(self, mission: AgentRunSummary) -> None:
        if not self._initialized or self._client is None:
            await self.initialize()
        assert self._client is not None

        doc_ref = self._client.collection("missions").document(mission.run_id)
        payload = mission.model_dump(mode="json")
        await doc_ref.set(payload)


    async def get_mission(self, mission_id: str) -> AgentRunSummary | None:
        if not self._initialized or self._client is None:
            await self.initialize()
        assert self._client is not None

        doc_ref = self._client.collection("missions").document(mission_id)
        doc = await doc_ref.get()
        if not doc.exists:
            return None
        return AgentRunSummary.model_validate(doc.to_dict())

    async def list_missions(self, limit: int = 50, offset: int = 0) -> list[AgentRunSummary]:
        if not self._initialized or self._client is None:
            await self.initialize()
        assert self._client is not None

        from google.cloud.firestore import Query
        query = (
            self._client.collection("missions")
            .order_by("started_at", direction=Query.DESCENDING)
            .offset(offset)
            .limit(limit)
        )
        missions: list[AgentRunSummary] = []
        async for doc in query.stream():
            missions.append(AgentRunSummary.model_validate(doc.to_dict()))
        return missions

    async def delete_mission(self, mission_id: str) -> bool:
        if not self._initialized or self._client is None:
            await self.initialize()
        assert self._client is not None

        doc_ref = self._client.collection("missions").document(mission_id)
        doc = await doc_ref.get()
        if not doc.exists:
            return False
        await doc_ref.delete()
        return True

    # -------------------------------------------------------------------------
    # Receipts
    # -------------------------------------------------------------------------

    async def save_receipt(
        self,
        receipt_or_scan_id: SuppressionReceipt | str,
        receipt: SuppressionReceipt | None = None,
        mission_id: str | None = None,
    ) -> None:
        if not self._initialized or self._client is None:
            await self.initialize()
        assert self._client is not None

        if isinstance(receipt_or_scan_id, SuppressionReceipt):
            target_receipt = receipt_or_scan_id
            target_mission_id = mission_id or (receipt if isinstance(receipt, str) else None)
        elif isinstance(receipt, SuppressionReceipt):
            target_receipt = receipt
            target_mission_id = str(receipt_or_scan_id)
        else:
            raise ValueError("Invalid parameters for save_receipt: must provide SuppressionReceipt")

        doc_ref = self._client.collection("receipts").document(target_receipt.receipt_id)
        payload = target_receipt.model_dump(mode="json")
        if target_mission_id:
            payload["mission_id"] = target_mission_id
        await doc_ref.set(payload)

    async def get_receipt(self, receipt_id: str) -> SuppressionReceipt | None:
        if not self._initialized or self._client is None:
            await self.initialize()
        assert self._client is not None

        doc_ref = self._client.collection("receipts").document(receipt_id)
        doc = await doc_ref.get()
        if not doc.exists:
            return None
        return SuppressionReceipt.model_validate(doc.to_dict())

    async def list_receipts(self, mission_id: str | None = None, limit: int = 50) -> list[SuppressionReceipt]:
        if not self._initialized or self._client is None:
            await self.initialize()
        assert self._client is not None

        from google.cloud.firestore import FieldFilter, Query
        coll = self._client.collection("receipts")
        if mission_id:
            query = (
                coll.where(filter=FieldFilter("mission_id", "==", mission_id))
                .order_by("submission_timestamp", direction=Query.DESCENDING)
                .limit(limit)
            )
        else:
            query = coll.order_by("submission_timestamp", direction=Query.DESCENDING).limit(limit)

        receipts: list[SuppressionReceipt] = []
        async for doc in query.stream():
            receipts.append(SuppressionReceipt.model_validate(doc.to_dict()))
        return receipts

    # -------------------------------------------------------------------------
    # Telemetry
    # -------------------------------------------------------------------------

    async def save_telemetry_event(
        self,
        scan_id_or_event: str | AgentTelemetryEvent,
        event: AgentTelemetryEvent | None = None,
    ) -> None:
        if not self._initialized or self._client is None:
            await self.initialize()
        assert self._client is not None

        if isinstance(scan_id_or_event, AgentTelemetryEvent):
            target_event = scan_id_or_event
            target_mission_id = target_event.scan_id
        elif isinstance(event, AgentTelemetryEvent):
            target_event = event
            target_mission_id = str(scan_id_or_event)
        else:
            raise ValueError("Invalid parameters for save_telemetry_event: must provide AgentTelemetryEvent")

        doc_ref = self._client.collection("telemetry").document(target_event.event_id)
        payload = target_event.model_dump(mode="json")
        payload["scan_id"] = target_mission_id
        payload["mission_id"] = target_mission_id
        await doc_ref.set(payload)

    async def list_telemetry_events(self, mission_id: str, limit: int = 100) -> list[AgentTelemetryEvent]:
        if not self._initialized or self._client is None:
            await self.initialize()
        assert self._client is not None

        from google.cloud.firestore import FieldFilter, Query
        query = (
            self._client.collection("telemetry")
            .where(filter=FieldFilter("scan_id", "==", mission_id))
            .order_by("timestamp", direction=Query.ASCENDING)
            .limit(limit)
        )
        events: list[AgentTelemetryEvent] = []
        async for doc in query.stream():
            events.append(AgentTelemetryEvent.model_validate(doc.to_dict()))
        return events

    # -------------------------------------------------------------------------
    # Findings
    # -------------------------------------------------------------------------

    async def save_finding(self, mission_id: str, finding: ExtractedEntityProfile) -> None:
        if not self._initialized or self._client is None:
            await self.initialize()
        assert self._client is not None

        finding_id = f"fnd_{uuid.uuid5(uuid.NAMESPACE_URL, f'{mission_id}:{finding.source_url}').hex[:12]}"
        doc_ref = self._client.collection("findings").document(finding_id)
        payload = finding.model_dump(mode="json")
        payload["mission_id"] = mission_id
        await doc_ref.set(payload)

    async def get_findings(self, mission_id: str) -> list[ExtractedEntityProfile]:
        if not self._initialized or self._client is None:
            await self.initialize()
        assert self._client is not None

        from google.cloud.firestore import FieldFilter
        query = self._client.collection("findings").where(filter=FieldFilter("mission_id", "==", mission_id))
        findings: list[ExtractedEntityProfile] = []
        async for doc in query.stream():
            findings.append(ExtractedEntityProfile.model_validate(doc.to_dict()))
        return findings
