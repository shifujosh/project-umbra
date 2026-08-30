"""
Project Umbra SSE Telemetry Broadcaster.
Provides asynchronous multi-subscriber Pub/Sub queue management per scan/mission ID,
heartbeat keep-alive pings, client disconnect detection, bounded replay buffering,
and standards-compliant Server-Sent Events serialization.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
import json
import logging
from typing import Any, AsyncGenerator
from fastapi import Request
from sse_starlette.sse import ServerSentEvent

from project_umbra.core.state import AgentTelemetryEvent, TelemetryEventType

logger = logging.getLogger(__name__)


class SSEBroadcaster:
    """
    Asynchronous Pub/Sub Telemetry Broadcaster for Project Umbra scans.
    Supports multi-client fan-out per mission, historical event replay for late joiners,
    heartbeat keep-alives, and clean disconnection reclamation.
    """

    def __init__(self, max_queue_size: int = 200, max_history_per_mission: int = 100, heartbeat_interval: float = 15.0) -> None:
        self.max_queue_size = max_queue_size
        self.max_history_per_mission = max_history_per_mission
        self.heartbeat_interval = heartbeat_interval
        self._subscribers: dict[str, set[asyncio.Queue[AgentTelemetryEvent | None]]] = defaultdict(set)
        self._history: dict[str, list[AgentTelemetryEvent]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def subscribe_queue(self, mission_id: str) -> asyncio.Queue[AgentTelemetryEvent | None]:
        """Subscribes an async queue to receive telemetry events for a specific mission_id."""
        queue: asyncio.Queue[AgentTelemetryEvent | None] = asyncio.Queue(maxsize=self.max_queue_size)
        async with self._lock:
            self._subscribers[mission_id].add(queue)
            logger.debug(f"[SSEBroadcaster] Subscribed client to mission {mission_id}. Total: {len(self._subscribers[mission_id])}")
        return queue

    async def unsubscribe(self, mission_id: str, queue: asyncio.Queue[AgentTelemetryEvent | None]) -> None:
        """Unsubscribes and cleans up an async queue from a mission's subscriber set."""
        async with self._lock:
            if mission_id in self._subscribers:
                self._subscribers[mission_id].discard(queue)
                if not self._subscribers[mission_id]:
                    del self._subscribers[mission_id]
                logger.debug(f"[SSEBroadcaster] Unsubscribed client from mission {mission_id}.")

    def publish(self, mission_id: str, event: AgentTelemetryEvent | dict[str, Any]) -> None:
        """
        Publishes a telemetry event to all active subscriber queues for a mission.
        Non-blocking: if a subscriber queue is full, the oldest unread event is dropped.
        """
        if isinstance(event, dict):
            telemetry_event = AgentTelemetryEvent.model_validate(event)
        else:
            telemetry_event = event

        # Record in bounded historical buffer for late joiners
        history_list = self._history[mission_id]
        history_list.append(telemetry_event)
        if len(history_list) > self.max_history_per_mission:
            history_list.pop(0)

        # Broadcast to all active subscriber queues
        subscriber_queues = list(self._subscribers.get(mission_id, set()))
        for q in subscriber_queues:
            try:
                q.put_nowait(telemetry_event)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()  # Drop oldest unread item
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(telemetry_event)
                except asyncio.QueueFull:
                    pass

    async def broadcast(self, mission_id: str, event: AgentTelemetryEvent | dict[str, Any]) -> None:
        """Async alias for publish."""
        self.publish(mission_id, event)

    def publish_eof(self, mission_id: str) -> None:
        """Sends an EOF sentinel (None) to signal end-of-stream to all mission subscribers."""
        subscriber_queues = list(self._subscribers.get(mission_id, set()))
        for q in subscriber_queues:
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:
                pass

    async def close_channel(self, mission_id: str) -> None:
        """Async alias for publish_eof."""
        self.publish_eof(mission_id)

    def get_history(self, mission_id: str) -> list[AgentTelemetryEvent]:
        """Returns a snapshot of historical events emitted for a mission."""
        return list(self._history.get(mission_id, []))

    def clear_mission(self, mission_id: str) -> None:
        """Cleans up subscribers and historical event buffers for a completed/pruned mission."""
        self._subscribers.pop(mission_id, None)
        self._history.pop(mission_id, None)

    async def event_generator(
        self,
        request: Request | None,
        mission_id: str,
        heartbeat_interval: float | None = None,
        replay_history: bool = True,
    ) -> AsyncGenerator[ServerSentEvent, None]:
        """
        Async generator yielding ServerSentEvent objects to FastAPI EventSourceResponse.
        Includes history replay, heartbeat keep-alive, client disconnect detection,
        and clean unsubscription on stream termination.
        """
        interval = heartbeat_interval or self.heartbeat_interval
        queue = await self.subscribe_queue(mission_id)

        try:
            # 1. Replay historical events if requested
            if replay_history:
                past_events = self.get_history(mission_id)
                for past_evt in past_events:
                    if request is not None and await request.is_disconnected():
                        return
                    yield ServerSentEvent(
                        id=past_evt.event_id,
                        event=past_evt.event_type.value,
                        data=past_evt.model_dump_json(),
                        retry=10000,
                    )

            # 2. Main event streaming loop with heartbeat timeout
            while True:
                if request is not None and await request.is_disconnected():
                    logger.debug(f"[SSEBroadcaster] Client disconnected from mission {mission_id}")
                    break

                try:
                    event = await asyncio.wait_for(queue.get(), timeout=interval)
                except asyncio.TimeoutError:
                    yield ServerSentEvent(
                        event="ping",
                        data=json.dumps({
                            "type": "heartbeat",
                            "mission_id": mission_id,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }),
                        comment="keep-alive",
                    )
                    continue

                # EOF Sentinel check
                if event is None:
                    break

                yield ServerSentEvent(
                    id=event.event_id,
                    event=event.event_type.value,
                    data=event.model_dump_json(),
                    retry=10000,
                )

                if event.event_type in (
                    TelemetryEventType.SCAN_COMPLETED,
                    TelemetryEventType.SCAN_FAILED,
                ):
                    await asyncio.sleep(0.05)
                    break

        except asyncio.CancelledError:
            logger.debug(f"[SSEBroadcaster] Stream task cancelled for mission {mission_id}")
            raise
        finally:
            await self.unsubscribe(mission_id, queue)

    async def subscribe(
        self,
        mission_id: str,
        heartbeat_interval: float | None = None,
        replay_history: bool = True,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """
        Async generator yielding dictionary events for direct subscriber consumers.
        """
        interval = heartbeat_interval or self.heartbeat_interval
        queue = await self.subscribe_queue(mission_id)

        try:
            if replay_history:
                past_events = self.get_history(mission_id)
                for past_evt in past_events:
                    yield {
                        "event": past_evt.event_type.value,
                        "id": past_evt.event_id,
                        "data": past_evt.model_dump_json(),
                    }

            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=interval)
                    if event is None:
                        yield {"event": "SCAN_COMPLETED", "data": json.dumps({"status": "STREAM_CLOSED"})}
                        break

                    yield {
                        "event": event.event_type.value,
                        "id": event.event_id,
                        "data": event.model_dump_json(),
                    }

                    if event.event_type in (
                        TelemetryEventType.SCAN_COMPLETED,
                        TelemetryEventType.SCAN_FAILED,
                    ):
                        break

                except asyncio.TimeoutError:
                    yield {"comment": "ping"}

        finally:
            await self.unsubscribe(mission_id, queue)
