"""
Unit and Integration Tests for Project Umbra SSE Telemetry Broadcaster (tests/test_sse.py).
Verifies Pub/Sub subscriber fan-out, queue backpressure handling, historical replay,
keep-alive heartbeats, client disconnection detection, and clean channel teardown.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from unittest.mock import AsyncMock, MagicMock
import pytest
from sse_starlette.sse import ServerSentEvent

from project_umbra.api.sse import SSEBroadcaster
from project_umbra.core.state import (
    AgentLifecycleState,
    AgentTelemetryEvent,
    TelemetryEventType,
)


@pytest.fixture
def sample_telemetry_event() -> AgentTelemetryEvent:
    return AgentTelemetryEvent(
        event_id="evt_sse_101",
        scan_id="scan_sse_test",
        timestamp=datetime.now(timezone.utc),
        event_type=TelemetryEventType.SCAN_INITIATED,
        state=AgentLifecycleState.INITIALIZED,
        message="Scan initiated for target",
        step_number=0,
        budget_remaining=25,
        payload={"target": "Eleanor Vance"},
    )


@pytest.mark.asyncio
async def test_sse_broadcaster_subscribe_and_publish(sample_telemetry_event: AgentTelemetryEvent):
    broadcaster = SSEBroadcaster()
    queue = await broadcaster.subscribe_queue("scan_1")

    broadcaster.publish("scan_1", sample_telemetry_event)

    received = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert received is not None
    assert received.event_id == sample_telemetry_event.event_id
    assert received.event_type == TelemetryEventType.SCAN_INITIATED

    await broadcaster.unsubscribe("scan_1", queue)


@pytest.mark.asyncio
async def test_sse_broadcaster_multi_subscriber_fanout(sample_telemetry_event: AgentTelemetryEvent):
    broadcaster = SSEBroadcaster()
    q1 = await broadcaster.subscribe_queue("scan_multi")
    q2 = await broadcaster.subscribe_queue("scan_multi")
    q3 = await broadcaster.subscribe_queue("scan_multi")

    await broadcaster.broadcast("scan_multi", sample_telemetry_event)

    r1 = await asyncio.wait_for(q1.get(), timeout=1.0)
    r2 = await asyncio.wait_for(q2.get(), timeout=1.0)
    r3 = await asyncio.wait_for(q3.get(), timeout=1.0)

    assert r1.event_id == sample_telemetry_event.event_id
    assert r2.event_id == sample_telemetry_event.event_id
    assert r3.event_id == sample_telemetry_event.event_id

    await broadcaster.unsubscribe("scan_multi", q1)
    await broadcaster.unsubscribe("scan_multi", q2)
    await broadcaster.unsubscribe("scan_multi", q3)


@pytest.mark.asyncio
async def test_sse_broadcaster_queue_full_drops_oldest(sample_telemetry_event: AgentTelemetryEvent):
    # Tiny queue to trigger overflow
    broadcaster = SSEBroadcaster(max_queue_size=2)
    queue = await broadcaster.subscribe_queue("scan_overflow")

    for i in range(5):
        evt = sample_telemetry_event.model_copy(deep=True)
        evt.event_id = f"evt_{i}"
        evt.step_number = i
        broadcaster.publish("scan_overflow", evt)

    # Queue size should be at max capacity and contain the newest items
    assert queue.qsize() <= 2

    r1 = await queue.get()
    r2 = await queue.get()
    # The oldest items 0, 1, 2 were dropped to make room for newer events
    assert r2.event_id == "evt_4"

    await broadcaster.unsubscribe("scan_overflow", queue)


@pytest.mark.asyncio
async def test_sse_broadcaster_history_replay_for_late_subscribers(sample_telemetry_event: AgentTelemetryEvent):
    broadcaster = SSEBroadcaster(max_history_per_mission=10)

    for i in range(3):
        evt = sample_telemetry_event.model_copy(deep=True)
        evt.event_id = f"evt_hist_{i}"
        broadcaster.publish("scan_hist", evt)

    history = broadcaster.get_history("scan_hist")
    assert len(history) == 3
    assert history[0].event_id == "evt_hist_0"
    assert history[2].event_id == "evt_hist_2"

    mock_request = MagicMock()
    mock_request.is_disconnected = AsyncMock(return_value=False)

    gen = broadcaster.event_generator(
        request=mock_request,
        mission_id="scan_hist",
        heartbeat_interval=0.5,
        replay_history=True,
    )

    replayed = []
    for _ in range(3):
        item = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
        replayed.append(item)

    assert len(replayed) == 3
    assert replayed[0].id == "evt_hist_0"
    assert replayed[1].id == "evt_hist_1"
    assert replayed[2].id == "evt_hist_2"

    # Clean up generator
    await gen.aclose()


@pytest.mark.asyncio
async def test_sse_broadcaster_eof_sentinel(sample_telemetry_event: AgentTelemetryEvent):
    broadcaster = SSEBroadcaster()
    queue = await broadcaster.subscribe_queue("scan_eof")

    broadcaster.publish("scan_eof", sample_telemetry_event)
    broadcaster.publish_eof("scan_eof")

    evt = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert evt is not None

    eof = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert eof is None

    await broadcaster.unsubscribe("scan_eof", queue)


@pytest.mark.asyncio
async def test_sse_broadcaster_heartbeat_ping():
    broadcaster = SSEBroadcaster(heartbeat_interval=0.1)
    mock_request = MagicMock()
    mock_request.is_disconnected = AsyncMock(return_value=False)

    gen = broadcaster.event_generator(
        request=mock_request,
        mission_id="scan_ping",
        heartbeat_interval=0.1,
        replay_history=False,
    )

    # Await heartbeat frame
    ping_event = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
    assert ping_event.event == "ping"
    assert "heartbeat" in ping_event.data

    await gen.aclose()


@pytest.mark.asyncio
async def test_sse_broadcaster_client_disconnect():
    broadcaster = SSEBroadcaster()
    mock_request = MagicMock()
    mock_request.is_disconnected = AsyncMock(return_value=True)

    gen = broadcaster.event_generator(
        request=mock_request,
        mission_id="scan_disc",
        heartbeat_interval=0.1,
        replay_history=False,
    )

    with pytest.raises(StopAsyncIteration):
        await gen.__anext__()


@pytest.mark.asyncio
async def test_sse_broadcaster_clear_mission(sample_telemetry_event: AgentTelemetryEvent):
    broadcaster = SSEBroadcaster()
    await broadcaster.subscribe_queue("scan_clear")
    broadcaster.publish("scan_clear", sample_telemetry_event)

    assert len(broadcaster.get_history("scan_clear")) == 1
    broadcaster.clear_mission("scan_clear")
    assert len(broadcaster.get_history("scan_clear")) == 0
    assert "scan_clear" not in broadcaster._subscribers
