"""
Empirical Adversarial & Stress Test Harness for Milestone 3 (Challenger 2).
Focus Areas:
1. High-concurrency batch submissions across 50+, 100+, 200+ simultaneous payloads.
2. HTTP error code cascades (400, 401, 403, 404, 422, 429, 500, 502, 503, 504).
3. Network simulation with transport timeouts (ConnectTimeout, ReadTimeout, WriteTimeout, PoolTimeout, ConnectError).
4. Uniform dispatcher resilience across all registered brokers (TruePeopleSearch, FastPeopleSearch, Radaris, Nuwber, Whitepages, PeopleConnect).
5. Mixed success/failure batch isolation under high concurrent load.
6. Cryptographic tracking hash uniqueness & collision resistance under massive scale.
7. Statutory compliance deadline calendar arithmetic & timezone invariants.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import random
import re
import pytest
import httpx

from project_umbra.core.state import (
    ExtractedEntityProfile,
    SuppressionActionPlan,
    SuppressionPayload,
    SuppressionReceipt,
    SuppressionStatus,
    TargetIdentityInput,
)
from project_umbra.tools.suppression_engine import (
    DISPATCHER_REGISTRY,
    DEFAULT_PROACTIVE_BROKERS,
    KNOWN_BROKER_REGISTRY,
    BaseBrokerDispatcher,
    FastPeopleSearchDispatcher,
    NuwberDispatcher,
    PeopleConnectDispatcher,
    RadarisDispatcher,
    SuppressionEngine,
    TruePeopleSearchDispatcher,
    WhitepagesDispatcher,
    calculate_compliance_deadline,
    create_suppression_receipt,
    generate_cryptographic_tracking_hash,
    map_response_to_status,
)


# ==============================================================================
# 1. High-Concurrency Batch Stress Tests (50+, 100+, 200+ payloads)
# ==============================================================================

@pytest.mark.asyncio
async def test_concurrent_batch_submissions_75_simulated() -> None:
    """Stress test 75 simultaneous batch submissions in simulation mode."""
    engine = SuppressionEngine(simulation_mode=True)
    target = TargetIdentityInput(
        full_name="Dr. Marcus Brody",
        primary_email="mbrody@example.com",
        phone_numbers=["555-010-9999"],
        current_city="New York",
        current_state="NY",
    )

    broker_keys = list(KNOWN_BROKER_REGISTRY.keys())
    payloads = [
        engine.build_payload(
            broker_id=broker_keys[i % len(broker_keys)],
            identity=target,
            profile_url=f"https://example.com/record/{i}",
        )
        for i in range(75)
    ]

    receipts = await engine.submit_all(payloads)

    assert len(receipts) == 75
    # Verify all receipts have valid IDs and status
    receipt_ids = {r.receipt_id for r in receipts}
    assert len(receipt_ids) == 75, "Receipt IDs must be globally unique"

    tracking_refs = {r.tracking_reference for r in receipts}
    assert len(tracking_refs) == 75, "Cryptographic tracking references must be unique for unique profile URLs"

    for r in receipts:
        assert r.status in {"CONFIRMED", "PENDING_VERIFICATION", "SUBMITTED"}
        assert r.response_code in {200, 202}
        assert r.tracking_reference.startswith("GP-SHA256-")
        assert len(r.tracking_reference) == 26  # GP-SHA256- + 16 hex chars
        assert r.compliance_deadline > r.submission_timestamp


@pytest.mark.asyncio
async def test_concurrent_batch_submissions_100_mock_network_with_jitter() -> None:
    """Stress test 100 simultaneous submissions over mock HTTP network with simulated network latency."""
    async def mock_handler(request: httpx.Request) -> httpx.Response:
        # Simulate non-blocking network I/O jitter between 1ms and 15ms
        jitter_s = random.uniform(0.001, 0.015)
        await asyncio.sleep(jitter_s)
        return httpx.Response(200, json={"status": "acknowledged", "path": str(request.url)})

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        engine = SuppressionEngine(simulation_mode=False)
        engine._client = client

        target = TargetIdentityInput(
            full_name="Helena Shaw",
            primary_email="hshaw@example.org",
            phone_numbers=["555-012-3456"],
        )

        broker_keys = list(KNOWN_BROKER_REGISTRY.keys())
        payloads = [
            engine.build_payload(
                broker_id=broker_keys[i % len(broker_keys)],
                identity=target,
                profile_url=f"https://broker-{i % len(broker_keys)}.com/p/helena-{i}",
            )
            for i in range(100)
        ]

        start_time = asyncio.get_event_loop().time()
        receipts = await engine.submit_all(payloads)
        duration = asyncio.get_event_loop().time() - start_time

        assert len(receipts) == 100
        assert all(r.status == "CONFIRMED" for r in receipts)
        assert all(r.response_code == 200 for r in receipts)
        # Even with 100 requests each with 1-15ms delay, concurrency ensures fast execution
        assert duration < 3.0, f"100 concurrent requests took {duration:.2f}s, expected < 3.0s"


@pytest.mark.asyncio
async def test_massive_concurrency_burst_200_payloads() -> None:
    """Stress test a massive burst of 200 concurrent payloads to verify event loop stability and memory safety."""
    engine = SuppressionEngine(simulation_mode=True)
    target = TargetIdentityInput(
        full_name="Victor Creed",
        primary_email="vcreed@weaponx.org",
    )

    payloads = [
        engine.build_payload(
            broker_id="radaris",
            identity=target,
            profile_url=f"https://radaris.com/p/victor-creed-{i}",
        )
        for i in range(200)
    ]

    receipts = await engine.submit_all(payloads)

    assert len(receipts) == 200
    assert all(r.broker_name == "Radaris" for r in receipts)
    assert all(r.status == "PENDING_VERIFICATION" for r in receipts)  # Radaris returns 202 in fixture
    assert all(r.response_code == 202 for r in receipts)


@pytest.mark.asyncio
async def test_multi_coroutine_shared_engine_concurrency() -> None:
    """Stress test 10 concurrent coroutines simultaneously dispatching batches to a single SuppressionEngine instance."""
    engine = SuppressionEngine(simulation_mode=True)
    target = TargetIdentityInput(full_name="Shared Engine Test", primary_email="shared@test.com")

    async def worker_task(worker_id: int) -> list[SuppressionReceipt]:
        payloads = [
            engine.build_payload(
                broker_id="truepeoplesearch",
                identity=target,
                profile_url=f"https://truepeoplesearch.com/find/person/shared-{worker_id}-{j}",
            )
            for j in range(10)
        ]
        return await engine.submit_all(payloads)

    tasks = [worker_task(w) for w in range(10)]
    results = await asyncio.gather(*tasks)

    total_receipts = [r for sublist in results for r in sublist]
    assert len(total_receipts) == 100
    assert len({r.receipt_id for r in total_receipts}) == 100


# ==============================================================================
# 2. HTTP Error Code Cascade Stress Tests (400, 401, 403, 404, 422, 429, 500, 502, 503, 504)
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status_code,expected_receipt_status,expected_payload_status",
    [
        (400, "FAILED", SuppressionStatus.FAILED),
        (401, "FAILED", SuppressionStatus.FAILED),
        (403, "FAILED", SuppressionStatus.FAILED),
        (404, "FAILED", SuppressionStatus.FAILED),
        (405, "FAILED", SuppressionStatus.FAILED),
        (408, "FAILED", SuppressionStatus.FAILED),
        (409, "FAILED", SuppressionStatus.FAILED),
        (410, "FAILED", SuppressionStatus.FAILED),
        (422, "FAILED", SuppressionStatus.FAILED),
        (429, "FAILED", SuppressionStatus.FAILED),
        (500, "FAILED", SuppressionStatus.FAILED),
        (501, "FAILED", SuppressionStatus.FAILED),
        (502, "FAILED", SuppressionStatus.FAILED),
        (503, "FAILED", SuppressionStatus.FAILED),
        (504, "FAILED", SuppressionStatus.FAILED),
        (520, "FAILED", SuppressionStatus.FAILED),
        (522, "FAILED", SuppressionStatus.FAILED),
    ],
)
async def test_http_error_code_cascades_and_status_assignment(
    status_code: int,
    expected_receipt_status: str,
    expected_payload_status: SuppressionStatus,
) -> None:
    """Verify that all 4xx, 5xx, and Cloudflare status codes result in graceful FAILED status assignment."""
    def error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, text=f"HTTP {status_code} Error Simulation")

    transport = httpx.MockTransport(error_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        dispatcher = BaseBrokerDispatcher()
        target = TargetIdentityInput(full_name="Error Test", primary_email="error@test.com")
        payload = SuppressionPayload(
            broker_id="generic",
            broker_name="Generic Test Broker",
            opt_out_type="automated_form",
            form_payload=dispatcher.build_form_payload(target),
            submission_url="https://example.com/optout",
        )

        receipt = await dispatcher.submit(payload, client=client, simulation_mode=False)

        assert receipt.status == expected_receipt_status
        assert payload.status == expected_payload_status
        assert receipt.response_code == status_code
        assert str(status_code) in receipt.confirmation_message
        assert receipt.tracking_reference.startswith("GP-SHA256-")
        assert receipt.compliance_deadline == calculate_compliance_deadline(receipt.submission_timestamp)


# ==============================================================================
# 3. Network Transport Timeouts & Failure Simulation Tests
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception_cls,error_msg",
    [
        (httpx.ConnectTimeout, "Connection to endpoint timed out after 10.0s"),
        (httpx.ReadTimeout, "Socket read timeout during response transfer"),
        (httpx.WriteTimeout, "Socket write timeout during payload transfer"),
        (httpx.PoolTimeout, "Connection pool timeout waiting for available slot"),
        (httpx.ConnectError, "Failed to establish TCP connection (ECONNREFUSED)"),
        (httpx.RemoteProtocolError, "Server disconnected without sending complete response"),
    ],
)
async def test_network_timeout_and_transport_exceptions(
    exception_cls: type[Exception],
    error_msg: str,
) -> None:
    """Verify that all httpx transport exceptions are caught and converted to valid FAILED receipts with response_code 500."""
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise exception_cls(error_msg)

    transport = httpx.MockTransport(timeout_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        dispatcher = BaseBrokerDispatcher()
        target = TargetIdentityInput(full_name="Timeout Test", primary_email="timeout@test.com")
        payload = SuppressionPayload(
            broker_id="generic",
            broker_name="Generic Broker",
            opt_out_type="automated_form",
            form_payload=dispatcher.build_form_payload(target),
            submission_url="https://example.com/optout",
        )

        receipt = await dispatcher.submit(payload, client=client, simulation_mode=False)

        assert receipt.status == "FAILED"
        assert payload.status == SuppressionStatus.FAILED
        assert receipt.response_code == 500
        assert "Submission failed:" in receipt.confirmation_message
        assert receipt.tracking_reference.startswith("GP-SHA256-")
        assert receipt.compliance_deadline > receipt.submission_timestamp


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_str",
    [
        "Network error connecting to {'host': 'broker.example.com', 'port': 443, 'ssl': True}",
        "Gateway error: {\"error\": \"upstream_timeout\", \"code\": 504, \"meta\": {\"attempt\": 3}}",
        "Invalid token in JSON payload: {unexpected_key_here}",
        "Malformed response body with unclosed brace {",
        "Raw error format: %s with {0} and {unmatched_field}",
    ],
)
async def test_network_exceptions_with_json_and_dict_payloads(error_str: str) -> None:
    """Verifies that network errors containing JSON/dict curly braces never trigger KeyError during receipt formatting."""
    def error_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.RequestError(error_str)

    transport = httpx.MockTransport(error_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        dispatcher = BaseBrokerDispatcher()
        target = TargetIdentityInput(full_name="Alice Vance", primary_email="alice@vance.internal")
        payload = SuppressionPayload(
            broker_id="generic",
            broker_name="Generic Broker",
            opt_out_type="automated_form",
            form_payload=dispatcher.build_form_payload(target),
            submission_url="https://example.com/optout",
        )

        receipt = await dispatcher.submit(payload, client=client, simulation_mode=False)

        assert receipt.status == "FAILED"
        assert payload.status == SuppressionStatus.FAILED
        assert receipt.response_code == 500
        assert "Submission failed:" in receipt.confirmation_message
        assert receipt.tracking_reference.startswith("GP-SHA256-")
        assert receipt.compliance_deadline > receipt.submission_timestamp


# ==============================================================================
# 4. Uniform Dispatcher Error Resilience Across All 6 Broker Classes
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "broker_id,dispatcher_instance",
    list(DISPATCHER_REGISTRY.items()),
)
async def test_all_registered_dispatchers_live_error_and_timeout_resilience(
    broker_id: str,
    dispatcher_instance: BaseBrokerDispatcher,
) -> None:
    """Verify that all specialized broker dispatchers uniformly handle network failures gracefully."""
    # Test 1: 504 Gateway Timeout
    def gateway_timeout_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(504, text="Gateway Timeout")

    transport_504 = httpx.MockTransport(gateway_timeout_handler)
    async with httpx.AsyncClient(transport=transport_504) as client_504:
        target = TargetIdentityInput(full_name="Dispatcher Subject", primary_email="dispatch@example.com")
        payload_504 = SuppressionPayload(
            broker_id=broker_id,
            broker_name=dispatcher_instance.broker_name,
            opt_out_type="automated_form",
            form_payload=dispatcher_instance.build_form_payload(target),
            submission_url=dispatcher_instance.default_endpoint,
        )
        receipt_504 = await dispatcher_instance.submit(payload_504, client=client_504, simulation_mode=False)
        assert receipt_504.status == "FAILED"
        assert receipt_504.response_code == 504
        assert payload_504.status == SuppressionStatus.FAILED

    # Test 2: Connection Timeout
    def connect_timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("Connect timeout to upstream host")

    transport_timeout = httpx.MockTransport(connect_timeout_handler)
    async with httpx.AsyncClient(transport=transport_timeout) as client_timeout:
        payload_timeout = SuppressionPayload(
            broker_id=broker_id,
            broker_name=dispatcher_instance.broker_name,
            opt_out_type="automated_form",
            form_payload=dispatcher_instance.build_form_payload(target),
            submission_url=dispatcher_instance.default_endpoint,
        )
        receipt_timeout = await dispatcher_instance.submit(payload_timeout, client=client_timeout, simulation_mode=False)
        assert receipt_timeout.status == "FAILED"
        assert receipt_timeout.response_code == 500
        assert payload_timeout.status == SuppressionStatus.FAILED


# ==============================================================================
# 5. Mixed Batch Concurrency Isolation (Successes + Errors + Timeouts)
# ==============================================================================

@pytest.mark.asyncio
async def test_mixed_status_concurrent_batch_60_payloads() -> None:
    """
    Stress test a heterogeneous batch of 60 payloads executed concurrently:
    - 20 succeed with HTTP 200 (CONFIRMED)
    - 10 succeed with HTTP 201 (SUBMITTED)
    - 10 fail with HTTP 429 Rate Limit (FAILED)
    - 10 fail with HTTP 500 Server Error (FAILED)
    - 10 fail with httpx.ReadTimeout (FAILED)
    Verify zero dropped items, exact status categorization, and no state bleeding.
    """
    async def mixed_handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if "status-200" in url_str:
            return httpx.Response(200, json={"ok": True})
        elif "status-201" in url_str:
            return httpx.Response(201, text="Created")
        elif "status-429" in url_str:
            return httpx.Response(429, text="Rate Limited")
        elif "status-500" in url_str:
            return httpx.Response(500, text="Internal Error")
        elif "timeout" in url_str:
            raise httpx.ReadTimeout("Simulated read timeout")
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(mixed_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        engine = SuppressionEngine(simulation_mode=False)
        engine._client = client
        target = TargetIdentityInput(full_name="Mixed Batch Subject", primary_email="mixed@example.com")

        payloads: list[SuppressionPayload] = []
        for i in range(20):
            p = engine.build_payload("truepeoplesearch", target)
            p.submission_url = f"https://example.com/status-200/{i}"
            payloads.append(p)
        for i in range(10):
            p = engine.build_payload("fastpeoplesearch", target)
            p.submission_url = f"https://example.com/status-201/{i}"
            payloads.append(p)
        for i in range(10):
            p = engine.build_payload("radaris", target)
            p.submission_url = f"https://example.com/status-429/{i}"
            payloads.append(p)
        for i in range(10):
            p = engine.build_payload("nuwber", target)
            p.submission_url = f"https://example.com/status-500/{i}"
            payloads.append(p)
        for i in range(10):
            p = engine.build_payload("whitepages", target)
            p.submission_url = f"https://example.com/timeout/{i}"
            payloads.append(p)

        receipts = await engine.submit_all(payloads)

        assert len(receipts) == 60

        confirmed = [r for r in receipts if r.status == "CONFIRMED"]
        submitted = [r for r in receipts if r.status == "SUBMITTED"]
        failed = [r for r in receipts if r.status == "FAILED"]

        assert len(confirmed) == 20
        assert len(submitted) == 10
        assert len(failed) == 30  # 10 (429) + 10 (500) + 10 (timeout)

        # Verify failed responses breakdown
        failed_429 = [r for r in failed if r.response_code == 429]
        failed_500 = [r for r in failed if r.response_code == 500]
        assert len(failed_429) == 10
        assert len(failed_500) == 20  # 10 HTTP 500 + 10 timeout (code 500)


# ==============================================================================
# 6. Cryptographic Hash Collision Resistance & Determinism
# ==============================================================================

def test_cryptographic_tracking_hash_scale_and_collision_resistance() -> None:
    """Verify that 1000 generated cryptographic hashes have zero collisions and strict format compliance."""
    base_ts = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
    hashes: set[str] = set()

    for i in range(1000):
        h = generate_cryptographic_tracking_hash(
            remediation_id=f"rem_{i:04d}",
            broker_id=f"broker_{i % 10}",
            timestamp=base_ts + timedelta(seconds=i),
            email=f"user_{i}@example.com",
            profile_url=f"https://broker.com/p/{i}",
        )
        assert re.match(r"^GP-SHA256-[0-9A-F]{16}$", h)
        hashes.add(h)

    assert len(hashes) == 1000, "Zero hash collisions expected across 1000 distinct submissions"


def test_cryptographic_tracking_hash_determinism() -> None:
    """Verify that exact same input parameters produce 100% deterministic tracking hashes."""
    ts = datetime(2026, 1, 15, 8, 30, 0, tzinfo=timezone.utc)
    h1 = generate_cryptographic_tracking_hash("rem_fixed", "truepeoplesearch", ts, "test@test.com", "https://tps.com/1")
    h2 = generate_cryptographic_tracking_hash("rem_fixed", "truepeoplesearch", ts, "test@test.com", "https://tps.com/1")
    assert h1 == h2


# ==============================================================================
# 7. Statutory Compliance Deadline & Status Mapping Verification
# ==============================================================================

def test_calculate_compliance_deadline_calendar_arithmetic() -> None:
    """Verify compliance deadline calculation across leap year and month boundaries."""
    # Leap year date: Feb 28, 2028 (2028 is leap year)
    ts_leap = datetime(2028, 2, 1, 10, 0, 0, tzinfo=timezone.utc)
    deadline_leap = calculate_compliance_deadline(ts_leap, days=30)
    assert deadline_leap == datetime(2028, 3, 2, 10, 0, 0, tzinfo=timezone.utc)

    # Year-end rollover: Dec 15, 2026 + 30 days -> Jan 14, 2027
    ts_yearend = datetime(2026, 12, 15, 0, 0, 0, tzinfo=timezone.utc)
    deadline_yearend = calculate_compliance_deadline(ts_yearend, days=30)
    assert deadline_yearend == datetime(2027, 1, 14, 0, 0, 0, tzinfo=timezone.utc)


def test_map_response_to_status_comprehensive_ranges() -> None:
    """Verify status code mapping for standard and non-standard HTTP codes."""
    assert map_response_to_status(200) == "CONFIRMED"
    assert map_response_to_status(202) == "PENDING_VERIFICATION"
    assert map_response_to_status(201) == "SUBMITTED"
    assert map_response_to_status(204) == "SUBMITTED"
    assert map_response_to_status(206) == "SUBMITTED"
    assert map_response_to_status(301) == "FAILED"
    assert map_response_to_status(302) == "FAILED"
    assert map_response_to_status(400) == "FAILED"
    assert map_response_to_status(401) == "FAILED"
    assert map_response_to_status(403) == "FAILED"
    assert map_response_to_status(404) == "FAILED"
    assert map_response_to_status(429) == "FAILED"
    assert map_response_to_status(500) == "FAILED"
    assert map_response_to_status(502) == "FAILED"
    assert map_response_to_status(504) == "FAILED"


# ==============================================================================
# 8. Plan Execution Concurrency via execute_plan()
# ==============================================================================

@pytest.mark.asyncio
async def test_suppression_engine_execute_plan_with_50_actions() -> None:
    """Stress test execute_plan() with a plan containing 50+ actions across varied brokers."""
    engine = SuppressionEngine(simulation_mode=True)
    target = TargetIdentityInput(full_name="Plan Scale Test", primary_email="scale@test.com")

    profiles = [
        ExtractedEntityProfile(
            target_id="tgt_scale",
            source_url=f"https://broker-{i % 5}.com/record/{i}",
            source_broker=f"broker_{i % 5}",
            matched_names=["Plan Scale Test"],
            confidence_score=0.90,
        )
        for i in range(50)
    ]

    # Deduplicated profiles should result in 5 unique brokers
    plan = engine.compile_plan(target_input=target, profiles=profiles)
    assert plan.total_actions == 5

    receipts = await engine.execute_plan(plan)
    assert len(receipts) == 5
    assert all(r.status in {"CONFIRMED", "PENDING_VERIFICATION", "SUBMITTED"} for r in receipts)
