"""
Tests for ProjectUmbraAgent Core & State Machine Loop (Tiers 1-5).
Verifies FSM transitions, step budgeting, loop detection, and telemetry streaming.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from unittest.mock import MagicMock

from project_umbra.classifiers.gemma_classifier import GemmaSanitizerClassifier
from project_umbra.core.agent import ProjectUmbraAgent
from project_umbra.core.decomposer import IdentityDecomposer
from project_umbra.core.dork_synthesizer import PrecisionDorkSynthesizer
from project_umbra.core.state import (
    AgentLifecycleState,
    AgentTelemetryEvent,
    BrokerScanTarget,
    TargetIdentityInput,
    TelemetryEventType,
)


@pytest.fixture
def sample_target() -> TargetIdentityInput:
    return TargetIdentityInput(
        full_name="Marcus Aurelius Brody",
        aliases=["Mark Brody"],
        primary_email="m.brody@texastech.edu",
        secondary_emails=["marcus.brody@gmail.com"],
        phone_numbers=["(214) 555-0192"],
        current_city="Dallas",
        current_state="TX",
        known_addresses=["1428 Elm Street, Dallas, TX 75201"],
        relatives=["Eleanor Brody"],
        employers=["Texas Tech University"],
        usernames=["mbrody_sec"],
    )


# ==============================================================================
# Tier 1: Complete Lifecycle Execution & Model Validation
# ==============================================================================

def test_tier1_target_identity_input_validation() -> None:
    """Verifies TargetIdentityInput strict validation and defaults."""
    target = TargetIdentityInput(full_name="John Doe")
    assert target.full_name == "John Doe"
    assert target.aliases == []
    assert target.secondary_emails == []
    assert target.phone_numbers == []

    # Invalid name (too short)
    with pytest.raises(ValidationError):
        TargetIdentityInput(full_name="A")


@pytest.mark.asyncio
async def test_tier1_agent_fsm_complete_lifecycle(sample_target: TargetIdentityInput) -> None:
    """Verifies that ProjectUmbraAgent transitions through all lifecycle states to COMPLETED."""
    recorded_events: list[AgentTelemetryEvent] = []

    async def event_collector(evt: AgentTelemetryEvent) -> None:
        recorded_events.append(evt)

    agent = ProjectUmbraAgent(max_budget=25)
    summary = await agent.run_mission(sample_target, event_callback=event_collector)

    assert summary.final_state == AgentLifecycleState.COMPLETED
    assert summary.vectors_analyzed > 0
    assert summary.dorks_executed > 0
    assert summary.brokers_scanned > 0
    assert summary.exposures_found > 0
    assert summary.pii_entities_sanitized > 0
    assert summary.remediations_generated > 0
    assert summary.budget_remaining >= 0
    assert len(summary.execution_state_log) > 0

    # Verify event types were emitted
    event_types = [e.event_type for e in recorded_events]
    assert TelemetryEventType.SCAN_INITIATED in event_types
    assert TelemetryEventType.STATE_TRANSITION in event_types
    assert TelemetryEventType.DORK_DISCOVERED in event_types
    assert TelemetryEventType.BROKER_EXPOSURE_DETECTED in event_types
    assert TelemetryEventType.PII_SANITIZED in event_types
    assert TelemetryEventType.ACTION_PLAN_GENERATED in event_types
    assert TelemetryEventType.SCAN_COMPLETED in event_types


# ==============================================================================
# Tier 2: Step Budget Exhaustion Graceful Handling
# ==============================================================================

@pytest.mark.asyncio
async def test_tier2_step_budget_exhaustion_graceful_recovery(
    sample_target: TargetIdentityInput,
) -> None:
    """Verifies that exhausting the step budget transitions to BUDGET_EXHAUSTED without crashing."""
    recorded_events: list[AgentTelemetryEvent] = []

    async def event_collector(evt: AgentTelemetryEvent) -> None:
        recorded_events.append(evt)

    # Restrict budget to only 2 steps
    agent = ProjectUmbraAgent(max_budget=2)
    summary = await agent.run_mission(sample_target, event_callback=event_collector)

    assert summary.final_state == AgentLifecycleState.BUDGET_EXHAUSTED
    assert summary.total_steps_executed >= 2
    assert summary.budget_remaining == 0

    event_types = [e.event_type for e in recorded_events]
    assert TelemetryEventType.BUDGET_EXHAUSTED in event_types
    assert TelemetryEventType.SCAN_COMPLETED not in event_types


@pytest.mark.asyncio
async def test_tier2_custom_dependency_injection(sample_target: TargetIdentityInput) -> None:
    """Verifies agent runs cleanly with custom decomposer, dork synthesizer, and gemma sanitizer."""
    custom_decomposer = IdentityDecomposer()
    custom_synthesizer = PrecisionDorkSynthesizer()
    custom_sanitizer = GemmaSanitizerClassifier(mode="heuristic")

    agent = ProjectUmbraAgent(
        decomposer=custom_decomposer,
        dork_synthesizer=custom_synthesizer,
        gemma_sanitizer=custom_sanitizer,
        max_budget=30,
    )
    summary = await agent.run_mission(sample_target)

    assert summary.final_state == AgentLifecycleState.COMPLETED
    assert summary.vectors_analyzed > 0
    assert summary.dorks_executed > 0
    assert summary.sanitization_result is not None


# ==============================================================================
# Tier 3: Loop Detection & Step Accounting
# ==============================================================================

@pytest.mark.asyncio
async def test_tier3_loop_detection_prevention(sample_target: TargetIdentityInput) -> None:
    """Verifies that duplicated broker scans or dorks are suppressed after 2 attempts."""
    dup_broker = BrokerScanTarget(
        broker_id="repeat_broker",
        broker_name="RepeatBroker",
        base_url="https://repeat.example.com",
        opt_out_url="https://repeat.example.com/optout",
        search_url_template="https://repeat.example.com/find?q={name}",
    )
    duplicate_targets = [dup_broker, dup_broker, dup_broker, dup_broker]

    recorded_events: list[AgentTelemetryEvent] = []

    async def event_collector(evt: AgentTelemetryEvent) -> None:
        recorded_events.append(evt)

    agent = ProjectUmbraAgent(max_budget=25, broker_targets=duplicate_targets)
    summary = await agent.run_mission(sample_target, event_callback=event_collector)

    assert summary.final_state == AgentLifecycleState.COMPLETED
    loop_events = [e for e in recorded_events if e.event_type == TelemetryEventType.LOOP_DETECTED]
    assert len(loop_events) >= 1


@pytest.mark.asyncio
async def test_tier3_step_records_and_summary_metrics(sample_target: TargetIdentityInput) -> None:
    """Verifies step logging accuracy, duration metrics, and budget decrements."""
    agent = ProjectUmbraAgent(max_budget=25)
    summary = await agent.run_mission(sample_target)

    assert len(summary.execution_state_log) == summary.total_steps_executed
    for idx, rec in enumerate(summary.execution_state_log, 1):
        assert rec.step_number == idx
        assert rec.budget_remaining == max(0, 25 - idx)
        assert rec.step_duration_ms >= 0.0


# ==============================================================================
# Tier 4: Telemetry Error Resilience & Custom Scan ID
# ==============================================================================

@pytest.mark.asyncio
async def test_tier4_telemetry_callback_exception_resilience(
    sample_target: TargetIdentityInput,
) -> None:
    """Verifies that exceptions in the telemetry callback do not interrupt the agent."""

    async def failing_callback(evt: AgentTelemetryEvent) -> None:
        raise ConnectionResetError("SSE Client disconnected unexpectedly")

    agent = ProjectUmbraAgent(max_budget=25)
    summary = await agent.run_mission(sample_target, event_callback=failing_callback)

    assert summary.final_state == AgentLifecycleState.COMPLETED
    assert summary.exposures_found > 0


@pytest.mark.asyncio
async def test_tier4_custom_scan_id(sample_target: TargetIdentityInput) -> None:
    """Verifies custom scan_id is propagated throughout the run summary and telemetry."""
    custom_id = "scan_custom_test_999"
    recorded_events: list[AgentTelemetryEvent] = []

    async def event_collector(evt: AgentTelemetryEvent) -> None:
        recorded_events.append(evt)

    agent = ProjectUmbraAgent(max_budget=25)
    summary = await agent.run_mission(sample_target, scan_id=custom_id, event_callback=event_collector)

    assert summary.run_id == custom_id
    assert all(e.scan_id == custom_id for e in recorded_events)


# ==============================================================================
# Tier 5: Adversarial & Offline Verification
# ==============================================================================

@pytest.mark.asyncio
async def test_tier5_offline_mock_execution(sample_target: TargetIdentityInput) -> None:
    """Verifies the agent executes fully offline with zero internet and zero API keys."""
    agent = ProjectUmbraAgent(
        gemini_client=None,
        decomposer=None,
        dork_synthesizer=None,
        serp_scanner=None,
        browser_scanner=None,
        extractor=None,
        gemma_sanitizer=None,
        suppression_engine=None,
        max_budget=25,
    )
    summary = await agent.run_mission(sample_target)

    assert summary.final_state == AgentLifecycleState.COMPLETED
    assert summary.sanitization_result is not None
    assert summary.remediation_plan is not None
    assert len(summary.remediation_plan.actions) > 0


@pytest.mark.asyncio
async def test_tier5_zero_budget_graceful_recovery(sample_target: TargetIdentityInput) -> None:
    """Verifies agent behavior when initialized with max_budget=0."""
    agent = ProjectUmbraAgent(max_budget=0)
    summary = await agent.run_mission(sample_target)

    assert summary.final_state == AgentLifecycleState.BUDGET_EXHAUSTED
    assert summary.budget_remaining == 0
