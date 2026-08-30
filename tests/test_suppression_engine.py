"""
Tests for SuppressionEngine, SuppressionActionPlan Compilation & Agent Integration (Tiers 1-5).
Verifies profile aggregation, removal URL mapping, CCPA/GDPR master notices,
broker payload formulation, and ProjectUmbraAgent Phase 6 FSM execution.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock

from project_umbra.core.agent import ProjectUmbraAgent
from project_umbra.core.state import (
    AgentLifecycleState,
    AgentTelemetryEvent,
    ExtractedEntityProfile,
    SuppressionActionPlan,
    SuppressionPayload,
    SuppressionStatus,
    TargetIdentityInput,
    TelemetryEventType,
)
from project_umbra.tools.suppression_engine import (
    DEFAULT_PROACTIVE_BROKERS,
    KNOWN_BROKER_REGISTRY,
    SuppressionEngine,
    aggregate_and_deduplicate_profiles,
    build_broker_payload,
    generate_broker_legal_letter,
    generate_master_ccpa_letter,
    generate_master_gdpr_letter,
    normalize_broker_id,
)


@pytest.fixture
def sample_target() -> TargetIdentityInput:
    return TargetIdentityInput(
        full_name="Dr. Marcus Aurelius Brody",
        aliases=["Mark Brody", "M. Brody"],
        primary_email="m.brody@cybersec-institute.org",
        secondary_emails=["marcus.brody@gmail.com"],
        phone_numbers=["(214) 555-0192", "+1-214-555-0199"],
        current_city="Dallas",
        current_state="TX",
        known_addresses=["1428 Elm Street, Dallas, TX 75201", "800 Main St, Austin, TX"],
        relatives=["Eleanor Brody", "Arthur Brody"],
        employers=["Cybersec Institute"],
        usernames=["mbrody_sec"],
    )


@pytest.fixture
def sample_extracted_profiles() -> list[ExtractedEntityProfile]:
    return [
        ExtractedEntityProfile(
            target_id="tgt_test_101",
            source_url="https://www.truepeoplesearch.com/find/person/px49281",
            source_broker="truepeoplesearch",
            matched_names=["Marcus A Brody", "Mark Brody"],
            age="42",
            phone_numbers=["(214) 555-0192"],
            email_addresses=["m.brody@cybersec-institute.org"],
            current_address="1428 Elm Street, Dallas, TX 75201",
            past_addresses=["800 Main St, Austin, TX"],
            relatives=["Eleanor Brody"],
            removal_url="https://www.truepeoplesearch.com/removal",
            confidence_score=0.96,
        ),
        ExtractedEntityProfile(
            target_id="tgt_test_101",
            source_url="https://www.fastpeoplesearch.com/name/marcus-brody_dallas-tx",
            source_broker="fastpeoplesearch",
            matched_names=["Marcus Aurelius Brody"],
            phone_numbers=["(214) 555-0192", "+1-214-555-0199"],
            email_addresses=["marcus.brody@gmail.com"],
            current_address="1428 Elm Street, Dallas, TX 75201",
            removal_url="https://www.fastpeoplesearch.com/removal",
            confidence_score=0.92,
        ),
        ExtractedEntityProfile(
            target_id="tgt_test_101",
            source_url="https://radaris.com/p/Marcus/Brody/",
            source_broker="radaris",
            matched_names=["Marcus Brody"],
            removal_url="https://radaris.com/control/privacy",
            confidence_score=0.88,
        ),
    ]


# ==============================================================================
# Tier 1: Plan Compilation & Legal Notice Verification
# ==============================================================================

def test_tier1_suppression_engine_compilation(sample_target: TargetIdentityInput, sample_extracted_profiles: list[ExtractedEntityProfile]) -> None:
    engine = SuppressionEngine()
    plan = engine.compile_plan(sample_target, sample_extracted_profiles, target_id="tgt_123")

    assert isinstance(plan, SuppressionActionPlan)
    assert plan.target_id == "tgt_123"
    assert plan.total_actions == 3
    assert len(plan.actions) == 3
    assert plan.master_ccpa_letter is not None
    assert plan.master_gdpr_letter is not None


def test_tier1_master_ccpa_letter_statutory_content(sample_target: TargetIdentityInput, sample_extracted_profiles: list[ExtractedEntityProfile]) -> None:
    letter = generate_master_ccpa_letter(sample_target, sample_extracted_profiles)
    assert "CALIFORNIA CONSUMER PRIVACY ACT" in letter
    assert "§ 1798.105" in letter
    assert "§ 1798.120" in letter
    assert "§ 1798.125" in letter
    assert "forty-five (45) calendar days" in letter
    assert sample_target.full_name in letter
    assert "m.brody@cybersec-institute.org" in letter
    assert "1428 Elm Street" in letter
    assert "Truepeoplesearch" in letter or "truepeoplesearch" in letter


def test_tier1_master_gdpr_letter_statutory_content(sample_target: TargetIdentityInput, sample_extracted_profiles: list[ExtractedEntityProfile]) -> None:
    letter = generate_master_gdpr_letter(sample_target, sample_extracted_profiles)
    assert "REGULATION (EU) 2016/679" in letter
    assert "ARTICLE 17" in letter
    assert "ARTICLE 21" in letter
    assert "ARTICLE 19" in letter
    assert "one (1) month" in letter
    assert sample_target.full_name in letter


# ==============================================================================
# Tier 2: Multi-Broker Aggregation, URL Mapping & Deduplication
# ==============================================================================

def test_tier2_profile_deduplication_and_merging(sample_target: TargetIdentityInput) -> None:
    duplicate_profiles = [
        ExtractedEntityProfile(
            target_id="tgt_dup",
            source_url="https://www.truepeoplesearch.com/find/1",
            source_broker="truepeoplesearch",
            matched_names=["Marcus Brody"],
            phone_numbers=["214-555-0100"],
            confidence_score=0.85,
        ),
        ExtractedEntityProfile(
            target_id="tgt_dup",
            source_url="https://www.truepeoplesearch.com/find/2",
            source_broker="truepeoplesearch",
            matched_names=["M. Brody"],
            phone_numbers=["214-555-0200"],
            email_addresses=["brody@example.com"],
            removal_url="https://www.truepeoplesearch.com/removal",
            confidence_score=0.95,
        ),
    ]
    deduped = aggregate_and_deduplicate_profiles(duplicate_profiles)
    assert len(deduped) == 1
    assert set(deduped[0].matched_names) == {"Marcus Brody", "M. Brody"}
    assert set(deduped[0].phone_numbers) == {"214-555-0100", "214-555-0200"}
    assert deduped[0].email_addresses == ["brody@example.com"]
    assert deduped[0].removal_url == "https://www.truepeoplesearch.com/removal"
    assert deduped[0].confidence_score == 0.95


def test_tier2_proactive_baseline_when_zero_exposures(sample_target: TargetIdentityInput) -> None:
    engine = SuppressionEngine()
    plan = engine.compile_plan(sample_target, profiles=[])
    assert plan.total_actions == len(DEFAULT_PROACTIVE_BROKERS)
    broker_ids = [a.broker_id for a in plan.actions]
    assert "truepeoplesearch" in broker_ids
    assert "fastpeoplesearch" in broker_ids
    assert "peopleconnect" in broker_ids


def test_tier2_broker_specific_form_schemas(sample_target: TargetIdentityInput) -> None:
    for broker_key in ["truepeoplesearch", "fastpeoplesearch", "radaris", "nuwber", "whitepages", "peopleconnect"]:
        payload = build_broker_payload(sample_target, None, broker_key)
        assert payload.broker_id == broker_key
        assert isinstance(payload.form_payload, dict)
        assert payload.legal_request_letter is not None
        assert payload.status == SuppressionStatus.PENDING


# ==============================================================================
# Tier 3: ProjectUmbraAgent Phase 6 Integration & Telemetry Streaming
# ==============================================================================

@pytest.mark.asyncio
async def test_tier3_agent_phase6_telemetry_broadcasting(sample_target: TargetIdentityInput) -> None:
    events: list[AgentTelemetryEvent] = []

    async def event_handler(evt: AgentTelemetryEvent) -> None:
        events.append(evt)

    engine = SuppressionEngine()
    agent = ProjectUmbraAgent(suppression_engine=engine, max_budget=25)
    summary = await agent.run_mission(sample_target, event_callback=event_handler)

    assert summary.final_state == AgentLifecycleState.COMPLETED
    assert summary.remediation_plan is not None
    assert summary.remediations_generated == len(summary.remediation_plan.actions)
    assert summary.remediations_generated > 0

    suppression_events = [e for e in events if e.event_type == TelemetryEventType.ACTION_PLAN_GENERATED]
    assert len(suppression_events) == summary.remediations_generated
    assert all("action" in e.payload for e in suppression_events)
    assert all(e.payload["external_action_dispatched"] is False for e in suppression_events)


# ==============================================================================
# Tier 4: End-to-End Mission Lifecycle & State Record Validation
# ==============================================================================

@pytest.mark.asyncio
async def test_tier4_end_to_end_mission_execution_with_suppression(sample_target: TargetIdentityInput) -> None:
    agent = ProjectUmbraAgent()
    summary = await agent.run_mission(sample_target)

    assert summary.final_state == AgentLifecycleState.COMPLETED
    assert summary.remediation_plan is not None
    assert len(summary.remediation_plan.actions) > 0
    assert summary.remediation_plan.master_ccpa_letter is not None
    assert summary.remediation_plan.master_gdpr_letter is not None

    suppression_steps = [s for s in summary.execution_state_log if s.state == AgentLifecycleState.GENERATING_REMEDIATIONS]
    assert len(suppression_steps) >= 1
    assert suppression_steps[0].tool_name == "action_plan_engine"
    assert summary.external_actions_dispatched == 0


# ==============================================================================
# Tier 5: Adversarial & Edge Case Handling
# ==============================================================================

@pytest.mark.asyncio
async def test_tier5_budget_exhaustion_emergency_consolidation(sample_target: TargetIdentityInput) -> None:
    agent = ProjectUmbraAgent(max_budget=3)
    summary = await agent.run_mission(sample_target)

    assert summary.final_state == AgentLifecycleState.BUDGET_EXHAUSTED
    assert summary.remediation_plan is not None
    assert summary.remediations_generated >= 0


def test_tier5_malformed_target_inputs() -> None:
    target = TargetIdentityInput(
        full_name="<script>alert('xss')</script> John Doe",
        aliases=["Robert'); DROP TABLE users;--"],
        primary_email="hacker@bad<domain>.org",
        known_addresses=["Unicode address: \u2603 \u2764 \u00e9"],
    )
    engine = SuppressionEngine()
    plan = engine.compile_plan(target)
    assert len(plan.actions) > 0
    assert "<script>" in (plan.master_ccpa_letter or "")
