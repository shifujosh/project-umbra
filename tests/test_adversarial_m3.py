"""
Adversarial and Edge Case Test Suite for Milestone 3 (Suppression Engine & Statutory Notices).
Covers boundary conditions, single-name mononyms, non-standard address layouts,
async client lifecycle context managers, custom broker dispatches, HTTP status cascades,
PeopleConnect brand subsets, and agent telemetry resilience.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import pytest
import httpx

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
    BROKER_REMOVAL_ENDPOINTS,
    DEFAULT_PROACTIVE_BROKERS,
    KNOWN_BROKER_REGISTRY,
    BaseBrokerDispatcher,
    LegalNoticeGenerator,
    PeopleConnectBrand,
    SuppressionEngine,
    aggregate_and_deduplicate_profiles,
    build_broker_payload,
    format_identity_schedule,
    generate_ccpa_notice,
    generate_cryptographic_tracking_hash,
    generate_gdpr_notice,
    generate_peopleconnect_payload,
    normalize_broker_id,
)


# ==============================================================================
# Mononym and Non-Standard Identity Handling
# ==============================================================================

def test_mononym_target_identity() -> None:
    target = TargetIdentityInput(
        full_name="Cher",
        primary_email="cher@example.com",
    )
    generator = LegalNoticeGenerator()
    ccpa = generator.generate_ccpa(target)
    assert "Cher" in ccpa
    assert "Cal. Civ. Code § 1798.105" in ccpa

    pc = generator.generate_peopleconnect(target)
    assert pc.form_payload["first_name"] == "Cher"
    assert pc.form_payload["last_name"] == ""


def test_complex_name_and_custom_address_parsing() -> None:
    target = TargetIdentityInput(
        full_name="Jean-Luc Picard",
        aliases=["Locutus"],
        known_addresses=["1701 Enterprise Way, Star City, CA 90210"],
    )
    pc = generate_peopleconnect_payload(target)
    assert pc.form_payload["first_name"] == "Jean-Luc"
    assert pc.form_payload["last_name"] == "Picard"
    assert pc.form_payload["city"] == "Star City"
    assert pc.form_payload["state"] == "CA"
    assert pc.form_payload["zip_code"] == "90210"


def test_peopleconnect_specific_brand_subset() -> None:
    target = TargetIdentityInput(
        full_name="Marcus Brody",
        primary_email="mbrody@example.com",
    )
    brands = [PeopleConnectBrand.INTELIUS, PeopleConnectBrand.TRUTHFINDER]
    pc = generate_peopleconnect_payload(target, target_brands=brands)
    assert set(pc.form_payload["target_brands"]) == {"intelius", "truthfinder"}


# ==============================================================================
# Unknown & Custom Broker Routing
# ==============================================================================

def test_unknown_and_custom_broker_payload_generation() -> None:
    target = TargetIdentityInput(full_name="Alice Smith", primary_email="alice@example.com")
    engine = SuppressionEngine(simulation_mode=True)
    payload = engine.build_payload("custom_breach_broker", target, profile_url="https://custom.com/p/alice")

    assert payload.broker_id == "custom_breach_broker"
    assert payload.form_payload["email"] == "alice@example.com"
    assert payload.target_profile_url == "https://custom.com/p/alice"

    dispatcher = engine.get_dispatcher("unknown_broker_xyz")
    assert isinstance(dispatcher, BaseBrokerDispatcher)


def test_normalize_broker_id_edge_cases() -> None:
    assert normalize_broker_id("True-People-Search") == "truepeoplesearch"
    assert normalize_broker_id(None, "https://www.FastPeopleSearch.com/name/john") == "fastpeoplesearch"
    assert normalize_broker_id(None, "https://sub.unknownbroker.org/lookup/123") == "sub_unknownbroker_org"
    assert normalize_broker_id(None, None) == "data_broker"


# ==============================================================================
# Deduplication Edge Cases
# ==============================================================================

def test_deduplication_empty_and_merging() -> None:
    assert aggregate_and_deduplicate_profiles([]) == []

    p1 = ExtractedEntityProfile(
        target_id="tgt_1",
        source_url="https://nuwber.com/person/p1",
        source_broker="nuwber",
        matched_names=["John Doe"],
        phone_numbers=["555-0001"],
        email_addresses=["john@work.com"],
        confidence_score=0.70,
    )
    p2 = ExtractedEntityProfile(
        target_id="tgt_1",
        source_url="https://nuwber.com/person/p1-alt",
        source_broker="nuwber",
        matched_names=["Johnny Doe"],
        phone_numbers=["555-0002"],
        email_addresses=["john@home.com"],
        removal_url="https://nuwber.com/removal/link",
        confidence_score=0.95,
    )

    merged = aggregate_and_deduplicate_profiles([p1, p2])
    assert len(merged) == 1
    assert set(merged[0].matched_names) == {"John Doe", "Johnny Doe"}
    assert set(merged[0].phone_numbers) == {"555-0001", "555-0002"}
    assert set(merged[0].email_addresses) == {"john@work.com", "john@home.com"}
    assert merged[0].removal_url == "https://nuwber.com/removal/link"
    assert merged[0].confidence_score == 0.95


# ==============================================================================
# Async Engine Lifecycle & HTTP Client Mocking
# ==============================================================================

@pytest.mark.asyncio
async def test_async_engine_context_manager() -> None:
    async with SuppressionEngine(simulation_mode=False) as engine:
        assert engine._client is not None

    assert engine._client is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status_code,expected_status",
    [
        (201, "SUBMITTED"),
        (204, "SUBMITTED"),
        (403, "FAILED"),
        (404, "FAILED"),
        (502, "FAILED"),
    ],
)
async def test_http_various_status_codes(status_code: int, expected_status: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, text="Response message")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        dispatcher = BaseBrokerDispatcher()
        target = TargetIdentityInput(full_name="Bob Jones", primary_email="bob@example.com")
        payload = SuppressionPayload(
            broker_id="generic",
            broker_name="Generic",
            opt_out_type="automated_form",
            form_payload=dispatcher.build_form_payload(target),
            submission_url="https://example.com/optout",
        )
        receipt = await dispatcher.submit(payload, client=client, simulation_mode=False)
        assert receipt.status == expected_status
        assert receipt.response_code == status_code


# ==============================================================================
# Full Agent Mission Lifecycle with Telemetry Validation
# ==============================================================================

@pytest.mark.asyncio
async def test_agent_mission_full_lifecycle_with_suppression() -> None:
    target = TargetIdentityInput(
        full_name="Agent Subject Test",
        primary_email="subject@test.com",
        current_city="Austin",
        current_state="TX",
    )
    events: list[AgentTelemetryEvent] = []

    async def callback(e: AgentTelemetryEvent) -> None:
        events.append(e)

    agent = ProjectUmbraAgent(max_budget=20)
    summary = await agent.run_mission(target, event_callback=callback)

    assert summary.final_state == AgentLifecycleState.COMPLETED
    assert summary.remediation_plan is not None
    assert summary.remediation_plan.total_actions > 0
    assert summary.remediation_plan.master_ccpa_letter is not None
    assert summary.remediation_plan.master_gdpr_letter is not None

    states = [e.state for e in events]
    assert AgentLifecycleState.GENERATING_REMEDIATIONS in states
    assert AgentLifecycleState.COMPLETED in states
