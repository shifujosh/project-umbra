from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Request
from sse_starlette.sse import ServerSentEvent, EventSourceResponse

demo_router = APIRouter(tags=["demo"])

DEMO_SCAN_ID = "demo_avery_mercer_001"
AVERY_CASE_LOCATIONS = [
    "Oakland, California",
    "Portland, Oregon",
    "Austin, Texas",
    "Santa Fe, New Mexico",
    "Chicago, Illinois",
    "Lisbon, Portugal",
]

# ── Rights-cleared controlled synthetic profile fixtures ─────────────────────
AVERY_FINDINGS: list[dict[str, Any]] = [
    {
        "source_broker": "TruePeopleSearch",
        "matched_names": ["Avery Mercer", "Avery J. Mercer", "A. Mercer"],
        "current_address": "Oakland, California",
        "phone_numbers": ["+1 (202) 555-0142"],
        "email_addresses": ["avery@helio.example", "avery.mercer@relay.example"],
        "relatives": [],
        "removal_url": "https://www.truepeoplesearch.com/removal",
        "overall_risk_score": 0.94,
        "confidence_score": 0.98,
        "broker_id": "truepeoplesearch",
        "provenance": "controlled_fixture",
    },
    {
        "source_broker": "FastPeopleSearch",
        "matched_names": ["Avery Mercer", "Avery J. Mercer", "ave_mercer"],
        "current_address": "Portland, Oregon",
        "phone_numbers": ["+1 (202) 555-0142"],
        "email_addresses": ["avery@helio.example"],
        "relatives": [],
        "removal_url": "https://www.fastpeoplesearch.com/removal",
        "overall_risk_score": 0.88,
        "confidence_score": 0.92,
        "broker_id": "fastpeoplesearch",
        "provenance": "controlled_fixture",
    },
    {
        "source_broker": "Radaris",
        "matched_names": ["Avery Mercer", "A. Mercer"],
        "current_address": "Austin, Texas",
        "phone_numbers": ["+1 (202) 555-0142"],
        "email_addresses": ["avery.mercer@relay.example"],
        "relatives": [],
        "removal_url": "https://radaris.com/control/privacy",
        "overall_risk_score": 0.82,
        "confidence_score": 0.89,
        "broker_id": "radaris",
        "provenance": "controlled_fixture",
    },
    {
        "source_broker": "Nuwber",
        "matched_names": ["Avery Mercer", "ave_mercer"],
        "current_address": "Santa Fe, New Mexico",
        "phone_numbers": ["+1 (202) 555-0142"],
        "email_addresses": ["avery@helio.example"],
        "relatives": [],
        "removal_url": "https://nuwber.com/removal/link",
        "overall_risk_score": 0.79,
        "confidence_score": 0.85,
        "broker_id": "nuwber",
        "provenance": "controlled_fixture",
    },
    {
        "source_broker": "Whitepages",
        "matched_names": ["Avery Mercer", "Avery J. Mercer"],
        "current_address": "Chicago, Illinois",
        "phone_numbers": ["+1 (202) 555-0142"],
        "email_addresses": ["avery@helio.example"],
        "relatives": [],
        "removal_url": "https://www.whitepages.com/suppression_requests",
        "overall_risk_score": 0.71,
        "confidence_score": 0.81,
        "broker_id": "whitepages",
        "provenance": "controlled_fixture",
    },
]

AVERY_ACTION_PACKAGES: list[dict[str, Any]] = [
    {
        "broker_name": "TruePeopleSearch",
        "status": "PREPARED",
        "notice_type": "CCPA Right to Delete Plan",
        "tracking_reference": "TPS-AVERY-001",
        "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provenance": "controlled_fixture",
        "external_action_dispatched": False,
    },
    {
        "broker_name": "FastPeopleSearch",
        "status": "PREPARED",
        "notice_type": "CCPA / Direct Opt-Out Plan",
        "tracking_reference": "FPS-AVERY-001",
        "content_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provenance": "controlled_fixture",
        "external_action_dispatched": False,
    },
    {
        "broker_name": "Radaris",
        "status": "PREPARED",
        "notice_type": "CPRA Deletion and Correction Plan",
        "tracking_reference": "RAD-AVERY-001",
        "content_hash": "f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provenance": "controlled_fixture",
        "external_action_dispatched": False,
    },
    {
        "broker_name": "Nuwber",
        "status": "PREPARED",
        "notice_type": "CCPA Right to Delete",
        "tracking_reference": "NUW-AVERY-001",
        "content_hash": "2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4f",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provenance": "controlled_fixture",
        "external_action_dispatched": False,
    },
    {
        "broker_name": "Whitepages",
        "status": "PREPARED",
        "notice_type": "PeopleConnect Master Suppression Notice",
        "tracking_reference": "WP-AVERY-001",
        "content_hash": "9e1c3a5b7d9f1c3a5b7d9f1c3a5b7d9f1c3a5b7d9f1c3a5b7d9f1c3a5b7d9f1a",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provenance": "controlled_fixture",
        "external_action_dispatched": False,
    },
]

# ── Cohesive Narrative Event Sequence ─────────────────────────────────────────
DEMO_SCRIPT: list[tuple[float, str, str, dict[str, Any]]] = [
    (0.3,  "mission_start",      "Controlled synthetic demo initialized for Avery Mercer · Target Ref: demo_avery_mercer_001", {"state": "INITIALIZING", "step_count": 0}),
    (0.5,  "info",               "Phase 1: Decomposing target identity into digital footprint search vectors…", {"state": "DECOMPOSING", "step_count": 1}),
    (0.6,  "tool",               "Identity Vector Decomposer: generated aliases → 'Avery Mercer', 'Avery J. Mercer', 'A. Mercer', 'ave_mercer'", {"step_count": 1}),
    (0.5,  "tool",               "Identity Vector Decomposer: email vectors → avery@helio.example, avery.mercer@relay.example", {"step_count": 1}),
    (0.4,  "tool",               "Identity Vector Decomposer: geo vectors → Oakland · Portland · Austin · Santa Fe · Chicago · Lisbon", {"step_count": 2}),
    (0.5,  "success",            "Identity decomposition complete: 6 synthetic location signals formulated for the controlled demo", {"step_count": 2}),
    (0.6,  "phase_transition",   "→ Phase 2: Dork Synthesis & Controlled SERP Fixture Replay", {"state": "SCANNING_SERP", "step_count": 2}),
    (0.4,  "tool",               'Dork Engine: site:truepeoplesearch.com "Avery Mercer" "Oakland California"', {"step_count": 3}),
    (0.4,  "tool",               'Dork Engine: site:fastpeoplesearch.com "Avery J. Mercer" "Portland Oregon"', {"step_count": 3}),
    (0.4,  "tool",               'Dork Engine: site:radaris.com "A. Mercer" "Austin Texas"', {"step_count": 3}),
    (0.4,  "tool",               'Dork Engine: site:nuwber.com "avery@helio.example" "Santa Fe"', {"step_count": 4}),
    (0.4,  "tool",               'Dork Engine: site:whitepages.com "Avery Mercer" "Chicago Illinois"', {"step_count": 4}),
    (0.4,  "tool",               'Public Profile Index: "@averymercer" "Helio Civic Lab"', {"step_count": 4}),
    (0.5,  "success",            "Dork synthesis finished: 23 precision query vectors generated across 7 taxonomies", {"step_count": 4}),
    (0.6,  "tool",               "Reconnaissance Engine: querying directory aggregator profiles (1/5)…", {"step_count": 5}),
    (0.5,  "info",               "Reconnaissance Engine: 5 data broker endpoints identified", {"step_count": 5}),
    (0.4,  "tool",               "Reconnaissance Engine: scanning public exposure indices (2/5)…", {"step_count": 6}),
    (0.4,  "info",               "Reconnaissance Engine: 0 public breaches detected for target handle", {"step_count": 6}),
    (0.5,  "success",            "Reconnaissance sweep complete — 5 broker endpoints queued for inspection", {"step_count": 7}),
    (0.6,  "phase_transition",   "→ Phase 3: Broker Profile Inspection & Acquisition", {"state": "SCANNING_BROKERS", "step_count": 7}),
    (0.6,  "tool",               "Broker Ingestion: acquiring TruePeopleSearch profile…", {"step_count": 8}),
    (0.6,  "info",               "Broker Ingestion: TruePeopleSearch profile acquired", {"step_count": 8}),
    (0.6,  "tool",               "Broker Ingestion: acquiring FastPeopleSearch profile…", {"step_count": 9}),
    (0.6,  "info",               "Broker Ingestion: FastPeopleSearch profile acquired", {"step_count": 9}),
    (0.6,  "tool",               "Broker Ingestion: acquiring Radaris profile…", {"step_count": 10}),
    (0.5,  "info",               "Broker Ingestion: Radaris profile acquired", {"step_count": 10}),
    (0.5,  "tool",               "Broker Ingestion: acquiring Nuwber profile…", {"step_count": 11}),
    (0.5,  "info",               "Broker Ingestion: Nuwber profile acquired", {"step_count": 11}),
    (0.5,  "tool",               "Broker Ingestion: acquiring Whitepages profile…", {"step_count": 12}),
    (0.5,  "info",               "Broker Ingestion: Whitepages profile acquired", {"step_count": 12}),
    (0.5,  "success",            "Broker acquisition complete — 5 target dossiers staged for extraction", {"step_count": 12}),
    (0.6,  "phase_transition",   "→ Phase 4: Gemini 3.7 Flash Structured Extraction", {"state": "EXTRACTING_EXPOSURES", "step_count": 12}),
    (0.6,  "tool",               "Gemini 3.7 Flash: extracting structured PII from TruePeopleSearch…", {"step_count": 13, "finding": AVERY_FINDINGS[0]}),
    (0.5,  "info",               "Gemini 3.7 Flash: TruePeopleSearch → 1 phone, 2 emails, verified portal URL", {"step_count": 13}),
    (0.5,  "tool",               "Gemini 3.7 Flash: extracting structured PII from FastPeopleSearch…", {"step_count": 14, "finding": AVERY_FINDINGS[1]}),
    (0.5,  "info",               "Gemini 3.7 Flash: FastPeopleSearch → 1 phone, 1 email, verified portal URL", {"step_count": 14}),
    (0.5,  "tool",               "Gemini 3.7 Flash: extracting structured PII from Radaris…", {"step_count": 14, "finding": AVERY_FINDINGS[2]}),
    (0.5,  "tool",               "Gemini 3.7 Flash: extracting structured PII from Nuwber…", {"step_count": 15, "finding": AVERY_FINDINGS[3]}),
    (0.5,  "tool",               "Gemini 3.7 Flash: extracting structured PII from Whitepages…", {"step_count": 15, "finding": AVERY_FINDINGS[4]}),
    (0.5,  "success",            "Structured extraction complete: 5 broker dossiers parsed and linked to identity graph", {"step_count": 16}),
    (0.6,  "phase_transition",   "→ Phase 5: PII Risk Classification & Token Redaction", {"state": "SANITIZING_PII", "step_count": 16}),
    (0.6,  "tool",               "PII Risk Engine: analyzing extracted phone, email, and location tokens…", {"step_count": 17}),
    (0.5,  "info",               "PII Risk Engine: 7 sensitive tokens classified → Exposure Index: HIGH (0.94)", {"step_count": 17}),
    (0.5,  "tool",               "PII Risk Engine: generating reversible surrogate-token map…", {"step_count": 18}),
    (0.5,  "success",            "PII classification & sanitization complete — telemetry scrubbed for privacy compliance", {"step_count": 18}),
    (0.6,  "phase_transition",   "→ Phase 6: Approval-Gated Remediation Plan Preparation", {"state": "GENERATING_REMEDIATIONS", "step_count": 18}),
    (0.5,  "tool",               "Action Plan Engine: assembling TruePeopleSearch CCPA Right to Delete package…", {"step_count": 19}),
    (0.5,  "success",            "TruePeopleSearch: READY FOR APPROVAL · Direct portal link staged · 0 dispatched", {"step_count": 19, "receipt": AVERY_ACTION_PACKAGES[0]}),
    (0.4,  "tool",               "Action Plan Engine: assembling FastPeopleSearch Direct Opt-Out package…", {"step_count": 20}),
    (0.5,  "success",            "FastPeopleSearch: READY FOR APPROVAL · Direct portal link staged · 0 dispatched", {"step_count": 20, "receipt": AVERY_ACTION_PACKAGES[1]}),
    (0.4,  "tool",               "Action Plan Engine: assembling Radaris CPRA deletion and correction package…", {"step_count": 21}),
    (0.5,  "success",            "Radaris: READY FOR APPROVAL · Direct portal link staged · 0 dispatched", {"step_count": 21, "receipt": AVERY_ACTION_PACKAGES[2]}),
    (0.4,  "tool",               "Action Plan Engine: assembling Nuwber CCPA Opt-Out package…", {"step_count": 22}),
    (0.5,  "success",            "Nuwber: READY FOR APPROVAL · Direct portal link staged · 0 dispatched", {"step_count": 22, "receipt": AVERY_ACTION_PACKAGES[3]}),
    (0.4,  "tool",               "Action Plan Engine: assembling Whitepages PeopleConnect Master Opt-Out package…", {"step_count": 23}),
    (0.5,  "success",            "Whitepages: READY FOR APPROVAL · Direct portal link staged · 0 dispatched", {"step_count": 23, "receipt": AVERY_ACTION_PACKAGES[4]}),
    (0.8,  "mission_complete",   "Mission complete — remediation plan ready for review · 5 broker actions prepared · 0 dispatched", {
        "state": "COMPLETE",
        "step_count": 23,
        "finding_count": 5,
        "receipt_count": 5,
        "findings": AVERY_FINDINGS,
        "receipts": AVERY_ACTION_PACKAGES,
        "external_actions_dispatched": 0,
    }),
]


async def _demo_event_stream(request: Request) -> AsyncGenerator[ServerSentEvent, None]:
    step = 0
    for delay, event_type, message, extra in DEMO_SCRIPT:
        if await request.is_disconnected():
            break
        await asyncio.sleep(delay)
        payload = {
            "event_type": event_type,
            "message": message,
            "mission_id": DEMO_SCAN_ID,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "demo": True,
            "synthetic_profile": True,
            "provenance": "controlled_fixture",
            "external_action_dispatched": False,
            **extra,
        }
        yield ServerSentEvent(
            id=str(step),
            event="message",
            data=json.dumps(payload),
            retry=5000,
        )
        step += 1


@demo_router.get("/stream", summary="Stream the controlled Avery Mercer synthetic demo via SSE")
async def demo_stream(request: Request) -> EventSourceResponse:
    return EventSourceResponse(
        _demo_event_stream(request),
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@demo_router.get("/profile", summary="Get controlled Avery Mercer demo findings and action packages")
async def demo_profile() -> dict:
    return {
        "target_name": "Avery Mercer",
        "aliases": ["Avery J. Mercer", "A. Mercer", "ave_mercer"],
        "primary_email": "avery@helio.example",
        "secondary_email": "avery.mercer@relay.example",
        "phone": "+1 (202) 555-0142",
        "handles": ["@averymercer", "@heliocivic"],
        "organization": "Helio Civic Lab",
        "role": "Community Researcher",
        "case_locations": AVERY_CASE_LOCATIONS,
        "findings": AVERY_FINDINGS,
        "receipts": AVERY_ACTION_PACKAGES,
        "demo": True,
        "synthetic_profile": True,
        "provenance": "controlled_fixture",
        "external_actions_dispatched": 0,
    }
