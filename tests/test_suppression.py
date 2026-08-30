"""
Unit and Integration Tests for Project Umbra Automated Suppression Engine & Legal Notice Generator (Tiers 1-5).
Verifies CCPA/CPRA statutory citations, GDPR Art. 17/21 compliance, PeopleConnect Master opt-out integrity,
cryptographic SHA-256 receipt hashing, statutory deadline calculation, HTTP simulation fixtures,
mock HTTP transport submissions, and adversarial stress resilience.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
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
    BROKER_REMOVAL_ENDPOINTS,
    DEFAULT_PROACTIVE_BROKERS,
    KNOWN_BROKER_REGISTRY,
    PEOPLECONNECT_BRAND_METADATA,
    SIMULATED_BROKER_RESPONSES,
    STATUTORY_COMPLIANCE_DAYS,
    BaseBrokerDispatcher,
    FastPeopleSearchDispatcher,
    LegalNoticeGenerator,
    LegalNoticeType,
    NuwberDispatcher,
    PeopleConnectBrand,
    PeopleConnectDispatcher,
    RadarisDispatcher,
    SuppressionEngine,
    TruePeopleSearchDispatcher,
    WhitepagesDispatcher,
    aggregate_and_deduplicate_profiles,
    build_broker_payload,
    calculate_compliance_deadline,
    create_suppression_receipt,
    format_identity_schedule,
    generate_broker_legal_letter,
    generate_ccpa_notice,
    generate_cryptographic_tracking_hash,
    generate_gdpr_notice,
    generate_master_ccpa_letter,
    generate_master_gdpr_letter,
    generate_peopleconnect_payload,
    generate_tracking_reference,
    map_response_to_status,
    normalize_broker_id,
)


@pytest.fixture
def rich_target() -> TargetIdentityInput:
    return TargetIdentityInput(
        full_name="Marcus Aurelius Brody",
        aliases=["Mark Brody", "M. A. Brody"],
        primary_email="m.brody@texastech.edu",
        secondary_emails=["marcus.brody@gmail.com"],
        phone_numbers=["(214) 555-0192", "555-0144"],
        current_city="Dallas",
        current_state="TX",
        known_addresses=["1428 Elm Street, Dallas, TX 75201", "PO Box 991, Austin, TX 78701"],
        relatives=["Eleanor Brody", "Arthur Brody"],
        employers=["Texas Tech University"],
        usernames=["mbrody_sec"],
    )


@pytest.fixture
def minimal_target() -> TargetIdentityInput:
    return TargetIdentityInput(full_name="Jane Doe")


@pytest.fixture
def sample_profiles() -> list[ExtractedEntityProfile]:
    return [
        ExtractedEntityProfile(
            target_id="tgt_test_123",
            source_url="https://www.truepeoplesearch.com/find/person/marcus-aurelius-brody",
            source_broker="truepeoplesearch",
            matched_names=["Marcus Aurelius Brody"],
            phone_numbers=["(214) 555-0192"],
            email_addresses=["m.brody@texastech.edu"],
            current_address="1428 Elm Street, Dallas, TX 75201",
            removal_url="https://www.truepeoplesearch.com/removal",
            confidence_score=0.95,
        ),
        ExtractedEntityProfile(
            target_id="tgt_test_123",
            source_url="https://www.fastpeoplesearch.com/name/marcus-aurelius-brody_dallas-tx",
            source_broker="fastpeoplesearch",
            matched_names=["Marcus Aurelius Brody"],
            phone_numbers=["(214) 555-0192"],
            removal_url="https://www.fastpeoplesearch.com/removal",
            confidence_score=0.90,
        ),
        ExtractedEntityProfile(
            target_id="tgt_test_123",
            source_url="https://radaris.com/p/marcus-aurelius-brody",
            source_broker="radaris",
            matched_names=["Marcus Aurelius Brody"],
            removal_url="https://radaris.com/control/privacy",
            confidence_score=0.88,
        ),
        ExtractedEntityProfile(
            target_id="tgt_test_123",
            source_url="https://nuwber.com/person/marcus-aurelius-brody",
            source_broker="nuwber",
            matched_names=["Marcus Aurelius Brody"],
            removal_url="https://nuwber.com/removal/link",
            confidence_score=0.92,
        ),
        ExtractedEntityProfile(
            target_id="tgt_test_123",
            source_url="https://www.whitepages.com/name/marcus-aurelius-brody/dallas-tx",
            source_broker="whitepages",
            matched_names=["Marcus Aurelius Brody"],
            removal_url="https://www.whitepages.com/suppression-requests",
            confidence_score=0.96,
        ),
    ]


# ==============================================================================
# Tier 1: Statutory Citations & Legal Notice Veracity
# ==============================================================================

def test_tier1_ccpa_statutory_citations(rich_target: TargetIdentityInput) -> None:
    notice = generate_ccpa_notice(rich_target, broker_name="FastPeopleSearch")
    assert "CALIFORNIA CIVIL CODE § 1798.100 ET SEQ." in notice
    assert "Cal. Civ. Code § 1798.105" in notice
    assert "Cal. Civ. Code § 1798.120" in notice
    assert "Cal. Civ. Code § 1798.125" in notice
    assert "Cal. Civ. Code § 1798.130(a)(2)" in notice
    assert "11 CCR § 7027" in notice
    assert "Cal. Civ. Code § 1798.105(c)(1)" in notice
    assert "penalty of perjury under the laws of the State of California" in notice
    assert "California Privacy Protection Agency" in notice or "CPPA" in notice


def test_tier1_gdpr_statutory_citations(rich_target: TargetIdentityInput) -> None:
    notice = generate_gdpr_notice(rich_target, controller_name="Radaris Europe")
    assert "REGULATION (EU) 2016/679" in notice
    assert "ARTICLE 17" in notice
    assert "Article 17(1)(a)" in notice
    assert "Article 17(1)(c)" in notice
    assert "Article 17(1)(d)" in notice
    assert "ARTICLE 21" in notice
    assert "Article 21(1)" in notice
    assert "Article 21(2)" in notice
    assert "Article 12(3)" in notice
    assert "Article 19" in notice
    assert "Article 83(5)" in notice
    assert "Article 77" in notice


# ==============================================================================
# Tier 2: Dynamic Parameter Injection & Identity Schedule
# ==============================================================================

def test_tier2_identity_schedule_formatting(rich_target: TargetIdentityInput) -> None:
    schedule = format_identity_schedule(rich_target, profile_url="https://example.com/p/marcus-brody")
    assert "Marcus Aurelius Brody" in schedule
    assert "Mark Brody, M. A. Brody" in schedule
    assert "m.brody@texastech.edu" in schedule
    assert "(214) 555-0192" in schedule
    assert "1428 Elm Street, Dallas, TX 75201" in schedule
    assert "Eleanor Brody" in schedule
    assert "https://example.com/p/marcus-brody" in schedule


def test_tier2_minimal_target_formatting(minimal_target: TargetIdentityInput) -> None:
    schedule = format_identity_schedule(minimal_target)
    assert "Jane Doe" in schedule
    assert "Known Aliases" not in schedule
    assert "Phone Numbers" not in schedule


# ==============================================================================
# Tier 3: PeopleConnect Master Payload Integrity
# ==============================================================================

def test_tier3_peopleconnect_master_payload(rich_target: TargetIdentityInput) -> None:
    payload = generate_peopleconnect_payload(rich_target)
    assert isinstance(payload, SuppressionPayload)
    assert payload.broker_id == "peopleconnect_master"
    assert payload.opt_out_type == "master_opt_out"
    assert payload.status == SuppressionStatus.PENDING
    assert "suppression.peopleconnect.us" in (payload.submission_url or "")

    fp = payload.form_payload
    assert fp["first_name"] == "Marcus"
    assert fp["last_name"] == "Brody"
    assert fp["email"] == "m.brody@texastech.edu"
    assert fp["phone"] == "(214) 555-0192"
    assert fp["city"] == "Dallas"
    assert fp["state"] == "TX"
    assert fp["opt_out_all_brands"] is True
    assert set(fp["target_brands"]) == {"truthfinder", "instantcheckmate", "intelius", "ussearch"}

    assert payload.legal_request_letter is not None
    assert "PeopleConnect, Inc." in payload.legal_request_letter
    assert "TruthFinder" in payload.legal_request_letter
    assert "InstantCheckmate" in payload.legal_request_letter or "Instant Checkmate" in payload.legal_request_letter
    assert "Intelius" in payload.legal_request_letter
    assert "USSearch" in payload.legal_request_letter or "US Search" in payload.legal_request_letter


# ==============================================================================
# Tier 4: Generator Class & Exposure Integration
# ==============================================================================

def test_tier4_legal_notice_generator_class(rich_target: TargetIdentityInput) -> None:
    generator = LegalNoticeGenerator()
    ccpa_doc = generator.generate_ccpa(rich_target, broker_name="TruePeopleSearch")
    assert "TruePeopleSearch" in ccpa_doc
    assert "Cal. Civ. Code § 1798.105" in ccpa_doc

    gdpr_doc = generator.generate_gdpr(rich_target, controller_name="Nuwber Inc")
    assert "Nuwber Inc" in gdpr_doc
    assert "ARTICLE 17" in gdpr_doc

    profile = ExtractedEntityProfile(
        target_id="tgt_1234",
        source_url="https://radaris.com/p/Marcus/Brody",
        source_broker="radaris",
        matched_names=["Marcus Brody"],
    )
    exposure_notice = generator.generate_notice_for_exposure(rich_target, profile, jurisdiction="CCPA")
    assert "Radaris" in exposure_notice
    assert "https://radaris.com/p/Marcus/Brody" in exposure_notice


# ==============================================================================
# Tier 5: Adversarial, Unicode, and Boundary Resilience
# ==============================================================================

@pytest.mark.parametrize(
    "name,city,state",
    [
        ("Dr. Sean O'Connor-Smith, Esq.", "San Francisco", "CA"),
        ("René François Étienne", "Montréal", "QC"),
        ("Éléonore Von Müller", "Berlin", "DE"),
        ("Mary-Jane Watson", "New York", "NY"),
    ],
)
def test_tier5_adversarial_names_and_unicode(name: str, city: str, state: str) -> None:
    target = TargetIdentityInput(
        full_name=name,
        current_city=city,
        current_state=state,
        primary_email="test.user@example.com",
    )
    ccpa = generate_ccpa_notice(target)
    assert name in ccpa
    assert city in ccpa

    gdpr = generate_gdpr_notice(target)
    assert name in gdpr

    payload = generate_peopleconnect_payload(target)
    assert payload.form_payload["first_name"] != ""
    assert payload.form_payload["email"] == "test.user@example.com"


# ==============================================================================
# Broker Payload Schemas & Dispatcher Tests
# ==============================================================================

class TestBrokerPayloadSchemas:
    def test_truepeoplesearch_payload_schema(self, rich_target: TargetIdentityInput) -> None:
        dispatcher = TruePeopleSearchDispatcher()
        payload = dispatcher.build_form_payload(rich_target, "https://www.truepeoplesearch.com/find/person/test")
        assert payload["RecordUrl"] == "https://www.truepeoplesearch.com/find/person/test"
        assert payload["Email"] == rich_target.primary_email
        assert payload["TermsAccepted"] == "true"
        assert "CCPA" in payload["Reason"]
        assert payload["FullName"] == rich_target.full_name

    def test_fastpeoplesearch_payload_schema(self, rich_target: TargetIdentityInput) -> None:
        dispatcher = FastPeopleSearchDispatcher()
        payload = dispatcher.build_form_payload(rich_target)
        assert "fastpeoplesearch.com" in payload["target_record_url"]
        assert payload["contact_email"] == rich_target.primary_email
        assert payload["agree_to_terms"] == "1"
        assert payload["subject_name"] == rich_target.full_name

    def test_radaris_payload_schema(self, rich_target: TargetIdentityInput) -> None:
        dispatcher = RadarisDispatcher()
        payload = dispatcher.build_form_payload(rich_target)
        assert payload["name"] == rich_target.full_name
        assert payload["email"] == rich_target.primary_email
        assert payload["action"] == "suppress_record"

    def test_nuwber_payload_schema(self, rich_target: TargetIdentityInput) -> None:
        dispatcher = NuwberDispatcher()
        payload = dispatcher.build_form_payload(rich_target)
        assert "nuwber.com" in payload["url"]
        assert payload["email"] == rich_target.primary_email
        assert "CCPA" in payload["jurisdiction"]

    def test_whitepages_payload_schema(self, rich_target: TargetIdentityInput) -> None:
        dispatcher = WhitepagesDispatcher()
        payload = dispatcher.build_form_payload(rich_target)
        assert "whitepages.com" in payload["listing_url"]
        assert payload["requester_email"] == rich_target.primary_email
        assert payload["requester_phone"] == rich_target.phone_numbers[0]
        assert payload["request_type"] == "full_suppression"

    def test_peopleconnect_master_payload(self, rich_target: TargetIdentityInput) -> None:
        dispatcher = PeopleConnectDispatcher()
        payload = dispatcher.build_form_payload(rich_target)
        assert payload["first_name"] == "Marcus"
        assert payload["last_name"] == "Brody"
        assert payload["email"] == rich_target.primary_email
        assert payload["request_type"] == "master_suppression"


# ==============================================================================
# Cryptographic Receipts & Statutory Deadlines
# ==============================================================================

class TestReceiptAndDeadlineGeneration:
    def test_sha256_tracking_hash_format_and_determinism(self) -> None:
        ts = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
        hash1 = generate_cryptographic_tracking_hash("rem_123", "truepeoplesearch", ts, "test@example.com")
        hash2 = generate_cryptographic_tracking_hash("rem_123", "truepeoplesearch", ts, "test@example.com")
        hash3 = generate_cryptographic_tracking_hash("rem_456", "truepeoplesearch", ts, "test@example.com")

        assert hash1.startswith("GP-SHA256-")
        assert len(hash1) == len("GP-SHA256-") + 16
        assert hash1 == hash2
        assert hash1 != hash3

    def test_statutory_30_day_deadline_calculation(self) -> None:
        start_ts = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        deadline = calculate_compliance_deadline(start_ts, days=STATUTORY_COMPLIANCE_DAYS)
        assert deadline == datetime(2026, 1, 31, 0, 0, 0, tzinfo=timezone.utc)
        assert (deadline - start_ts).days == 30

    @pytest.mark.parametrize(
        "status_code, expected_status",
        [
            (200, "CONFIRMED"),
            (202, "PENDING_VERIFICATION"),
            (201, "SUBMITTED"),
            (204, "SUBMITTED"),
            (400, "FAILED"),
            (404, "FAILED"),
            (500, "FAILED"),
            (503, "FAILED"),
        ],
    )
    def test_map_response_to_status(self, status_code: int, expected_status: str) -> None:
        assert map_response_to_status(status_code) == expected_status

    def test_create_suppression_receipt_complete_structure(self) -> None:
        receipt = create_suppression_receipt(
            remediation_id="rem_abcdef12",
            broker_name="TruePeopleSearch",
            broker_id="truepeoplesearch",
            notice_type="Automated Web Form",
            status_code=200,
            confirmation_message="Removal request processed for {email}.",
            email="m.brody@texastech.edu",
        )
        assert isinstance(receipt, SuppressionReceipt)
        assert receipt.status == "CONFIRMED"
        assert receipt.response_code == 200
        assert "m.brody@texastech.edu" in receipt.confirmation_message
        assert receipt.tracking_reference.startswith("GP-SHA256-")
        assert receipt.compliance_deadline > receipt.submission_timestamp
        assert (receipt.compliance_deadline - receipt.submission_timestamp).days == 30
        assert receipt.downloadable_notice_url is not None

    def test_create_suppression_receipt_with_json_and_dict_error_strings(self) -> None:
        """Tests that confirmation_message containing arbitrary JSON, dict representations, or curly braces never crashes."""
        problematic_messages = [
            '{"error": "rate_limited", "retry_after": 60}',
            "Error connecting to {'host': 'broker.com', 'port': 443}",
            "Unclosed brace { in response body",
            "Complex format: {email} recorded with metadata {'status': 'ok', 'ref': '{tracking_ref}'}",
            "Empty braces {} and invalid spec {999}",
        ]
        for msg in problematic_messages:
            receipt = create_suppression_receipt(
                remediation_id="rem_robust_01",
                broker_name="Radaris",
                broker_id="radaris",
                notice_type="Automated Form",
                status_code=500,
                confirmation_message=msg,
                email="alice@example.com",
            )
            assert isinstance(receipt, SuppressionReceipt)
            assert receipt.status == "FAILED"
            assert isinstance(receipt.confirmation_message, str)
            # When {email} is present, it should be replaced
            if "{email}" in msg:
                assert "alice@example.com" in receipt.confirmation_message


# ==============================================================================
# Simulation Mode Submissions
# ==============================================================================

class TestSimulationModeSubmissions:
    @pytest.mark.asyncio
    async def test_engine_simulation_submission_all_brokers(
        self,
        rich_target: TargetIdentityInput,
    ) -> None:
        engine = SuppressionEngine(simulation_mode=True)
        broker_ids = ["truepeoplesearch", "fastpeoplesearch", "radaris", "nuwber", "whitepages"]

        for bid in broker_ids:
            payload = engine.build_payload(bid, rich_target)
            receipt = await engine.submit_suppression(payload)

            assert isinstance(receipt, SuppressionReceipt)
            assert receipt.status in ("CONFIRMED", "PENDING_VERIFICATION")
            assert receipt.response_code in (200, 202)
            assert receipt.tracking_reference.startswith("GP-SHA256-")
            assert receipt.broker_name.lower().replace(" ", "") == bid

    @pytest.mark.asyncio
    async def test_concurrent_plan_execution_in_simulation(
        self,
        rich_target: TargetIdentityInput,
        sample_profiles: list[ExtractedEntityProfile],
    ) -> None:
        engine = SuppressionEngine(simulation_mode=True)
        plan = engine.generate_remediation_plan(rich_target, sample_profiles)

        assert plan.total_actions == len(sample_profiles)
        receipts = await engine.execute_plan(plan)

        assert len(receipts) == len(sample_profiles)
        assert all(isinstance(r, SuppressionReceipt) for r in receipts)
        assert all(r.status in ("CONFIRMED", "PENDING_VERIFICATION") for r in receipts)


# ==============================================================================
# HTTP Client Dispatch & Mock Transport
# ==============================================================================

class TestHTTPTransportDispatches:
    @pytest.mark.asyncio
    async def test_http_success_200_dispatcher(self, rich_target: TargetIdentityInput) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"status": "success", "message": "Opt-out confirmed"})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            dispatcher = TruePeopleSearchDispatcher()
            payload = SuppressionPayload(
                remediation_id="rem_1001",
                broker_id="truepeoplesearch",
                broker_name="TruePeopleSearch",
                opt_out_type="automated_form",
                submission_url="https://www.truepeoplesearch.com/removal",
                form_payload=dispatcher.build_form_payload(rich_target),
            )
            receipt = await dispatcher.submit(payload, client=client, simulation_mode=False)

            assert receipt.status == "CONFIRMED"
            assert receipt.response_code == 200
            assert payload.status == SuppressionStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_http_accepted_202_dispatcher(self, rich_target: TargetIdentityInput) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(202, json={"status": "pending_verification"})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            dispatcher = RadarisDispatcher()
            payload = SuppressionPayload(
                remediation_id="rem_1002",
                broker_id="radaris",
                broker_name="Radaris",
                opt_out_type="automated_form",
                submission_url="https://radaris.com/control/privacy",
                form_payload=dispatcher.build_form_payload(rich_target),
            )
            receipt = await dispatcher.submit(payload, client=client, simulation_mode=False)

            assert receipt.status == "PENDING_VERIFICATION"
            assert receipt.response_code == 202
            assert payload.status == SuppressionStatus.SUBMITTED

    @pytest.mark.asyncio
    async def test_http_500_error_handling(self, rich_target: TargetIdentityInput) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            dispatcher = NuwberDispatcher()
            payload = SuppressionPayload(
                remediation_id="rem_1003",
                broker_id="nuwber",
                broker_name="Nuwber",
                opt_out_type="automated_form",
                submission_url="https://nuwber.com/removal/link",
                form_payload=dispatcher.build_form_payload(rich_target),
            )
            receipt = await dispatcher.submit(payload, client=client, simulation_mode=False)

            assert receipt.status == "FAILED"
            assert receipt.response_code == 500
            assert payload.status == SuppressionStatus.FAILED

    @pytest.mark.asyncio
    async def test_adversarial_timeout_resilience(self, rich_target: TargetIdentityInput) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Connection timed out")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            dispatcher = WhitepagesDispatcher()
            payload = SuppressionPayload(
                remediation_id="rem_timeout",
                broker_id="whitepages",
                broker_name="Whitepages",
                opt_out_type="automated_form",
                submission_url="https://www.whitepages.com/suppression-requests",
                form_payload=dispatcher.build_form_payload(rich_target),
            )
            receipt = await dispatcher.submit(payload, client=client, simulation_mode=False)

            assert receipt.status == "FAILED"
            assert receipt.response_code == 500
            assert "failed" in receipt.confirmation_message.lower()

    @pytest.mark.asyncio
    async def test_dispatcher_exception_with_dict_repr_resilience(self, rich_target: TargetIdentityInput) -> None:
        """Verifies dispatcher handles exceptions containing dictionary representations without unhandled KeyError."""
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.RequestError("Network error connecting to {'host': 'example.com', 'port': 443}")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            dispatcher = BaseBrokerDispatcher()
            payload = SuppressionPayload(
                remediation_id="rem_err_dict",
                broker_id="generic",
                broker_name="Generic",
                opt_out_type="automated_form",
                submission_url="https://example.com/optout",
                form_payload={"email": "alice@example.com"},
            )
            receipt = await dispatcher.submit(payload, client=client, simulation_mode=False)

            assert receipt.status == "FAILED"
            assert receipt.response_code == 500
            assert payload.status == SuppressionStatus.FAILED
            assert "{'host': 'example.com', 'port': 443}" in receipt.confirmation_message

    @pytest.mark.asyncio
    async def test_batch_concurrency_stress(self, rich_target: TargetIdentityInput) -> None:
        engine = SuppressionEngine(simulation_mode=True)
        payloads = [
            engine.build_payload("truepeoplesearch", rich_target)
            for _ in range(50)
        ]
        receipts = await engine.submit_all(payloads)

        assert len(receipts) == 50
        receipt_ids = {r.receipt_id for r in receipts}
        assert len(receipt_ids) == 50
