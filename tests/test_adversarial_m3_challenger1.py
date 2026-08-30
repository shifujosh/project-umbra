"""
Adversarial Stress Test Suite — Milestone 3 Challenger 1.
Author: Challenger 1 (Statutory Veracity & Cryptographic Hash Challenger)

Coverage:
1. Complex Persona Stress Testing (100+ Aliases, Multi-script Unicode, Mononyms, Invalid Addresses, Missing Data).
2. Cryptographic Tracking Hash Uniqueness & Collision Resistance (10,000 Generated Receipts & Avalanche Properties).
3. Statutory Legal Veracity & Mandatory Citation Audits (CCPA/CPRA Cal. Civ. Code & GDPR Reg (EU) 2016/679).
4. PeopleConnect Master Opt-Out Payload Integrity & Multi-Brand Syndication.
5. Large-Scale Profile Aggregation, Deduplication & Boundary Condition Handling.
6. Dispatcher Status Code Resilience & Receipt Status Mapping.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import re
import uuid
from pydantic import ValidationError
import pytest

from project_umbra.core.state import (
    ExtractedEntityProfile,
    SuppressionActionPlan,
    SuppressionPayload,
    SuppressionReceipt,
    SuppressionStatus,
    TargetIdentityInput,
)
from project_umbra.tools.suppression_engine import (
    STATUTORY_COMPLIANCE_DAYS,
    DEFAULT_PROACTIVE_BROKERS,
    KNOWN_BROKER_REGISTRY,
    PEOPLECONNECT_BRAND_METADATA,
    LegalNoticeGenerator,
    LegalNoticeType,
    PeopleConnectBrand,
    SuppressionEngine,
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


# ==============================================================================
# 1. Complex Persona Stress Testing (100+ Aliases, Unicode, Mononyms, Bad Addrs)
# ==============================================================================

class TestComplexPersonaStress:
    """Stress tests notice generation against extreme and hostile persona inputs."""

    def test_150_aliases_persona_generation(self) -> None:
        """Tests that a target with 150 unique aliases formats cleanly across all notices without truncation or crash."""
        aliases = [f"Alias_SuperUser_{i:03d}_{'αβγ' if i % 2 == 0 else 'xyz'}" for i in range(150)]
        target = TargetIdentityInput(
            full_name="Dr. Alexander James Vance",
            aliases=aliases,
            primary_email="avance@blackmesa.internal",
            secondary_emails=[f"avance_sec_{i}@bm.org" for i in range(10)],
            phone_numbers=["+1 (555) 019-2834", "+1 (555) 019-9999"],
            known_addresses=["Sector C Test Labs, Black Mesa, NM 87001", "104 Freeman Way, Albuquerque, NM 87101"],
            current_city="Albuquerque",
            current_state="NM",
        )

        # 1. CCPA Notice
        ccpa_notice = generate_ccpa_notice(target, broker_name="TruePeopleSearch")
        assert target.full_name in ccpa_notice
        assert "avance@blackmesa.internal" in ccpa_notice
        assert "Alias_SuperUser_000_αβγ" in ccpa_notice
        assert "Alias_SuperUser_149_xyz" in ccpa_notice

        # 2. GDPR Notice
        gdpr_notice = generate_gdpr_notice(target, controller_name="Data Controller EU")
        assert target.full_name in gdpr_notice
        assert "Alias_SuperUser_075_xyz" in gdpr_notice

        # 3. Master CCPA Letter
        master_ccpa = generate_master_ccpa_letter(target)
        assert len(master_ccpa) > 500
        assert "Alias_SuperUser_100_αβγ" in master_ccpa

        # 4. Master GDPR Letter
        master_gdpr = generate_master_gdpr_letter(target)
        assert len(master_gdpr) > 500
        assert "Alias_SuperUser_120_αβγ" in master_gdpr

        # 5. PeopleConnect Payload
        pc_payload = generate_peopleconnect_payload(target)
        assert len(pc_payload.form_payload["aliases"]) == 150
        assert pc_payload.form_payload["first_name"] == "Dr."
        assert pc_payload.form_payload["last_name"] == "Vance"
        assert len(pc_payload.form_payload["secondary_emails"]) == 10

    def test_multilingual_unicode_and_rtl_persona(self) -> None:
        """Tests handling of Cyrillic, Arabic, CJK, Hebrew, Greek, accented Latin, and Emojis."""
        target = TargetIdentityInput(
            full_name="Владимир François 🐉 艾莉森 Al-Mansoor",
            aliases=["田中太郎", "أمير المؤمنين", "Σωκράτης", "Björk Guðmundsdóttir", "🕵️‍♂️ Ghost_User"],
            primary_email="vladimir.francois@ünicode-domain.org",
            secondary_emails=["alias1@موقع.عرب", "cjk_user@测试.cn"],
            phone_numbers=["+81 90-1234-5678", "+971 50 123 4567"],
            known_addresses=["東京都千代田区千代田1-1", "10 Rue de la Paix, 75002 Paris, France"],
            current_city="Paris",
            current_state="Île-de-France",
        )

        # Ensure no UnicodeEncodeError / UnicodeDecodeError in formatting
        schedule = format_identity_schedule(target)
        assert "Владимир François 🐉 艾莉森 Al-Mansoor" in schedule
        assert "田中太郎" in schedule
        assert "أمير المؤمنين" in schedule
        assert "Björk Guðmundsdóttir" in schedule
        assert "🕵️‍♂️ Ghost_User" in schedule

        ccpa_notice = generate_ccpa_notice(target)
        assert "Владимир François 🐉 艾莉森 Al-Mansoor" in ccpa_notice

        gdpr_notice = generate_gdpr_notice(target)
        assert "Regulation (EU) 2016/679" in gdpr_notice
        assert "vladimir.francois@ünicode-domain.org" in gdpr_notice

        # Test hash computation with complex Unicode strings
        tracking_hash = generate_cryptographic_tracking_hash(
            remediation_id="rem_unicode_01",
            broker_id="broker_unicode",
            timestamp=datetime.now(timezone.utc),
            email=target.primary_email,
            profile_url="https://example.com/p/艾莉森-123",
        )
        assert tracking_hash.startswith("GP-SHA256-")
        assert len(tracking_hash) == len("GP-SHA256-") + 16

        # Test build_broker_payload with non-ASCII characters
        payload = build_broker_payload(target, None, "truepeoplesearch")
        assert payload.broker_id == "truepeoplesearch"
        assert payload.form_payload["FullName"] == target.full_name

    def test_mononyms_and_single_character_validation(self) -> None:
        """Tests handling of valid mononyms (Prince, Cher, Plato, Bo, Io, Li, Wu) and validates min_length=2 boundary."""
        mononyms = ["Cher", "Prince", "Plato", "Madonna", "Voltaire", "Bo", "Io", "Li", "Wu"]
        for mono in mononyms:
            target = TargetIdentityInput(
                full_name=mono,
                primary_email=f"{mono.lower()}@celebrity.internal",
            )
            pc_payload = generate_peopleconnect_payload(target)
            assert pc_payload.form_payload["first_name"] == mono
            assert pc_payload.form_payload["last_name"] == ""

            ccpa_notice = generate_ccpa_notice(target)
            assert mono in ccpa_notice

            gdpr_notice = generate_gdpr_notice(target)
            assert mono in gdpr_notice

            # Broker payload generation
            payload = build_broker_payload(target, None, "nuwber")
            assert payload.form_payload["email"] == f"{mono.lower()}@celebrity.internal"

        # Boundary test: single character name must raise Pydantic ValidationError (min_length=2)
        with pytest.raises(ValidationError):
            TargetIdentityInput(full_name="X")
        with pytest.raises(ValidationError):
            TargetIdentityInput(full_name="A")
        with pytest.raises(ValidationError):
            TargetIdentityInput(full_name="")

    def test_malformed_and_edge_case_addresses(self) -> None:
        """Tests address parsing resilience with diverse malformed, missing, and non-standard addresses."""
        test_cases = [
            # 1. Empty known addresses, empty city/state
            TargetIdentityInput(full_name="John Doe", known_addresses=[]),
            # 2. Single word address
            TargetIdentityInput(full_name="Jane Doe", known_addresses=["Nowhere"]),
            # 3. Address without commas
            TargetIdentityInput(full_name="Bob Smith", known_addresses=["123 Main St Springfield IL 62701"]),
            # 4. Multi-comma international address
            TargetIdentityInput(full_name="Alice Brown", known_addresses=["Flat 4B, 10 Baker Street, Marylebone, London, W1U 3BW, UK"]),
            # 5. Extremely long 500-char address
            TargetIdentityInput(full_name="Long Addr", known_addresses=["A" * 500]),
            # 6. Address with special characters & HTML tags
            TargetIdentityInput(full_name="Safe Subject", known_addresses=["<script>alert(1)</script>, Apt #3 & 1/2, PO Box 999"]),
        ]

        for target in test_cases:
            # PeopleConnect address parsing must not crash
            pc_payload = generate_peopleconnect_payload(target)
            assert isinstance(pc_payload.form_payload["city"], str)
            assert isinstance(pc_payload.form_payload["state"], str)
            assert isinstance(pc_payload.form_payload["zip_code"], str)

            # Format identity schedule must not crash
            schedule = format_identity_schedule(target)
            assert target.full_name in schedule

            # CCPA / GDPR generation
            ccpa = generate_ccpa_notice(target)
            gdpr = generate_gdpr_notice(target)
            assert len(ccpa) > 100
            assert len(gdpr) > 100

    def test_missing_and_extreme_contact_channels(self) -> None:
        """Tests targets with missing emails, missing phones, or 50+ phone numbers."""
        # Target with 0 emails, 0 phones, 0 addresses
        target_bare = TargetIdentityInput(full_name="Bare Subject")
        plan_bare = SuppressionEngine(simulation_mode=True).compile_plan(target_bare)
        assert plan_bare.total_actions == 6
        assert len(plan_bare.master_ccpa_letter) > 100
        assert len(plan_bare.master_gdpr_letter) > 100

        # Target with 50 phone numbers
        target_phones = TargetIdentityInput(
            full_name="Phone Heavy",
            primary_email="phones@example.com",
            phone_numbers=[f"+1-555-010-{i:04d}" for i in range(50)],
        )
        schedule = format_identity_schedule(target_phones)
        assert "+1-555-010-0000" in schedule
        assert "+1-555-010-0049" in schedule


# ==============================================================================
# 2. Cryptographic Hash Uniqueness & Collision Resistance (10,000 Receipts)
# ==============================================================================

class TestCryptographicTrackingHashStress:
    """Stress tests collision resistance, determinism, and avalanche properties of tracking hashes."""

    def test_10000_receipt_hash_uniqueness(self) -> None:
        """
        Generates 10,000 receipts across varying remediation IDs, broker IDs,
        timestamps, and emails, asserting 100% collision-free hashes.
        """
        hashes_seen: set[str] = set()
        receipt_ids_seen: set[str] = set()
        base_time = datetime(2026, 8, 28, 0, 0, 0, tzinfo=timezone.utc)
        brokers = ["truepeoplesearch", "fastpeoplesearch", "radaris", "nuwber", "whitepages", "peopleconnect"]

        for i in range(10_000):
            rem_id = f"rem_{uuid.uuid4().hex[:8]}"
            broker_id = brokers[i % len(brokers)]
            # Microsecond timestamp increments to simulate high-velocity concurrent dispatches
            ts = base_time + timedelta(microseconds=i * 17)
            email = f"user_{i:05d}@privacy.test"
            profile_url = f"https://{broker_id}.com/p/user_{i:05d}"

            receipt = create_suppression_receipt(
                remediation_id=rem_id,
                broker_name=broker_id.title(),
                broker_id=broker_id,
                notice_type="Automated Form",
                status_code=200,
                confirmation_message="Opt-out processed",
                email=email,
                profile_url=profile_url,
                submission_timestamp=ts,
            )

            # Assertions on each receipt
            assert receipt.tracking_reference.startswith("GP-SHA256-")
            assert len(receipt.tracking_reference) == 26  # GP-SHA256- (10 chars) + 16 hex chars
            assert re.match(r"^GP-SHA256-[0-9A-F]{16}$", receipt.tracking_reference)
            assert receipt.status == "CONFIRMED"
            assert receipt.response_code == 200
            assert receipt.compliance_deadline == ts + timedelta(days=30)
            assert receipt.downloadable_notice_url.startswith("https://receipts.project-umbra.internal/v1/notices/")

            # Collision detection
            assert receipt.tracking_reference not in hashes_seen, f"Collision detected for hash {receipt.tracking_reference} at iteration {i}"
            hashes_seen.add(receipt.tracking_reference)
            receipt_ids_seen.add(receipt.receipt_id)

        assert len(hashes_seen) == 10_000
        assert len(receipt_ids_seen) == 10_000

    def test_same_timestamp_different_remediation_uniqueness(self) -> None:
        """Tests that identical timestamps across 1,000 distinct requests yield 0 hash collisions."""
        fixed_ts = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
        hashes: set[str] = set()

        for i in range(1_000):
            h = generate_cryptographic_tracking_hash(
                remediation_id=f"rem_{i:06d}",
                broker_id="radaris",
                timestamp=fixed_ts,
                email="fixed@example.com",
                profile_url="https://radaris.com/p/fixed",
            )
            assert h not in hashes
            hashes.add(h)

        assert len(hashes) == 1_000

    def test_avalanche_effect_single_bit_flip(self) -> None:
        """
        Verifies the avalanche effect: changing 1 character in input causes
        significant change in the resulting tracking reference hex digest.
        """
        ts = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
        h1 = generate_cryptographic_tracking_hash("rem_00000001", "brokerA", ts, "user@a.com")
        h2 = generate_cryptographic_tracking_hash("rem_00000002", "brokerA", ts, "user@a.com")
        h3 = generate_cryptographic_tracking_hash("rem_00000001", "brokerB", ts, "user@a.com")
        h4 = generate_cryptographic_tracking_hash("rem_00000001", "brokerA", ts, "user@b.com")

        # Extract 16 hex chars
        hex1 = h1.replace("GP-SHA256-", "")
        hex2 = h2.replace("GP-SHA256-", "")
        hex3 = h3.replace("GP-SHA256-", "")
        hex4 = h4.replace("GP-SHA256-", "")

        # Compute character differences
        def diff_count(s1: str, s2: str) -> int:
            return sum(c1 != c2 for c1, c2 in zip(s1, s2))

        assert diff_count(hex1, hex2) >= 10, "Avalanche test 1 failed: insufficient hex divergence"
        assert diff_count(hex1, hex3) >= 10, "Avalanche test 2 failed: insufficient hex divergence"
        assert diff_count(hex1, hex4) >= 10, "Avalanche test 3 failed: insufficient hex divergence"

    def test_deterministic_reproducibility(self) -> None:
        """Verifies that identical parameters produce identical cryptographic hashes."""
        ts = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
        h1 = generate_cryptographic_tracking_hash("rem_exact_1", "fastpeoplesearch", ts, "alice@test.com", "http://fps.com/1")
        h2 = generate_cryptographic_tracking_hash("rem_exact_1", "fastpeoplesearch", ts, "alice@test.com", "http://fps.com/1")
        assert h1 == h2


# ==============================================================================
# 3. Statutory Legal Veracity & Mandatory Citation Audits
# ==============================================================================

class TestStatutoryVeracityAndCitations:
    """Verifies precision and legal veracity of CCPA/CPRA and GDPR statutory citations."""

    def test_ccpa_statutory_citations_completeness(self) -> None:
        """
        Validates all mandatory CCPA/CPRA legal citations in single-broker and master notices:
        - Cal. Civ. Code § 1798.100 et seq.
        - Cal. Civ. Code § 1798.105 (Right to Deletion)
        - Cal. Civ. Code § 1798.120 (Right to Opt-Out of Sale/Sharing)
        - Cal. Civ. Code § 1798.125 (Non-Discrimination)
        - Cal. Civ. Code § 1798.130 (10-day receipt confirmation & 45-day deletion timeline)
        - 11 CCR § 7027(f) (15 business days opt-out timeline)
        - Cal. Civ. Code § 1798.105(c)(1) (Downstream cascade deletion mandate)
        - Cal. Civ. Code § 1798.199.90 (CPPA statutory civil penalties up to $7,500)
        - Perjury declaration under California law
        """
        target = TargetIdentityInput(
            full_name="Evelyn Carter",
            primary_email="ecarter@california.org",
            current_city="San Francisco",
            current_state="CA",
        )
        ccpa_single = generate_ccpa_notice(target, broker_name="Acme Data Broker")
        master_ccpa = generate_master_ccpa_letter(target)

        # Single notice verification
        assert "1798.100" in ccpa_single
        assert "1798.105" in ccpa_single  # Deletion
        assert "1798.120" in ccpa_single  # Opt-out
        assert "1798.125" in ccpa_single  # Non-discrimination
        assert "1798.130" in ccpa_single  # 45-day timeline
        assert "10 business days" in ccpa_single or "ten (10) business days" in ccpa_single
        assert "45" in ccpa_single  # 45 days
        assert "11 CCR § 7027" in ccpa_single or "7027" in ccpa_single  # 15 days
        assert "1798.105(c)" in ccpa_single  # Downstream cascade
        assert "1798.199.90" in ccpa_single  # CPPA enforcement
        assert "$7,500" in ccpa_single
        assert "penalty of perjury" in ccpa_single.lower()

        # Master letter verification
        assert "1798.100" in master_ccpa
        assert "1798.105" in master_ccpa
        assert "1798.120" in master_ccpa
        assert "1798.121" in master_ccpa  # Sensitive PI limit
        assert "1798.125" in master_ccpa
        assert "1798.130" in master_ccpa
        assert "penalty of perjury" in master_ccpa.lower()

    def test_gdpr_statutory_citations_completeness(self) -> None:
        """
        Validates all mandatory GDPR Regulation (EU) 2016/679 legal citations:
        - Regulation (EU) 2016/679
        - Article 17(1)(a)-(d) & Article 17(2) (Right to Erasure / Right to be forgotten)
        - Article 21(1), 21(2), 21(3) (Right to object to processing & direct marketing/profiling)
        - Article 19 (Communication to recipients / Downstream notification)
        - Article 12(3) (One month / 30-day statutory response timeframe)
        - Article 77 (Supervisory Authority complaints)
        - Article 83(5)(b) (€20,000,000 or 4% global turnover administrative fines)
        """
        target = TargetIdentityInput(
            full_name="Jean-Luc Picard",
            primary_email="jpicard@starfleet.eu",
            current_city="La Barre",
            current_state="Bourgogne",
        )
        gdpr_single = generate_gdpr_notice(target, controller_name="Acme Profiling SAS")
        master_gdpr = generate_master_gdpr_letter(target)

        # Single notice verification
        assert "2016/679" in gdpr_single
        assert "Article 17" in gdpr_single
        assert "Article 17(1)(a)" in gdpr_single
        assert "Article 17(1)(c)" in gdpr_single
        assert "Article 17(1)(d)" in gdpr_single
        assert "Article 21" in gdpr_single
        assert "Article 21(1)" in gdpr_single
        assert "Article 21(2)" in gdpr_single
        assert "Article 21(3)" in gdpr_single
        assert "Article 19" in gdpr_single
        assert "Article 12(3)" in gdpr_single
        assert "Article 77" in gdpr_single
        assert "Article 83(5)(b)" in gdpr_single
        assert "20,000,000" in gdpr_single
        assert "4%" in gdpr_single

        # Master letter verification
        assert "2016/679" in master_gdpr
        assert "Article 17" in master_gdpr
        assert "Article 21" in master_gdpr
        assert "Article 19" in master_gdpr
        assert "Article 12(3)" in master_gdpr
        assert "Article 77" in master_gdpr
        assert "Article 77 GDPR" in master_gdpr


# ==============================================================================
# 4. PeopleConnect Master Opt-Out Payload Integrity
# ==============================================================================

class TestPeopleConnectPayloadIntegrity:
    """Verifies PeopleConnect syndicated multi-brand payload formatting and brand coverage."""

    def test_peopleconnect_syndicated_brands_completeness(self) -> None:
        """Verifies TruthFinder, InstantCheckmate, Intelius, USSearch brands are mapped."""
        target = TargetIdentityInput(
            full_name="Robert Oppenheimer",
            aliases=["J. Robert Oppenheimer", "Oppie"],
            primary_email="roppenheimer@losalamos.gov",
            phone_numbers=["+1 (505) 667-5000"],
            known_addresses=["1000 Trinity Dr, Los Alamos, NM 87544"],
            current_city="Los Alamos",
            current_state="NM",
        )
        payload = generate_peopleconnect_payload(target)

        assert payload.broker_id == "peopleconnect_master"
        assert payload.opt_out_type == "master_opt_out"
        assert payload.submission_url == "https://suppression.peopleconnect.us/api/suppression/request"

        fp = payload.form_payload
        assert fp["first_name"] == "Robert"
        assert fp["last_name"] == "Oppenheimer"
        assert fp["opt_out_all_brands"] is True
        assert set(fp["target_brands"]) == {"truthfinder", "instantcheckmate", "intelius", "ussearch"}
        assert fp["city"] == "Los Alamos"
        assert fp["state"] == "NM"
        assert fp["suppression_scope"] == "COMPLETE_REMOVAL"

        # Check legal demand letter content
        letter = payload.legal_request_letter
        assert "TruthFinder" in letter
        assert "Instant Checkmate" in letter or "InstantCheckmate" in letter
        assert "Intelius" in letter
        assert "US Search" in letter or "USSearch" in letter
        assert "PeopleConnect, Inc." in letter


# ==============================================================================
# 5. Large-Scale Profile Aggregation & Deduplication
# ==============================================================================

class TestProfileAggregationAndDeduplication:
    """Tests aggregation of multiple conflicting and duplicate OSINT profiles."""

    def test_100_duplicate_profiles_deduplication(self) -> None:
        """Verifies 100 duplicate findings from the same broker merge into 1 comprehensive profile."""
        profiles = [
            ExtractedEntityProfile(
                target_id="tgt_test",
                source_url=f"https://www.truepeoplesearch.com/find/person/john-doe?page={i}",
                source_broker="TruePeopleSearch",
                matched_names=["John Doe", f"John Doe {i}"],
                phone_numbers=[f"555-01{i:02d}"],
                email_addresses=[f"jdoe{i}@test.com"],
                current_address="123 Main St, Austin, TX" if i == 0 else None,
                past_addresses=[f"Old Address {i}, Austin, TX"],
                relatives=[f"Relative {i}"],
                associates=[f"Associate {i}"],
                removal_url="https://www.truepeoplesearch.com/removal" if i == 50 else None,
                confidence_score=0.5 + (i * 0.004),  # Reaches ~0.9
            )
            for i in range(100)
        ]

        deduped = aggregate_and_deduplicate_profiles(profiles)
        assert len(deduped) == 1
        merged = deduped[0]
        assert merged.source_broker == "TruePeopleSearch"
        assert len(merged.matched_names) == 101  # John Doe + 100 unique names
        assert len(merged.phone_numbers) == 100
        assert len(merged.email_addresses) == 100
        assert len(merged.past_addresses) == 100
        assert len(merged.relatives) == 100
        assert merged.current_address == "123 Main St, Austin, TX"
        assert merged.removal_url == "https://www.truepeoplesearch.com/removal"
        assert merged.confidence_score >= 0.89


# ==============================================================================
# 6. Dispatcher Status Code Resilience & Receipt Mapping
# ==============================================================================

class TestDispatcherStatusCodeResilience:
    """Tests that all HTTP response status codes map accurately to typed receipt statuses."""

    @pytest.mark.parametrize(
        "status_code, expected_status",
        [
            (200, "CONFIRMED"),
            (201, "SUBMITTED"),
            (202, "PENDING_VERIFICATION"),
            (204, "SUBMITTED"),
            (301, "FAILED"),
            (400, "FAILED"),
            (401, "FAILED"),
            (403, "FAILED"),
            (404, "FAILED"),
            (429, "FAILED"),
            (500, "FAILED"),
            (502, "FAILED"),
            (503, "FAILED"),
            (504, "FAILED"),
        ],
    )
    def test_status_code_mapping_matrix(self, status_code: int, expected_status: str) -> None:
        """Verifies mapping of HTTP status codes to SuppressionReceipt status."""
        assert map_response_to_status(status_code) == expected_status
        receipt = create_suppression_receipt(
            remediation_id="rem_test",
            broker_name="Test Broker",
            broker_id="test_broker",
            notice_type="Notice",
            status_code=status_code,
            confirmation_message="Message",
        )
        assert receipt.status == expected_status
        assert receipt.response_code == status_code


# ==============================================================================
# 7. Suppression Engine End-to-End Batch Execution
# ==============================================================================

class TestSuppressionEngineBatchExecution:
    """Tests high-concurrency batch execution and plan generation."""

    @pytest.mark.asyncio
    async def test_concurrent_plan_execution_simulation(self) -> None:
        """Executes a 6-broker remediation plan in simulation mode concurrently."""
        target = TargetIdentityInput(
            full_name="Sarah Connor",
            primary_email="sconnor@resistance.internal",
            phone_numbers=["+1 (310) 555-0199"],
            current_city="Los Angeles",
            current_state="CA",
        )
        engine = SuppressionEngine(simulation_mode=True)
        plan = engine.compile_plan(target)
        assert plan.total_actions == 6

        receipts = await engine.execute_plan(plan)
        assert len(receipts) == 6

        statuses = [r.status for r in receipts]
        assert "CONFIRMED" in statuses
        assert "PENDING_VERIFICATION" in statuses  # Radaris returns 202 in fixture

        for r in receipts:
            assert r.tracking_reference.startswith("GP-SHA256-")
            assert (r.compliance_deadline - r.submission_timestamp).days == 30
