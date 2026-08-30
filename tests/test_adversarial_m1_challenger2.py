"""
Empirical Challenger 2 Adversarial Stress Test Suite for Milestone 1.
Focus: Gemma 2 PII Token Masking, Exact Byte-for-Byte Reversibility (50+ and 100+ Entities),
False Positive Resistance, Structured Profile Sanitization, and Risk Score Boundaries.
"""

from __future__ import annotations

import hashlib
import random
import re
import string
import pytest

from project_umbra.classifiers.gemma_classifier import GemmaSanitizerClassifier
from project_umbra.classifiers.heuristics import (
    DeterministicPIIExtractor,
    FastPIISanitizer,
    validate_luhn,
)
from project_umbra.core.state import (
    ExtractedEntityProfile,
    PIISeverity,
    PIITokenType,
)


# ==============================================================================
# Helpers for Stress Test Generation
# ==============================================================================

def generate_luhn_valid_credit_card(prefix: str = "4", length: int = 16) -> str:
    """Generate a valid credit card number that passes Luhn checksum."""
    digits = [int(d) for d in prefix]
    while len(digits) < length - 1:
        digits.append(random.randint(0, 9))

    # Calculate check digit
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 0:
            doubled = digit * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += digit
    check_digit = (10 - (checksum % 10)) % 10
    digits.append(check_digit)
    card_str = "".join(str(d) for d in digits)
    assert validate_luhn(card_str), f"Generated card {card_str} failed Luhn check"
    return card_str


# ==============================================================================
# Suite 1: Massive Reversibility & Scale Stress Testing (50+ and 100+ Entities)
# ==============================================================================

class TestMassiveReversibilityScale:
    """Stress tests exact byte-for-byte reversibility with 50+ and 100+ embedded PII entities."""

    @pytest.fixture
    def classifier(self) -> GemmaSanitizerClassifier:
        return GemmaSanitizerClassifier(mode="heuristic")

    def test_reversibility_50_plus_unique_entities(self, classifier: GemmaSanitizerClassifier) -> None:
        """
        Generate large realistic OSINT leak corpus with >60 unique PII entities
        and verify 100% byte-for-byte reconstruction via SHA-256 hash.
        """
        random.seed(42)
        corpus_segments = [
            "=== PROJECT UMBRA OSINT EXPOSURE DATASET ===",
            "Target leak dossier compiled from multi-broker sweep.",
        ]

        expected_tokens: list[str] = []

        # 1. 10 SSNs (Valid area codes between 100 and 899)
        for i in range(10):
            area = 100 + i * 15
            ssn = f"{area:03d}-{random.randint(10, 99):02d}-{random.randint(1000, 9999):04d}"
            corpus_segments.append(f"Subject #{i+1} Tax ID record: SSN {ssn} (Verified).")
            expected_tokens.append(ssn)

        # 2. 10 Credit Cards (Valid Luhn)
        for i in range(10):
            cc = generate_luhn_valid_credit_card(prefix=random.choice(["4", "51", "55", "37"]))
            corpus_segments.append(f"Payment card authorization: Card Number {cc} exp 12/28.")
            expected_tokens.append(cc)

        # 3. 12 Emails
        for i in range(12):
            email = f"operative_alpha_{i:02d}.leaked_record@investigation-target{i}.org"
            corpus_segments.append(f"Contact email address: {email} found in breached credentials.")
            expected_tokens.append(email)

        # 4. 10 Phones
        for i in range(10):
            phone = f"(202) {random.randint(200, 899):03d}-{random.randint(1000, 9999):04d}"
            corpus_segments.append(f"Direct mobile terminal: {phone} listed on darknet forum.")
            expected_tokens.append(phone)

        # 5. 8 Physical Addresses (Standard US street address format with recognized suffixes)
        addresses = [
            "100 Pennsylvania Ave, Washington, DC 20500",
            "742 Evergreen Terrace, Springfield, OR 97477",
            "221 Baker St, New York, NY 10001",
            "1600 Amphitheatre Pkwy, Mountain View, CA 94043",
            "1 Apple Park Way, Cupertino, CA 95014",
            "350 Fifth Ave, New York, NY 10118",
            "400 Broad St, Seattle, WA 98109",
            "500 South Buena Vista St, Burbank, CA 91521",
        ]
        for addr in addresses:
            corpus_segments.append(f"Residential physical location: {addr} confirmed by utility billing.")
            expected_tokens.append(addr)

        # 6. 8 Dates of Birth
        for i in range(8):
            year = 1970 + i * 3
            dob = f"{year}-0{i+1:01d}-15"
            corpus_segments.append(f"Target Vital Registry: Born {dob} according to public records.")
            expected_tokens.append(dob)

        # 7. 6 IPv4 & IPv6 Addresses
        ips = [
            "192.168.1.1",
            "10.240.0.125",
            "172.16.254.1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "fe80:0000:0000:0000:0204:61ff:fe9d:f156",
            "198.51.100.42",
        ]
        for ip in ips:
            corpus_segments.append(f"Network footprint gateway access logged from IP {ip} at ingress.")
            expected_tokens.append(ip)

        # 8. 6 Password Hashes
        hashes = [
            "$2a$12$e8kZ1qX7gL5Qo6N9W1M8Z.rX7gL5Qo6N9W1M8Z.rX7gL5Qo6N9W.",
            "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgTVEvUzrc5Ah+xDaElkWdjmmnhPN/HRw",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "d41d8cd98f00b204e9800998ecf8427e",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        ]
        for h in hashes:
            corpus_segments.append(f"Exposed authentication hash token: {h} extracted from SQL dump.")
            expected_tokens.append(h)

        original_corpus = "\n".join(corpus_segments)
        original_hash = hashlib.sha256(original_corpus.encode("utf-8")).hexdigest()

        # Sanitize corpus
        sanitization_result = classifier.classify_and_sanitize(original_corpus)

        # Assert at least 50 entities discovered
        assert sanitization_result.total_pii_count >= 50, (
            f"Expected at least 50 PII entities, found {sanitization_result.total_pii_count}"
        )
        assert sanitization_result.critical_pii_count >= 20, (
            f"Expected at least 20 critical PII entities (SSN, CC, Hashes), found {sanitization_result.critical_pii_count}"
        )

        # Assert no sensitive tokens remain in sanitized text
        for token in expected_tokens:
            assert token not in sanitization_result.sanitized_text, (
                f"Leaked token '{token}' found in sanitized text!"
            )

        # Restore sanitized text
        restored_corpus = classifier.restore_sanitized_text(
            sanitization_result.sanitized_text,
            sanitization_result.redaction_map,
        )
        restored_hash = hashlib.sha256(restored_corpus.encode("utf-8")).hexdigest()

        # Assert exact byte-for-byte match
        assert restored_corpus == original_corpus, "Restored text does not match original plaintext!"
        assert len(restored_corpus) == len(original_corpus), "Length mismatch in restored text!"
        assert restored_hash == original_hash, "SHA-256 checksum mismatch in restored text!"

    def test_reversibility_100_plus_entities_extreme_scale(self, classifier: GemmaSanitizerClassifier) -> None:
        """Extreme scale stress test: 120+ unique PII entities across 10 categories."""
        random.seed(99)
        lines = ["# EXTREME SCALE OSINT BREACH RECONSTRUCTION DUMP"]
        tokens = []

        # 30 SSNs
        for i in range(30):
            ssn = f"{200 + i:03d}-{random.randint(10, 99):02d}-{random.randint(1000, 9999):04d}"
            lines.append(f"Rec_{i}: SSN={ssn}")
            tokens.append(ssn)

        # 30 Emails
        for i in range(30):
            em = f"target_user_{i:03d}@enterprise-corp-{i % 5}.net"
            lines.append(f"Rec_{i}: Email={em}")
            tokens.append(em)

        # 30 Phones
        for i in range(30):
            ph = f"(312) {random.randint(200, 899):03d}-{random.randint(1000, 9999):04d}"
            lines.append(f"Rec_{i}: Phone={ph}")
            tokens.append(ph)

        # 30 IP Addresses
        for i in range(30):
            ip = f"10.{i}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            lines.append(f"Rec_{i}: IngressIP={ip}")
            tokens.append(ip)

        doc = "\n".join(lines)
        doc_hash = hashlib.sha256(doc.encode("utf-8")).hexdigest()

        res = classifier.classify_and_sanitize(doc)
        assert res.total_pii_count >= 100

        restored = classifier.restore_sanitized_text(res.sanitized_text, res.redaction_map)
        assert restored == doc
        assert hashlib.sha256(restored.encode("utf-8")).hexdigest() == doc_hash

    def test_reversibility_substring_nested_collisions(self, classifier: GemmaSanitizerClassifier) -> None:
        """
        Adversarial test: Substring collisions where shorter PII values are substrings
        of longer PII values (e.g. email inside longer email, phone inside long phone, address parts).
        """
        text = (
            "Primary: user@domain.com, Alias: super_user@domain.com, Corporate: user@domain.com.uk\n"
            "Mobile: (555) 123-4567, Dispatch: 1-(555) 123-4567\n"
            "Location A: 100 Main St, Austin, TX 78701\n"
            "Location B: Suite 400, 100 Main St, Austin, TX 78701"
        )
        original_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

        res = classifier.classify_and_sanitize(text)
        restored = classifier.restore_sanitized_text(res.sanitized_text, res.redaction_map)

        assert restored == text
        assert hashlib.sha256(restored.encode("utf-8")).hexdigest() == original_hash

    def test_repeated_interleaved_tokens_reversibility(self, classifier: GemmaSanitizerClassifier) -> None:
        """Verify tokens repeated dozens of times throughout text are properly mapped and restored."""
        token_email = "target.ceo@conglomerate.global"
        token_ssn = "345-67-8901"
        token_phone = "(415) 888-9999"

        lines = []
        for i in range(50):
            lines.append(f"Row {i:02d}: Email {token_email} with SSN {token_ssn} and phone {token_phone}.")

        full_text = "\n".join(lines)
        res = classifier.classify_and_sanitize(full_text)

        assert token_email not in res.sanitized_text
        assert token_ssn not in res.sanitized_text
        assert token_phone not in res.sanitized_text

        # All 50 occurrences must be replaced by [PII_EMAIL_01], [PII_SSN_01], [PII_PHONE_01]
        assert res.sanitized_text.count("[PII_EMAIL_01]") == 50
        assert res.sanitized_text.count("[PII_SSN_01]") == 50
        assert res.sanitized_text.count("[PII_PHONE_01]") == 50

        restored = classifier.restore_sanitized_text(res.sanitized_text, res.redaction_map)
        assert restored == full_text


# ==============================================================================
# Suite 2: False Positive Resistance & Precision
# ==============================================================================

class TestFalsePositiveResistance:
    """Stress tests false positive resistance against non-PII tokens."""

    @pytest.fixture
    def classifier(self) -> GemmaSanitizerClassifier:
        return GemmaSanitizerClassifier(mode="heuristic")

    def test_tracking_numbers_not_flagged_as_credit_cards(self, classifier: GemmaSanitizerClassifier) -> None:
        """
        Courier tracking numbers (FedEx, UPS, USPS, DHL) must NOT be misclassified as Credit Cards.
        """
        tracking_text = """
        Shipment Status Updates:
        - FedEx Express: 986578342109
        - UPS Ground: 1Z9999999999999999
        - USPS Certified Mail: 9400111899562537684132
        - DHL Express Airway: 1234567890
        - Amazon Logistics: TBA123456789012
        """
        res = classifier.classify_and_sanitize(tracking_text)
        cc_entities = [e for e in res.detected_entities if e.token_type == PIITokenType.CREDIT_CARD]
        assert len(cc_entities) == 0, f"False positive credit card detected: {cc_entities}"
        assert res.critical_pii_count == 0

    def test_invalid_ssn_area_codes_and_tax_numbers(self, classifier: GemmaSanitizerClassifier) -> None:
        """
        SSNs with invalid area codes (000, 666, 900-999) or non-SSN numeric patterns
        must be rejected as valid SSNs.
        """
        bogus_ssn_text = """
        Invalid identifiers:
        - 000-12-3456 (Area 000 never issued)
        - 666-45-6789 (Area 666 never issued)
        - 900-12-3456 (Area 900+ reserved/invalid)
        - 999-99-9999 (Area 999 invalid)
        - Serial: SN-123456789
        - Catalog Part: 888442211
        """
        res = classifier.classify_and_sanitize(bogus_ssn_text)
        ssn_entities = [e for e in res.detected_entities if e.token_type == PIITokenType.SSN]
        for entity in ssn_entities:
            # None of the invalid area codes should appear in SSN entities
            assert not entity.original_value.startswith("000"), f"000 SSN detected: {entity.original_value}"
            assert not entity.original_value.startswith("666"), f"666 SSN detected: {entity.original_value}"
            assert not entity.original_value.startswith("9"), f"9xx SSN detected: {entity.original_value}"

    def test_generic_proper_nouns_not_flagged_without_context(self, classifier: GemmaSanitizerClassifier) -> None:
        """
        Standard proper nouns and corporate terminology must not be flagged as FULL_NAME
        unless explicit contextual labeling is present.
        """
        generic_text = """
        The United States Department of Commerce released new guidelines in Washington DC.
        General Electric and Microsoft Corporation announced joint initiatives with San Francisco Bay Area.
        Internal Server Error was reported by Cloudflare. Status Code 500.
        """
        res = classifier.classify_and_sanitize(generic_text)
        name_entities = [e for e in res.detected_entities if e.token_type == PIITokenType.FULL_NAME]
        assert len(name_entities) == 0, f"False positive full name detected: {name_entities}"

    def test_git_commit_hashes_and_short_hex_not_misclassified(self, classifier: GemmaSanitizerClassifier) -> None:
        """
        Short hex hashes (7-8 chars) or 16-char IDs must not trigger SHA-256 or MD5 hashes.
        """
        code_text = """
        Git commit: a1b2c3d (feat: initial commit)
        Short hash: 7f8e9d0a
        UUID: 550e8400-e29b-41d4-a716-446655440000
        Build ID: build_20260828_9941
        """
        res = classifier.classify_and_sanitize(code_text)
        hash_entities = [e for e in res.detected_entities if e.token_type == PIITokenType.PASSWORD_HASH]
        assert len(hash_entities) == 0, f"False positive password hash detected: {hash_entities}"


# ==============================================================================
# Suite 3: Structured Profile Sanitization & Risk Score Boundaries
# ==============================================================================

class TestStructuredProfileAndRiskScoreBoundaries:
    """Stress tests ExtractedEntityProfile sanitization, restoration, and risk scoring."""

    @pytest.fixture
    def classifier(self) -> GemmaSanitizerClassifier:
        return GemmaSanitizerClassifier(mode="heuristic")

    def test_comprehensive_profile_sanitization_and_restoration(self, classifier: GemmaSanitizerClassifier) -> None:
        """
        Full ExtractedEntityProfile with all fields populated: names, phones, emails,
        addresses, relatives, past addresses, removal url.
        """
        original_profile = ExtractedEntityProfile(
            target_id="tgt_profile_9988",
            source_url="https://nuwber.com/person/dr-gordon-freeman",
            source_broker="Nuwber",
            matched_names=["Dr Gordon Freeman"],
            age="45",
            phone_numbers=["(505) 555-0143", "505-555-0199"],
            email_addresses=["gfreeman@blackmesa.gov", "gordon.freeman@mit.edu"],
            current_address="104 Materials Way, Sector C, Black Mesa, NM 87501",
            past_addresses=[
                "77 Massachusetts Ave, Cambridge, MA 02139",
                "123 Main St, Albuquerque, NM 87101",
            ],
            relatives=["Alyx Vance", "Eli Vance"],
            associates=["Barney Calhoun", "Isaac Kleiner"],
            removal_url="https://nuwber.com/optout/gfreeman",
            confidence_score=0.98,
        )

        sanitized_profile, sanitization_res = classifier.sanitize_profile(original_profile)

        # Verify sensitive fields are masked in the profile
        assert sanitized_profile.email_addresses[0].startswith("[PII_EMAIL_")
        assert sanitized_profile.email_addresses[1].startswith("[PII_EMAIL_")
        assert sanitized_profile.phone_numbers[0].startswith("[PII_PHONE_")
        assert "gfreeman@blackmesa.gov" not in sanitized_profile.email_addresses
        assert "(505) 555-0143" not in sanitized_profile.phone_numbers

        # Verify risk score is high
        assert sanitization_res.overall_risk_score >= 50.0

        # Restore profile
        restored_profile = classifier.restore_profile(sanitized_profile, sanitization_res.redaction_map)

        # Assert complete fidelity
        assert restored_profile.model_dump() == original_profile.model_dump()
        assert restored_profile.target_id == "tgt_profile_9988"
        assert restored_profile.email_addresses == ["gfreeman@blackmesa.gov", "gordon.freeman@mit.edu"]
        assert restored_profile.phone_numbers == ["(505) 555-0143", "505-555-0199"]
        assert restored_profile.relatives == ["Alyx Vance", "Eli Vance"]

    def test_risk_score_exact_boundary_calculations(self, classifier: GemmaSanitizerClassifier) -> None:
        """
        Verify exact mathematical bounds of risk score:
        - Empty = 0.0
        - Full Name only (Low: 3.0 * 0.85 = 2.55)
        - Email only (Medium: 8.0 * 0.98 = 7.84)
        - Phone only (High: 18.0 * 0.95 = 17.10)
        - SSN only (Critical: 35.0 * 0.99 = 34.65)
        - 3 Critical items -> clamped to 100.0 (3 * 34.65 = 103.95 -> 100.0)
        """
        # 1. Empty text
        assert classifier.classify_and_sanitize("").overall_risk_score == 0.0
        assert classifier.classify_and_sanitize("   ").overall_risk_score == 0.0

        # 2. Email only
        res_email = classifier.classify_and_sanitize("Email: user@example.com")
        assert res_email.overall_risk_score == 7.84

        # 3. Phone only
        res_phone = classifier.classify_and_sanitize("Phone: (555) 234-5678")
        assert res_phone.overall_risk_score == 17.10

        # 4. SSN only
        res_ssn = classifier.classify_and_sanitize("SSN: 123-45-6789")
        assert res_ssn.overall_risk_score == 34.65

        # 5. Two SSNs (2 * 34.65 = 69.30)
        res_2ssn = classifier.classify_and_sanitize("SSNs: 123-45-6789 and 234-56-7890")
        assert res_2ssn.overall_risk_score == 69.30

        # 6. Three SSNs -> Clamped at 100.0 (3 * 34.65 = 103.95 -> 100.0)
        res_3ssn = classifier.classify_and_sanitize("SSNs: 123-45-6789, 234-56-7890, 345-67-8901")
        assert res_3ssn.overall_risk_score == 100.0

        # 7. Ten SSNs + 5 Credit Cards -> Clamped at 100.0
        massive_crit = " ".join([f"SSN: 123-4{i:01d}-6789" for i in range(10)])
        res_massive = classifier.classify_and_sanitize(massive_crit)
        assert res_massive.overall_risk_score == 100.0

    @pytest.mark.asyncio
    async def test_async_sanitization_and_fast_sanitizer(self, classifier: GemmaSanitizerClassifier) -> None:
        """Verify async wrapper and FastPIISanitizer produce identical output."""
        sample_text = "Subject Alice (SSN 123-45-6789) can be reached at alice@domain.org or (555) 999-1111."

        # Async invocation
        async_res = await classifier.sanitize_and_classify_async(sample_text)
        sync_res = classifier.classify_and_sanitize(sample_text)
        fast_res = FastPIISanitizer().sanitize(sample_text)

        assert async_res.sanitized_text == sync_res.sanitized_text
        assert async_res.overall_risk_score == sync_res.overall_risk_score
        assert fast_res.sanitized_text == sync_res.sanitized_text
        assert fast_res.overall_risk_score == sync_res.overall_risk_score
