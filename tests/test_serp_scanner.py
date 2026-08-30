"""
Tests for Project Umbra SERP Scanner Tool & Search Grounding Engine (Tiers 1-5).
Verifies:
- Tier 1: Schema validation, PII token matching, and basic finding structures.
- Tier 2: Dynamic risk level scoring across 7 dork taxonomies and sensitive keywords.
- Tier 3: HTML parsing for DuckDuckGo Lite, SearXNG JSON parsing, and Google GenAI grounding.
- Tier 4: Concurrency-bounded batch execution, URL deduplication, and timeout/error fallback.
- Tier 5: Complete offline mock fixture execution and integration with ProjectUmbraAgent.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from project_umbra.config import settings
from project_umbra.core.agent import ProjectUmbraAgent
from project_umbra.core.state import (
    AgentLifecycleState,
    DorkCategory,
    DorkQuery,
    PriorityLevel,
    SERPFinding,
    TargetIdentityInput,
)
from project_umbra.tools.serp_scanner import SERPScanner, CRITICAL_KEYWORDS


@pytest.fixture
def sample_target_input() -> TargetIdentityInput:
    return TargetIdentityInput(
        full_name="Marcus Aurelius Brody",
        aliases=["Mark Brody", "M. Brody"],
        primary_email="m.brody@texastech.edu",
        secondary_emails=["marcus.brody@gmail.com"],
        phone_numbers=["(214) 555-0192", "214-555-0199"],
        current_city="Dallas",
        current_state="TX",
        known_addresses=["1428 Elm Street, Dallas, TX 75201"],
        relatives=["Eleanor Brody", "Arthur Brody"],
        employers=["Texas Tech University"],
        usernames=["mbrody_sec", "mbrody99"],
    )


@pytest.fixture
def sample_dorks() -> list[DorkQuery]:
    return [
        DorkQuery(
            dork_id="drk_doc_01",
            category=DorkCategory.DOCUMENTS_SPREADSHEETS,
            raw_query='filetype:pdf "Marcus Aurelius Brody" "Dallas"',
            encoded_url="https://www.google.com/search?q=filetype%3Apdf+%22Marcus+Aurelius+Brody%22",
            target_vector_id="vec_01",
            expected_signal="Sensitive PDF document disclosures",
            risk_level=PriorityLevel.HIGH,
        ),
        DorkQuery(
            dork_id="drk_paste_01",
            category=DorkCategory.PASTEBINS_DUMPS,
            raw_query='site:pastebin.com "m.brody@texastech.edu"',
            encoded_url="https://www.google.com/search?q=site%3Apastebin.com+%22m.brody%40texastech.edu%22",
            target_vector_id="vec_02",
            expected_signal="Pastebin breach leak",
            risk_level=PriorityLevel.CRITICAL,
        ),
        DorkQuery(
            dork_id="drk_cred_01",
            category=DorkCategory.CREDENTIAL_LEAKS,
            raw_query='"m.brody@texastech.edu" password OR hash',
            encoded_url="https://www.google.com/search?q=%22m.brody%40texastech.edu%22+password",
            target_vector_id="vec_03",
            expected_signal="Compromised credentials",
            risk_level=PriorityLevel.CRITICAL,
        ),
        DorkQuery(
            dork_id="drk_broker_01",
            category=DorkCategory.DATA_BROKER_PROFILES,
            raw_query='site:truepeoplesearch.com "Marcus Brody" "Dallas, TX"',
            encoded_url="https://www.google.com/search?q=site%3Atruepeoplesearch.com",
            target_vector_id="vec_04",
            expected_signal="Public directory listing",
            risk_level=PriorityLevel.HIGH,
        ),
        DorkQuery(
            dork_id="drk_social_01",
            category=DorkCategory.SOCIAL_EXPOSURE,
            raw_query='site:linkedin.com/in "Marcus Brody" "Texas Tech"',
            encoded_url="https://www.google.com/search?q=site%3Alinkedin.com%2Fin",
            target_vector_id="vec_05",
            expected_signal="Professional profile",
            risk_level=PriorityLevel.LOW,
        ),
    ]


# ==============================================================================
# Tier 1: Schema & Model Validation
# ==============================================================================

class TestTier1SchemaValidation:
    """Verifies SERPFinding schema properties, PII token detection, and initialization."""

    def test_serp_finding_schema_and_defaults(self) -> None:
        """Verifies SERPFinding field validation, default factories, and extra ignoring."""
        finding = SERPFinding(
            dork_id="drk_test_100",
            title="Leaked Employee Records",
            url="https://example.com/leak.pdf",
            snippet="Record containing sensitive data for Marcus Brody",
            domain="example.com",
            risk_level=PriorityLevel.CRITICAL,
            matched_pii_tokens=["Marcus Brody"],
            dork_category=DorkCategory.DOCUMENTS_SPREADSHEETS,
        )

        assert finding.finding_id is not None
        assert len(finding.finding_id) >= 6
        assert finding.dork_id == "drk_test_100"
        assert finding.risk_level == PriorityLevel.CRITICAL
        assert "Marcus Brody" in finding.matched_pii_tokens
        assert finding.dork_category == DorkCategory.DOCUMENTS_SPREADSHEETS
        assert finding.discovered_at is not None

    def test_extract_pii_tokens_comprehensive(self, sample_target_input: TargetIdentityInput) -> None:
        """Verifies _extract_pii_tokens detects names, aliases, emails, phones, and locations."""
        scanner = SERPScanner(mode="mock")

        text = (
            "Found entry for Mark Brody with email m.brody@texastech.edu and secondary "
            "contact marcus.brody@gmail.com located in Dallas at 1428 Elm Street. "
            "Phone is (214) 555-0192. Handle: mbrody_sec."
        )

        tokens = scanner._extract_pii_tokens(text, target_input=sample_target_input)

        assert "Mark Brody" in tokens
        assert "m.brody@texastech.edu" in tokens
        assert "marcus.brody@gmail.com" in tokens
        assert "(214) 555-0192" in tokens
        assert "Dallas" in tokens
        assert "mbrody_sec" in tokens


# ==============================================================================
# Tier 2: Dynamic Risk Level Scoring
# ==============================================================================

class TestTier2RiskRating:
    """Verifies contextual risk calculation based on taxonomy, tokens, and sensitive keywords."""

    def test_credential_leak_is_always_critical(self) -> None:
        scanner = SERPScanner(mode="mock")
        risk = scanner._calculate_risk(
            category=DorkCategory.CREDENTIAL_LEAKS,
            title="DeHashed Result",
            snippet="User record found",
            matched_tokens=["target@example.com"],
        )
        assert risk == PriorityLevel.CRITICAL

    def test_critical_keyword_escalation(self) -> None:
        scanner = SERPScanner(mode="mock")
        # Documents category with password keyword should escalate to CRITICAL
        risk = scanner._calculate_risk(
            category=DorkCategory.DOCUMENTS_SPREADSHEETS,
            title="Internal Document",
            snippet="Found plaintext password: Secret123",
            matched_tokens=["John Doe"],
        )
        assert risk == PriorityLevel.CRITICAL

    def test_pastebin_and_code_repos_risk(self) -> None:
        scanner = SERPScanner(mode="mock")
        # 2 tokens -> CRITICAL
        risk_multi = scanner._calculate_risk(
            category=DorkCategory.PASTEBINS_DUMPS,
            title="Pastebin Entry",
            snippet="User record data",
            matched_tokens=["John Doe", "john@example.com"],
        )
        assert risk_multi == PriorityLevel.CRITICAL

        # 1 token -> HIGH
        risk_single = scanner._calculate_risk(
            category=DorkCategory.PASTEBINS_DUMPS,
            title="Pastebin Entry",
            snippet="User record data",
            matched_tokens=["John Doe"],
        )
        assert risk_single == PriorityLevel.HIGH

    def test_broker_profiles_risk(self) -> None:
        scanner = SERPScanner(mode="mock")
        risk = scanner._calculate_risk(
            category=DorkCategory.DATA_BROKER_PROFILES,
            title="TruePeopleSearch Result",
            snippet="Public profile for John Doe in Dallas, TX",
            matched_tokens=["John Doe", "Dallas, TX"],
        )
        assert risk == PriorityLevel.HIGH

    def test_social_exposure_risk(self) -> None:
        scanner = SERPScanner(mode="mock")
        risk = scanner._calculate_risk(
            category=DorkCategory.SOCIAL_EXPOSURE,
            title="LinkedIn Profile",
            snippet="Engineer at TechCorp",
            matched_tokens=["John Doe"],
        )
        assert risk == PriorityLevel.LOW


# ==============================================================================
# Tier 3: HTML & Endpoint Response Parsers
# ==============================================================================

class TestTier3Parsers:
    """Verifies parsing of DuckDuckGo Lite HTML and mock endpoints."""

    def test_parse_duckduckgo_lite_html(self) -> None:
        raw_html = """
        <html>
        <body>
            <table>
                <tr>
                    <td>
                        <a class="result-link" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fpastebin.com%2Fraw%2Fabc12345&rut=...">
                            ComboBreach 2024 - <b>Marcus Brody</b> Leak
                        </a>
                    </td>
                </tr>
                <tr>
                    <td class="result-snippet">
                        Found compromised credentials for m.brody@texastech.edu in public dump.
                    </td>
                </tr>
                <tr>
                    <td>
                        <a class="result-link" href="https://example.com/record/99">
                            Public Docket - State Court
                        </a>
                    </td>
                </tr>
                <tr>
                    <td class="result-snippet">
                        Civil docket record for Marcus Aurelius Brody.
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        scanner = SERPScanner(mode="duckduckgo_lite")
        results = scanner.parse_duckduckgo_lite_html(
            raw_html, "drk_test_1", DorkCategory.PASTEBINS_DUMPS
        )

        assert len(results) == 2
        assert results[0]["url"] == "https://pastebin.com/raw/abc12345"
        assert "Marcus Brody" in results[0]["title"]
        assert "m.brody@texastech.edu" in results[0]["snippet"]
        assert results[0]["domain"] == "pastebin.com"

        assert results[1]["url"] == "https://example.com/record/99"
        assert results[1]["domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_searxng_parser(self, sample_dorks: list[DorkQuery]) -> None:
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {
                    "title": "SearXNG Finding",
                    "url": "https://dehashed.com/search?query=test",
                    "content": "Compromised record found",
                }
            ]
        }
        mock_client.get.return_value = mock_response

        scanner = SERPScanner(
            mode="searxng", searxng_url="https://searx.internal", http_client=mock_client
        )
        findings = await scanner.execute_dork(sample_dorks[0])

        assert len(findings) == 1
        assert findings[0].url == "https://dehashed.com/search?query=test"
        assert findings[0].domain == "dehashed.com"

    @pytest.mark.asyncio
    async def test_google_genai_search_records_provider_ledger(
        self,
        sample_dorks: list[DorkQuery],
    ) -> None:
        response = SimpleNamespace(
            text="Grounded result summary",
            response_id="search-response-123",
            model_version=None,
            usage_metadata={"prompt_token_count": 42, "candidates_token_count": 11},
            candidates=[
                SimpleNamespace(
                    grounding_metadata=SimpleNamespace(
                        grounding_chunks=[
                            SimpleNamespace(
                                web=SimpleNamespace(
                                    uri="https://example.com/avery",
                                    title="Grounded Avery result",
                                )
                            )
                        ]
                    )
                )
            ],
        )
        client = MagicMock()
        client.models.generate_content.return_value = response
        scanner = SERPScanner(
            mode="google_genai",
            gemini_client=client,
            jitter_min_ms=0,
            jitter_max_ms=0,
        )

        findings = await scanner.execute_dork(sample_dorks[0])

        assert findings
        assert scanner.last_model_invocation == {
            "provider": "google_genai_sdk",
            "operation": "grounded_search",
            "requested_model": "gemini-3.7-flash",
            "model_version": None,
            "response_id": "search-response-123",
            "usage": {"prompt_token_count": 42, "candidates_token_count": 11},
        }


# ==============================================================================
# Tier 4: Batch Concurrency, Deduplication & Error Resilience
# ==============================================================================

class TestTier4BatchAndErrorResilience:
    """Verifies concurrency bounding, URL deduplication, and graceful fallback."""

    @pytest.mark.asyncio
    async def test_batch_execution_concurrency_and_deduplication(
        self,
        sample_dorks: list[DorkQuery],
        sample_target_input: TargetIdentityInput,
    ) -> None:
        scanner = SERPScanner(mode="mock", max_concurrency=2)
        findings = await scanner.batch_execute_dorks(
            sample_dorks,
            target_input=sample_target_input,
            max_concurrency=2,
            timeout_per_dork=5.0,
        )

        assert len(findings) > 0
        # Ensure all findings have unique URLs
        urls = [f.url for f in findings]
        assert len(urls) == len(set(urls))

        # Check matched PII tokens
        for f in findings:
            assert isinstance(f, SERPFinding)
            assert f.risk_level in PriorityLevel

    @pytest.mark.asyncio
    async def test_live_search_http_error_falls_back_to_mock(
        self,
        sample_dorks: list[DorkQuery],
        sample_target_input: TargetIdentityInput,
    ) -> None:
        mock_client = AsyncMock()
        mock_client.post.side_effect = ConnectionError("Network unreachable")

        scanner = SERPScanner(mode="duckduckgo_lite", http_client=mock_client)
        findings = await scanner.execute_dork(sample_dorks[0], target_input=sample_target_input)

        # Must cleanly fall back to mock fixture without raising
        assert len(findings) > 0
        assert any(
            sample_target_input.full_name in f.title or sample_target_input.full_name in f.snippet
            for f in findings
        )


# ==============================================================================
# Tier 5: Mock Fixtures & Agent Integration
# ==============================================================================

class TestTier5MockAndAgentIntegration:
    """Verifies all 7 taxonomy fixtures and end-to-end integration into ProjectUmbraAgent."""

    @pytest.mark.asyncio
    async def test_all_seven_taxonomies_have_mock_templates(
        self,
        sample_target_input: TargetIdentityInput,
    ) -> None:
        scanner = SERPScanner(mode="mock")
        for cat in DorkCategory:
            dork = DorkQuery(
                dork_id=f"drk_{cat.value}",
                category=cat,
                raw_query=f'query for {cat.value} "{sample_target_input.full_name}"',
                encoded_url="https://google.com",
                target_vector_id="vec_01",
                expected_signal=cat.value,
                risk_level=PriorityLevel.MEDIUM,
            )
            findings = await scanner.execute_dork(dork, target_input=sample_target_input)
            assert len(findings) > 0
            assert all(isinstance(f, SERPFinding) for f in findings)
            assert any(sample_target_input.full_name in f.title or sample_target_input.full_name in f.snippet for f in findings)

    @pytest.mark.asyncio
    async def test_agent_integration_with_serp_scanner(
        self,
        sample_target_input: TargetIdentityInput,
    ) -> None:
        serp_scanner = SERPScanner(mode="mock")
        agent = ProjectUmbraAgent(serp_scanner=serp_scanner, max_budget=25)

        summary = await agent.run_mission(sample_target_input)

        assert summary.final_state == AgentLifecycleState.COMPLETED
        assert summary.dorks_executed > 0
        assert summary.exposures_found > 0
        # Check that SERP scanner step was recorded
        serp_steps = [s for s in summary.execution_state_log if s.tool_name == "controlled_serp_fixture"]
        assert len(serp_steps) > 0
        assert all(s.provenance.value == "controlled_fixture" for s in serp_steps)
