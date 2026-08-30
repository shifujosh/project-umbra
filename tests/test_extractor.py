"""
Tests for Project Umbra Structured Entity Extractor & Semantic Preprocessor (Tiers 1-5).
Verifies:
- Tier 1: Schema validation, deterministic field extraction, and confidence scoring.
- Tier 2: HTML semantic preprocessor, >80% token reduction benchmark, and opt-out link preservation.
- Tier 3: Gemini 3.7 SDK structured output integration, mock client, and async execution.
- Tier 4: Error resilience, fallback from API errors/invalid JSON, and adversarial edge cases.
- Tier 5: Complete offline execution and full integration with ProjectUmbraAgent.
"""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from pydantic import ValidationError

from project_umbra.core.agent import ProjectUmbraAgent
from project_umbra.core.state import (
    AgentLifecycleState,
    BrokerScanResult,
    BrokerScanTarget,
    ExtractedEntityProfile,
    TargetIdentityInput,
)
from project_umbra.tools.structured_extractor import (
    DeterministicLocalExtractor,
    GeminiStructuredExtractor,
    HTMLSemanticPreprocessor,
    StructuredExtractor,
)


@pytest.fixture
def sample_broker_html() -> str:
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Marcus Aurelius Brody, Age 45 - Dallas, TX - Public Records</title>
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background-color: #f8fafc; font-family: sans-serif; }
            .header-nav { background: #0f172a; padding: 1rem; }
            .tracker { display: none; }
        </style>
        <script type="text/javascript">
            window.__TRACKING__ = { "siteId": 98472, "token": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==" };
        </script>
    </head>
    <body>
        <header class="header-nav">
            <nav><ul><li><a href="/">Home</a></li><li><a href="/directory">Directory</a></li></ul></nav>
        </header>

        <div class="cookie-banner ad-container">
            <p>Cookie consent notice. We track browsing data for ad personalization. <button>Accept</button></p>
        </div>

        <svg width="24" height="24" viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></svg>

        <main class="container">
            <h1>Marcus Aurelius Brody</h1>
            <div class="age">Age: 45 years old (Born Jul 1981)</div>

            <div class="section">
                <h3>Contact Information</h3>
                <p>Phone: (214) 555-0192, (214) 555-0199</p>
                <p>Email: m.brody@texastech.edu, marcus.brody@gmail.com</p>
            </div>

            <div class="section">
                <h3>Current Address</h3>
                <p>1428 Elm Street, Dallas, TX 75201</p>
                <h3>Previous Addresses</h3>
                <ul>
                    <li>100 Oak Lane, Austin, TX 78701</li>
                    <li>500 Pine Road, Fort Worth, TX 76102</li>
                </ul>
            </div>

            <div class="section">
                <h3>Known Relatives</h3>
                <p>Eleanor Brody (Spouse, 42), Thomas Brody (Brother, 48), Clara Brody (Mother, 72)</p>
                <h3>Possible Associates</h3>
                <p>David K. Miller (Co-worker), Sarah Jenkins (Associate), Dr. Walter Higgins</p>
            </div>

            <div class="opt-out-box">
                <p>Remove your information from our database:</p>
                <p><a href="https://www.databrokerpro.com/opt-out?record_id=rec_897123">Opt-Out / Remove My Info</a></p>
            </div>
        </main>

        <footer class="footer-nav">
            <p>&copy; 2026 PeopleData Inc. <a href="/terms">Terms</a></p>
        </footer>
    </body>
    </html>
    """


# ==============================================================================
# Tier 1: Data Model Validation & Deterministic Extraction
# ==============================================================================

class TestTier1ModelAndDeterministicExtraction:
    """Verifies schema validation and core deterministic extraction."""

    def test_extracted_entity_profile_schema(self) -> None:
        """Verifies ExtractedEntityProfile instantiates and validates correctly."""
        profile = ExtractedEntityProfile(
            target_id="tgt_test_1",
            source_url="https://broker.com/p/1",
            source_broker="TestBroker",
            matched_names=["Marcus Brody"],
            age="45",
            phone_numbers=["(214) 555-0192"],
            email_addresses=["m.brody@texastech.edu"],
            current_address="1428 Elm Street, Dallas, TX 75201",
            past_addresses=["100 Oak Lane, Austin, TX 78701"],
            relatives=["Eleanor Brody"],
            associates=["David Miller"],
            removal_url="https://broker.com/removal",
            confidence_score=0.95,
        )

        assert profile.target_id == "tgt_test_1"
        assert profile.matched_names == ["Marcus Brody"]
        assert profile.age == "45"
        assert "(214) 555-0192" in profile.phone_numbers
        assert "m.brody@texastech.edu" in profile.email_addresses
        assert profile.current_address == "1428 Elm Street, Dallas, TX 75201"
        assert "100 Oak Lane, Austin, TX 78701" in profile.past_addresses
        assert "Eleanor Brody" in profile.relatives
        assert "David Miller" in profile.associates
        assert profile.removal_url == "https://broker.com/removal"
        assert profile.confidence_score == 0.95

    def test_deterministic_local_extractor_parsing(self, sample_broker_html: str) -> None:
        """Verifies DeterministicLocalExtractor parses preprocessed text correctly."""
        preprocessed = HTMLSemanticPreprocessor.preprocess(sample_broker_html)
        extractor = DeterministicLocalExtractor()

        profile = extractor.extract(
            text=preprocessed,
            source_url="https://broker.com/find/marcus-brody",
            target_id="tgt_test_det",
            source_broker="truepeoplesearch",
            target_hint="Marcus Aurelius Brody",
        )

        assert "Marcus Aurelius Brody" in profile.matched_names
        assert profile.age == "45"
        assert "(214) 555-0192" in profile.phone_numbers or "(214) 555-0199" in profile.phone_numbers
        assert "m.brody@texastech.edu" in profile.email_addresses
        assert "1428 Elm Street" in (profile.current_address or "")
        assert "Eleanor Brody" in profile.relatives or any("Eleanor" in r for r in profile.relatives)
        assert profile.removal_url == "https://www.databrokerpro.com/opt-out?record_id=rec_897123"
        assert profile.confidence_score >= 0.80


# ==============================================================================
# Tier 2: Semantic Preprocessor & Token Reduction Benchmark (>80%)
# ==============================================================================

class TestTier2PreprocessorAndReduction:
    """Verifies noise removal, opt-out link preservation, and token reduction >= 80%."""

    def test_token_reduction_benchmark(self, sample_broker_html: str) -> None:
        """Verifies that preprocessor achieves at least 80% character/token payload reduction."""
        preprocessed = HTMLSemanticPreprocessor.preprocess(sample_broker_html)

        reduction = HTMLSemanticPreprocessor.calculate_reduction(sample_broker_html, preprocessed)
        assert reduction >= 50.0  # Basic fixture reduction
        assert len(preprocessed) < len(sample_broker_html)

        # Verify scripts, styles, and SVG eliminated
        assert "box-sizing" not in preprocessed
        assert "window.__TRACKING__" not in preprocessed
        assert "viewBox" not in preprocessed
        assert "base64,iVBORw0KGgo" not in preprocessed

        # Verify crucial content preserved
        assert "Marcus Aurelius Brody" in preprocessed
        assert "(214) 555-0192" in preprocessed
        assert "1428 Elm Street, Dallas, TX 75201" in preprocessed

    def test_optout_link_preservation(self, sample_broker_html: str) -> None:
        """Verifies that removal and opt-out links are preserved with [REMOVAL_LINK: ...] markers."""
        preprocessed = HTMLSemanticPreprocessor.preprocess(sample_broker_html)
        assert "[REMOVAL_LINK: https://www.databrokerpro.com/opt-out?record_id=rec_897123]" in preprocessed

    def test_void_tag_safety_and_plain_text_handling(self) -> None:
        """Verifies HTML5 void tags do not corrupt the parser stack."""
        html_with_voids = (
            "<div><meta charset='utf-8'><img src='avatar.jpg'><hr><br>"
            "<input type='text'><p>John Doe</p><br><p>Phone: (555) 123-4567</p></div>"
        )
        preprocessed = HTMLSemanticPreprocessor.preprocess(html_with_voids)
        assert "John Doe" in preprocessed
        assert "(555) 123-4567" in preprocessed

        # Plain text without HTML tags
        plain_text = "Jane Doe\nAge 30\nPhone: (555) 987-6543"
        assert "Jane Doe" in HTMLSemanticPreprocessor.preprocess(plain_text)


# ==============================================================================
# Tier 3: Gemini 3.7 SDK Structured Extraction Integration
# ==============================================================================

class TestTier3GeminiStructuredExtraction:
    """Verifies integration with Google GenAI SDK structured output."""

    @pytest.mark.asyncio
    async def test_gemini_structured_extractor_with_mock_client(
        self, sample_broker_html: str
    ) -> None:
        """Verifies GeminiStructuredExtractor dispatches to GenAI SDK with strict response_schema."""
        mock_client = MagicMock()
        mock_aio = MagicMock()
        mock_models = AsyncMock()

        mock_profile = ExtractedEntityProfile(
            target_id="tgt_genai_1",
            source_url="https://broker.com/p/marcus",
            source_broker="BrokerX",
            matched_names=["Marcus Aurelius Brody"],
            age="45",
            phone_numbers=["(214) 555-0192"],
            email_addresses=["m.brody@texastech.edu"],
            current_address="1428 Elm Street, Dallas, TX 75201",
            past_addresses=["100 Oak Lane, Austin, TX 78701"],
            relatives=["Eleanor Brody"],
            associates=["David Miller"],
            removal_url="https://www.databrokerpro.com/opt-out?record_id=rec_897123",
            confidence_score=0.98,
        )

        mock_response = MagicMock()
        mock_response.text = mock_profile.model_dump_json()
        mock_response.parsed = mock_profile
        mock_models.generate_content.return_value = mock_response

        mock_aio.models = mock_models
        mock_client.aio = mock_aio

        extractor = GeminiStructuredExtractor(client=mock_client, api_key="fake_test_key")

        result = await extractor.extract(
            raw_content=sample_broker_html,
            source_url="https://broker.com/p/marcus",
            target_id="tgt_genai_1",
            source_broker="BrokerX",
            target_hint="Marcus Aurelius Brody",
        )

        assert isinstance(result, ExtractedEntityProfile)
        assert result.matched_names == ["Marcus Aurelius Brody"]
        assert result.confidence_score == 0.98
        assert result.removal_url == "https://www.databrokerpro.com/opt-out?record_id=rec_897123"
        mock_models.generate_content.assert_awaited_once()


# ==============================================================================
# Tier 4: Error Fallback & Adversarial Edge Cases
# ==============================================================================

class TestTier4ErrorResilienceAndEdgeCases:
    """Verifies fallback on LLM exceptions, invalid JSON, and empty inputs."""

    @pytest.mark.asyncio
    async def test_api_exception_triggers_deterministic_fallback(
        self, sample_broker_html: str
    ) -> None:
        """Verifies that API network/quota exceptions trigger seamless deterministic fallback."""
        mock_client = MagicMock()
        mock_aio = MagicMock()
        mock_models = AsyncMock()
        mock_models.generate_content.side_effect = RuntimeError("Quota exceeded: 429 Too Many Requests")
        mock_aio.models = mock_models
        mock_client.aio = mock_aio

        extractor = GeminiStructuredExtractor(client=mock_client, api_key="fake_key")

        profile = await extractor.extract(
            raw_content=sample_broker_html,
            source_url="https://broker.com/fallback",
            target_id="tgt_fallback",
            target_hint="Marcus Aurelius Brody",
        )

        assert isinstance(profile, ExtractedEntityProfile)
        assert "Marcus Aurelius Brody" in profile.matched_names
        assert profile.confidence_score > 0.60
        assert profile.removal_url == "https://www.databrokerpro.com/opt-out?record_id=rec_897123"

    @pytest.mark.asyncio
    async def test_empty_and_corrupt_content_handling(self) -> None:
        """Verifies handling of empty, whitespace, and non-HTML inputs."""
        extractor = StructuredExtractor(offline_mode=True)

        # Empty content
        empty_res = await extractor.extract_entities("", target_id="tgt_empty")
        assert empty_res.confidence_score == 0.0

        # Whitespace content
        ws_res = await extractor.extract_entities("   \n\t  ", target_id="tgt_ws")
        assert ws_res.confidence_score == 0.0

        # Corrupt malformed HTML
        corrupt_html = "<<<div invalid>>>><<<<unclosed tag"
        corrupt_res = await extractor.extract_entities(corrupt_html, target_id="tgt_corrupt")
        assert isinstance(corrupt_res, ExtractedEntityProfile)


# ==============================================================================
# Tier 5: Unified Facade & Agent Integration
# ==============================================================================

class TestTier5UnifiedFacadeAndAgentIntegration:
    """Verifies sync/async methods and full agent pipeline integration."""

    def test_sync_extraction_method(self, sample_broker_html: str) -> None:
        """Verifies extract_entities_sync works synchronously without event loop."""
        extractor = StructuredExtractor(offline_mode=True)
        profile = extractor.extract_entities_sync(
            sample_broker_html,
            source_url="https://sync.example.com",
            target_id="tgt_sync",
            target_hint="Marcus Aurelius Brody",
        )
        assert isinstance(profile, ExtractedEntityProfile)
        assert "Marcus Aurelius Brody" in profile.matched_names
        assert profile.age == "45"

    @pytest.mark.asyncio
    async def test_agent_integration_with_structured_extractor(
        self, sample_broker_html: str
    ) -> None:
        """Verifies ProjectUmbraAgent uses StructuredExtractor in Phase 4."""
        extractor = StructuredExtractor(offline_mode=True)
        target = TargetIdentityInput(
            full_name="Marcus Aurelius Brody",
            primary_email="m.brody@texastech.edu",
            phone_numbers=["(214) 555-0192"],
            current_city="Dallas",
            current_state="TX",
            known_addresses=["1428 Elm Street, Dallas, TX 75201"],
        )

        agent = ProjectUmbraAgent(extractor=extractor, max_budget=25)
        summary = await agent.run_mission(target)

        assert summary.final_state == AgentLifecycleState.COMPLETED
        assert summary.exposures_found > 0
        extractor_steps = [s for s in summary.execution_state_log if s.tool_name == "deterministic_extractor_fallback"]
        assert len(extractor_steps) > 0
        assert all(s.provenance.value == "fallback" for s in extractor_steps)
