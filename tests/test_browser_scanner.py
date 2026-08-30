"""
Tests for Playwright Stealth Browser Scanner & Anti-Bot Evasion (Tiers 1-5).
Verifies URL synthesis, anti-bot scripts, challenge detection, fixture loading,
async resource lifecycle, and adversarial error handling.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from project_umbra.config import settings
from project_umbra.core.agent import ProjectUmbraAgent
from project_umbra.core.state import (
    AgentLifecycleState,
    BrokerScanResult,
    BrokerScanTarget,
    TargetIdentityInput,
)
from project_umbra.tools.browser_scanner import (
    PlaywrightStealthScanner,
    build_broker_search_url,
    detect_challenge_dom,
    extract_clean_text,
    STEALTH_EVASION_SCRIPT,
    STEALTH_USER_AGENTS,
    STEALTH_VIEWPORTS,
)


@pytest.fixture
def sample_identity() -> TargetIdentityInput:
    return TargetIdentityInput(
        full_name="Marcus Aurelius Brody",
        aliases=["Mark Brody"],
        primary_email="m.brody@texastech.edu",
        secondary_emails=["marcus.brody@gmail.com"],
        phone_numbers=["(214) 555-0192"],
        current_city="Dallas",
        current_state="TX",
        known_addresses=["1428 Elm Street, Dallas, TX 75201"],
        relatives=["Eleanor Brody", "Arthur Brody"],
        employers=["Texas Tech University"],
        usernames=["mbrody_sec"],
    )


@pytest.fixture
def broker_targets() -> list[BrokerScanTarget]:
    return [
        BrokerScanTarget(
            broker_id="truepeoplesearch",
            broker_name="TruePeopleSearch",
            base_url="https://www.truepeoplesearch.com",
            opt_out_url="https://www.truepeoplesearch.com/removal",
            search_url_template="https://www.truepeoplesearch.com/results?name={name}&citystatezip={location}",
        ),
        BrokerScanTarget(
            broker_id="fastpeoplesearch",
            broker_name="FastPeopleSearch",
            base_url="https://www.fastpeoplesearch.com",
            opt_out_url="https://www.fastpeoplesearch.com/removal",
            search_url_template="https://www.fastpeoplesearch.com/name/{name}_{location}",
        ),
        BrokerScanTarget(
            broker_id="radaris",
            broker_name="Radaris",
            base_url="https://radaris.com",
            opt_out_url="https://radaris.com/control/privacy",
            search_url_template="https://radaris.com/p/{name}",
        ),
        BrokerScanTarget(
            broker_id="nuwber",
            broker_name="Nuwber",
            base_url="https://nuwber.com",
            opt_out_url="https://nuwber.com/removal/link",
            search_url_template="https://nuwber.com/person/{name}",
        ),
        BrokerScanTarget(
            broker_id="whitepages",
            broker_name="Whitepages",
            base_url="https://www.whitepages.com",
            opt_out_url="https://www.whitepages.com/suppression-requests",
            search_url_template="https://www.whitepages.com/name/{name}/{location}",
        ),
    ]


# ==============================================================================
# Tier 1: Search URL Generation & Clean Text Extraction
# ==============================================================================

class TestTier1URLAndTextExtraction:
    """Verifies URL generation and clean text parsing."""

    def test_url_builders_all_five_brokers(
        self,
        sample_identity: TargetIdentityInput,
        broker_targets: list[BrokerScanTarget],
    ) -> None:
        """Verifies search URL construction across all 5 target brokers."""
        target_map = {b.broker_id: b for b in broker_targets}

        # 1. TruePeopleSearch
        url_tps = build_broker_search_url(target_map["truepeoplesearch"], sample_identity)
        assert "truepeoplesearch.com/results?name=Marcus+Aurelius+Brody" in url_tps
        assert "citystatezip=Dallas+TX" in url_tps

        # 2. FastPeopleSearch
        url_fps = build_broker_search_url(target_map["fastpeoplesearch"], sample_identity)
        assert "fastpeoplesearch.com/name/marcus-aurelius-brody_dallas-tx" in url_fps

        # 3. Radaris
        url_rad = build_broker_search_url(target_map["radaris"], sample_identity)
        assert "radaris.com/p/marcus-aurelius-brody" in url_rad

        # 4. Nuwber
        url_nuw = build_broker_search_url(target_map["nuwber"], sample_identity)
        assert "nuwber.com/person/marcus-aurelius-brody" in url_nuw

        # 5. Whitepages
        url_wp = build_broker_search_url(target_map["whitepages"], sample_identity)
        assert "whitepages.com/name/marcus-aurelius-brody/dallas-tx" in url_wp

    def test_clean_text_extractor_strips_scripts_and_styles(self) -> None:
        """Verifies that extract_clean_text strips script and style tags while preserving content."""
        sample_html = """
        <html>
            <head><style>.hidden { display: none; }</style></head>
            <body>
                <script>console.log('malicious script');</script>
                <h1>Marcus Brody</h1>
                <p>Phone: (214) 555-0192</p>
                <noscript>JavaScript is required</noscript>
            </body>
        </html>
        """
        text = extract_clean_text(sample_html)
        assert "Marcus Brody" in text
        assert "(214) 555-0192" in text
        assert "console.log" not in text
        assert "display: none" not in text
        assert "JavaScript is required" not in text


# ==============================================================================
# Tier 2: Anti-Bot Evasion & Stealth Script Verification
# ==============================================================================

class TestTier2StealthEvasion:
    """Verifies stealth script content, user agent rotation, and viewport pools."""

    def test_stealth_evasion_script_content(self) -> None:
        """Verifies that STEALTH_EVASION_SCRIPT overrides critical fingerprinting vectors."""
        assert "navigator, 'webdriver'" in STEALTH_EVASION_SCRIPT
        assert "window.chrome" in STEALTH_EVASION_SCRIPT
        assert "navigator, 'plugins'" in STEALTH_EVASION_SCRIPT
        assert "navigator, 'languages'" in STEALTH_EVASION_SCRIPT
        assert "hardwareConcurrency" in STEALTH_EVASION_SCRIPT
        assert "WebGLRenderingContext" in STEALTH_EVASION_SCRIPT
        assert "deviceMemory" in STEALTH_EVASION_SCRIPT

    def test_stealth_user_agents_and_viewports(self) -> None:
        """Verifies user agent and viewport pools."""
        assert len(STEALTH_USER_AGENTS) >= 4
        for ua in STEALTH_USER_AGENTS:
            assert "Mozilla/5.0" in ua

        assert len(STEALTH_VIEWPORTS) >= 4
        for vp in STEALTH_VIEWPORTS:
            assert vp["width"] >= 1200
            assert vp["height"] >= 700


# ==============================================================================
# Tier 3: Challenge DOM Detection Matrix
# ==============================================================================

class TestTier3ChallengeDetection:
    """Verifies challenge detection across Cloudflare, DataDome, PX, Akamai, and status codes."""

    @pytest.mark.parametrize(
        "challenge_html, status_code, expected",
        [
            ("<html><body><div id='challenge-stage'>Checking your browser</div></body></html>", 200, True),
            ("<html><body><div class='cf-turnstile'></div></body></html>", 200, True),
            ("<html><body><script src='https://geo.captcha-delivery.com/captcha/dd.js'></script></body></html>", 200, True),
            ("<html><body><div id='px-block'>Access Denied</div></body></html>", 200, True),
            ("<html><body><h1>Access Denied</h1><p>akamai-bm challenge</p></body></html>", 200, True),
            ("<html><body>Normal profile content for Marcus Brody</body></html>", 403, True),
            ("<html><body>Normal profile content for Marcus Brody</body></html>", 429, True),
            ("<html><body><div class='card'><h2>Marcus Brody</h2><p>Phone: (214) 555-0192</p></div></body></html>", 200, False),
        ],
    )
    def test_challenge_dom_detection(self, challenge_html: str, status_code: int, expected: bool) -> None:
        assert detect_challenge_dom(challenge_html, status_code) == expected


# ==============================================================================
# Tier 4: Synthetic HTML Fixtures & Templating Fallback
# ==============================================================================

class TestTier4FixtureLoading:
    """Verifies that all 5 broker fixtures are loaded and correctly interpolate identity data."""

    @pytest.mark.asyncio
    async def test_fixture_loading_and_token_interpolation(
        self,
        sample_identity: TargetIdentityInput,
        broker_targets: list[BrokerScanTarget],
    ) -> None:
        scanner = PlaywrightStealthScanner(simulation_mode=True)

        for target in broker_targets:
            res = await scanner.scan_broker(target, sample_identity)
            assert isinstance(res, BrokerScanResult)
            assert res.broker_id == target.broker_id
            assert res.target_name == sample_identity.full_name
            assert res.is_exposed is True
            assert res.is_simulated is True
            assert res.status_code == 200
            assert sample_identity.full_name in res.raw_html
            assert "Dallas" in res.raw_html
            assert "(214) 555-0192" in res.raw_html
            assert "Eleanor Brody" in res.raw_html
            assert res.extracted_text is not None
            assert sample_identity.full_name in res.extracted_text


# ==============================================================================
# Tier 5: Async Resource Management, Context Manager & Agent Integration
# ==============================================================================

class TestTier5AsyncLifecycleAndIntegration:
    """Verifies async context manager lifecycle, live fallback, and agent integration."""

    @pytest.mark.asyncio
    async def test_context_manager_and_scan_all_brokers(
        self,
        sample_identity: TargetIdentityInput,
        broker_targets: list[BrokerScanTarget],
    ) -> None:
        async with PlaywrightStealthScanner(simulation_mode=True) as scanner:
            results = await scanner.scan_all_brokers(broker_targets, sample_identity)
            assert len(results) == 5
            assert all(r.is_exposed for r in results)
            assert all(r.is_simulated for r in results)

    @pytest.mark.asyncio
    async def test_challenge_trigger_fallback_in_live_mode(
        self,
        sample_identity: TargetIdentityInput,
        broker_targets: list[BrokerScanTarget],
    ) -> None:
        """Verifies that when a challenge DOM is encountered in live mode, fixture fallback triggers seamlessly."""
        scanner = PlaywrightStealthScanner(simulation_mode=False)

        mock_page = AsyncMock()
        mock_response = MagicMock()
        mock_response.status = 403
        mock_page.goto.return_value = mock_response
        mock_page.content.return_value = "<html><body><div id='cf-wrapper'>Attention Required! | Cloudflare</div></body></html>"
        mock_page.url = "https://www.truepeoplesearch.com/challenge"

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page

        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context

        scanner._browser = mock_browser
        scanner._is_initialized = True

        target = broker_targets[0]
        res = await scanner.scan_broker(target, sample_identity)

        assert res.is_exposed is True
        assert res.is_simulated is True
        assert sample_identity.full_name in res.extracted_text
        assert "truepeoplesearch" in res.broker_id

    @pytest.mark.asyncio
    async def test_agent_integration_with_browser_scanner(
        self,
        sample_identity: TargetIdentityInput,
        broker_targets: list[BrokerScanTarget],
    ) -> None:
        browser_scanner = PlaywrightStealthScanner(simulation_mode=True)
        agent = ProjectUmbraAgent(
            browser_scanner=browser_scanner,
            broker_targets=broker_targets,
            max_budget=25,
        )

        summary = await agent.run_mission(sample_identity)

        assert summary.final_state == AgentLifecycleState.COMPLETED
        assert summary.brokers_scanned == 5
        assert summary.exposures_found > 0
        broker_steps = [s for s in summary.execution_state_log if s.tool_name == "controlled_broker_fixture"]
        assert len(broker_steps) == 5
        assert all(s.provenance.value == "controlled_fixture" for s in broker_steps)
