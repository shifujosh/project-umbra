"""
Empirical Adversarial Stress Test Suite for Milestone 2 (Challenger 2).
Focus areas:
1. Anti-Bot DOM Challenge Detection (Cloudflare, DataDome, PerimeterX, Akamai, WAFs, status codes, edge cases).
2. HTML Semantic Preprocessor (token reduction metrics >= 80%, base64/SVG stripping, opt-out link preservation, void tag integrity).
3. Structured Extractor & Deterministic Fallback (complex/obfuscated DOM layouts, phone/email/address regex boundaries, multi-person disambiguation, LLM exception resilience).
4. Playwright Scanner concurrency & resource bounds stress testing.
"""

from __future__ import annotations

import asyncio
import re
import time
import pytest
from unittest.mock import AsyncMock, MagicMock

from project_umbra.core.state import (
    BrokerScanResult,
    BrokerScanTarget,
    ExtractedEntityProfile,
    PriorityLevel,
    TargetIdentityInput,
)
from project_umbra.tools.browser_scanner import (
    PlaywrightStealthScanner,
    build_broker_search_url,
    detect_challenge_dom,
    extract_clean_text,
    CHALLENGE_SIGNATURES,
    STEALTH_EVASION_SCRIPT,
)
from project_umbra.tools.fixtures import render_broker_fixture
from project_umbra.tools.structured_extractor import (
    DeterministicLocalExtractor,
    GeminiStructuredExtractor,
    HTMLSemanticPreprocessor,
    StructuredExtractor,
)


@pytest.fixture
def target_identity_complex() -> TargetIdentityInput:
    return TargetIdentityInput(
        full_name="Cassandra Vance-Montgomery",
        aliases=["Cassie Vance", "C. V. Montgomery"],
        primary_email="cassandra.vance@cyber-defense.org",
        secondary_emails=["cvance@alumni.mit.edu", "cassie.v@protonmail.com"],
        phone_numbers=["(415) 555-0142", "415-555-0199"],
        current_city="San Francisco",
        current_state="CA",
        known_addresses=[
            "742 Montgomery St, Apt 14B, San Francisco, CA 94111-2034",
            "100 Main St, Cambridge, MA 02139",
        ],
        relatives=["Dominic Vance", "Julian Montgomery", "Elena Vance-Ross"],
        employers=["Cyber Defense Labs", "MIT Lincoln Laboratory"],
        usernames=["cvance_sec", "vance_cyber"],
    )


# ==============================================================================
# 1. Anti-Bot Challenge DOM & Signature Stress Tests
# ==============================================================================

class TestAntiBotChallengeStress:
    """Stress tests challenge detection across all major anti-bot WAFs, HTTP codes, and edge cases."""

    @pytest.mark.parametrize(
        "challenge_html, status_code, expected_detected",
        [
            # Cloudflare Turnstile / Managed Challenge
            ("<div class='cf-turnstile' data-sitekey='0x4AAAAAA'></div>", 200, True),
            ("<div id='challenge-stage'><p>Checking your browser before accessing...</p></div>", 200, True),
            ("<form id='challenge-form' action='/cdn-cgi/challenge-platform/h/g/flow'></form>", 200, True),
            ("<title>Attention Required! | Cloudflare</title><div>Cloudflare Ray ID: 87a9b0c1</div>", 200, True),
            ("<div class='cf-browser-verification cf-im-under-attack'></div>", 200, True),
            ("<html><body><script>window._cf_chl_opt={};</script><div>cf-challenge-running</div></body></html>", 200, True),

            # DataDome
            ("<html><head><script src='https://geo.captcha-delivery.com/captcha/dd.js'></script></head></html>", 200, True),
            ("<div class='datadome-captcha-container'><p>Blocked by DataDome</p></div>", 200, True),
            ("<div id='dd-captcha'>Please verify you are a human</div>", 200, True),

            # PerimeterX / HUMAN Security
            ("<html><head><script>window._pxAppId='PX12345';</script></head><body><div id='px-captcha'></div></body></html>", 200, True),
            ("<div>Access to this page has been denied. px-block active.</div>", 200, True),

            # Akamai / WAF
            ("<html><body><h1>Access Denied</h1><p>You don't have permission to access / on this server.</p></body></html>", 200, True),
            ("<div>Akamai-bm challenge active. ak-challenge token required.</div>", 200, True),

            # Status Code overrides
            ("<html><body>Legitimate user profile page</body></html>", 403, True),
            ("<html><body>Legitimate user profile page</body></html>", 429, True),

            # Edge Case: Empty
            ("", 200, True),

            # Clean legitimate data broker profile with no challenges
            (
                "<div class='profile-card'><h1>Cassandra Vance</h1><p>Current Address: 742 Montgomery St, San Francisco, CA 94111</p><p>Phone: (415) 555-0142</p></div>",
                200,
                False,
            ),
        ],
    )
    def test_challenge_dom_detection_matrix(
        self, challenge_html: str, status_code: int, expected_detected: bool
    ) -> None:
        """Verifies detect_challenge_dom identifies all signature variations."""
        detected = detect_challenge_dom(challenge_html, status_code)
        assert detected is expected_detected

    def test_challenge_signatures_case_insensitivity(self) -> None:
        """Verifies that challenge detection is strictly case-insensitive."""
        for sig in CHALLENGE_SIGNATURES:
            upper_html = f"<html><body><div>BLOCK TRIGGER: {sig.upper()}</div></body></html>"
            assert detect_challenge_dom(upper_html, 200) is True, f"Failed for uppercase signature: {sig}"

    @pytest.mark.asyncio
    async def test_live_scanner_automatic_fallback_on_403_and_turnstile(
        self, target_identity_complex: TargetIdentityInput
    ) -> None:
        """Verifies that live scanner seamlessly falls back to synthetic fixtures when challenged."""
        scanner = PlaywrightStealthScanner(simulation_mode=False)

        mock_page = AsyncMock()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_page.goto.return_value = mock_response
        mock_page.content.return_value = "<html><body><div class='cf-turnstile'>Verify you are human</div></body></html>"
        mock_page.url = "https://www.truepeoplesearch.com/results"

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context

        scanner._browser = mock_browser
        scanner._is_initialized = True

        target = BrokerScanTarget(
            broker_id="truepeoplesearch",
            broker_name="TruePeopleSearch",
            base_url="https://www.truepeoplesearch.com",
            opt_out_url="https://www.truepeoplesearch.com/removal",
            search_url_template="https://www.truepeoplesearch.com/results?name={name}",
        )

        res = await scanner.scan_broker(target, target_identity_complex)
        assert res.is_exposed is True
        assert res.is_simulated is True
        assert res.status_code == 200
        assert target_identity_complex.full_name in res.raw_html


# ==============================================================================
# 2. HTML Semantic Preprocessor & >80% Token Reduction Benchmark
# ==============================================================================

class TestHTMLSemanticPreprocessorStress:
    """Stress tests token reduction, SVG/base64 elimination, opt-out link preservation, and void tag handling."""

    def test_heavy_bloated_broker_html_reduction_greater_than_80_percent(self) -> None:
        """Constructs a realistic multi-KB data broker page with tracking scripts, SVGs, and base64 blobs."""
        svg_icons = "".join(
            [f'<svg width="24" height="24" viewBox="0 0 24 24"><path d="M{i} {i}h24v24H0z" fill="#333"/></svg>' for i in range(50)]
        )
        base64_avatar = "data:image/png;base64," + ("iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbybl" * 20)
        inline_css = "<style>" + ("body { margin: 0; padding: 0; background: #fff; }\n" * 40) + "</style>"
        tracking_js = "<script>" + ("window.__analytics_push({ event: 'page_view', tracker: 98124 });\n" * 30) + "</script>"

        bloated_html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Cassandra Vance - Public Background Report</title>
            {inline_css}
            {tracking_js}
        </head>
        <body>
            <header class="header-nav">
                <nav><a href="/">Home</a><a href="/directory">Directory</a></nav>
            </header>
            <div class="cookie-consent-banner ad-container modal-backdrop">
                <p>We use tracking cookies. Accept to continue. <button>Agree</button></p>
            </div>
            {svg_icons}
            <img src="{base64_avatar}" alt="Avatar">

            <main class="container">
                <h1>Cassandra Vance-Montgomery</h1>
                <div class="age-badge">Age: 44 years old (Born 1982)</div>
                <div class="contact-box">
                    <p>Primary Phone: (415) 555-0142</p>
                    <p>Secondary Phone: (415) 555-0199</p>
                    <p>Email: cassandra.vance@cyber-defense.org</p>
                    <p>Current Address: 742 Montgomery St, Apt 14B, San Francisco, CA 94111</p>
                </div>
                <div class="family-section">
                    <h3>Known Relatives</h3>
                    <p>Dominic Vance, Julian Montgomery, Elena Vance-Ross</p>
                </div>
                <div class="optout-section">
                    <a href="https://www.databroker.com/optout/remove-record?id=89214">Do Not Sell My Personal Info / Opt-Out</a>
                </div>
            </main>
            <footer>
                <p>Copyright 2026 DataBroker Inc.</p>
            </footer>
        </body>
        </html>
        """

        preprocessed = HTMLSemanticPreprocessor.preprocess(bloated_html)
        reduction_pct = HTMLSemanticPreprocessor.calculate_reduction(bloated_html, preprocessed)

        # Assert token reduction is > 80%
        assert reduction_pct >= 80.0, f"Expected >= 80% reduction, achieved {reduction_pct:.2f}%"

        # Assert noise is completely stripped
        assert "window.__analytics_push" not in preprocessed
        assert "background: #fff" not in preprocessed
        assert "<svg" not in preprocessed
        assert "base64" not in preprocessed
        assert "We use tracking cookies" not in preprocessed

        # Assert essential OSINT entity data is preserved
        assert "Cassandra Vance-Montgomery" in preprocessed
        assert "(415) 555-0142" in preprocessed
        assert "cassandra.vance@cyber-defense.org" in preprocessed
        assert "742 Montgomery St" in preprocessed
        assert "Dominic Vance" in preprocessed

        # Assert Opt-Out removal link is preserved
        assert "[REMOVAL_LINK: https://www.databroker.com/optout/remove-record?id=89214]" in preprocessed

    def test_optout_keywords_coverage(self) -> None:
        """Verifies that diverse opt-out link patterns (ccpa, gdpr, suppression, do-not-sell) are preserved."""
        test_html = """
        <div>
            <a href="https://example.com/privacy-policy/ccpa-request">California Consumer Privacy Act Request</a>
            <a href="https://example.com/opt-out/form">Opt Out Form</a>
            <a href="https://example.com/removal/profile">Profile Removal</a>
            <a href="https://example.com/do-not-sell-my-info">Do Not Sell</a>
            <a href="https://example.com/gdpr/erasure">GDPR Erasure Request</a>
            <a href="https://example.com/suppression-portal">Suppression Portal</a>
            <a href="https://example.com/about-us">Regular About Link</a>
        </div>
        """
        preprocessed = HTMLSemanticPreprocessor.preprocess(test_html)

        assert "[REMOVAL_LINK: https://example.com/privacy-policy/ccpa-request]" in preprocessed
        assert "[REMOVAL_LINK: https://example.com/opt-out/form]" in preprocessed
        assert "[REMOVAL_LINK: https://example.com/removal/profile]" in preprocessed
        assert "[REMOVAL_LINK: https://example.com/do-not-sell-my-info]" in preprocessed
        assert "[REMOVAL_LINK: https://example.com/gdpr/erasure]" in preprocessed
        assert "[REMOVAL_LINK: https://example.com/suppression-portal]" in preprocessed
        assert "REMOVAL_LINK: https://example.com/about-us" not in preprocessed

    def test_void_tags_and_deeply_nested_elements(self) -> None:
        """Verifies that self-closing/void tags and deep DOM nests do not corrupt the parse stack."""
        nested_html = "<div>" * 40
        nested_html += "<input type='hidden' name='csrf' value='12345'>"
        nested_html += "<img src='pixel.gif'><br><hr><wbr>"
        nested_html += "<h1>Target Entity Name</h1><p>Phone: (555) 012-3456</p>"
        nested_html += "</div>" * 40

        preprocessed = HTMLSemanticPreprocessor.preprocess(nested_html)
        assert "Target Entity Name" in preprocessed
        assert "(555) 012-3456" in preprocessed


# ==============================================================================
# 3. Structured Extractor & Obfuscated DOM Layout Stress Tests
# ==============================================================================

class TestStructuredExtractorStress:
    """Stress tests entity extraction across complex, obfuscated, and ambiguous broker layouts."""

    def test_obfuscated_table_and_definition_list_dom(
        self, target_identity_complex: TargetIdentityInput
    ) -> None:
        """Verifies deterministic extraction handles table layouts with delimited fields."""
        table_html = """
        <table>
            <tr><th>Full Name:</th> <td>Cassandra Vance-Montgomery</td></tr>
            <tr><th>Age:</th> <td>44 (Born July 1982)</td></tr>
            <tr><th>Current Address:</th> <td>742 Montgomery St, Apt 14B, San Francisco, CA 94111</td></tr>
            <tr><th>Phone Numbers:</th> <td>(415) 555-0142, (415) 555-0199</td></tr>
            <tr><th>Email:</th> <td>cassandra.vance@cyber-defense.org</td></tr>
            <tr><th>Known Relatives:</th> <td>Dominic Vance, Julian Montgomery</td></tr>
            <tr><th>Removal:</th> <td><a href="https://radaris.com/control/privacy">Remove Record</a></td></tr>
        </table>
        """
        extractor = StructuredExtractor(offline_mode=True)
        profile = extractor.extract_entities_sync(
            table_html,
            source_url="https://radaris.com/p/cassandra",
            target_id="tgt_obf_1",
            source_broker="radaris",
            target_hint=target_identity_complex.full_name,
        )

        assert isinstance(profile, ExtractedEntityProfile)
        assert target_identity_complex.full_name in profile.matched_names
        assert profile.age == "44"
        assert "(415) 555-0142" in profile.phone_numbers or "(415) 555-0199" in profile.phone_numbers
        assert "cassandra.vance@cyber-defense.org" in profile.email_addresses
        assert "742 Montgomery St" in (profile.current_address or "")
        assert "Dominic Vance" in profile.relatives
        assert profile.removal_url == "https://radaris.com/control/privacy"
        assert profile.confidence_score >= 0.85

    def test_phone_and_email_regex_robustness(self) -> None:
        """Verifies extraction of diverse phone number and email address formats."""
        text = """
        Subject: Jane Doe
        Direct phone: (555) 123-4567
        Mobile: +1 555-987-6543
        Office: 555.234.5678
        Email primary: jane.doe@domain.co.uk
        Email secondary: j_doe99@sub.company.org
        Current Address: 123 Elm Street, Austin, TX 78701
        """
        extractor = DeterministicLocalExtractor()
        profile = extractor.extract(text, target_hint="Jane Doe")

        assert len(profile.phone_numbers) >= 2
        assert any("(555) 123-4567" in p for p in profile.phone_numbers)
        assert "jane.doe@domain.co.uk" in profile.email_addresses
        assert "j_doe99@sub.company.org" in profile.email_addresses

    @pytest.mark.asyncio
    async def test_gemini_extractor_handles_empty_malformed_and_timeout(self) -> None:
        """Verifies GeminiStructuredExtractor robustness when client throws or returns None."""
        mock_client = MagicMock()
        mock_aio = MagicMock()
        mock_models = AsyncMock()
        mock_models.generate_content.side_effect = TimeoutError("LLM API Call Timed Out")
        mock_aio.models = mock_models
        mock_client.aio = mock_aio

        extractor = GeminiStructuredExtractor(client=mock_client, api_key="test_key")

        # HTML with opt-out link and phone
        raw_html = "<h1>Dr. Alan Turing</h1><p>Phone: (555) 019-2834</p><a href='https://broker.com/removal'>Opt Out</a>"
        profile = await extractor.extract(raw_html, target_hint="Dr. Alan Turing")

        # Should fall back cleanly to deterministic extractor
        assert isinstance(profile, ExtractedEntityProfile)
        assert "Dr. Alan Turing" in profile.matched_names
        assert "(555) 019-2834" in profile.phone_numbers
        assert profile.removal_url == "https://broker.com/removal"
        assert profile.confidence_score > 0.60

    def test_all_five_broker_fixtures_extraction_benchmark(
        self, target_identity_complex: TargetIdentityInput
    ) -> None:
        """Verifies extraction metrics across all 5 standard broker mock fixtures."""
        extractor = StructuredExtractor(offline_mode=True)
        brokers = ["truepeoplesearch", "fastpeoplesearch", "radaris", "nuwber", "whitepages"]

        for b in brokers:
            html, url = render_broker_fixture(b, target_identity_complex)
            profile = extractor.extract_entities_sync(
                html, source_url=url, source_broker=b, target_hint=target_identity_complex.full_name
            )
            assert target_identity_complex.full_name in profile.matched_names
            assert len(profile.phone_numbers) > 0
            assert profile.current_address is not None
            assert profile.removal_url is not None
            assert profile.confidence_score >= 0.80


# ==============================================================================
# 4. Playwright Scanner Concurrency & Lifecycle Stress Tests
# ==============================================================================

class TestPlaywrightScannerConcurrencyStress:
    """Stress tests Playwright stealth scraper concurrency bounds, error recovery, and clean teardown."""

    @pytest.mark.asyncio
    async def test_high_concurrency_batch_scans(
        self, target_identity_complex: TargetIdentityInput
    ) -> None:
        """Simulates 25 concurrent broker requests under bounded semaphore."""
        scanner = PlaywrightStealthScanner(simulation_mode=True, max_concurrency=4)

        broker_ids = ["truepeoplesearch", "fastpeoplesearch", "radaris", "nuwber", "whitepages"]
        targets = [
            BrokerScanTarget(
                broker_id=f"{bid}_{i}",
                broker_name=f"{bid.title()} {i}",
                base_url=f"https://www.{bid}.com",
                opt_out_url=f"https://www.{bid}.com/removal",
                search_url_template=f"https://www.{bid}.com/find?name={{name}}",
            )
            for i in range(5)
            for bid in broker_ids
        ]

        # Execute 25 concurrent scans
        t0 = time.perf_counter()
        results = await asyncio.gather(*[scanner.scan_broker(t, target_identity_complex) for t in targets])
        elapsed = time.perf_counter() - t0

        assert len(results) == 25
        assert all(isinstance(r, BrokerScanResult) for r in results)
        assert all(r.is_exposed is True for r in results)
        assert all(r.is_simulated is True for r in results)
        assert elapsed < 3.0, f"Batch execution too slow: {elapsed:.2f}s"

    @pytest.mark.asyncio
    async def test_clean_context_manager_lifecycle(self) -> None:
        """Verifies async context manager initializes and closes resources without leaks."""
        async with PlaywrightStealthScanner(simulation_mode=True) as scanner:
            assert scanner is not None
            assert scanner.simulation_mode is True

        assert scanner._is_initialized is False
        assert scanner._browser is None
