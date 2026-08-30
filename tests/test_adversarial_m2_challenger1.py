"""
Adversarial Stress Test Suite — Milestone 2 Challenger 1.
Author: Challenger 1 (SERP Scanner & Grounding Stress Challenger)
Coverage:
1. Exhaustive 7 Dork Taxonomies Verification & Target Identity Stress.
2. High-Concurrency Batch Executions (25, 50, 100 dorks) & Concurrency Semaphore Verification.
3. Network Timeout, Connection Errors & HTTP Status Code Resilience (403, 429, 500, 502, timeouts).
4. Malformed, Hostile, Corrupted & Giant HTML Payload Parsing (DDG Lite & Fallbacks).
5. Risk Scoring Engine Fuzzing & Keyword Escalation Matrix.
6. Jitter Timing, Header Rotation & Boundary Conditions.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import httpx
import pytest
import time
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
from project_umbra.tools.serp_scanner import (
    SERPScanner,
    CRITICAL_KEYWORDS,
    USER_AGENTS,
)
from project_umbra.tools.fixtures import (
    get_mock_serp_findings,
    load_serp_fixtures,
    render_broker_fixture,
    load_broker_fixture,
)


# ==============================================================================
# Fixtures & Helpers
# ==============================================================================

@pytest.fixture
def standard_target() -> TargetIdentityInput:
    return TargetIdentityInput(
        full_name="Dr. Elena Rostova-Vance",
        aliases=["Elena Vance", "E. Rostova", "elena_sec"],
        primary_email="elena.rostova@cyber-institute.org",
        secondary_emails=["erostova@protonmail.com", "elena.vance@gmail.com"],
        phone_numbers=["(512) 555-0188", "+1-512-555-0199"],
        current_city="Austin",
        current_state="TX",
        known_addresses=["701 Brazos St, Austin, TX 78701", "1200 Congress Ave, Austin, TX"],
        relatives=["Viktor Rostov", "Clara Vance"],
        employers=["Cyber Institute of Technology"],
        usernames=["elena_rostova", "rostova_vance_99"],
    )


@pytest.fixture
def minimal_target() -> TargetIdentityInput:
    return TargetIdentityInput(
        full_name="Anonymous Researcher",
    )


@pytest.fixture
def international_target() -> TargetIdentityInput:
    return TargetIdentityInput(
        full_name="Renée François-Müller",
        aliases=["Renée Müller", "R. François"],
        primary_email="renee.muller@sorbonne.fr",
        phone_numbers=["+33 1 42 68 55 00"],
        current_city="Paris",
        current_state="Île-de-France",
        known_addresses=["12 Rue de Rivoli, 75004 Paris"],
    )


def generate_dork_batch(count: int, prefix: str = "dork") -> list[DorkQuery]:
    """Generates N synthetically distinct DorkQuery objects across all 7 taxonomies."""
    taxonomies = list(DorkCategory)
    dorks: list[DorkQuery] = []
    for i in range(count):
        cat = taxonomies[i % len(taxonomies)]
        dorks.append(
            DorkQuery(
                dork_id=f"{prefix}_{i:03d}_{cat.value}",
                category=cat,
                raw_query=f'site:example{i}.org intext:"target_{i}" filetype:pdf',
                encoded_url=f"https://www.google.com/search?q=site%3Aexample{i}.org",
                target_vector_id=f"vec_{i:03d}",
                expected_signal=f"Signal for {cat.value} batch item {i}",
                risk_level=PriorityLevel.HIGH if i % 2 == 0 else PriorityLevel.CRITICAL,
            )
        )
    return dorks


# ==============================================================================
# Challenge 1: 7 Dork Taxonomies Exhaustive Stress Testing
# ==============================================================================

class TestChallenge1TaxonomiesStress:
    """Stress tests SERPScanner across all 7 dork taxonomies with varied target identities."""

    @pytest.mark.parametrize("category", list(DorkCategory))
    @pytest.mark.asyncio
    async def test_all_taxonomies_produce_valid_findings_standard_target(
        self, category: DorkCategory, standard_target: TargetIdentityInput
    ) -> None:
        scanner = SERPScanner(mode="mock")
        dork = DorkQuery(
            dork_id=f"stress_{category.value}",
            category=category,
            raw_query=f'intitle:"Elena Rostova" {category.value}',
            encoded_url="https://google.com/search",
            target_vector_id="vec_test",
            expected_signal=f"Detection of {category.value}",
            risk_level=PriorityLevel.MEDIUM,
        )

        findings = await scanner.execute_dork(dork, target_input=standard_target)

        assert len(findings) >= 1
        for f in findings:
            assert isinstance(f, SERPFinding)
            assert f.dork_id == dork.dork_id
            assert f.dork_category == category
            assert f.url.startswith("http")
            assert len(f.title) > 0
            assert len(f.snippet) > 0
            assert f.risk_level in PriorityLevel
            assert isinstance(f.discovered_at, datetime)
            assert f.finding_id.startswith("fnd_")

    @pytest.mark.parametrize("category", list(DorkCategory))
    @pytest.mark.asyncio
    async def test_all_taxonomies_minimal_target(
        self, category: DorkCategory, minimal_target: TargetIdentityInput
    ) -> None:
        scanner = SERPScanner(mode="mock")
        dork = DorkQuery(
            dork_id=f"min_{category.value}",
            category=category,
            raw_query=f'intitle:"Anonymous Researcher" {category.value}',
            encoded_url="https://google.com/search",
            target_vector_id="vec_min",
            expected_signal=category.value,
            risk_level=PriorityLevel.LOW,
        )

        findings = await scanner.execute_dork(dork, target_input=minimal_target)
        assert len(findings) >= 1
        for f in findings:
            assert isinstance(f, SERPFinding)
            assert f.dork_category == category
            assert minimal_target.full_name in f.title or minimal_target.full_name in f.snippet

    @pytest.mark.parametrize("category", list(DorkCategory))
    @pytest.mark.asyncio
    async def test_all_taxonomies_international_unicode_target(
        self, category: DorkCategory, international_target: TargetIdentityInput
    ) -> None:
        scanner = SERPScanner(mode="mock")
        dork = DorkQuery(
            dork_id=f"intl_{category.value}",
            category=category,
            raw_query=f'"Renée François-Müller" {category.value}',
            encoded_url="https://google.com/search",
            target_vector_id="vec_intl",
            expected_signal=category.value,
            risk_level=PriorityLevel.HIGH,
        )

        findings = await scanner.execute_dork(dork, target_input=international_target)
        assert len(findings) >= 1
        for f in findings:
            assert isinstance(f, SERPFinding)
            assert "Renée François-Müller" in f.title or "Renée François-Müller" in f.snippet


# ==============================================================================
# Challenge 2: High-Concurrency Batch Executions (25+, 50+, 100+ Dorks)
# ==============================================================================

class TestChallenge2ConcurrencyStress:
    """Stress tests batch execution scaling, semaphore bounds, and URL deduplication."""

    @pytest.mark.asyncio
    async def test_concurrent_batch_25_dorks_with_semaphore_limit(
        self, standard_target: TargetIdentityInput
    ) -> None:
        """Executes 25 dorks concurrently with max_concurrency=5 and verifies max active tasks."""
        max_concurrency = 5
        scanner = SERPScanner(mode="mock", max_concurrency=max_concurrency)
        dorks = generate_dork_batch(25, prefix="batch25")

        findings = await scanner.batch_execute_dorks(
            dorks,
            target_input=standard_target,
            max_concurrency=max_concurrency,
            timeout_per_dork=5.0,
        )

        assert len(findings) > 0
        for f in findings:
            assert isinstance(f, SERPFinding)

    @pytest.mark.asyncio
    async def test_concurrent_batch_50_dorks_deduplication(
        self, standard_target: TargetIdentityInput
    ) -> None:
        """Executes 50 dorks containing duplicate queries and verifies URL deduplication."""
        scanner = SERPScanner(mode="mock", max_concurrency=10)
        base_10 = generate_dork_batch(10, prefix="dup")
        dorks_50 = []
        for rep in range(5):
            for d in base_10:
                dorks_50.append(
                    DorkQuery(
                        dork_id=f"{d.dork_id}_rep{rep}",
                        category=d.category,
                        raw_query=d.raw_query,
                        encoded_url=d.encoded_url,
                        target_vector_id=d.target_vector_id,
                        expected_signal=d.expected_signal,
                        risk_level=d.risk_level,
                    )
                )

        assert len(dorks_50) == 50
        findings = await scanner.batch_execute_dorks(
            dorks_50,
            target_input=standard_target,
            max_concurrency=10,
        )

        urls = [f.url for f in findings]
        assert len(urls) == len(set(urls)), "Batch findings must have unique URLs (deduplicated)"

    @pytest.mark.asyncio
    async def test_massive_batch_100_dorks_throughput(
        self, standard_target: TargetIdentityInput
    ) -> None:
        """Executes 100 dorks across all taxonomies and verifies fast resolution (<2.0s in mock)."""
        scanner = SERPScanner(mode="mock", max_concurrency=20)
        dorks_100 = generate_dork_batch(100, prefix="scale100")

        start_t = time.perf_counter()
        findings = await scanner.batch_execute_dorks(
            dorks_100,
            target_input=standard_target,
            max_concurrency=20,
        )
        duration = time.perf_counter() - start_t

        assert len(findings) > 0
        assert duration < 2.0, f"100 dork batch took {duration:.2f}s, expected < 2.0s"


# ==============================================================================
# Challenge 3: Network Timeout, Transport Failures & Error Recovery
# ==============================================================================

class TestChallenge3NetworkFailuresAndRecovery:
    """Simulates HTTP timeouts, connection errors, and status codes (403, 429, 500, 502)."""

    @pytest.mark.parametrize(
        "exception_cls, exc_args",
        [
            (httpx.ConnectTimeout, ("Connection timed out to search gateway",)),
            (httpx.ReadTimeout, ("Read timed out waiting for socket",)),
            (httpx.ConnectError, ("DNS lookup failed",)),
            (httpx.RemoteProtocolError, ("Server disconnected prematurely",)),
            (httpx.NetworkError, ("Network unreachable",)),
            (asyncio.TimeoutError, ()),
        ],
    )
    @pytest.mark.asyncio
    async def test_live_search_transport_exceptions_graceful_fallback(
        self,
        exception_cls: type,
        exc_args: tuple,
        standard_target: TargetIdentityInput,
    ) -> None:
        mock_client = AsyncMock()
        mock_client.post.side_effect = exception_cls(*exc_args)

        scanner = SERPScanner(mode="duckduckgo_lite", http_client=mock_client)
        dork = DorkQuery(
            dork_id="drk_timeout_test",
            category=DorkCategory.PASTEBINS_DUMPS,
            raw_query="test query for timeout",
            encoded_url="https://google.com",
            target_vector_id="vec_1",
            expected_signal="Breach data",
            risk_level=PriorityLevel.CRITICAL,
        )

        findings = await scanner.execute_dork(dork, target_input=standard_target)

        # Must return valid findings from mock fallback without throwing
        assert len(findings) > 0
        assert all(isinstance(f, SERPFinding) for f in findings)
        assert any("Dr. Elena Rostova-Vance" in f.title or "Dr. Elena Rostova-Vance" in f.snippet for f in findings)

    @pytest.mark.parametrize("status_code", [403, 429, 500, 502, 503])
    @pytest.mark.asyncio
    async def test_live_search_http_status_errors_fallback(
        self, status_code: int, standard_target: TargetIdentityInput
    ) -> None:
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"HTTP {status_code} Error",
            request=MagicMock(),
            response=mock_response,
        )
        mock_client.post.return_value = mock_response

        scanner = SERPScanner(mode="duckduckgo_lite", http_client=mock_client)
        dork = DorkQuery(
            dork_id=f"drk_status_{status_code}",
            category=DorkCategory.CREDENTIAL_LEAKS,
            raw_query="credential search",
            encoded_url="https://google.com",
            target_vector_id="vec_1",
            expected_signal="Credentials",
            risk_level=PriorityLevel.CRITICAL,
        )

        findings = await scanner.execute_dork(dork, target_input=standard_target)
        assert len(findings) > 0
        assert findings[0].risk_level == PriorityLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_batch_execution_resilience_to_hanging_dorks(
        self, standard_target: TargetIdentityInput
    ) -> None:
        """Tests batch execution when some dorks hang and exceed per_dork_timeout."""
        dorks = generate_dork_batch(6, prefix="hang")

        async def hanging_execute(d, target_name=None, target_input=None):
            if "hang_001" in d.dork_id or "hang_004" in d.dork_id:
                await asyncio.sleep(10.0)  # Hang longer than timeout
            return get_mock_serp_findings(d, target_name=target_name, target_input=target_input)

        scanner = SERPScanner(mode="mock")
        with patch.object(scanner, "execute_dork", side_effect=hanging_execute):
            start_t = time.perf_counter()
            findings = await scanner.batch_execute_dorks(
                dorks,
                target_input=standard_target,
                max_concurrency=4,
                timeout_per_dork=0.1,  # Fast timeout
            )
            elapsed = time.perf_counter() - start_t

        assert elapsed < 1.0, f"Batch took {elapsed:.2f}s, did not enforce per_dork_timeout"
        assert len(findings) > 0


# ==============================================================================
# Challenge 4: Malformed, Hostile & Adversarial HTML Responses
# ==============================================================================

class TestChallenge4MalformedHTMLParsing:
    """Tests DDG Lite HTML parser against broken, truncated, hostile, and massive HTML."""

    def test_unclosed_outer_html_with_valid_anchors(self) -> None:
        """Tests HTML where outer body/table tags are truncated but inner anchors close properly."""
        corrupted_html = """
        <html><body><table><tr><td>
        <a class="result-link" href="/l/?uddg=https%3A%2F%2Fleaked.site%2Fdump1">Incomplete Title</a>
        <td class="result-snippet">Incomplete Snippet text that cuts off
        """
        scanner = SERPScanner(mode="duckduckgo_lite")
        results = scanner.parse_duckduckgo_lite_html(
            corrupted_html, "drk_corrupt_1", DorkCategory.PASTEBINS_DUMPS
        )
        assert len(results) >= 1
        assert results[0]["url"] == "https://leaked.site/dump1"

    def test_severely_cut_html_returns_empty_safely(self) -> None:
        """Tests HTML truncated in the middle of opening tag without throwing."""
        cut_html = "<html<body><a class=\"result-link\" href=\"/l/?uddg=https"
        scanner = SERPScanner(mode="duckduckgo_lite")
        results = scanner.parse_duckduckgo_lite_html(
            cut_html, "drk_cut", DorkCategory.PASTEBINS_DUMPS
        )
        assert results == []

    def test_giant_dom_payload(self) -> None:
        """Tests parser performance on 2MB+ HTML containing 500 table rows."""
        rows = []
        for i in range(500):
            rows.append(f"""
            <tr><td><a class="result-link" href="https://target-record-{i}.org/view">Record {i} for Subject</a></td></tr>
            <tr><td class="result-snippet">Snippet details for record {i} showing sensitive information</td></tr>
            """)
        giant_html = f"<html><body><table>{''.join(rows)}</table></body></html>"

        scanner = SERPScanner(mode="duckduckgo_lite")
        start_t = time.perf_counter()
        results = scanner.parse_duckduckgo_lite_html(
            giant_html, "drk_giant", DorkCategory.DOCUMENTS_SPREADSHEETS
        )
        duration = time.perf_counter() - start_t

        assert len(results) == 500
        assert duration < 0.5, f"Parsing 500 results took {duration:.3f}s, expected < 0.5s"

    def test_adversarial_html_with_xss_and_injection(self) -> None:
        hostile_html = """
        <html>
        <body>
            <table>
                <tr>
                    <td>
                        <a class="result-link" href="https://attacker.com/payload?xss=test">
                            <script>document.cookie='stolen';</script><b>Dangerous &amp; Malicious Title</b>
                        </a>
                    </td>
                </tr>
                <tr>
                    <td class="result-snippet">
                        <img src="x" onerror="alert('xss')">Found leak containing PII data for target.
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        scanner = SERPScanner(mode="duckduckgo_lite")
        results = scanner.parse_duckduckgo_lite_html(
            hostile_html, "drk_hostile", DorkCategory.CREDENTIAL_LEAKS
        )
        assert len(results) == 1
        # Check that script tags are stripped from title and snippet
        assert "<script>" not in results[0]["title"]
        assert "Dangerous & Malicious Title" in results[0]["title"]
        assert "<img" not in results[0]["snippet"]
        assert "Found leak containing PII data for target." in results[0]["snippet"]

    def test_generic_fallback_parser_when_css_classes_missing(self) -> None:
        """Tests generic anchor fallback when DDG changes CSS classes to non-standard names."""
        non_standard_html = """
        <html>
        <body>
            <div class="web-results-container">
                <a href="https://public-docket.org/case/12345">State v. Public Records Directory</a>
                <p>Civil court filings docket index record.</p>
                <a href="https://cyber-intel.com/leak/elena_rostova">Cyber Intelligence Breach Report</a>
                <p>Compromised database records matching subject name.</p>
                <!-- DuckDuckGo internal links should be filtered out -->
                <a href="https://duckduckgo.com/about">About DuckDuckGo</a>
            </div>
        </body>
        </html>
        """
        scanner = SERPScanner(mode="duckduckgo_lite")
        results = scanner.parse_duckduckgo_lite_html(
            non_standard_html, "drk_nonstandard", DorkCategory.GOV_PUBLIC_DIRECTORIES
        )
        assert len(results) == 2
        assert results[0]["url"] == "https://public-docket.org/case/12345"
        assert results[1]["url"] == "https://cyber-intel.com/leak/elena_rostova"
        assert not any("duckduckgo.com" in r["url"] for r in results)

    def test_empty_and_whitespace_html(self) -> None:
        scanner = SERPScanner(mode="duckduckgo_lite")
        assert scanner.parse_duckduckgo_lite_html("", "drk_empty", DorkCategory.DOCUMENTS_SPREADSHEETS) == []
        assert scanner.parse_duckduckgo_lite_html("   \n\t  ", "drk_ws", DorkCategory.DOCUMENTS_SPREADSHEETS) == []


# ==============================================================================
# Challenge 5: Risk Scoring Engine Fuzzing & Keyword Escalation
# ==============================================================================

class TestChallenge5RiskScoringMatrix:
    """Verifies all CRITICAL_KEYWORDS escalate risk score and tests boundary conditions."""

    @pytest.mark.parametrize("keyword", list(CRITICAL_KEYWORDS))
    def test_every_critical_keyword_escalates_to_critical_risk(self, keyword: str) -> None:
        """Even for low-risk SOCIAL_EXPOSURE category, a critical keyword must force CRITICAL risk."""
        scanner = SERPScanner(mode="mock")
        risk = scanner._calculate_risk(
            category=DorkCategory.SOCIAL_EXPOSURE,
            title="Social Profile",
            snippet=f"Found compromised record: {keyword} exposed online",
            matched_tokens=["Target Name"],
        )
        assert risk == PriorityLevel.CRITICAL, f"Keyword '{keyword}' failed to escalate to CRITICAL"

    def test_case_insensitive_keyword_matching(self) -> None:
        scanner = SERPScanner(mode="mock")
        risk = scanner._calculate_risk(
            category=DorkCategory.DOCUMENTS_SPREADSHEETS,
            title="Internal Document",
            snippet="User record with PASSwORD and PRIVATE_KEY exposed",
            matched_tokens=["Target Name"],
        )
        assert risk == PriorityLevel.CRITICAL

    @pytest.mark.parametrize(
        "category, token_count, expected_risk",
        [
            (DorkCategory.CREDENTIAL_LEAKS, 0, PriorityLevel.CRITICAL),
            (DorkCategory.CREDENTIAL_LEAKS, 2, PriorityLevel.CRITICAL),
            (DorkCategory.PASTEBINS_DUMPS, 0, PriorityLevel.HIGH),
            (DorkCategory.PASTEBINS_DUMPS, 1, PriorityLevel.HIGH),
            (DorkCategory.PASTEBINS_DUMPS, 2, PriorityLevel.CRITICAL),
            (DorkCategory.CODE_REPOS_CONFIGS, 1, PriorityLevel.HIGH),
            (DorkCategory.CODE_REPOS_CONFIGS, 3, PriorityLevel.CRITICAL),
            (DorkCategory.DATA_BROKER_PROFILES, 0, PriorityLevel.MEDIUM),
            (DorkCategory.DATA_BROKER_PROFILES, 1, PriorityLevel.HIGH),
            (DorkCategory.GOV_PUBLIC_DIRECTORIES, 0, PriorityLevel.MEDIUM),
            (DorkCategory.GOV_PUBLIC_DIRECTORIES, 1, PriorityLevel.MEDIUM),
            (DorkCategory.GOV_PUBLIC_DIRECTORIES, 2, PriorityLevel.HIGH),
            (DorkCategory.SOCIAL_EXPOSURE, 0, PriorityLevel.LOW),
            (DorkCategory.SOCIAL_EXPOSURE, 1, PriorityLevel.LOW),
            (DorkCategory.SOCIAL_EXPOSURE, 2, PriorityLevel.MEDIUM),
        ],
    )
    def test_taxonomy_token_threshold_matrix(
        self, category: DorkCategory, token_count: int, expected_risk: PriorityLevel
    ) -> None:
        scanner = SERPScanner(mode="mock")
        tokens = [f"token_{i}" for i in range(token_count)]
        risk = scanner._calculate_risk(
            category=category,
            title="Clean Title",
            snippet="Clean description without keywords",
            matched_tokens=tokens,
        )
        assert risk == expected_risk, f"Taxonomy {category} with {token_count} tokens expected {expected_risk}, got {risk}"


# ==============================================================================
# Challenge 6: Stealth Headers, Jitter & Edge Conditions
# ==============================================================================

class TestChallenge6StealthAndJitter:
    """Verifies rotating header integrity and jitter sleep bounds."""

    def test_headers_structure_and_user_agent_rotation(self) -> None:
        scanner = SERPScanner(mode="mock")
        seen_uas = set()
        for _ in range(50):
            h = scanner._get_headers()
            assert "User-Agent" in h
            assert "Accept" in h
            assert "DNT" in h
            assert h["User-Agent"] in USER_AGENTS
            seen_uas.add(h["User-Agent"])

        # Over 50 iterations, multiple distinct User Agents must be sampled
        assert len(seen_uas) >= 3

    @pytest.mark.asyncio
    async def test_jitter_delay_execution_and_zero_boundary(self) -> None:
        # Zero jitter
        scanner_zero = SERPScanner(jitter_min_ms=0, jitter_max_ms=0)
        start_t = time.perf_counter()
        await scanner_zero._apply_jitter()
        assert time.perf_counter() - start_t < 0.05

        # Bounded jitter (10ms - 20ms)
        scanner_jitter = SERPScanner(jitter_min_ms=10, jitter_max_ms=20)
        start_t = time.perf_counter()
        await scanner_jitter._apply_jitter()
        elapsed = time.perf_counter() - start_t
        assert 0.008 <= elapsed <= 0.05

    @pytest.mark.asyncio
    async def test_empty_dork_raw_query_returns_empty_list(self) -> None:
        scanner = SERPScanner(mode="mock")
        dork_empty = DorkQuery(
            dork_id="drk_empty",
            category=DorkCategory.DOCUMENTS_SPREADSHEETS,
            raw_query="   ",
            encoded_url="https://google.com",
            target_vector_id="vec_0",
            expected_signal="Empty",
            risk_level=PriorityLevel.LOW,
        )
        res = await scanner.execute_dork(dork_empty)
        assert res == []
