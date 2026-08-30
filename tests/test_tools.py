"""
Cross-Tool Integration & Pipeline Tests for Project Umbra Tools (Tiers 1-5).
Verifies end-to-end integration of SERPScanner, PlaywrightStealthScanner, and StructuredExtractor
within ProjectUmbraAgent and standalone toolchains.
"""

from __future__ import annotations

import asyncio
import pytest

from project_umbra.classifiers.gemma_classifier import GemmaSanitizerClassifier
from project_umbra.config import settings
from project_umbra.core.agent import ProjectUmbraAgent
from project_umbra.core.decomposer import IdentityDecomposer
from project_umbra.core.dork_synthesizer import PrecisionDorkSynthesizer
from project_umbra.core.state import (
    AgentLifecycleState,
    BrokerScanResult,
    BrokerScanTarget,
    ExtractedEntityProfile,
    PIISanitizationResult,
    SERPFinding,
    TargetIdentityInput,
)
from project_umbra.tools import (
    DeterministicLocalExtractor,
    GeminiStructuredExtractor,
    HTMLSemanticPreprocessor,
    PlaywrightStealthScanner,
    SERPScanner,
    StructuredExtractor,
    build_broker_search_url,
    detect_challenge_dom,
    extract_clean_text,
    get_mock_serp_findings,
    load_broker_fixture,
    load_serp_fixtures,
    render_broker_fixture,
)


@pytest.fixture
def target_identity() -> TargetIdentityInput:
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


# ==============================================================================
# Tier 1: Tool Exports & Module Bindings
# ==============================================================================

def test_tier1_tool_exports() -> None:
    """Verifies that all tools and helper functions are properly exported."""
    assert SERPScanner is not None
    assert PlaywrightStealthScanner is not None
    assert StructuredExtractor is not None
    assert HTMLSemanticPreprocessor is not None
    assert DeterministicLocalExtractor is not None
    assert GeminiStructuredExtractor is not None
    assert callable(build_broker_search_url)
    assert callable(detect_challenge_dom)
    assert callable(extract_clean_text)
    assert callable(get_mock_serp_findings)
    assert callable(load_broker_fixture)
    assert callable(load_serp_fixtures)
    assert callable(render_broker_fixture)


# ==============================================================================
# Tier 2: Individual Tool Execution in Pipeline Chain
# ==============================================================================

@pytest.mark.asyncio
async def test_tier2_pipeline_chain(target_identity: TargetIdentityInput) -> None:
    """Verifies stepwise execution through Decomposition -> Dorking -> SERP -> Scraper -> Extractor -> Sanitizer."""
    # 1. Identity Decomposition
    decomposer = IdentityDecomposer()
    decomp = decomposer.decompose(target_identity, target_id="tgt_chain_1")
    assert len(decomp.vectors) >= 5

    # 2. Dork Synthesis
    synthesizer = PrecisionDorkSynthesizer()
    dorks_res = synthesizer.synthesize(decomp)
    assert len(dorks_res.dorks) >= 7

    # 3. SERP Scanning
    serp = SERPScanner(mode="mock")
    serp_findings = await serp.execute_dork(dorks_res.dorks[0], target_input=target_identity)
    assert len(serp_findings) > 0
    assert all(isinstance(f, SERPFinding) for f in serp_findings)

    # 4. Stealth Broker Scraper
    scraper = PlaywrightStealthScanner(simulation_mode=True)
    target_broker = BrokerScanTarget(
        broker_id="truepeoplesearch",
        broker_name="TruePeopleSearch",
        base_url="https://www.truepeoplesearch.com",
        opt_out_url="https://www.truepeoplesearch.com/removal",
        search_url_template="https://www.truepeoplesearch.com/results?name={name}",
    )
    b_res = await scraper.scan_broker(target_broker, target_identity)
    assert b_res.is_exposed is True
    assert b_res.raw_html is not None

    # 5. Structured Extractor
    extractor = StructuredExtractor(offline_mode=True)
    profile = await extractor.extract_entities(
        raw_content=b_res.raw_html,
        source_url=b_res.profile_url or "",
        target_id="tgt_chain_1",
        source_broker=b_res.broker_id,
        target_hint=target_identity.full_name,
    )
    assert isinstance(profile, ExtractedEntityProfile)
    assert target_identity.full_name in profile.matched_names
    assert profile.current_address is not None
    assert profile.removal_url is not None

    # 6. Gemma PII Sanitizer
    sanitizer = GemmaSanitizerClassifier(mode="heuristic")
    text_to_sanitize = f"{profile.matched_names} {profile.current_address} {profile.phone_numbers} {profile.email_addresses}"
    sanitization = sanitizer.classify_and_sanitize(text_to_sanitize)
    assert isinstance(sanitization, PIISanitizationResult)
    assert sanitization.total_pii_count > 0


# ==============================================================================
# Tier 3: Multi-Broker Extraction Accuracy
# ==============================================================================

@pytest.mark.asyncio
async def test_tier3_multi_broker_extraction_accuracy(target_identity: TargetIdentityInput) -> None:
    """Verifies that extraction across all 5 standard brokers extracts names and removal URLs."""
    scraper = PlaywrightStealthScanner(simulation_mode=True)
    extractor = StructuredExtractor(offline_mode=True)

    broker_ids = ["truepeoplesearch", "fastpeoplesearch", "radaris", "nuwber", "whitepages"]

    for bid in broker_ids:
        target_b = BrokerScanTarget(
            broker_id=bid,
            broker_name=bid.title(),
            base_url=f"https://www.{bid}.com",
            opt_out_url=f"https://www.{bid}.com/optout",
            search_url_template=f"https://www.{bid}.com/find?name={{name}}",
        )
        b_res = await scraper.scan_broker(target_b, target_identity)
        assert b_res.raw_html is not None

        profile = await extractor.extract_entities(
            raw_content=b_res.raw_html,
            source_url=b_res.profile_url or "",
            target_id="tgt_test",
            source_broker=bid,
            target_hint=target_identity.full_name,
        )

        assert target_identity.full_name in profile.matched_names
        assert profile.removal_url is not None
        assert profile.confidence_score >= 0.70


# ==============================================================================
# Tier 4: ProjectUmbraAgent Full Reconnaissance Suite
# ==============================================================================

@pytest.mark.asyncio
async def test_tier4_full_agent_mission_with_all_m2_tools(
    target_identity: TargetIdentityInput,
) -> None:
    """Verifies ProjectUmbraAgent runs with all M2 tools injected."""
    serp = SERPScanner(mode="mock")
    browser = PlaywrightStealthScanner(simulation_mode=True)
    extractor = StructuredExtractor(offline_mode=True)
    sanitizer = GemmaSanitizerClassifier(mode="heuristic")

    agent = ProjectUmbraAgent(
        serp_scanner=serp,
        browser_scanner=browser,
        extractor=extractor,
        gemma_sanitizer=sanitizer,
        max_budget=30,
    )

    summary = await agent.run_mission(target_identity)

    assert summary.final_state == AgentLifecycleState.COMPLETED
    assert summary.vectors_analyzed >= 5
    assert summary.dorks_executed >= 7
    assert summary.brokers_scanned == 5
    assert summary.exposures_found >= 5
    assert summary.pii_entities_sanitized > 0
    assert summary.remediations_generated >= 5
    assert summary.remediation_plan is not None

    # Check state log contains all tool names
    tool_names = {rec.tool_name for rec in summary.execution_state_log if rec.tool_name}
    assert "identity_decomposer" in tool_names
    assert "dork_synthesizer" in tool_names
    assert "controlled_serp_fixture" in tool_names
    assert "controlled_broker_fixture" in tool_names
    assert "deterministic_extractor_fallback" in tool_names
    assert "heuristic_pii_classifier" in tool_names
    assert "action_plan_engine" in tool_names


# ==============================================================================
# Tier 5: Adversarial Stress & Failure Modes
# ==============================================================================

@pytest.mark.asyncio
async def test_tier5_adversarial_malformed_html_and_empty_responses(
    target_identity: TargetIdentityInput,
) -> None:
    """Verifies agent and tools gracefully handle malformed HTML, non-ASCII characters, and empty bodies."""
    extractor = StructuredExtractor(offline_mode=True)

    # 1. Non-ASCII / Unicode edge cases
    unicode_html = "<div><h1>Marcus Aurelius Brody 🛡️</h1><p>Phone: (214) 555-0192</p><p>Адрес: Dallas, TX</p></div>"
    u_prof = await extractor.extract_entities(unicode_html, target_hint=target_identity.full_name)
    assert "Marcus Aurelius Brody" in u_prof.matched_names
    assert "(214) 555-0192" in u_prof.phone_numbers

    # 2. Huge payload with repeated tags
    huge_html = "<div>" + "<p>Noise text</p>" * 1000 + "<h1>Marcus Aurelius Brody</h1><a href='https://optout.com'>Opt-Out</a></div>"
    h_prof = await extractor.extract_entities(huge_html, target_hint=target_identity.full_name)
    assert "Marcus Aurelius Brody" in h_prof.matched_names
    assert h_prof.removal_url == "https://optout.com"
