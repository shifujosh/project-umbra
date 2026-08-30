"""
Tests for Precision Dork Synthesizer Engine (Tiers 1-5).
Verifies 7 taxonomies, operator syntax correctness, length guards, and URL encoding.
"""

from __future__ import annotations

import urllib.parse
import pytest
from project_umbra.core.decomposer import IdentityDecomposer
from project_umbra.core.dork_synthesizer import PrecisionDorkSynthesizer
from project_umbra.core.state import (
    DorkCategory,
    PriorityLevel,
    TargetIdentityInput,
)


@pytest.fixture
def decomposer() -> IdentityDecomposer:
    return IdentityDecomposer()


@pytest.fixture
def synthesizer() -> PrecisionDorkSynthesizer:
    return PrecisionDorkSynthesizer()


# ============================================================================
# Tier 1: Happy-Path Isolation Tests (≥5 Cases)
# ============================================================================

def test_tier1_synthesizes_all_7_taxonomies(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies that all 7 dork categories are synthesized for a complete target."""
    target = TargetIdentityInput(
        full_name="Marcus Aurelius Brody",
        aliases=["Mark Brody"],
        primary_email="mbrody@cyberdefense.org",
        phone_numbers=["(555) 019-2834"],
        current_city="Austin",
        current_state="TX",
        employers=["CyberDefense Inc"],
        usernames=["mbrody_sec"],
    )
    decomp = decomposer.decompose(target)
    result = synthesizer.synthesize(decomp)

    assert result.total_dorks >= 10
    categories = {d.category for d in result.dorks}
    assert DorkCategory.DOCUMENTS_SPREADSHEETS in categories
    assert DorkCategory.PASTEBINS_DUMPS in categories
    assert DorkCategory.CODE_REPOS_CONFIGS in categories
    assert DorkCategory.CREDENTIAL_LEAKS in categories
    assert DorkCategory.GOV_PUBLIC_DIRECTORIES in categories
    assert DorkCategory.DATA_BROKER_PROFILES in categories
    assert DorkCategory.SOCIAL_EXPOSURE in categories


def test_tier1_documents_spreadsheets_dork_syntax(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies documents & spreadsheets dork operators and terms."""
    target = TargetIdentityInput(
        full_name="Alice Vance",
        primary_email="avance@blackmesa.gov",
    )
    decomp = decomposer.decompose(target)
    result = synthesizer.synthesize(decomp)

    doc_dorks = [d for d in result.dorks if d.category == DorkCategory.DOCUMENTS_SPREADSHEETS]
    assert len(doc_dorks) >= 1
    dork = doc_dorks[0]
    assert "filetype:pdf" in dork.raw_query
    assert '"Alice Vance"' in dork.raw_query
    assert "SSN" in dork.raw_query or "confidential" in dork.raw_query


def test_tier1_pastebins_dumps_dork_syntax(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies pastebin site operators and target email inclusion."""
    target = TargetIdentityInput(
        full_name="Gordon Freeman",
        primary_email="gfreeman@blackmesa.gov",
    )
    decomp = decomposer.decompose(target)
    result = synthesizer.synthesize(decomp)

    paste_dorks = [d for d in result.dorks if d.category == DorkCategory.PASTEBINS_DUMPS]
    assert len(paste_dorks) >= 1
    assert any("site:pastebin.com" in d.raw_query for d in paste_dorks)
    assert any('"gfreeman@blackmesa.gov"' in d.raw_query for d in paste_dorks)


def test_tier1_code_repos_dork_syntax(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies github/gitlab search syntax and secret keywords."""
    target = TargetIdentityInput(
        full_name="Dev Target",
        primary_email="dev@startup.io",
        usernames=["devtarget99"],
    )
    decomp = decomposer.decompose(target)
    result = synthesizer.synthesize(decomp)

    code_dorks = [d for d in result.dorks if d.category == DorkCategory.CODE_REPOS_CONFIGS]
    assert len(code_dorks) >= 1
    assert any("site:github.com" in d.raw_query for d in code_dorks)
    assert any("filename:.env" in d.raw_query or "api_key" in d.raw_query for d in code_dorks)


def test_tier1_credential_leaks_dork_syntax(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies intext credential leak operators."""
    target = TargetIdentityInput(
        full_name="Victim User",
        primary_email="victim@leak.com",
    )
    decomp = decomposer.decompose(target)
    result = synthesizer.synthesize(decomp)

    cred_dorks = [d for d in result.dorks if d.category == DorkCategory.CREDENTIAL_LEAKS]
    assert len(cred_dorks) >= 1
    assert any('intext:"victim@leak.com"' in d.raw_query for d in cred_dorks)


# ============================================================================
# Tier 2: Search Operator Syntax & Grammar Compliance (≥5 Cases)
# ============================================================================

def test_tier2_no_space_after_colons(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies that search operators (site:, filetype:, inurl:, intext:) never have trailing whitespace."""
    target = TargetIdentityInput(
        full_name="Jane Doe",
        primary_email="jane@doe.org",
        usernames=["janedoe"],
        current_city="Seattle",
        current_state="WA",
    )
    decomp = decomposer.decompose(target)
    result = synthesizer.synthesize(decomp)

    for dork in result.dorks:
        q = dork.raw_query
        assert "site: " not in q, f"Space found after 'site:' in {q}"
        assert "filetype: " not in q, f"Space found after 'filetype:' in {q}"
        assert "inurl: " not in q, f"Space found after 'inurl:' in {q}"
        assert "intext: " not in q, f"Space found after 'intext:' in {q}"


def test_tier2_boolean_or_capitalization(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies that boolean OR is always capitalized (not lowercase 'or')."""
    target = TargetIdentityInput(
        full_name="Jane Doe",
        primary_email="jane@doe.org",
    )
    decomp = decomposer.decompose(target)
    result = synthesizer.synthesize(decomp)

    for dork in result.dorks:
        tokens = dork.raw_query.split()
        assert "or" not in tokens, f"Lowercase 'or' found in {dork.raw_query}"


def test_tier2_url_encoding_validity(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies encoded_url starts with Google search prefix and decodes back to raw_query."""
    target = TargetIdentityInput(full_name="Jane Doe", primary_email="jane@doe.org")
    decomp = decomposer.decompose(target)
    result = synthesizer.synthesize(decomp)

    for dork in result.dorks:
        assert dork.encoded_url.startswith("https://www.google.com/search?q=")
        query_part = dork.encoded_url.split("https://www.google.com/search?q=", 1)[1]
        decoded = urllib.parse.unquote_plus(query_part)
        assert decoded == dork.raw_query


def test_tier2_query_length_budget_guard(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies all queries satisfy the 2048 character limit."""
    target = TargetIdentityInput(
        full_name="A" * 100 + " B" * 100,
        primary_email="test@longdomain" + "x" * 100 + ".com",
    )
    decomp = decomposer.decompose(target)
    result = synthesizer.synthesize(decomp)

    for dork in result.dorks:
        assert len(dork.raw_query) <= 2048


def test_tier2_priority_sorting(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies dorks are sorted: CRITICAL -> HIGH -> MEDIUM -> LOW."""
    target = TargetIdentityInput(
        full_name="Priority Target",
        primary_email="target@email.com",
        usernames=["targetuser"],
    )
    decomp = decomposer.decompose(target)
    result = synthesizer.synthesize(decomp)

    order = {
        PriorityLevel.CRITICAL: 0,
        PriorityLevel.HIGH: 1,
        PriorityLevel.MEDIUM: 2,
        PriorityLevel.LOW: 3,
    }
    for i in range(len(result.dorks) - 1):
        c_p = order[result.dorks[i].risk_level]
        n_p = order[result.dorks[i + 1].risk_level]
        assert c_p <= n_p


# ============================================================================
# Tier 3: Async & Sync API Equivalence
# ============================================================================

@pytest.mark.asyncio
async def test_tier3_async_sync_equivalence(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies async wrapper returns identical result to sync method."""
    target = TargetIdentityInput(full_name="Alan Turing", primary_email="aturing@bletchley.ac.uk")
    decomp = decomposer.decompose(target)
    res_sync = synthesizer.synthesize_sync(decomp)
    res_async = await synthesizer.synthesize_async(decomp)

    assert res_sync.total_dorks == res_async.total_dorks
    assert [d.dork_id for d in res_sync.dorks] == [d.dork_id for d in res_async.dorks]


# ============================================================================
# Tier 4: Real-World Workload Test
# ============================================================================

def test_tier4_broker_dork_generation(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies generation of people search broker dorks with location coordinates."""
    target = TargetIdentityInput(
        full_name="Sarah Connor",
        current_city="Los Angeles",
        current_state="CA",
        phone_numbers=["213-555-0199"],
    )
    decomp = decomposer.decompose(target)
    result = synthesizer.synthesize(decomp)

    broker_dorks = [d for d in result.dorks if d.category == DorkCategory.DATA_BROKER_PROFILES]
    assert len(broker_dorks) >= 2
    assert any("truepeoplesearch.com" in d.raw_query for d in broker_dorks)
    assert any("213-555-0199" in d.raw_query for d in broker_dorks)


# ============================================================================
# Tier 5: Adversarial Inputs
# ============================================================================

def test_tier5_adversarial_quotes_handling(
    decomposer: IdentityDecomposer, synthesizer: PrecisionDorkSynthesizer
) -> None:
    """Verifies safe handling of quotation marks in raw target names."""
    target = TargetIdentityInput(
        full_name='Robert "Bob" O\'Connor',
        primary_email='bob"test"@email.com',
    )
    decomp = decomposer.decompose(target)
    result = synthesizer.synthesize(decomp)

    assert result.total_dorks > 0
    for d in result.dorks:
        assert d.dork_id.startswith("drk_")
        assert d.encoded_url.startswith("https://www.google.com/search?q=")
