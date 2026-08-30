"""
Tests for Identity Decomposition Engine (Tiers 1-5).
Verifies normalization, 5 vector categories, permutations, priority sorting, and edge cases.
"""

from __future__ import annotations

import pytest
from project_umbra.core.decomposer import IdentityDecomposer, PhoneFormats
from project_umbra.core.state import (
    PriorityLevel,
    TargetIdentityInput,
    VectorCategory,
)


@pytest.fixture
def decomposer() -> IdentityDecomposer:
    return IdentityDecomposer()


# ============================================================================
# Tier 1: Happy-Path Isolation Tests (≥5 Cases)
# ============================================================================

def test_tier1_decomposition_all_vector_categories(decomposer: IdentityDecomposer) -> None:
    """Verifies that all 5 vector categories are produced for a rich input."""
    target = TargetIdentityInput(
        full_name="Joshua Alan Smith",
        aliases=["Josh Smith"],
        primary_email="joshua.smith@examplecorp.io",
        secondary_emails=["jsmith99@gmail.com"],
        phone_numbers=["(555) 234-5678"],
        current_city="Austin",
        current_state="TX",
        known_addresses=["123 Main St, Apt 4B"],
        relatives=["Sarah Smith"],
        employers=["Acme Cyber"],
        usernames=["joshsec"],
    )
    result = decomposer.decompose(target)

    assert result.target_id is not None
    assert result.total_vectors > 10
    categories = {v.category for v in result.vectors}
    assert VectorCategory.DIRECT_IDENTIFIER in categories
    assert VectorCategory.DIGITAL_FOOTPRINT in categories
    assert VectorCategory.RELATIONAL_AFFILIATION in categories
    assert VectorCategory.GEOGRAPHIC_PHYSICAL in categories
    assert VectorCategory.BREACH_CREDENTIAL in categories


def test_tier1_phone_normalization_formats() -> None:
    """Verifies phone normalization into E.164, national hyphenated, parens, and dotted."""
    p1 = PhoneFormats("(555) 123-4567")
    assert p1.e164 == "+15551234567"
    assert p1.national_hyphenated == "555-123-4567"
    assert p1.national_parens == "(555) 123-4567"
    assert p1.national_dotted == "555.123.4567"

    p2 = PhoneFormats("+1-555-987-6543")
    assert p2.e164 == "+15559876543"
    assert p2.national_hyphenated == "555-987-6543"


def test_tier1_name_permutations(decomposer: IdentityDecomposer) -> None:
    """Verifies generation of name permutations and prefix/suffix stripping."""
    name_info = decomposer.normalize_name("Dr. Joshua Alan Smith Jr.")
    assert name_info["clean_name"] == "Joshua Alan Smith"
    assert name_info["first_name"] == "Joshua"
    assert name_info["last_name"] == "Smith"
    assert "Joshua Alan Smith" in name_info["permutations"]
    assert "Joshua Smith" in name_info["permutations"]
    assert "Smith, Joshua" in name_info["permutations"]
    assert "J. Smith" in name_info["permutations"]


def test_tier1_email_decomposition(decomposer: IdentityDecomposer) -> None:
    """Verifies consumer vs custom domain tagging and handle extraction."""
    res_gmail = decomposer.normalize_email("joshua.smith+newsletter@gmail.com")
    assert res_gmail["clean_email"] == "joshua.smith+newsletter@gmail.com"
    assert res_gmail["handle"] == "joshua.smith+newsletter"
    assert res_gmail["base_handle"] == "joshua.smith"
    assert res_gmail["domain"] == "gmail.com"
    assert res_gmail["is_consumer"] is True

    res_custom = decomposer.normalize_email("target@redacted-corp.com")
    assert res_custom["domain"] == "redacted-corp.com"
    assert res_custom["is_consumer"] is False


def test_tier1_address_normalization(decomposer: IdentityDecomposer) -> None:
    """Verifies street abbreviation expansion."""
    norm = decomposer.normalize_address("456 Elm St., Apt. 2A")
    assert "Street" in norm
    assert "Apt" in norm


# ============================================================================
# Tier 2: Boundary & Edge Case Tests (≥5 Cases)
# ============================================================================

def test_tier2_minimal_identity(decomposer: IdentityDecomposer) -> None:
    """Verifies behavior when only a full name is provided."""
    target = TargetIdentityInput(full_name="Jane Doe")
    result = decomposer.decompose(target)

    assert result.total_vectors >= 1
    assert result.vectors[0].query_term == "Jane Doe"
    assert result.vectors[0].priority == PriorityLevel.CRITICAL


def test_tier2_whitespace_and_casing(decomposer: IdentityDecomposer) -> None:
    """Verifies handling of messy whitespace and mixed casing."""
    target = TargetIdentityInput(
        full_name="   Alice   M.   Vanderbilt   ",
        primary_email="  ALICE@DOMAIN.COM  ",
        phone_numbers=[" 555.333.2222 "],
        current_state="texas",
    )
    result = decomposer.decompose(target)

    email_vec = next(v for v in result.vectors if "@" in v.query_term)
    assert email_vec.query_term == "alice@domain.com"
    state_vec = next((v for v in result.vectors if "TX" in v.query_term or "Texas" in v.query_term), None)
    assert state_vec is not None


def test_tier2_international_phone_number() -> None:
    """Verifies handling of non-US international phone numbers."""
    p = PhoneFormats("+44 20 7123 4567")
    assert p.e164 == "+442071234567"


def test_tier2_duplicate_vectors_prevention(decomposer: IdentityDecomposer) -> None:
    """Verifies that duplicated terms across fields do not produce redundant vectors."""
    target = TargetIdentityInput(
        full_name="John Doe",
        aliases=["John Doe", "john doe"],
        primary_email="johndoe@gmail.com",
        secondary_emails=["johndoe@gmail.com"],
    )
    result = decomposer.decompose(target)

    seen = set()
    for v in result.vectors:
        key = (v.category, v.query_term.lower())
        assert key not in seen, f"Duplicate vector found: {key}"
        seen.add(key)


def test_tier2_state_resolution(decomposer: IdentityDecomposer) -> None:
    """Verifies bidirectional state code and full name resolution."""
    code, full = decomposer.resolve_state("California")
    assert code == "CA"
    assert full == "California"

    code2, full2 = decomposer.resolve_state("ny")
    assert code2 == "NY"
    assert full2 == "New York"


# ============================================================================
# Tier 3: Priority Sorting & Determinism Tests
# ============================================================================

def test_tier3_priority_sorting_order(decomposer: IdentityDecomposer) -> None:
    """Verifies that vectors are strictly sorted: CRITICAL -> HIGH -> MEDIUM -> LOW."""
    target = TargetIdentityInput(
        full_name="Robert Vance",
        primary_email="rvance@vancerefrigeration.com",
        phone_numbers=["(555) 555-5555"],
        relatives=["Phyllis Lapin-Vance"],
    )
    result = decomposer.decompose(target)

    priority_map = {
        PriorityLevel.CRITICAL: 0,
        PriorityLevel.HIGH: 1,
        PriorityLevel.MEDIUM: 2,
        PriorityLevel.LOW: 3,
    }
    for i in range(len(result.vectors) - 1):
        curr_p = priority_map[result.vectors[i].priority]
        next_p = priority_map[result.vectors[i + 1].priority]
        assert curr_p <= next_p, f"Sorting violation at index {i}: {result.vectors[i].priority} vs {result.vectors[i+1].priority}"


def test_tier3_target_id_determinism(decomposer: IdentityDecomposer) -> None:
    """Verifies target_id is 100% deterministic across multiple runs."""
    t1 = TargetIdentityInput(full_name="Gordon Freeman", primary_email="gfreeman@blackmesa.gov")
    t2 = TargetIdentityInput(full_name="Gordon Freeman", primary_email="gfreeman@blackmesa.gov")
    assert decomposer.compute_target_id(t1) == decomposer.compute_target_id(t2)


# ============================================================================
# Tier 4: Real-World Workload Test
# ============================================================================

def test_tier4_executive_real_world_identity(decomposer: IdentityDecomposer) -> None:
    """Verifies complete decomposition for a realistic C-level executive persona."""
    executive = TargetIdentityInput(
        full_name="Elena Rostova-Davenport",
        aliases=["Elena Davenport", "E. Rostova"],
        primary_email="elena.davenport@quantum-fintech.io",
        secondary_emails=["elena_r@icloud.com"],
        phone_numbers=["+1 (415) 890-1234", "415.555.0192"],
        current_city="San Francisco",
        current_state="CA",
        known_addresses=["100 Montgomery St, Suite 2200", "742 Evergreen Terr"],
        relatives=["Alexander Davenport", "Mikhail Rostov"],
        employers=["Quantum FinTech Corp", "Goldman Sachs"],
        usernames=["erostova", "elenad_sec"],
    )
    res = decomposer.decompose(executive)

    assert res.total_vectors >= 15
    critical_vectors = [v for v in res.vectors if v.priority == PriorityLevel.CRITICAL]
    assert len(critical_vectors) >= 2  # Primary name and primary email
    breach_vectors = [v for v in res.vectors if v.category == VectorCategory.BREACH_CREDENTIAL]
    assert len(breach_vectors) >= 3


# ============================================================================
# Tier 5: Adversarial Inputs
# ============================================================================

def test_tier5_adversarial_special_chars(decomposer: IdentityDecomposer) -> None:
    """Verifies safe handling of SQL/command injection payloads in fields."""
    adversarial = TargetIdentityInput(
        full_name="John'; DROP TABLE users;--",
        primary_email="victim<script>alert(1)</script>@test.com",
        usernames=["../../../etc/passwd"],
    )
    res = decomposer.decompose(adversarial)
    assert res.total_vectors > 0
    for v in res.vectors:
        assert v.vector_id.startswith("vec_")
