"""
Project Umbra Identity Decomposition Engine.
Decomposes raw TargetIdentityInput into multi-dimensional InvestigativeVector objects.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from project_umbra.core.state import (
    IdentityDecompositionResult,
    InvestigativeVector,
    PriorityLevel,
    TargetIdentityInput,
    VectorCategory,
)

# Standard 2-way US State lookup table
US_STATES: dict[str, str] = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California",
    "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware", "FL": "Florida", "GA": "Georgia",
    "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois", "IN": "Indiana", "IA": "Iowa",
    "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine", "MD": "Maryland",
    "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi", "MO": "Missouri",
    "MT": "Montana", "NE": "Nebraska", "NV": "Nevada", "NH": "New Hampshire", "NJ": "New Jersey",
    "NM": "New Mexico", "NY": "New York", "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio",
    "OK": "Oklahoma", "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina",
    "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas", "UT": "Utah", "VT": "Vermont",
    "VA": "Virginia", "WA": "Washington", "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming",
    "DC": "District of Columbia",
}
STATE_NAME_TO_CODE: dict[str, str] = {v.lower(): k for k, v in US_STATES.items()}

CONSUMER_EMAIL_DOMAINS: set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
    "proton.me", "protonmail.com", "aol.com", "mail.com", "zoho.com",
    "live.com", "msn.com", "comcast.net", "sbcglobal.net",
}

STREET_ABBREVIATIONS: dict[str, str] = {
    r"\bst\.?\b": "Street",
    r"\bave\.?\b": "Avenue",
    r"\bblvd\.?\b": "Boulevard",
    r"\brd\.?\b": "Road",
    r"\bdr\.?\b": "Drive",
    r"\bln\.?\b": "Lane",
    r"\bct\.?\b": "Court",
    r"\bpl\.?\b": "Place",
    r"\bapt\.?\b": "Apt",
    r"\bste\.?\b": "Suite",
    r"\bpkwy\.?\b": "Parkway",
}

HONORIFICS_REGEX = re.compile(r"^(mr|mrs|ms|miss|dr|prof|rev|hon)\.?\s+", re.IGNORECASE)
SUFFIXES_REGEX = re.compile(r"(?:,\s*|\s+)(jr|sr|ii|iii|iv|v|esq|md|phd|ph\.d\.|dds)\.?$", re.IGNORECASE)


class PhoneFormats:
    """Parses and normalizes raw phone strings into standard representations."""

    def __init__(self, raw: str) -> None:
        self.raw = raw.strip()
        self.digits_only = re.sub(r"[^\d]", "", self.raw)
        self.e164: str | None = None
        self.national_hyphenated: str | None = None
        self.national_parens: str | None = None
        self.national_dotted: str | None = None

        if len(self.digits_only) == 10:
            area, prefix, line = self.digits_only[:3], self.digits_only[3:6], self.digits_only[6:]
            self.e164 = f"+1{self.digits_only}"
            self.national_hyphenated = f"{area}-{prefix}-{line}"
            self.national_parens = f"({area}) {prefix}-{line}"
            self.national_dotted = f"{area}.{prefix}.{line}"
        elif len(self.digits_only) == 11 and self.digits_only.startswith("1"):
            area, prefix, line = self.digits_only[1:4], self.digits_only[4:7], self.digits_only[7:]
            self.e164 = f"+{self.digits_only}"
            self.national_hyphenated = f"{area}-{prefix}-{line}"
            self.national_parens = f"({area}) {prefix}-{line}"
            self.national_dotted = f"{area}.{prefix}.{line}"
        elif len(self.digits_only) > 6:
            # International or non-standard fallback
            if self.raw.startswith("+"):
                self.e164 = f"+{self.digits_only}"
            else:
                self.e164 = f"+{self.digits_only}"
            self.national_hyphenated = self.digits_only


class IdentityDecomposer:
    """
    Decomposes raw TargetIdentityInput into a deduplicated, weighted,
    and categorized list of InvestigativeVector instances.
    """

    def __init__(self) -> None:
        pass

    def compute_target_id(self, target: TargetIdentityInput) -> str:
        """Generates a deterministic 16-character hex hash for the target."""
        seed = f"{target.full_name.lower().strip()}:{target.primary_email or ''}:{','.join(target.phone_numbers)}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]

    def _create_vector_id(self, target_id: str, category: VectorCategory, term: str) -> str:
        """Generates a deterministic vector ID."""
        seed = f"{target_id}:{category.value}:{term.lower().strip()}"
        return f"vec_{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12]}"

    def normalize_name(self, raw_name: str) -> dict[str, Any]:
        """Strips honorifics, suffixes, and produces permutation list."""
        name = raw_name.strip()
        name = HONORIFICS_REGEX.sub("", name).strip()
        name = SUFFIXES_REGEX.sub("", name).strip()

        parts = name.split()
        first_name = parts[0] if parts else ""
        last_name = parts[-1] if len(parts) > 1 else ""
        middle_names = parts[1:-1] if len(parts) > 2 else []

        permutations: list[str] = [name]
        if first_name and last_name:
            permutations.append(f"{first_name} {last_name}")
            permutations.append(f"{last_name}, {first_name}")
            if middle_names:
                permutations.append(f"{first_name} {middle_names[0][0]}. {last_name}")
            permutations.append(f"{first_name[0]}. {last_name}")

        # Deduplicate while preserving order
        unique_perms: list[str] = list(dict.fromkeys(permutations))

        return {
            "clean_name": name,
            "first_name": first_name,
            "last_name": last_name,
            "middle_names": middle_names,
            "permutations": unique_perms,
        }

    def normalize_email(self, email: str) -> dict[str, str | bool]:
        """Extracts username, domain, base handle, and custom domain flag."""
        clean_email = email.strip().lower()
        handle, domain = clean_email.split("@", 1) if "@" in clean_email else (clean_email, "")
        base_handle = handle.split("+")[0]
        is_consumer = domain in CONSUMER_EMAIL_DOMAINS
        return {
            "clean_email": clean_email,
            "handle": handle,
            "base_handle": base_handle,
            "domain": domain,
            "is_consumer": is_consumer,
        }

    def normalize_address(self, raw_address: str) -> str:
        """Normalizes common street abbreviations."""
        addr = raw_address.strip()
        for pattern, replacement in STREET_ABBREVIATIONS.items():
            addr = re.sub(pattern, replacement, addr, flags=re.IGNORECASE)
        return addr

    def resolve_state(self, state_input: str | None) -> tuple[str | None, str | None]:
        """Returns (2-letter code, full state name) if found."""
        if not state_input:
            return None, None
        s = state_input.strip()
        if len(s) == 2 and s.upper() in US_STATES:
            return s.upper(), US_STATES[s.upper()]
        s_lower = s.lower()
        if s_lower in STATE_NAME_TO_CODE:
            code = STATE_NAME_TO_CODE[s_lower]
            return code, US_STATES[code]
        return s, s

    def decompose(self, target: TargetIdentityInput, target_id: str | None = None) -> IdentityDecompositionResult:
        """Main decomposition entrypoint (sync)."""
        resolved_target_id = target_id or self.compute_target_id(target)
        vectors: list[InvestigativeVector] = []
        seen_terms: set[tuple[VectorCategory, str]] = set()

        def add_vec(
            category: VectorCategory,
            query_term: str,
            weight: float,
            priority: PriorityLevel,
            rationale: str,
            meta: dict[str, Any] | None = None,
        ) -> None:
            clean_term = query_term.strip()
            if not clean_term:
                return
            key = (category, clean_term.lower())
            if key in seen_terms:
                return
            seen_terms.add(key)
            vec_id = self._create_vector_id(resolved_target_id, category, clean_term)
            vectors.append(
                InvestigativeVector(
                    vector_id=vec_id,
                    category=category,
                    query_term=clean_term,
                    weight=weight,
                    priority=priority,
                    rationale=rationale,
                    metadata=meta or {},
                )
            )

        # 1. DIRECT_IDENTIFIER
        name_info = self.normalize_name(target.full_name)
        add_vec(
            VectorCategory.DIRECT_IDENTIFIER,
            name_info["clean_name"],
            weight=1.0,
            priority=PriorityLevel.CRITICAL,
            rationale="Primary legal name exact match",
            meta={"name_type": "primary_full"},
        )
        for perm in name_info["permutations"][1:]:
            add_vec(
                VectorCategory.DIRECT_IDENTIFIER,
                perm,
                weight=0.9,
                priority=PriorityLevel.HIGH,
                rationale="Standard name permutation",
                meta={"name_type": "permutation"},
            )

        for alias in target.aliases:
            if alias.strip():
                alias_info = self.normalize_name(alias)
                add_vec(
                    VectorCategory.DIRECT_IDENTIFIER,
                    alias_info["clean_name"],
                    weight=0.85,
                    priority=PriorityLevel.HIGH,
                    rationale="Known alias or alternate name",
                    meta={"name_type": "alias"},
                )

        all_emails: list[tuple[str, bool]] = []
        if target.primary_email:
            all_emails.append((target.primary_email, True))
        for sec in target.secondary_emails:
            all_emails.append((sec, False))

        for email_val, is_primary in all_emails:
            if email_val.strip():
                em_info = self.normalize_email(email_val)
                add_vec(
                    VectorCategory.DIRECT_IDENTIFIER,
                    str(em_info["clean_email"]),
                    weight=1.0 if is_primary else 0.85,
                    priority=PriorityLevel.CRITICAL if is_primary else PriorityLevel.HIGH,
                    rationale=f"{'Primary' if is_primary else 'Secondary'} email exact match",
                    meta={"is_primary": is_primary},
                )
                # Digital footprint from email handle
                if em_info["base_handle"] and len(str(em_info["base_handle"])) >= 3:
                    add_vec(
                        VectorCategory.DIGITAL_FOOTPRINT,
                        str(em_info["base_handle"]),
                        weight=0.80,
                        priority=PriorityLevel.HIGH,
                        rationale="Email handle as digital anchor",
                    )
                # Custom domain
                if not em_info["is_consumer"] and em_info["domain"]:
                    add_vec(
                        VectorCategory.DIGITAL_FOOTPRINT,
                        str(em_info["domain"]),
                        weight=0.75,
                        priority=PriorityLevel.MEDIUM,
                        rationale="Custom or corporate domain associated with target",
                    )
                # Breach credential vector for email
                add_vec(
                    VectorCategory.BREACH_CREDENTIAL,
                    str(em_info["clean_email"]),
                    weight=1.0 if is_primary else 0.90,
                    priority=PriorityLevel.CRITICAL if is_primary else PriorityLevel.HIGH,
                    rationale="Email breach search coordinate",
                )

        # Phone numbers
        for raw_phone in target.phone_numbers:
            if raw_phone.strip():
                p = PhoneFormats(raw_phone)
                if p.e164:
                    add_vec(
                        VectorCategory.DIRECT_IDENTIFIER,
                        p.e164,
                        weight=0.95,
                        priority=PriorityLevel.HIGH,
                        rationale="Phone number in E.164 format",
                    )
                if p.national_hyphenated:
                    add_vec(
                        VectorCategory.DIRECT_IDENTIFIER,
                        p.national_hyphenated,
                        weight=0.95,
                        priority=PriorityLevel.HIGH,
                        rationale="Phone number in national hyphenated format",
                    )
                if p.national_parens:
                    add_vec(
                        VectorCategory.DIRECT_IDENTIFIER,
                        p.national_parens,
                        weight=0.90,
                        priority=PriorityLevel.HIGH,
                        rationale="Phone number in standard parenthesized format",
                    )
                if p.national_hyphenated:
                    add_vec(
                        VectorCategory.BREACH_CREDENTIAL,
                        p.national_hyphenated,
                        weight=0.80,
                        priority=PriorityLevel.HIGH,
                        rationale="Phone number breach search coordinate",
                    )

        # 2. DIGITAL_FOOTPRINT (Usernames)
        for uname in target.usernames:
            clean_u = uname.lstrip("@").strip()
            if clean_u:
                add_vec(
                    VectorCategory.DIGITAL_FOOTPRINT,
                    clean_u,
                    weight=0.85,
                    priority=PriorityLevel.HIGH,
                    rationale="Explicit digital username/handle",
                )
                add_vec(
                    VectorCategory.BREACH_CREDENTIAL,
                    clean_u,
                    weight=0.85,
                    priority=PriorityLevel.HIGH,
                    rationale="Username credential leak search coordinate",
                )

        # 3. RELATIONAL_AFFILIATION
        for rel in target.relatives:
            if rel.strip():
                rel_info = self.normalize_name(rel)
                add_vec(
                    VectorCategory.RELATIONAL_AFFILIATION,
                    rel_info["clean_name"],
                    weight=0.75,
                    priority=PriorityLevel.MEDIUM,
                    rationale="Known relative or co-habitant",
                )
                # Combine target surname with relative if different
                if name_info["last_name"] and rel_info["last_name"] != name_info["last_name"]:
                    add_vec(
                        VectorCategory.RELATIONAL_AFFILIATION,
                        f'"{rel_info["clean_name"]}" "{name_info["last_name"]}"',
                        weight=0.70,
                        priority=PriorityLevel.MEDIUM,
                        rationale="Relative cross-referenced with target surname",
                    )

        for emp in target.employers:
            clean_emp = emp.strip()
            if clean_emp:
                add_vec(
                    VectorCategory.RELATIONAL_AFFILIATION,
                    f'"{name_info["clean_name"]}" "{clean_emp}"',
                    weight=0.80,
                    priority=PriorityLevel.HIGH,
                    rationale="Target name correlated with employer",
                )

        # 4. GEOGRAPHIC_PHYSICAL
        state_code, state_full = self.resolve_state(target.current_state)
        loc_parts: list[str] = []
        if target.current_city and target.current_city.strip():
            loc_parts.append(target.current_city.strip())
        if state_code:
            loc_parts.append(state_code)

        if loc_parts:
            loc_str = " ".join(loc_parts)
            add_vec(
                VectorCategory.GEOGRAPHIC_PHYSICAL,
                f'"{name_info["clean_name"]}" "{loc_str}"',
                weight=0.95,
                priority=PriorityLevel.HIGH,
                rationale="Target name with city/state geographical anchor",
            )
            if state_full and state_full != state_code:
                add_vec(
                    VectorCategory.GEOGRAPHIC_PHYSICAL,
                    f'"{name_info["clean_name"]}" "{target.current_city}" "{state_full}"',
                    weight=0.90,
                    priority=PriorityLevel.HIGH,
                    rationale="Target name with full state name anchor",
                )

        for addr in target.known_addresses:
            if addr.strip():
                norm_addr = self.normalize_address(addr)
                add_vec(
                    VectorCategory.GEOGRAPHIC_PHYSICAL,
                    f'"{name_info["clean_name"]}" "{norm_addr}"',
                    weight=0.85,
                    priority=PriorityLevel.HIGH,
                    rationale="Target name with known street address",
                )
                add_vec(
                    VectorCategory.GEOGRAPHIC_PHYSICAL,
                    norm_addr,
                    weight=0.70,
                    priority=PriorityLevel.MEDIUM,
                    rationale="Known physical street address coordinate",
                )

        # Sort vectors: CRITICAL -> HIGH -> MEDIUM -> LOW, then by weight descending
        priority_order = {
            PriorityLevel.CRITICAL: 0,
            PriorityLevel.HIGH: 1,
            PriorityLevel.MEDIUM: 2,
            PriorityLevel.LOW: 3,
        }
        vectors.sort(key=lambda v: (priority_order[v.priority], -v.weight))

        return IdentityDecompositionResult(
            target_id=resolved_target_id,
            timestamp=datetime.now(timezone.utc),
            raw_input=target,
            vectors=vectors,
            total_vectors=len(vectors),
        )

    async def decompose_async(
        self, target: TargetIdentityInput, target_id: str | None = None
    ) -> IdentityDecompositionResult:
        """Asynchronous wrapper for decomposition."""
        return self.decompose(target, target_id=target_id)

    def decompose_sync(
        self, target: TargetIdentityInput, target_id: str | None = None
    ) -> IdentityDecompositionResult:
        """Explicit synchronous decomposition method."""
        return self.decompose(target, target_id=target_id)
