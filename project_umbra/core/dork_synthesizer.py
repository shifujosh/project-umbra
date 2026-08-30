"""
Project Umbra Precision Dork Synthesizer.
Generates targeted Google search dorks across 7 vulnerability and OSINT taxonomies.
"""

from __future__ import annotations

import hashlib
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from project_umbra.core.decomposer import IdentityDecomposer, PhoneFormats
from project_umbra.core.state import (
    DorkCategory,
    DorkQuery,
    DorkSynthesisResult,
    IdentityDecompositionResult,
    InvestigativeVector,
    PriorityLevel,
    TargetIdentityInput,
    VectorCategory,
)


class PrecisionDorkSynthesizer:
    """
    Synthesizes precision Google search dorks from decomposed identity vectors.
    """

    def __init__(self) -> None:
        pass

    def _create_dork_id(self, target_id: str, category: DorkCategory, query: str) -> str:
        """Generates a deterministic dork ID."""
        seed = f"{target_id}:{category.value}:{query.strip()}"
        return f"drk_{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12]}"

    def _build_dork(
        self,
        target_id: str,
        category: DorkCategory,
        raw_query: str,
        target_vector_id: str,
        expected_signal: str,
        risk_level: PriorityLevel,
    ) -> DorkQuery:
        """Builds a validated and URL-encoded DorkQuery object."""
        clean_query = raw_query.strip()
        encoded_url = f"https://www.google.com/search?q={urllib.parse.quote_plus(clean_query)}"
        dork_id = self._create_dork_id(target_id, category, clean_query)
        return DorkQuery(
            dork_id=dork_id,
            category=category,
            raw_query=clean_query,
            encoded_url=encoded_url,
            target_vector_id=target_vector_id,
            expected_signal=expected_signal,
            risk_level=risk_level,
        )

    def synthesize(
        self,
        decomposition: IdentityDecompositionResult,
    ) -> DorkSynthesisResult:
        """
        Synthesizes precision search dorks across all 7 taxonomies.
        """
        target = decomposition.raw_input
        target_id = decomposition.target_id
        dorks: list[DorkQuery] = []
        seen_queries: set[str] = set()

        def add_dork(
            category: DorkCategory,
            query: str,
            vector_id: str,
            expected_signal: str,
            risk_level: PriorityLevel,
        ) -> None:
            clean_q = query.strip()
            if not clean_q or clean_q in seen_queries:
                return
            # Check maximum query length limit (2048 chars for search engines)
            if len(clean_q) > 2048:
                clean_q = clean_q[:2048]
            seen_queries.add(clean_q)
            dorks.append(
                self._build_dork(
                    target_id=target_id,
                    category=category,
                    raw_query=clean_q,
                    target_vector_id=vector_id,
                    expected_signal=expected_signal,
                    risk_level=risk_level,
                )
            )

        # Extract normalized attributes from decomposition
        name_vec = next(
            (v for v in decomposition.vectors if v.category == VectorCategory.DIRECT_IDENTIFIER and "primary_full" in str(v.metadata)),
            decomposition.vectors[0] if decomposition.vectors else None,
        )
        primary_name = name_vec.query_term if name_vec else target.full_name
        primary_vec_id = name_vec.vector_id if name_vec else "vec_root"

        emails: list[tuple[str, str, bool]] = []
        for v in decomposition.vectors:
            if v.category == VectorCategory.DIRECT_IDENTIFIER and "@" in v.query_term:
                is_pri = bool(v.metadata.get("is_primary", False))
                emails.append((v.query_term, v.vector_id, is_pri))

        phones: list[tuple[str, str]] = []
        for v in decomposition.vectors:
            if v.category == VectorCategory.DIRECT_IDENTIFIER and any(c.isdigit() for c in v.query_term) and "@" not in v.query_term:
                phones.append((v.query_term, v.vector_id))

        usernames: list[tuple[str, str]] = []
        for v in decomposition.vectors:
            if v.category == VectorCategory.DIGITAL_FOOTPRINT and "@" not in v.query_term and "." not in v.query_term:
                usernames.append((v.query_term, v.vector_id))

        location_vec = next(
            (v for v in decomposition.vectors if v.category == VectorCategory.GEOGRAPHIC_PHYSICAL and target.current_city and target.current_city.lower() in v.query_term.lower()),
            None,
        )

        # -------------------------------------------------------------
        # 1. DOCUMENTS & SPREADSHEETS
        # -------------------------------------------------------------
        add_dork(
            DorkCategory.DOCUMENTS_SPREADSHEETS,
            f'"{primary_name}" (filetype:pdf OR filetype:xlsx OR filetype:csv) ("SSN" OR "social security" OR "confidential" OR "DOB" OR "date of birth")',
            primary_vec_id,
            "Exposed sensitive documents containing name and SSN/DOB",
            PriorityLevel.CRITICAL,
        )
        if location_vec:
            add_dork(
                DorkCategory.DOCUMENTS_SPREADSHEETS,
                f'"{primary_name}" "{target.current_city or ""}" filetype:pdf ("resume" OR "curriculum vitae" OR "address" OR "phone")',
                location_vec.vector_id,
                "Exposed resumes or directories with personal contact details",
                PriorityLevel.HIGH,
            )
        for em_val, em_id, is_pri in emails:
            if is_pri:
                add_dork(
                    DorkCategory.DOCUMENTS_SPREADSHEETS,
                    f'"{em_val}" (filetype:pdf OR filetype:xlsx OR filetype:csv OR filetype:docx) ("confidential" OR "internal" OR "restricted")',
                    em_id,
                    "Corporate or private documents leaking primary email",
                    PriorityLevel.HIGH,
                )

        # -------------------------------------------------------------
        # 2. PASTEBINS & DUMPS
        # -------------------------------------------------------------
        for em_val, em_id, is_pri in emails:
            add_dork(
                DorkCategory.PASTEBINS_DUMPS,
                f'(site:pastebin.com OR site:justpaste.it OR site:ghostbin.co OR site:rentry.co OR site:dpaste.org) "{em_val}"',
                em_id,
                f"Raw pastebin exposure for {'primary' if is_pri else 'secondary'} email",
                PriorityLevel.CRITICAL if is_pri else PriorityLevel.HIGH,
            )

        add_dork(
            DorkCategory.PASTEBINS_DUMPS,
            f'(site:pastebin.com OR site:justpaste.it OR site:rentry.co) "{primary_name}" ("password" OR "leak" OR "database" OR "breach")',
            primary_vec_id,
            "Pastebin breach dump containing full legal name",
            PriorityLevel.HIGH,
        )

        for ph_val, ph_id in phones[:2]:
            add_dork(
                DorkCategory.PASTEBINS_DUMPS,
                f'(site:pastebin.com OR site:justpaste.it) "{ph_val}"',
                ph_id,
                "Pastebin leak containing phone number",
                PriorityLevel.HIGH,
            )

        # -------------------------------------------------------------
        # 3. CODE REPOS & CONFIGS
        # -------------------------------------------------------------
        for em_val, em_id, is_pri in emails:
            if is_pri:
                add_dork(
                    DorkCategory.CODE_REPOS_CONFIGS,
                    f'(site:github.com OR site:gitlab.com OR site:bitbucket.org) "{em_val}" ("api_key" OR "password" OR "secret" OR "token" OR "credentials")',
                    em_id,
                    "API keys, secrets, or passwords committed to public git repositories",
                    PriorityLevel.CRITICAL,
                )
                add_dork(
                    DorkCategory.CODE_REPOS_CONFIGS,
                    f'site:gist.github.com "{em_val}"',
                    em_id,
                    "GitHub Gist public notes or snippet leaks",
                    PriorityLevel.MEDIUM,
                )

        for u_val, u_id in usernames:
            add_dork(
                DorkCategory.CODE_REPOS_CONFIGS,
                f'(site:github.com OR site:gitlab.com) "{u_val}" (filename:.env OR filename:credentials OR filename:config.json OR "id_rsa")',
                u_id,
                "Exposed .env, SSH keys, or credential files under username",
                PriorityLevel.HIGH,
            )

        # -------------------------------------------------------------
        # 4. CREDENTIAL LEAKS
        # -------------------------------------------------------------
        for em_val, em_id, is_pri in emails:
            add_dork(
                DorkCategory.CREDENTIAL_LEAKS,
                f'intext:"{em_val}" (intext:"hash" OR intext:"md5" OR intext:"sha256" OR intext:"combo" OR intext:"combolist" OR intext:"stealer")',
                em_id,
                "Password combo lists, stealer logs, or password hash leaks",
                PriorityLevel.CRITICAL if is_pri else PriorityLevel.HIGH,
            )
            add_dork(
                DorkCategory.CREDENTIAL_LEAKS,
                f'intext:"{em_val}" (intext:"pass:" OR intext:"pwd:" OR intext:"password:")',
                em_id,
                "Plaintext password breach dump entries",
                PriorityLevel.CRITICAL if is_pri else PriorityLevel.HIGH,
            )

        for u_val, u_id in usernames:
            add_dork(
                DorkCategory.CREDENTIAL_LEAKS,
                f'intext:"{u_val}" (intext:"breach" OR intext:"dump" OR intext:"combo" OR intext:"stealer logs")',
                u_id,
                "Username-targeted credential dump entries",
                PriorityLevel.HIGH,
            )

        # -------------------------------------------------------------
        # 5. GOV & PUBLIC DIRECTORIES
        # -------------------------------------------------------------
        add_dork(
            DorkCategory.GOV_PUBLIC_DIRECTORIES,
            f'(site:gov OR site:mil) (inurl:directory OR inurl:staff OR inurl:roster) "{primary_name}"',
            primary_vec_id,
            "Government or military staff directory listing",
            PriorityLevel.MEDIUM,
        )
        if target.current_city and target.current_state:
            add_dork(
                DorkCategory.GOV_PUBLIC_DIRECTORIES,
                f'site:gov (inurl:voter OR inurl:assessment OR inurl:parcel) "{primary_name}" "{target.current_city}"',
                primary_vec_id,
                "Municipal voter records or property tax assessment listings",
                PriorityLevel.HIGH,
            )
            add_dork(
                DorkCategory.GOV_PUBLIC_DIRECTORIES,
                f'site:gov "{primary_name}" "{target.current_state}" ("property" OR "deed" OR "tax" OR "court" OR "license")',
                primary_vec_id,
                "State public court records, licenses, or property deed filings",
                PriorityLevel.HIGH,
            )

        # -------------------------------------------------------------
        # 6. DATA BROKER PROFILES
        # -------------------------------------------------------------
        city_state_str = f'"{target.current_city}" "{target.current_state}"' if target.current_city and target.current_state else ""
        add_dork(
            DorkCategory.DATA_BROKER_PROFILES,
            f'(site:truepeoplesearch.com/find/person OR site:fastpeoplesearch.com OR site:radaris.com/p) "{primary_name}" {city_state_str}'.strip(),
            primary_vec_id,
            "Aggregated personal profile on major people search brokers",
            PriorityLevel.HIGH,
        )
        add_dork(
            DorkCategory.DATA_BROKER_PROFILES,
            f'(site:nuwber.com/person OR site:whitepages.com/name OR site:clustrmaps.com/person) "{primary_name}" {target.current_city or ""}'.strip(),
            primary_vec_id,
            "Secondary broker background report and relative linkages",
            PriorityLevel.HIGH,
        )
        for ph_val, ph_id in phones[:2]:
            add_dork(
                DorkCategory.DATA_BROKER_PROFILES,
                f'(site:truepeoplesearch.com OR site:fastpeoplesearch.com OR site:radaris.com) "{ph_val}"',
                ph_id,
                "Reverse phone lookup broker listings",
                PriorityLevel.HIGH,
            )
        for em_val, em_id, _ in emails[:1]:
            add_dork(
                DorkCategory.DATA_BROKER_PROFILES,
                f'(site:cyberbackgroundchecks.com OR site:thatsthem.com) "{em_val}"',
                em_id,
                "Reverse email lookup broker listings",
                PriorityLevel.HIGH,
            )

        # -------------------------------------------------------------
        # 7. SOCIAL EXPOSURE
        # -------------------------------------------------------------
        for u_val, u_id in usernames:
            add_dork(
                DorkCategory.SOCIAL_EXPOSURE,
                f'(site:linkedin.com/in OR site:facebook.com OR site:instagram.com OR site:x.com OR site:twitter.com) "{u_val}"',
                u_id,
                "Exposed social media profiles matching handle",
                PriorityLevel.MEDIUM,
            )
            add_dork(
                DorkCategory.SOCIAL_EXPOSURE,
                f'(site:tiktok.com/@ OR site:youtube.com/@ OR site:medium.com/@ OR site:reddit.com/user) "{u_val}"',
                u_id,
                "Content creator and forum account exposures",
                PriorityLevel.LOW,
            )

        if target.employers:
            add_dork(
                DorkCategory.SOCIAL_EXPOSURE,
                f'(site:linkedin.com/in) "{primary_name}" "{target.employers[0]}"',
                primary_vec_id,
                "LinkedIn professional profile and employment history",
                PriorityLevel.MEDIUM,
            )
        else:
            add_dork(
                DorkCategory.SOCIAL_EXPOSURE,
                f'(site:linkedin.com/in OR site:facebook.com) "{primary_name}" "{target.current_city or ""}"'.strip(),
                primary_vec_id,
                "Social profiles matched by full name and locality",
                PriorityLevel.MEDIUM,
            )

        # Sort dorks: CRITICAL -> HIGH -> MEDIUM -> LOW
        priority_order = {
            PriorityLevel.CRITICAL: 0,
            PriorityLevel.HIGH: 1,
            PriorityLevel.MEDIUM: 2,
            PriorityLevel.LOW: 3,
        }
        dorks.sort(key=lambda d: priority_order[d.risk_level])

        return DorkSynthesisResult(
            target_id=target_id,
            dorks=dorks,
            total_dorks=len(dorks),
        )

    async def synthesize_async(
        self, decomposition: IdentityDecompositionResult
    ) -> DorkSynthesisResult:
        """Asynchronous wrapper for dork synthesis."""
        return self.synthesize(decomposition)

    def synthesize_sync(
        self, decomposition: IdentityDecompositionResult
    ) -> DorkSynthesisResult:
        """Explicit synchronous synthesis method."""
        return self.synthesize(decomposition)
