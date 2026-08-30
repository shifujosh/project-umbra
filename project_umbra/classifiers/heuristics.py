"""
Deterministic Heuristics Engine for PII Pattern Matching & Token Extraction.
Provides sub-millisecond regex tokenizers with Luhn validation, SSN sanity checks,
cryptographic hash signatures, and address heuristics.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from project_umbra.core.state import (
    PIISanitizationResult,
    PIISeverity,
    PIITokenEntity,
    PIITokenType,
)

# ----------------------------------------------------------------------
# Compiled High-Precision Regular Expressions
# ----------------------------------------------------------------------

# 1. SSN: 3-2-4 digits with hyphen, space, or continuous (avoiding all 000, 666, 9xx area codes)
RE_SSN = re.compile(r"\b(?!000|666|9\d{2})(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b")

# 2. Email: RFC 5322 compatible
RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    re.IGNORECASE,
)

# 3. Phone: North American NANP, international E.164, extensions
RE_PHONE = re.compile(
    r"(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b|"
    r"\+(?:[0-9] ?){6,14}[0-9]\b"
)

# 4. Credit Cards: Visa, MasterCard, Amex, Discover, Diners, JCB
RE_CREDIT_CARD = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"           # Visa
    r"5[1-5][0-9]{14}|"                         # MasterCard
    r"3[47][0-9]{13}|"                          # American Express
    r"3(?:0[0-5]|[68][0-9])[0-9]{11}|"          # Diners Club
    r"6(?:011|5[0-9]{2})[0-9]{12}|"             # Discover
    r"(?:2131|1800|35\d{3})\d{11}"              # JCB
    r")\b|"
    r"\b(?:\d{4}[- ]){3}\d{4}\b|"               # Formatted 16-digit
    r"\b3[47]\d{2}[- ]\d{6}[- ]\d{5}\b"         # Formatted Amex 15-digit
)

# 5. IP Address: IPv4 and IPv6
RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
)

# 6. Password Hashes (Bcrypt, Argon2, SHA-256, SHA-1, MD5)
RE_HASH_BCRYPT = re.compile(r"\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{50,60}")
RE_HASH_ARGON2 = re.compile(r"\$argon2(?:id|[id])\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+")
RE_HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")

# 7. Date of Birth: ISO (YYYY-MM-DD), US (MM/DD/YYYY), Textual (Month DD, YYYY)
RE_DOB_ISO = re.compile(r"\b(?:19\d\d|20[0-2]\d)-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b")
RE_DOB_US = re.compile(r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19\d\d|20[0-2]\d)\b")
RE_DOB_TEXT = re.compile(
    r"\b(?:Born|DOB|Birthdate|Date of Birth)?[:\s]*"
    r"((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* (?:[0-2]?[0-9]|3[01]),? (?:19\d\d|20[0-2]\d))\b",
    re.IGNORECASE,
)

# 8. Physical Address: US Street Addresses
RE_PHYSICAL_ADDRESS = re.compile(
    r"\b\d{1,5}\s+[A-Za-z0-9.\s]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct|Circle|Cir|Terrace|Terr|Trail|Trl|Highway|Hwy|Way|Pkwy|Parkway|Place|Pl)"
    r"(?:,\s*(?:Apt|Suite|Unit|Ste|#)\s*[A-Za-z0-9-]+)?"
    r",\s*[A-Za-z\s]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?\b",
    re.IGNORECASE,
)

# 9. Contextual Relatives & Names
RE_RELATIVE_CONTEXT = re.compile(
    r"(?:Relatives?|Family|Associates?|Spouse|Sibling|Parent|Children|Known Relatives)[:\s]+"
    r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+(?:,\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)*)",
    re.IGNORECASE,
)

RE_NAME_CONTEXT = re.compile(
    r"(?:Full Name|Target Name|Subject Name|Name)[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",
    re.IGNORECASE,
)


# ----------------------------------------------------------------------
# Validation Helpers
# ----------------------------------------------------------------------

def validate_luhn(card_number: str) -> bool:
    """Validate credit card number using Luhn checksum algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def get_default_severity(token_type: PIITokenType) -> PIISeverity:
    """Return default severity classification for a given token type."""
    mapping = {
        PIITokenType.SSN: PIISeverity.CRITICAL,
        PIITokenType.CREDIT_CARD: PIISeverity.CRITICAL,
        PIITokenType.PASSWORD_HASH: PIISeverity.CRITICAL,
        PIITokenType.PHYSICAL_ADDRESS: PIISeverity.HIGH,
        PIITokenType.PHONE: PIISeverity.HIGH,
        PIITokenType.DATE_OF_BIRTH: PIISeverity.HIGH,
        PIITokenType.EMAIL: PIISeverity.MEDIUM,
        PIITokenType.RELATIVE_NAME: PIISeverity.MEDIUM,
        PIITokenType.IP_ADDRESS: PIISeverity.MEDIUM,
        PIITokenType.FULL_NAME: PIISeverity.LOW,
    }
    return mapping.get(token_type, PIISeverity.LOW)


# ----------------------------------------------------------------------
# Deterministic Extractor Class
# ----------------------------------------------------------------------

class DeterministicPIIExtractor:
    """Extracts raw candidate PII spans with zero latency and high precision."""

    def extract_candidates(self, text: str) -> list[dict[str, Any]]:
        """
        Scan text for all 10 PII token types.
        Returns list of dicts: {"type": PIITokenType, "value": str, "start": int, "end": int, "severity": PIISeverity, "confidence": float}
        """
        candidates: list[dict[str, Any]] = []
        if not text or not text.strip():
            return candidates

        # 1. SSN
        for match in RE_SSN.finditer(text):
            val = match.group(0)
            candidates.append({
                "type": PIITokenType.SSN,
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "severity": PIISeverity.CRITICAL,
                "confidence": 0.99,
            })

        # 2. Credit Cards (with Luhn check)
        for match in RE_CREDIT_CARD.finditer(text):
            val = match.group(0)
            if validate_luhn(val):
                candidates.append({
                    "type": PIITokenType.CREDIT_CARD,
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "severity": PIISeverity.CRITICAL,
                    "confidence": 0.98,
                })

        # 3. Password Hashes
        for rx in (RE_HASH_BCRYPT, RE_HASH_ARGON2, RE_HASH_SHA256, RE_HASH_SHA1, RE_HASH_MD5):
            for match in rx.finditer(text):
                val = match.group(0)
                candidates.append({
                    "type": PIITokenType.PASSWORD_HASH,
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "severity": PIISeverity.CRITICAL,
                    "confidence": 0.95,
                })

        # 4. Email
        for match in RE_EMAIL.finditer(text):
            val = match.group(0)
            candidates.append({
                "type": PIITokenType.EMAIL,
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "severity": PIISeverity.MEDIUM,
                "confidence": 0.98,
            })

        # 5. Phone
        for match in RE_PHONE.finditer(text):
            val = match.group(0).strip()
            if len(re.sub(r"\D", "", val)) >= 10:
                candidates.append({
                    "type": PIITokenType.PHONE,
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "severity": PIISeverity.HIGH,
                    "confidence": 0.95,
                })

        # 6. Physical Address
        for match in RE_PHYSICAL_ADDRESS.finditer(text):
            val = match.group(0).strip()
            candidates.append({
                "type": PIITokenType.PHYSICAL_ADDRESS,
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "severity": PIISeverity.HIGH,
                "confidence": 0.92,
            })

        # 7. Date of Birth
        for rx in (RE_DOB_ISO, RE_DOB_US, RE_DOB_TEXT):
            for match in rx.finditer(text):
                val = match.group(1) if match.lastindex else match.group(0)
                candidates.append({
                    "type": PIITokenType.DATE_OF_BIRTH,
                    "value": val.strip(),
                    "start": match.start(),
                    "end": match.end(),
                    "severity": PIISeverity.HIGH,
                    "confidence": 0.90,
                })

        # 8. IP Address
        for rx in (RE_IPV4, RE_IPV6):
            for match in rx.finditer(text):
                val = match.group(0)
                candidates.append({
                    "type": PIITokenType.IP_ADDRESS,
                    "value": val,
                    "start": match.start(),
                    "end": match.end(),
                    "severity": PIISeverity.MEDIUM,
                    "confidence": 0.92,
                })

        # 9. Relatives (Contextual)
        for match in RE_RELATIVE_CONTEXT.finditer(text):
            raw_names = match.group(1)
            for name in re.split(r",\s*", raw_names):
                name = name.strip()
                if name:
                    candidates.append({
                        "type": PIITokenType.RELATIVE_NAME,
                        "value": name,
                        "start": match.start(),
                        "end": match.end(),
                        "severity": PIISeverity.MEDIUM,
                        "confidence": 0.85,
                    })

        # 10. Full Name (Contextual)
        for match in RE_NAME_CONTEXT.finditer(text):
            name = match.group(1).strip()
            if name:
                candidates.append({
                    "type": PIITokenType.FULL_NAME,
                    "value": name,
                    "start": match.start(),
                    "end": match.end(),
                    "severity": PIISeverity.LOW,
                    "confidence": 0.85,
                })

        return candidates


class FastPIISanitizer:
    """Convenience synchronous sanitizer wrapping DeterministicPIIExtractor."""

    SEVERITY_WEIGHTS = {
        PIISeverity.CRITICAL: 35.0,
        PIISeverity.HIGH: 18.0,
        PIISeverity.MEDIUM: 8.0,
        PIISeverity.LOW: 3.0,
    }

    def __init__(self) -> None:
        self.extractor = DeterministicPIIExtractor()

    def sanitize(self, text: str) -> PIISanitizationResult:
        """Sanitizes text, replacing detected PII with surrogate tokens."""
        if not text or not text.strip():
            return PIISanitizationResult(
                sanitized_text=text or "",
                detected_entities=[],
                redaction_map={},
                critical_pii_count=0,
                total_pii_count=0,
                overall_risk_score=0.0,
            )

        candidates = self.extractor.extract_candidates(text)
        type_counters: dict[str, int] = {}
        value_to_surrogate: dict[str, str] = {}
        redaction_map: dict[str, str] = {}
        detected_entities: list[PIITokenEntity] = []

        # Deduplicate
        dedup: dict[str, dict[str, Any]] = {}
        for c in candidates:
            val = c["value"]
            if val not in dedup or c["severity"] == PIISeverity.CRITICAL:
                dedup[val] = c

        for cand in dedup.values():
            val = cand["value"]
            ttype = cand["type"]
            sev = cand["severity"]
            conf = cand.get("confidence", 0.95)

            if val not in value_to_surrogate:
                type_counters[ttype.value] = type_counters.get(ttype.value, 0) + 1
                surrogate = f"[PII_{ttype.value}_{type_counters[ttype.value]:02d}]"
                value_to_surrogate[val] = surrogate
                redaction_map[surrogate] = val
            else:
                surrogate = value_to_surrogate[val]

            detected_entities.append(
                PIITokenEntity(
                    entity_id=f"ent_{uuid.uuid4().hex[:8]}",
                    token_type=ttype,
                    original_value=val,
                    surrogate_token=surrogate,
                    severity=sev,
                    confidence=conf,
                )
            )

        sanitized_text = text
        sorted_replacements = sorted(value_to_surrogate.items(), key=lambda x: len(x[0]), reverse=True)
        for orig, surrogate in sorted_replacements:
            sanitized_text = sanitized_text.replace(orig, surrogate)

        critical_count = sum(1 for e in detected_entities if e.severity == PIISeverity.CRITICAL)
        raw_score = sum(self.SEVERITY_WEIGHTS.get(e.severity, 3.0) * e.confidence for e in detected_entities)
        risk_score = round(min(100.0, raw_score), 2)

        return PIISanitizationResult(
            sanitized_text=sanitized_text,
            detected_entities=detected_entities,
            redaction_map=redaction_map,
            critical_pii_count=critical_count,
            total_pii_count=len(detected_entities),
            overall_risk_score=risk_score,
        )
