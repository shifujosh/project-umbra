"""
Project Umbra LLM-Assisted Structured Entity Extractor & Semantic Preprocessor.
Extracts structured OSINT profiles from scraped broker HTML and text using:
1. HTML Semantic Preprocessor (>80% token reduction)
2. Gemini 3.7 Flash Structured Output (Google GenAI SDK response_schema)
3. Deterministic Local Extractor Fallback (zero-token, offline test resilience)
"""

from __future__ import annotations

import asyncio
from html.parser import HTMLParser
import logging
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from project_umbra.config import settings
from project_umbra.core.state import ExecutionProvenance, ExtractedEntityProfile

logger = logging.getLogger(__name__)

# HTML5 void elements that must not be pushed onto the container ignore stack
VOID_HTML_TAGS = {
    "meta", "link", "img", "input", "br", "hr", "area", "base",
    "col", "embed", "param", "source", "track", "wbr",
}

# Container tags stripped entirely (tag and contents)
IGNORED_CONTAINER_TAGS = {
    "script", "style", "noscript", "svg", "iframe", "canvas",
    "head", "template", "object", "embed", "video", "audio",
    "header", "nav", "footer", "aside",
}

# Tags that define structural line breaks
STRUCTURAL_BLOCK_TAGS = {
    "div", "p", "h1", "h2", "h3", "h4", "h5", "h6",
    "li", "tr", "dt", "dd", "section", "article", "main", "br", "hr",
}

# Keywords indicating removal or privacy opt-out links
OPTOUT_KEYWORDS = {
    "optout", "opt-out", "removal", "remove", "privacy",
    "suppression", "control", "do-not-sell", "ccpa", "gdpr",
}

# Class and ID substrings indicating noise, ads, and banners
NOISE_CLASS_KEYWORDS = {
    "cookie-banner", "cookie-consent", "ad-container",
    "advertisement", "sidebar-ad", "modal-backdrop", "banner",
}


# ==============================================================================
# 1. HTML Semantic Preprocessor
# ==============================================================================

class HTMLSemanticPreprocessor:
    """
    Strips non-semantic elements, styles, scripts, SVG graphics, inline base64 images,
    and boilerplate headers/footers to reduce token payloads by >80% while preserving
    entity contexts and removal/opt-out URLs.
    """

    class _SemanticParser(HTMLParser):
        def __init__(self, preserve_optout_links: bool = True) -> None:
            super().__init__()
            self.result: list[str] = []
            self.ignore_stack: list[str] = []
            self.preserve_optout = preserve_optout_links

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            tag_lower = tag.lower()
            attr_dict = {k.lower(): (v or "") for k, v in attrs}

            class_id = (attr_dict.get("class", "") + " " + attr_dict.get("id", "")).lower()
            is_noise = any(b in class_id for b in NOISE_CLASS_KEYWORDS)
            should_ignore = (tag_lower in IGNORED_CONTAINER_TAGS) or is_noise

            if should_ignore:
                if tag_lower not in VOID_HTML_TAGS:
                    self.ignore_stack.append(tag_lower)
                return

            if self.ignore_stack:
                if tag_lower not in VOID_HTML_TAGS:
                    self.ignore_stack.append(tag_lower)
                return

            if tag_lower == "a" and "href" in attr_dict and self.preserve_optout:
                href = attr_dict["href"]
                if any(k in href.lower() for k in OPTOUT_KEYWORDS):
                    self.result.append(f" [REMOVAL_LINK: {href}] ")
            elif tag_lower in STRUCTURAL_BLOCK_TAGS:
                self.result.append("\n")

        def handle_endtag(self, tag: str) -> None:
            tag_lower = tag.lower()
            if tag_lower in VOID_HTML_TAGS:
                return

            if self.ignore_stack:
                if tag_lower in self.ignore_stack:
                    while self.ignore_stack:
                        popped = self.ignore_stack.pop()
                        if popped == tag_lower:
                            break
                return

            if tag_lower in STRUCTURAL_BLOCK_TAGS:
                self.result.append("\n")

        def handle_data(self, data: str) -> None:
            if not self.ignore_stack:
                self.result.append(data)

    @classmethod
    def preprocess(cls, html_or_text: str, preserve_optout_links: bool = True) -> str:
        """
        Preprocesses raw HTML or text, stripping noise and preserving semantic entity context.
        """
        if not html_or_text or not html_or_text.strip():
            return ""

        # Fast-path for plain text without HTML tags
        if "<" not in html_or_text and ">" not in html_or_text:
            lines = [re.sub(r"[ \t]+", " ", line).strip() for line in html_or_text.splitlines()]
            return "\n".join([line for line in lines if line])

        # 1. Strip HTML comments
        text = re.sub(r"<!--.*?-->", "", html_or_text, flags=re.DOTALL)
        # 2. Strip inline base64 images and large data URIs
        text = re.sub(r"data:image\/[^;]+;base64,[a-zA-Z0-9+/=]+", "", text)
        # 3. Strip SVG blocks via regex fast-path
        text = re.sub(r"<svg\b[^>]*>.*?</svg>", "", text, flags=re.DOTALL | re.IGNORECASE)
        # 4. Strip script, style, and noscript blocks via regex fast-path
        text = re.sub(r"<(script|style|noscript)\b[^>]*>.*?</\1>", "", text, flags=re.DOTALL | re.IGNORECASE)

        # 5. Parse DOM using semantic cleaner
        parser = cls._SemanticParser(preserve_optout_links=preserve_optout_links)
        parser.feed(text)
        extracted = "".join(parser.result)

        # 6. Normalize whitespace and collapse blank lines
        lines = [re.sub(r"[ \t]+", " ", line).strip() for line in extracted.splitlines()]
        cleaned = "\n".join([line for line in lines if line])
        return cleaned

    @classmethod
    def calculate_reduction(cls, raw: str, preprocessed: str) -> float:
        """Calculates the percentage token/character payload reduction."""
        if not raw:
            return 0.0
        return max(0.0, (1.0 - len(preprocessed) / len(raw)) * 100.0)


# ==============================================================================
# 2. Deterministic Local Extractor Fallback
# ==============================================================================

class DeterministicLocalExtractor:
    """
    Rule-based deterministic extractor for zero-token offline execution
    and fallback resilience when LLM APIs are unavailable.
    """

    RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.IGNORECASE)
    RE_PHONE = re.compile(
        r"(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b"
    )
    RE_AGE = re.compile(
        r"\b(?:Age[:\s]*|Age\s+)?(\d{2,3})(?:\s*(?:years old|\(Born|\b))",
        re.IGNORECASE,
    )
    RE_ADDRESS = re.compile(
        r"\b\d{1,5}\s+[A-Za-z0-9.\s]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct|Circle|Cir|Way|Pkwy|Parkway|Place|Pl)"
        r"(?:,\s*(?:Apt|Suite|Unit|Ste|#)\s*[A-Za-z0-9-]+)?"
        r",?\s+[A-Za-z\s]+,?\s+[A-Z]{2}\s+\d{5}(?:-\d{4})?\b",
        re.IGNORECASE,
    )
    RE_REMOVAL_LINK = re.compile(r"\[REMOVAL_LINK:\s*([^\s\]]+)\]", re.IGNORECASE)
    RE_URL = re.compile(r"https?://[^\s<>\"\'\)]+", re.IGNORECASE)

    def extract(
        self,
        text: str,
        source_url: str = "",
        target_id: str = "",
        source_broker: str | None = None,
        target_hint: str | None = None,
    ) -> ExtractedEntityProfile:
        """Extracts structured fields from preprocessed text using deterministic rules."""
        matched_names: list[str] = []
        if target_hint and target_hint.strip():
            matched_names.append(target_hint.strip())

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if lines:
            first_line = lines[0]
            words = first_line.split()
            if 2 <= len(words) <= 4 and not any(
                kw in first_line.lower()
                for kw in ["age", "phone", "contact", "address", "result", "search", "privacy", "welcome", "record"]
            ):
                if first_line not in matched_names:
                    matched_names.insert(0, first_line)

        # Age
        age: str | None = None
        age_match = self.RE_AGE.search(text)
        if age_match:
            age = age_match.group(1)

        # Phone numbers
        phones: list[str] = []
        for p in self.RE_PHONE.findall(text):
            if isinstance(p, tuple):
                formatted = f"({p[0]}) {p[1]}-{p[2]}"
                if formatted not in phones:
                    phones.append(formatted)
            elif isinstance(p, str):
                if p not in phones:
                    phones.append(p)

        # Emails
        emails = list(dict.fromkeys(self.RE_EMAIL.findall(text)))

        # Addresses
        current_addr: str | None = None
        past_addrs: list[str] = []

        curr_match = re.search(r"Current Address[:\s]+([^\n]+)", text, re.IGNORECASE)
        if curr_match:
            cand = self.RE_ADDRESS.search(curr_match.group(1))
            if cand:
                current_addr = cand.group(0).strip()
            else:
                current_addr = curr_match.group(1).strip()

        all_addrs = self.RE_ADDRESS.findall(text)
        for addr in all_addrs:
            addr_clean = addr.strip()
            if current_addr and addr_clean == current_addr:
                continue
            if addr_clean not in past_addrs:
                past_addrs.append(addr_clean)

        if not current_addr and all_addrs:
            current_addr = all_addrs[0].strip()
            past_addrs = [a.strip() for a in all_addrs[1:]]

        # Relatives & Associates
        def extract_names_from_section(label_pattern: str) -> list[str]:
            res: list[str] = []
            pattern = re.compile(
                r"(?:" + label_pattern + r")[:\s]+([^\n]+)",
                re.IGNORECASE,
            )
            m = pattern.search(text)
            if m:
                raw = m.group(1)
                cleaned = re.sub(r"\([^)]*\)", "", raw)
                for item in re.split(r"[,;]\s*", cleaned):
                    item_clean = item.strip()
                    if not item_clean or len(item_clean.split()) < 2:
                        continue
                    if any(
                        kw in item_clean.lower()
                        for kw in ["relatives", "associates", "address", "phone", "email", "born", "record"]
                    ):
                        continue
                    if item_clean not in res:
                        res.append(item_clean)
            return res

        relatives = extract_names_from_section(r"Known Relatives|Relatives|Family")
        associates = extract_names_from_section(r"Possible Associates|Associates|Co-workers")

        # Removal URL
        removal_url: str | None = None
        rem_match = self.RE_REMOVAL_LINK.search(text)
        if rem_match:
            removal_url = rem_match.group(1).strip()
        else:
            for url in self.RE_URL.findall(text):
                if any(
                    k in url.lower()
                    for k in ["optout", "opt-out", "removal", "remove", "privacy", "suppression"]
                ):
                    removal_url = url
                    break

        # Confidence Calculation
        score = 0.60
        if matched_names:
            score += 0.10
        if phones:
            score += 0.08
        if emails:
            score += 0.08
        if current_addr:
            score += 0.08
        if relatives:
            score += 0.04
        if removal_url:
            score += 0.02
        confidence = round(min(0.99, score), 2)

        return ExtractedEntityProfile(
            target_id=target_id or "tgt_unknown",
            source_url=source_url,
            source_broker=source_broker,
            matched_names=matched_names,
            age=age,
            phone_numbers=phones,
            email_addresses=emails,
            current_address=current_addr,
            past_addresses=past_addrs,
            relatives=relatives,
            associates=associates,
            removal_url=removal_url,
            confidence_score=confidence,
            provenance=ExecutionProvenance.FALLBACK,
            extraction_provider="deterministic_local",
        )


# ==============================================================================
# 3. Gemini 3.7 Flash Structured Extractor
# ==============================================================================


class GeminiExtractionPayload(BaseModel):
    """Strict model-output schema, excluding runtime provenance metadata."""

    model_config = ConfigDict(extra="ignore")

    target_id: str
    source_url: str
    source_broker: str | None = None
    matched_names: list[str] = Field(default_factory=list)
    age: str | None = None
    phone_numbers: list[str] = Field(default_factory=list)
    email_addresses: list[str] = Field(default_factory=list)
    current_address: str | None = None
    past_addresses: list[str] = Field(default_factory=list)
    relatives: list[str] = Field(default_factory=list)
    associates: list[str] = Field(default_factory=list)
    removal_url: str | None = None
    confidence_score: float = Field(default=0.9, ge=0.0, le=1.0)

class GeminiStructuredExtractor:
    """
    Google GenAI SDK (Gemini 3.7 Flash) Structured Output Extractor.
    Extracts structured entity profiles conforming to ExtractedEntityProfile
    using response_mime_type="application/json" and response_schema=ExtractedEntityProfile.
    """

    DEFAULT_SYSTEM_INSTRUCTION = (
        "You are Project Umbra's high-precision OSINT Structural Entity Extractor. "
        "Extract target identity attributes from the provided scraped broker profile "
        "into the strict JSON schema. Extract matched names, ages, phone numbers, "
        "email addresses, current address, past addresses, relatives, associates, "
        "and direct opt-out / removal URLs. Assign an empirical confidence score (0.0 - 1.0). "
        "Do not hallucinate entities not present in the input text."
    )

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str | None = None,
        client: Any | None = None,
        offline_mode: bool = False,
    ) -> None:
        self.api_key = api_key or settings.GEMINI_API_KEY
        self.model_name = model_name or settings.GEMINI_MODEL or "gemini-3.7-flash"
        self.offline_mode = offline_mode
        self._client = client
        self.fallback_extractor = DeterministicLocalExtractor()

    def _get_client(self) -> Any:
        if self.offline_mode:
            return None
        if self._client is not None:
            return self._client
        if not self.api_key:
            return None
        try:
            import google.genai as genai
            self._client = genai.Client(api_key=self.api_key)
            return self._client
        except Exception:
            return None

    async def extract(
        self,
        raw_content: str,
        source_url: str = "",
        target_id: str = "",
        source_broker: str | None = None,
        target_hint: str | None = None,
    ) -> ExtractedEntityProfile:
        """
        Asynchronously extracts structured profile using Gemini 3.7 Flash with deterministic fallback.
        """
        if not raw_content or not raw_content.strip():
            return ExtractedEntityProfile(
                target_id=target_id or "tgt_empty",
                source_url=source_url,
                source_broker=source_broker,
                matched_names=[target_hint] if target_hint else [],
                confidence_score=0.0,
                provenance=ExecutionProvenance.FALLBACK,
                extraction_provider="deterministic_local",
            )

        # 1. Semantic preprocessing (strip noise, styles, scripts, SVGs)
        cleaned_text = HTMLSemanticPreprocessor.preprocess(raw_content)

        client = self._get_client()
        if client is None or self.offline_mode:
            # Deterministic fallback
            return self.fallback_extractor.extract(
                text=cleaned_text,
                source_url=source_url,
                target_id=target_id,
                source_broker=source_broker,
                target_hint=target_hint,
            )

        # 2. Invoke Gemini 3.7 Flash structured extraction
        try:
            from google.genai import types

            config = types.GenerateContentConfig(
                system_instruction=self.DEFAULT_SYSTEM_INSTRUCTION,
                response_mime_type="application/json",
                response_schema=GeminiExtractionPayload,
                temperature=0.1,
            )

            prompt = (
                f"Source URL: {source_url}\n"
                f"Source Broker: {source_broker or 'Unknown'}\n"
                f"Target Name Hint: {target_hint or 'None'}\n\n"
                f"Scraped Profile Content:\n{cleaned_text}"
            )

            response = await client.aio.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config,
            )

            # Parse returned structured JSON
            if hasattr(response, "text") and response.text:
                payload = GeminiExtractionPayload.model_validate_json(response.text)
            elif hasattr(response, "parsed") and response.parsed:
                payload = (
                    response.parsed
                    if isinstance(response.parsed, GeminiExtractionPayload)
                    else GeminiExtractionPayload.model_validate(response.parsed)
                )
            else:
                raise ValueError("Empty response from Gemini structured output")
            profile = ExtractedEntityProfile.model_validate(payload.model_dump())

            # Post-process: ensure metadata fields are populated
            if not profile.target_id or profile.target_id == "tgt_unknown":
                profile.target_id = target_id or "tgt_extracted"
            if not profile.source_url:
                profile.source_url = source_url
            if not profile.source_broker:
                profile.source_broker = source_broker
            profile.provenance = ExecutionProvenance.LIVE
            profile.extraction_provider = "google_genai_sdk"
            profile.extraction_model = self.model_name
            response_id = getattr(response, "response_id", None)
            model_version = getattr(response, "model_version", None)
            profile.model_response_id = response_id if isinstance(response_id, str) else None
            profile.model_version = model_version if isinstance(model_version, str) else None
            usage_metadata = getattr(response, "usage_metadata", None)
            if usage_metadata is not None:
                if isinstance(usage_metadata, dict):
                    profile.model_usage = usage_metadata
                elif hasattr(usage_metadata, "model_dump"):
                    dumped_usage = usage_metadata.model_dump(mode="json")
                    if isinstance(dumped_usage, dict):
                        profile.model_usage = dumped_usage

            # Post-process: guarantee removal URL if deterministic engine detected one
            if not profile.removal_url:
                det_profile = self.fallback_extractor.extract(
                    cleaned_text, source_url, target_id, source_broker, target_hint
                )
                if det_profile.removal_url:
                    profile.removal_url = det_profile.removal_url

            return profile

        except Exception as exc:
            logger.warning(
                "Gemini structured extraction failed (%s), using deterministic fallback.",
                type(exc).__name__,
            )
            return self.fallback_extractor.extract(
                text=cleaned_text,
                source_url=source_url,
                target_id=target_id,
                source_broker=source_broker,
                target_hint=target_hint,
            )


# ==============================================================================
# 4. Unified High-Level Facade
# ==============================================================================

class StructuredExtractor:
    """
    Unified high-level facade for structured entity extraction.
    Combines HTML semantic preprocessing, Gemini 3.7 structured output,
    and deterministic local regex/DOM fallback.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str | None = None,
        client: Any | None = None,
        offline_mode: bool = False,
    ) -> None:
        self.preprocessor = HTMLSemanticPreprocessor()
        self.gemini_extractor = GeminiStructuredExtractor(
            api_key=api_key,
            model_name=model_name,
            client=client,
            offline_mode=offline_mode,
        )
        self.local_extractor = DeterministicLocalExtractor()

    async def extract_entities(
        self,
        raw_content: str,
        source_url: str = "",
        target_id: str = "",
        source_broker: str | None = None,
        target_hint: str | None = None,
    ) -> ExtractedEntityProfile:
        """
        Asynchronously extract structured entity profile from raw HTML or text.
        """
        return await self.gemini_extractor.extract(
            raw_content=raw_content,
            source_url=source_url,
            target_id=target_id,
            source_broker=source_broker,
            target_hint=target_hint,
        )

    def extract_entities_sync(
        self,
        raw_content: str,
        source_url: str = "",
        target_id: str = "",
        source_broker: str | None = None,
        target_hint: str | None = None,
    ) -> ExtractedEntityProfile:
        """
        Synchronous extraction using deterministic local engine.
        """
        cleaned_text = self.preprocessor.preprocess(raw_content)
        return self.local_extractor.extract(
            text=cleaned_text,
            source_url=source_url,
            target_id=target_id,
            source_broker=source_broker,
            target_hint=target_hint,
        )
