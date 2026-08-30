"""
Project Umbra SERP Scanner Tool & Search Grounding Engine.
Provides dual-mode search execution:
1. Live HTTP search execution (DuckDuckGo Lite, Google GenAI Search Grounding, SearXNG)
   with header rotation, jitter delays, anti-bot evasion, and graceful fallback.
2. Deterministic mock fixture execution with realistic OSINT findings across all 7 taxonomies.
3. Concurrency-bounded batch execution via asyncio.Semaphore with per-task timeout controls.
4. Automatic PII token detection and context-aware risk level scoring.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import random
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Literal

import httpx

from project_umbra.config import settings
from project_umbra.core.state import (
    DorkCategory,
    DorkQuery,
    ExecutionProvenance,
    PriorityLevel,
    SERPFinding,
    TargetIdentityInput,
)
from project_umbra.tools.fixtures import get_mock_serp_findings

logger = logging.getLogger(__name__)


# ==============================================================================
# Stealth & Header Rotation Constants
# ==============================================================================

USER_AGENTS = [
    # macOS Safari & Chrome
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
    # Windows Chrome & Edge & Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    # Linux Chrome & Firefox
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Mobile iOS & Android Safari/Chrome
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.105 Mobile Safari/537.36",
]

CRITICAL_KEYWORDS = {
    "password", "passwd", "hash", "ssn", "social security", "api_key",
    "secret_key", "private_key", "db_dump", "database dump", "credential dump",
    "seed phrase", "auth_token", "bearer", "access_token", "private_token",
    "confidential", "internal only", "leaked", "breach", "stealer",
}


# ==============================================================================
# SERP Scanner Class
# ==============================================================================

class SERPScanner:
    """
    Automated search query executor and SERP parser for OSINT discovery.
    Supports Live (DuckDuckGo Lite, Google GenAI, SearXNG) and Mock Fixture modes.
    """

    def __init__(
        self,
        mode: Literal["auto", "duckduckgo_lite", "google_genai", "searxng", "mock"] | None = None,
        gemini_client: Any | None = None,
        searxng_url: str | None = None,
        max_concurrency: int | None = None,
        timeout_seconds: float | None = None,
        jitter_min_ms: int | None = None,
        jitter_max_ms: int | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.mode = mode or settings.SERP_MODE
        self.gemini_client = gemini_client
        self.searxng_url = searxng_url or settings.SEARXNG_URL
        self.max_concurrency = max_concurrency or settings.SERP_MAX_CONCURRENCY
        self.timeout_seconds = timeout_seconds or settings.SERP_TIMEOUT_SECONDS
        self.jitter_min_ms = jitter_min_ms if jitter_min_ms is not None else settings.SERP_JITTER_MIN_MS
        self.jitter_max_ms = jitter_max_ms if jitter_max_ms is not None else settings.SERP_JITTER_MAX_MS
        self._custom_client = http_client
        self._semaphore = asyncio.Semaphore(self.max_concurrency)
        self.last_provenance = ExecutionProvenance.LIVE
        self.last_model_invocation: dict[str, Any] | None = None

    def _fixture_findings(
        self,
        dork: DorkQuery,
        target_name: str | None,
        target_input: TargetIdentityInput | None,
        provenance: ExecutionProvenance,
    ) -> list[SERPFinding]:
        findings = get_mock_serp_findings(
            dork,
            target_name=target_name,
            target_input=target_input,
        )
        for finding in findings:
            finding.provenance = provenance
        self.last_provenance = provenance
        return findings

    def _get_headers(self) -> dict[str, str]:
        """Generates realistic rotating headers for stealth execution."""
        ua = random.choice(USER_AGENTS)
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }

    async def _apply_jitter(self) -> None:
        """Applies randomized jitter delay between requests."""
        if self.jitter_max_ms > 0 and self.jitter_max_ms >= self.jitter_min_ms:
            delay = random.uniform(self.jitter_min_ms / 1000.0, self.jitter_max_ms / 1000.0)
            if delay > 0:
                await asyncio.sleep(delay)

    # --------------------------------------------------------------------------
    # PII Matching & Risk Calculation
    # --------------------------------------------------------------------------

    def _extract_pii_tokens(
        self,
        text: str,
        target_name: str | None = None,
        target_input: TargetIdentityInput | None = None,
    ) -> list[str]:
        """Identifies matched target identity tokens in scraped SERP text."""
        tokens_to_check: set[str] = set()

        if target_name and len(target_name.strip()) >= 2:
            tokens_to_check.add(target_name.strip())

        if target_input:
            if target_input.full_name and len(target_input.full_name.strip()) >= 2:
                tokens_to_check.add(target_input.full_name.strip())
            for alias in target_input.aliases:
                if alias and len(alias.strip()) >= 2:
                    tokens_to_check.add(alias.strip())
            if target_input.primary_email:
                tokens_to_check.add(target_input.primary_email.strip())
            for em in target_input.secondary_emails:
                if em and len(em.strip()) >= 3:
                    tokens_to_check.add(em.strip())
            for ph in target_input.phone_numbers:
                if ph and len(ph.strip()) >= 3:
                    tokens_to_check.add(ph.strip())
            for un in target_input.usernames:
                if un and len(un.strip()) >= 2:
                    tokens_to_check.add(un.strip())
            if target_input.current_city and len(target_input.current_city.strip()) >= 2:
                tokens_to_check.add(target_input.current_city.strip())
            for addr in target_input.known_addresses:
                if addr and len(addr.strip()) >= 3:
                    tokens_to_check.add(addr.strip())

        matched: list[str] = []
        lower_text = text.lower()
        for tok in tokens_to_check:
            if tok.lower() in lower_text:
                matched.append(tok)

        return sorted(list(set(matched)), key=lambda x: -len(x))

    def _calculate_risk(
        self,
        category: DorkCategory,
        title: str,
        snippet: str,
        matched_tokens: list[str],
    ) -> PriorityLevel:
        """Calculates finding risk rating based on taxonomy, tokens, and sensitive keywords."""
        comb = f"{title} {snippet}".lower()

        has_critical_keyword = any(kw in comb for kw in CRITICAL_KEYWORDS)
        if category == DorkCategory.CREDENTIAL_LEAKS or has_critical_keyword:
            return PriorityLevel.CRITICAL

        if category in (DorkCategory.PASTEBINS_DUMPS, DorkCategory.CODE_REPOS_CONFIGS):
            return PriorityLevel.CRITICAL if len(matched_tokens) >= 2 else PriorityLevel.HIGH

        if category == DorkCategory.DOCUMENTS_SPREADSHEETS:
            return (
                PriorityLevel.CRITICAL
                if ("ssn" in comb or "dob" in comb or len(matched_tokens) >= 2)
                else PriorityLevel.HIGH
            )

        if category == DorkCategory.DATA_BROKER_PROFILES:
            return PriorityLevel.HIGH if len(matched_tokens) >= 1 else PriorityLevel.MEDIUM

        if category == DorkCategory.GOV_PUBLIC_DIRECTORIES:
            return PriorityLevel.HIGH if len(matched_tokens) >= 2 else PriorityLevel.MEDIUM

        if category == DorkCategory.SOCIAL_EXPOSURE:
            return PriorityLevel.MEDIUM if len(matched_tokens) >= 2 else PriorityLevel.LOW

        return PriorityLevel.MEDIUM if matched_tokens else PriorityLevel.LOW

    # --------------------------------------------------------------------------
    # Live Search Engine Parsers
    # --------------------------------------------------------------------------

    def parse_duckduckgo_lite_html(
        self, html_content: str, dork_id: str, category: DorkCategory
    ) -> list[dict[str, str]]:
        """Parses HTML results returned by DuckDuckGo Lite."""
        results: list[dict[str, str]] = []
        clean_html = html.unescape(html_content)

        # Match table rows containing result links and snippets
        # DDG Lite format: <a class="result-link" href="...">Title</a> ... <td class="result-snippet">Snippet</td>
        link_pattern = re.compile(
            r'<a\s+[^>]*class=["\']result-link["\'][^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL,
        )
        snippet_pattern = re.compile(
            r'<td\s+[^>]*class=["\']result-snippet["\'][^>]*>(.*?)</td>',
            re.IGNORECASE | re.DOTALL,
        )

        raw_links = link_pattern.findall(clean_html)
        raw_snippets = snippet_pattern.findall(clean_html)

        # Fallback generic anchor extractor if DDG Lite CSS classes change
        if not raw_links:
            generic_pattern = re.compile(
                r'<a\s+[^>]*href=["\'](https?://[^"\']+|/l/\?[^"\']+)["\'][^>]*>(.*?)</a>',
                re.IGNORECASE | re.DOTALL,
            )
            for href, text in generic_pattern.findall(clean_html):
                clean_t = re.sub(r"<[^>]+>", "", text).strip()
                if clean_t and "duckduckgo" not in href.lower() and len(clean_t) > 3:
                    raw_links.append((href, clean_t))

        count = max(len(raw_links), len(raw_snippets))
        for i in range(count):
            if i < len(raw_links):
                raw_href, raw_title = raw_links[i]
                title = re.sub(r"<[^>]+>", "", raw_title).strip()
                # Handle DDG redirection URL /l/?uddg=https%3A%2F%2F...
                if "/l/?uddg=" in raw_href:
                    parsed_q = urllib.parse.parse_qs(urllib.parse.urlparse(raw_href).query)
                    target_url = parsed_q.get("uddg", [raw_href])[0]
                elif raw_href.startswith("/"):
                    target_url = f"https://duckduckgo.com{raw_href}"
                else:
                    target_url = raw_href
            else:
                continue

            snippet = ""
            if i < len(raw_snippets):
                snippet = re.sub(r"<[^>]+>", "", raw_snippets[i]).strip()

            domain = urllib.parse.urlparse(target_url).netloc or "web"

            if target_url and title:
                results.append({
                    "title": title,
                    "url": target_url,
                    "snippet": snippet or f"Discovered record on {domain}",
                    "domain": domain,
                })

        return results

    async def _execute_duckduckgo_lite(
        self, query: str, dork: DorkQuery, client: httpx.AsyncClient
    ) -> list[dict[str, str]]:
        """Executes HTTP search against DuckDuckGo Lite endpoint."""
        await self._apply_jitter()
        headers = self._get_headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = {"q": query, "kl": "us-en"}

        resp = await client.post(
            "https://lite.duckduckgo.com/lite/",
            headers=headers,
            data=data,
            timeout=self.timeout_seconds,
            follow_redirects=True,
        )
        resp.raise_for_status()
        return self.parse_duckduckgo_lite_html(resp.text, dork.dork_id, dork.category)

    async def _execute_searxng(
        self, query: str, dork: DorkQuery, client: httpx.AsyncClient
    ) -> list[dict[str, str]]:
        """Executes query against configured SearXNG JSON endpoint."""
        if not self.searxng_url:
            raise ValueError("SearXNG URL is not configured")

        await self._apply_jitter()
        endpoint = f"{self.searxng_url.rstrip('/')}/search"
        params = {"q": query, "format": "json"}
        resp = await client.get(
            endpoint, params=params, headers=self._get_headers(), timeout=self.timeout_seconds
        )
        resp.raise_for_status()
        data = resp.json()
        raw_items = data.get("results", [])

        results: list[dict[str, str]] = []
        for item in raw_items:
            u = item.get("url", "")
            results.append({
                "title": item.get("title", "Result"),
                "url": u,
                "snippet": item.get("content", ""),
                "domain": urllib.parse.urlparse(u).netloc,
            })
        return results

    async def _execute_google_genai(
        self, query: str, dork: DorkQuery
    ) -> list[dict[str, str]]:
        """Executes grounded search query via Google GenAI SDK."""
        if not self.gemini_client and not settings.GEMINI_API_KEY:
            raise ValueError("Google GenAI client or GEMINI_API_KEY required")

        # Dynamic import / call to google-genai
        from google import genai

        client = self.gemini_client or genai.Client(api_key=settings.GEMINI_API_KEY)

        prompt = f"Execute this search dork and summarize all exact web search results found: {query}"
        response = await asyncio.to_thread(
            client.models.generate_content,
            model=settings.GEMINI_MODEL,
            contents=prompt,
            config={"tools": [{"google_search": {}}]},
        )
        usage_metadata = getattr(response, "usage_metadata", None)
        usage: dict[str, Any] = {}
        if isinstance(usage_metadata, dict):
            usage = usage_metadata
        elif usage_metadata is not None and hasattr(usage_metadata, "model_dump"):
            dumped = usage_metadata.model_dump(mode="json")
            if isinstance(dumped, dict):
                usage = dumped
        response_id = getattr(response, "response_id", None)
        model_version = getattr(response, "model_version", None)
        self.last_model_invocation = {
            "provider": "google_genai_sdk",
            "operation": "grounded_search",
            "requested_model": settings.GEMINI_MODEL,
            "model_version": model_version if isinstance(model_version, str) else None,
            "response_id": response_id if isinstance(response_id, str) else None,
            "usage": usage,
        }

        results: list[dict[str, str]] = []
        candidates = getattr(response, "candidates", [])
        if candidates:
            grounding_meta = getattr(candidates[0], "grounding_metadata", None)
            if grounding_meta and getattr(grounding_meta, "grounding_chunks", None):
                for chunk in grounding_meta.grounding_chunks:
                    web = getattr(chunk, "web", None)
                    if web:
                        uri = getattr(web, "uri", "")
                        title = getattr(web, "title", "Grounded Search Result")
                        results.append({
                            "title": title,
                            "url": uri,
                            "snippet": response.text[:300] if hasattr(response, "text") else title,
                            "domain": urllib.parse.urlparse(uri).netloc,
                        })

        if not results and hasattr(response, "text") and response.text:
            results.append({
                "title": f"Google Grounded Result for {dork.category.value}",
                "url": f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}",
                "snippet": response.text[:300],
                "domain": "google.com",
            })
        return results

    # --------------------------------------------------------------------------
    # Main Execution Interfaces
    # --------------------------------------------------------------------------

    async def execute_dork(
        self,
        dork: DorkQuery,
        target_name: str | None = None,
        target_input: TargetIdentityInput | None = None,
    ) -> list[SERPFinding]:
        """
        Executes a single dork query using the selected mode or fallback.
        Returns validated SERPFinding records with risk scores and matched PII tokens.
        """
        if not dork.raw_query or not dork.raw_query.strip():
            return []

        mode = self.mode
        parsed_items: list[dict[str, str]] = []
        self.last_model_invocation = None

        if mode == "mock":
            return self._fixture_findings(
                dork,
                target_name,
                target_input,
                ExecutionProvenance.CONTROLLED_FIXTURE,
            )

        async def _run_live() -> list[dict[str, str]]:
            async with self._semaphore:
                client = self._custom_client or httpx.AsyncClient(timeout=self.timeout_seconds)
                try:
                    if mode in ("duckduckgo_lite", "auto"):
                        return await self._execute_duckduckgo_lite(dork.raw_query, dork, client)
                    elif mode == "google_genai":
                        return await self._execute_google_genai(dork.raw_query, dork)
                    elif mode == "searxng":
                        return await self._execute_searxng(dork.raw_query, dork, client)
                    else:
                        return []
                finally:
                    if not self._custom_client:
                        await client.aclose()

        try:
            parsed_items = await asyncio.wait_for(_run_live(), timeout=self.timeout_seconds)
        except Exception as exc:
            logger.warning(
                "Live search failed (%s), falling back to mock fixture for dork: %s",
                type(exc).__name__,
                dork.dork_id,
            )
            return self._fixture_findings(
                dork,
                target_name,
                target_input,
                ExecutionProvenance.FALLBACK,
            )

        if not parsed_items and mode == "auto":
            return self._fixture_findings(
                dork,
                target_name,
                target_input,
                ExecutionProvenance.FALLBACK,
            )

        findings: list[SERPFinding] = []
        for item in parsed_items:
            t = item.get("title", "Unknown Title")
            u = item.get("url", "")
            s = item.get("snippet", "")
            dom = item.get("domain", urllib.parse.urlparse(u).netloc or "web")

            matched_pii = self._extract_pii_tokens(
                f"{t} {s} {u}", target_name=target_name, target_input=target_input
            )
            risk = self._calculate_risk(dork.category, t, s, matched_pii)

            findings.append(
                SERPFinding(
                    finding_id=f"fnd_{hashlib.sha256(f'{dork.dork_id}:{u}'.encode()).hexdigest()[:8]}",
                    dork_id=dork.dork_id,
                    title=t,
                    url=u,
                    snippet=s,
                    domain=dom,
                    discovered_at=datetime.now(timezone.utc),
                    risk_level=risk,
                    matched_pii_tokens=matched_pii,
                    dork_category=dork.category,
                    provenance=ExecutionProvenance.LIVE,
                )
            )

        self.last_provenance = ExecutionProvenance.LIVE
        return findings

    async def batch_execute_dorks(
        self,
        dorks: list[DorkQuery],
        target_name: str | None = None,
        target_input: TargetIdentityInput | None = None,
        max_concurrency: int | None = None,
        timeout_per_dork: float | None = None,
    ) -> list[SERPFinding]:
        """
        Executes a collection of dorks concurrently with bounded concurrency and timeout controls.
        """
        if not dorks:
            return []

        concurrency = max_concurrency or self.max_concurrency
        semaphore = asyncio.Semaphore(concurrency)
        per_dork_timeout = timeout_per_dork or self.timeout_seconds

        async def _safe_execute(d: DorkQuery) -> list[SERPFinding]:
            async with semaphore:
                try:
                    return await asyncio.wait_for(
                        self.execute_dork(d, target_name=target_name, target_input=target_input),
                        timeout=per_dork_timeout,
                    )
                except Exception as e:
                    logger.error(
                        "Error executing dork %s in batch (%s)",
                        d.dork_id,
                        type(e).__name__,
                    )
                    return self._fixture_findings(
                        d,
                        target_name,
                        target_input,
                        ExecutionProvenance.FALLBACK,
                    )

        tasks = [_safe_execute(d) for d in dorks]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: list[SERPFinding] = []
        seen_urls: set[str] = set()

        for res in batch_results:
            if isinstance(res, list):
                for f in res:
                    if f.url not in seen_urls:
                        seen_urls.add(f.url)
                        all_findings.append(f)

        return all_findings
