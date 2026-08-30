"""
Project Umbra Resilient Playwright Stealth Browser Scanner & Anti-Bot Evasion.
Scrapes public people-search directories with anti-bot evasion scripts,
challenge DOM detection (Cloudflare/DataDome/PerimeterX/Akamai),
and deterministic synthetic HTML fixture fallback.
"""

from __future__ import annotations

import asyncio
import html
from html.parser import HTMLParser
import logging
from pathlib import Path
import random
import re
import time
from typing import Any
from urllib.parse import quote, quote_plus

from project_umbra.config import settings
from project_umbra.core.state import (
    BrokerScanResult,
    BrokerScanTarget,
    ExecutionProvenance,
    TargetIdentityInput,
)
from project_umbra.tools.fixtures import render_broker_fixture

logger = logging.getLogger(__name__)

# Directory path for synthetic mock HTML fixtures
FIXTURES_DIR = Path(__file__).parent / "fixtures"

# User-Agent rotation pool (Modern Chrome on macOS and Windows)
STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]

# Viewport dimensions rotation pool
STEALTH_VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1440, "height": 900},
    {"width": 1536, "height": 864},
    {"width": 1366, "height": 768},
]

# Anti-Bot Evasion JavaScript Init Script
STEALTH_EVASION_SCRIPT = """
(() => {
    // 1. Mask navigator.webdriver
    Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
        configurable: true
    });

    // 2. Mock window.chrome object
    if (!window.chrome) {
        window.chrome = {};
    }
    window.chrome.runtime = {
        PlatformOs: { MAC: 'mac', WIN: 'win', ANDROID: 'android', CROS: 'cros', LINUX: 'linux' },
        PlatformArch: { ARM: 'arm', X86_64: 'x86-64' },
        RequestUpdateCheckStatus: { NO_UPDATE: 'no_update', UPDATE_AVAILABLE: 'update_available' },
        OnInstalledReason: { INSTALL: 'install', UPDATE: 'update' }
    };
    window.chrome.loadTimes = function() {
        return {
            commitLoadTime: Date.now() / 1000 - 0.5,
            connectionInfo: 'http/1.1',
            finishDocumentLoadTime: Date.now() / 1000 - 0.2,
            finishLoadTime: Date.now() / 1000 - 0.1,
            firstPaintAfterLoadTime: 0,
            firstPaintTime: Date.now() / 1000 - 0.3,
            navigationType: 'Other',
            requestTime: Date.now() / 1000 - 1.0,
            startLoadTime: Date.now() / 1000 - 0.9,
            wasAlternateProtocolAvailable: false,
            wasFetchedViaSpdy: false,
            wasNpnNegotiated: false
        };
    };
    window.chrome.csi = function() {
        return {
            onloadT: Date.now(),
            pageT: 850,
            startE: Date.now() - 850,
            tran: 15
        };
    };
    window.chrome.app = {
        isInstalled: false,
        InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
        RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }
    };

    // 3. Spoof Plugins & MimeTypes
    const fakePlugins = [
        { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
        { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
        { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
        { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
        { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: 'Portable Document Format' }
    ];
    Object.defineProperty(navigator, 'plugins', {
        get: () => fakePlugins,
        configurable: true
    });
    Object.defineProperty(navigator, 'mimeTypes', {
        get: () => [
            { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: fakePlugins[0] },
            { type: 'text/pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: fakePlugins[0] }
        ],
        configurable: true
    });

    // 4. Spoof Languages
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
        configurable: true
    });
    Object.defineProperty(navigator, 'language', {
        get: () => 'en-US',
        configurable: true
    });

    // 5. Spoof Hardware Concurrency & Memory
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8, configurable: true });
    Object.defineProperty(navigator, 'deviceMemory', { get: () => 8, configurable: true });

    // 6. Permissions Spoofing
    const origPermissions = window.navigator.permissions ? window.navigator.permissions.query : null;
    if (origPermissions) {
        window.navigator.permissions.query = (params) => (
            params.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                origPermissions(params)
        );
    }

    // 7. WebGL Vendor / Renderer Masking
    if (typeof WebGLRenderingContext !== 'undefined') {
        const getParam = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(param) {
            if (param === 37445) return 'Google Inc. (Apple)';
            if (param === 37446) return 'ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)';
            return getParam.apply(this, [param]);
        };
    }
    if (typeof WebGL2RenderingContext !== 'undefined') {
        const getParam2 = WebGL2RenderingContext.prototype.getParameter;
        WebGL2RenderingContext.prototype.getParameter = function(param) {
            if (param === 37445) return 'Google Inc. (Apple)';
            if (param === 37446) return 'ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)';
            return getParam2.apply(this, [param]);
        };
    }
})();
"""

# Signatures indicating bot challenge, CAPTCHA, or blocking DOM
CHALLENGE_SIGNATURES = [
    # Cloudflare
    "cf-challenge-running",
    "cf-turnstile",
    "cf-browser-verification",
    "challenge-platform",
    "checking your browser",
    "attention required",
    "cloudflare ray id",
    "challenge-stage",
    "cf-wrapper",
    # DataDome
    "geo.captcha-delivery.com",
    "datadome",
    "blocked by datadome",
    "dd-captcha",
    "please verify you are a human",
    # PerimeterX / HUMAN
    "_pxappid",
    "px-captcha",
    "access to this page has been denied",
    "px-block",
    # Akamai / WAF
    "ak-challenge",
    "akamai-bm",
    "access denied",
    "you don't have permission to access",
]


class _HTMLTextExtractor(HTMLParser):
    """Clean standard-library HTML text extractor stripping script/style tags."""

    def __init__(self) -> None:
        super().__init__()
        self.text_parts: list[str] = []
        self._skip_tag = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in ("script", "style", "svg", "noscript", "head"):
            self._skip_tag = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in ("script", "style", "svg", "noscript", "head"):
            self._skip_tag = False
        elif tag.lower() in ("p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"):
            self.text_parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_tag:
            clean = data.strip()
            if clean:
                self.text_parts.append(clean + " ")

    def get_text(self) -> str:
        raw = "".join(self.text_parts)
        # Normalize repeated newlines and whitespace
        return re.sub(r"\n\s*\n", "\n", raw).strip()


def extract_clean_text(html_content: str) -> str:
    """Strips tags and returns readable semantic text."""
    if not html_content:
        return ""
    parser = _HTMLTextExtractor()
    try:
        parser.feed(html_content)
        return parser.get_text()
    except Exception:
        # Regex fallback
        no_scripts = re.sub(r"<(script|style).*?</\1>", "", html_content, flags=re.DOTALL | re.IGNORECASE)
        no_tags = re.sub(r"<[^>]+>", " ", no_scripts)
        return re.sub(r"\s+", " ", html.unescape(no_tags)).strip()


def detect_challenge_dom(html_content: str, status_code: int = 200) -> bool:
    """
    Detects whether the DOM or HTTP status indicates an anti-bot challenge.
    """
    if status_code in (403, 429):
        return True
    if not html_content:
        return True

    lower_html = html_content.lower()
    for sig in CHALLENGE_SIGNATURES:
        if sig in lower_html:
            return True
    return False


def build_broker_search_url(broker: BrokerScanTarget, identity: TargetIdentityInput) -> str:
    """
    Constructs an optimized target search URL for the given data broker.
    """
    name_encoded = quote_plus(identity.full_name)
    name_slug = re.sub(r"[^a-z0-9]+", "-", identity.full_name.lower()).strip("-")

    city = identity.current_city or ""
    state = identity.current_state or ""
    location_str = f"{city} {state}".strip()
    loc_encoded = quote_plus(location_str)
    loc_slug = re.sub(r"[^a-z0-9]+", "-", f"{city}-{state}".lower()).strip("-")

    broker_id = broker.broker_id.lower()

    if broker_id == "truepeoplesearch":
        if location_str:
            return f"https://www.truepeoplesearch.com/results?name={name_encoded}&citystatezip={loc_encoded}"
        return f"https://www.truepeoplesearch.com/results?name={name_encoded}"

    elif broker_id == "fastpeoplesearch":
        if loc_slug:
            return f"https://www.fastpeoplesearch.com/name/{name_slug}_{loc_slug}"
        return f"https://www.fastpeoplesearch.com/name/{name_slug}"

    elif broker_id == "radaris":
        return f"https://radaris.com/p/{name_slug}"

    elif broker_id == "nuwber":
        return f"https://nuwber.com/person/{name_slug}"

    elif broker_id == "whitepages":
        if loc_slug:
            return f"https://www.whitepages.com/name/{name_slug}/{loc_slug}"
        return f"https://www.whitepages.com/name/{name_slug}"

    # Default template formatting
    return broker.search_url_template.format(
        name=name_encoded,
        location=loc_encoded or "",
    )


class PlaywrightStealthScanner:
    """
    Resilient Playwright stealth browser scraper with anti-bot evasion,
    challenge DOM detection, single shared browser instance, and
    deterministic synthetic fixture fallback.
    """

    def __init__(
        self,
        headless: bool | None = None,
        simulation_mode: bool | None = None,
        timeout_ms: int | None = None,
        max_concurrency: int = 3,
        fixtures_dir: Path | None = None,
    ) -> None:
        self.headless = settings.PLAYWRIGHT_HEADLESS if headless is None else headless
        self.simulation_mode = settings.PLAYWRIGHT_SIMULATION_MODE if simulation_mode is None else simulation_mode
        self.timeout_ms = settings.PLAYWRIGHT_TIMEOUT_MS if timeout_ms is None else timeout_ms
        self.max_concurrency = max_concurrency
        self.fixtures_dir = fixtures_dir or FIXTURES_DIR

        self._playwright: Any | None = None
        self._browser: Any | None = None
        self._semaphore = asyncio.Semaphore(self.max_concurrency)
        self._lock = asyncio.Lock()
        self._is_initialized = False

    async def initialize(self) -> None:
        """Initializes the shared Playwright Chromium browser instance."""
        if self._is_initialized or self.simulation_mode:
            return

        async with self._lock:
            if self._is_initialized:
                return

            try:
                from playwright.async_api import async_playwright
                self._playwright = await async_playwright().start()
                self._browser = await self._playwright.chromium.launch(
                    headless=self.headless,
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-web-security",
                        "--disable-features=IsolateOrigins,site-per-process",
                    ],
                )
                self._is_initialized = True
                logger.info("PlaywrightStealthScanner initialized shared browser.")
            except Exception as e:
                logger.warning(
                    "Failed to launch live Playwright browser (%s). Falling back to simulation mode.",
                    type(e).__name__,
                )
                self.simulation_mode = True

    async def close(self) -> None:
        """Gracefully closes all browser instances and stops Playwright."""
        async with self._lock:
            if self._browser:
                try:
                    await self._browser.close()
                except Exception:
                    pass
                self._browser = None

            if self._playwright:
                try:
                    await self._playwright.stop()
                except Exception:
                    pass
                self._playwright = None

            self._is_initialized = False
            logger.info("PlaywrightStealthScanner shut down cleanly.")

    async def __aenter__(self) -> PlaywrightStealthScanner:
        await self.initialize()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    def load_synthetic_fixture(
        self,
        broker_id: str,
        identity: TargetIdentityInput,
    ) -> tuple[str, str]:
        """
        Loads the synthetic HTML fixture for the broker and interpolates target identity data.
        Returns tuple of (rendered_html, profile_url).
        """
        return render_broker_fixture(broker_id, identity)

    async def scan_broker(
        self,
        target: BrokerScanTarget,
        identity: TargetIdentityInput,
    ) -> BrokerScanResult:
        """
        Executes a stealth scan against a target broker with automatic anti-bot evasion
        and deterministic fixture fallback.
        """
        t0 = time.perf_counter()
        target_location = f"{identity.current_city or ''} {identity.current_state or ''}".strip() or None
        search_url = build_broker_search_url(target, identity)

        # 1. Explicit controlled-fixture mode. In live mode initialize the
        # browser lazily so callers cannot accidentally skip real acquisition.
        if self.simulation_mode:
            rendered_html, profile_url = self.load_synthetic_fixture(target.broker_id, identity)
            extracted_text = extract_clean_text(rendered_html)
            dur_ms = (time.perf_counter() - t0) * 1000
            return BrokerScanResult(
                broker_id=target.broker_id,
                target_name=identity.full_name,
                target_location=target_location,
                profile_url=profile_url,
                is_exposed=True,
                raw_html=rendered_html,
                extracted_text=extracted_text,
                status_code=200,
                execution_time_ms=dur_ms,
                is_simulated=True,
                provenance=ExecutionProvenance.CONTROLLED_FIXTURE,
            )

        if not self._is_initialized or not self._browser:
            await self.initialize()
        if self.simulation_mode or not self._browser:
            rendered_html, profile_url = self.load_synthetic_fixture(target.broker_id, identity)
            extracted_text = extract_clean_text(rendered_html)
            dur_ms = (time.perf_counter() - t0) * 1000
            return BrokerScanResult(
                broker_id=target.broker_id,
                target_name=identity.full_name,
                target_location=target_location,
                profile_url=profile_url,
                is_exposed=True,
                raw_html=rendered_html,
                extracted_text=extracted_text,
                status_code=200,
                execution_time_ms=dur_ms,
                is_simulated=True,
                provenance=ExecutionProvenance.FALLBACK,
            )

        # 2. Live Stealth Browser Sweep
        async with self._semaphore:
            context = None
            page = None
            try:
                # Randomize stealth context parameters
                user_agent = random.choice(STEALTH_USER_AGENTS)
                viewport = random.choice(STEALTH_VIEWPORTS)

                context = await self._browser.new_context(
                    user_agent=user_agent,
                    viewport=viewport,
                    locale="en-US",
                    timezone_id="America/New_York",
                    extra_http_headers={
                        "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
                        "Sec-Ch-Ua-Mobile": "?0",
                        "Sec-Ch-Ua-Platform": '"macOS"' if "Macintosh" in user_agent else '"Windows"',
                        "Accept-Language": "en-US,en;q=0.9",
                        "Upgrade-Insecure-Requests": "1",
                    },
                )

                # Inject anti-bot stealth scripts before page navigation
                await context.add_init_script(STEALTH_EVASION_SCRIPT)
                page = await context.new_page()

                # Human jitter delay
                await asyncio.sleep(random.uniform(0.15, 0.35))

                response = await page.goto(
                    search_url,
                    timeout=self.timeout_ms,
                    wait_until="domcontentloaded",
                )

                status_code = response.status if response else 200
                html_content = await page.content()
                current_url = page.url

                # Check for anti-bot challenges or access denial
                if detect_challenge_dom(html_content, status_code):
                    logger.info(
                        f"Bot challenge detected on {target.broker_id} (Status {status_code}). Triggering fixture fallback."
                    )
                    rendered_html, profile_url = self.load_synthetic_fixture(target.broker_id, identity)
                    extracted_text = extract_clean_text(rendered_html)
                    dur_ms = (time.perf_counter() - t0) * 1000
                    return BrokerScanResult(
                        broker_id=target.broker_id,
                        target_name=identity.full_name,
                        target_location=target_location,
                        profile_url=profile_url,
                        is_exposed=True,
                        raw_html=rendered_html,
                        extracted_text=extracted_text,
                        status_code=200,
                        execution_time_ms=dur_ms,
                        is_simulated=True,
                        provenance=ExecutionProvenance.FALLBACK,
                    )

                # Successful Live Scrape
                extracted_text = extract_clean_text(html_content)
                is_exposed = identity.full_name.lower() in extracted_text.lower()
                dur_ms = (time.perf_counter() - t0) * 1000

                return BrokerScanResult(
                    broker_id=target.broker_id,
                    target_name=identity.full_name,
                    target_location=target_location,
                    profile_url=current_url if is_exposed else None,
                    is_exposed=is_exposed,
                    raw_html=html_content,
                    extracted_text=extracted_text,
                    status_code=status_code,
                    execution_time_ms=dur_ms,
                    is_simulated=False,
                    provenance=ExecutionProvenance.LIVE,
                )

            except Exception as exc:
                logger.warning(
                    "Stealth scan failed on %s (%s). Triggering fallback fixture.",
                    target.broker_id,
                    type(exc).__name__,
                )
                rendered_html, profile_url = self.load_synthetic_fixture(target.broker_id, identity)
                extracted_text = extract_clean_text(rendered_html)
                dur_ms = (time.perf_counter() - t0) * 1000
                return BrokerScanResult(
                    broker_id=target.broker_id,
                    target_name=identity.full_name,
                    target_location=target_location,
                    profile_url=profile_url,
                    is_exposed=True,
                    raw_html=rendered_html,
                    extracted_text=extracted_text,
                    status_code=200,
                    execution_time_ms=dur_ms,
                    is_simulated=True,
                    provenance=ExecutionProvenance.FALLBACK,
                )
            finally:
                if page:
                    try:
                        await page.close()
                    except Exception:
                        pass
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass

    async def scan_all_brokers(
        self,
        targets: list[BrokerScanTarget],
        identity: TargetIdentityInput,
    ) -> list[BrokerScanResult]:
        """
        Executes concurrent stealth sweeps across multiple broker targets.
        """
        tasks = [self.scan_broker(target, identity) for target in targets]
        return await asyncio.gather(*tasks)
