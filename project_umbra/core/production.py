"""Production dependency composition for the Umbra investigation agent."""

from __future__ import annotations

import logging
import os
from typing import Any

from project_umbra.classifiers.gemma_classifier import GemmaSanitizerClassifier
from project_umbra.config import settings
from project_umbra.core.agent import ProjectUmbraAgent
from project_umbra.tools.browser_scanner import PlaywrightStealthScanner
from project_umbra.tools.serp_scanner import SERPScanner
from project_umbra.tools.structured_extractor import StructuredExtractor
from project_umbra.tools.suppression_engine import SuppressionEngine

logger = logging.getLogger(__name__)


def _build_genai_client(api_key: str | None) -> Any | None:
    """Build a Google GenAI SDK client only when credentials are available."""
    resolved_key = (api_key or os.environ.get("GEMINI_API_KEY") or settings.GEMINI_API_KEY).strip()
    if not resolved_key:
        return None

    try:
        from google import genai

        return genai.Client(api_key=resolved_key)
    except Exception as exc:
        logger.warning(
            "Google GenAI client initialization failed (%s)",
            type(exc).__name__,
        )
        return None


def build_production_agent(
    *,
    max_budget: int | None = None,
    api_key: str | None = None,
) -> ProjectUmbraAgent:
    """
    Compose the production investigation pipeline.

    This factory wires discovery, browser acquisition, structured extraction,
    truthful PII classification, and action-plan generation. It intentionally
    does not call any suppression dispatch API.
    """
    resolved_key = api_key or os.environ.get("GEMINI_API_KEY") or settings.GEMINI_API_KEY
    genai_client = _build_genai_client(resolved_key)

    classifier_mode = settings.PII_CLASSIFIER_MODE
    classifier_client = genai_client if classifier_mode == "neural" else None

    return ProjectUmbraAgent(
        gemini_client=genai_client,
        serp_scanner=SERPScanner(
            mode=settings.SERP_MODE,
            gemini_client=genai_client,
        ),
        browser_scanner=PlaywrightStealthScanner(
            headless=settings.PLAYWRIGHT_HEADLESS,
            simulation_mode=settings.PLAYWRIGHT_SIMULATION_MODE,
            timeout_ms=settings.PLAYWRIGHT_TIMEOUT_MS,
        ),
        extractor=StructuredExtractor(
            api_key=resolved_key,
            model_name=settings.GEMINI_MODEL,
            client=genai_client,
            offline_mode=genai_client is None,
        ),
        gemma_sanitizer=GemmaSanitizerClassifier(
            mode=classifier_mode,
            gemma_model=settings.GEMMA_MODEL,
            genai_client=classifier_client,
        ),
        suppression_engine=SuppressionEngine(
            simulation_mode=settings.PLAYWRIGHT_SIMULATION_MODE,
        ),
        max_budget=settings.AGENT_MAX_STEP_BUDGET if max_budget is None else max_budget,
    )


__all__ = ["build_production_agent"]
