"""
Project Umbra Configuration & Settings Module.
Uses Pydantic Settings for typed, environment-driven configuration.
"""

from __future__ import annotations

from typing import Literal
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global application settings and configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application & Server
    APP_NAME: str = "Project Umbra"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development", "production", "test"] = "development"
    PORT: int = Field(default=8000, description="Server port")
    HOST: str = Field(default="0.0.0.0", description="Server bind host")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    APP_COMMIT_SHA: str = Field(default="unknown", description="Source commit deployed to this service")
    UMBRA_OPERATOR_TOKEN: str = Field(
        default="",
        description="Privileged operator access token for production missions",
    )
    JUDGE_ACCESS_TOKEN: str = Field(
        default="",
        description="Deprecated production access token retained for deployment compatibility",
    )
    UMBRA_ACCESS_SECRET: str = Field(default="", description="HMAC secret for mission-scoped capability tokens")
    MISSION_TOKEN_TTL_SECONDS: int = Field(default=86400, ge=300, le=604800)
    CORS_ALLOWED_ORIGINS: str = Field(
        default="",
        description="Comma-separated explicit browser origins; wildcard origins are never credentialed",
    )

    # AI Model Configuration
    GEMINI_API_KEY: str = Field(default="", description="Google Gemini API Key")
    GEMINI_MODEL: str = Field(default="gemini-3.7-flash", description="Primary reasoning & extraction model")
    GEMMA_MODEL: str = Field(default="gemma-2-9b-it", description="Secondary PII classification model")
    GEMMA_LOCAL_PIPELINE: bool = Field(default=False, description="Use local HF pipeline for Gemma if True")
    PII_CLASSIFIER_MODE: Literal["heuristic", "neural"] = Field(
        default="heuristic",
        description="PII classifier implementation; telemetry reports the configured mode truthfully",
    )

    # Persistence Configuration
    PERSISTENCE_MODE: Literal["auto", "firestore", "sqlite"] = Field(
        default="auto",
        description="Dual-mode persistence selector: 'auto', 'firestore', or 'sqlite'",
    )
    GCP_PROJECT_ID: str = Field(default="", description="GCP Project ID for Firestore")
    FIRESTORE_DATABASE: str = Field(default="(default)", description="Firestore database name")
    SQLITE_DB_PATH: str = Field(default="data/project_umbra.db", description="Local SQLite path")

    # Agent Execution Controls
    AGENT_MAX_STEP_BUDGET: int = Field(default=25, description="Maximum execution step budget")
    PLAYWRIGHT_HEADLESS: bool = Field(default=True, description="Run Playwright in headless mode")
    PLAYWRIGHT_SIMULATION_MODE: bool = Field(default=False, description="Force deterministic mock fixtures")
    PLAYWRIGHT_TIMEOUT_MS: int = Field(default=15000, description="Browser navigation timeout")

    # SERP Scanner Configuration
    SERP_MODE: Literal["auto", "duckduckgo_lite", "google_genai", "searxng", "mock"] = Field(
        default="auto",
        description="SERP query provider: 'auto', 'duckduckgo_lite', 'google_genai', 'searxng', or 'mock'",
    )
    SERP_MAX_CONCURRENCY: int = Field(default=3, description="Maximum concurrent SERP queries")
    SERP_TIMEOUT_SECONDS: float = Field(default=10.0, description="Per-dork query timeout in seconds")
    SERP_JITTER_MIN_MS: int = Field(default=150, description="Minimum request jitter delay in milliseconds")
    SERP_JITTER_MAX_MS: int = Field(default=600, description="Maximum request jitter delay in milliseconds")
    SEARXNG_URL: str = Field(default="", description="Base URL for SearXNG instance if configured")


# Global singleton instance
settings = Settings()
