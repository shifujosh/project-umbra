# ============================================================
# Project Umbra — Multi-Stage Cloud Run Dockerfile
# Optimized for Playwright + Python 3.12 on Google Cloud Run
# ============================================================

# ── Stage 1: Build deps ──────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install --no-cache-dir \
        pydantic>=2.10.0 \
        pydantic-settings>=2.7.0 \
        google-genai>=2.0.0 \
        google-cloud-firestore>=2.21.0 \
        fastapi>=0.115.0 \
        uvicorn>=0.30.0 \
        sse-starlette>=2.1.0 \
        playwright>=1.49.0 \
        aiosqlite>=0.20.0 \
        httpx>=0.28.0 \
        python-dotenv>=1.0.0 \
        aiofiles>=24.0.0


# ── Stage 2: Runtime ─────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Install Playwright browser system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Chromium deps
    libnss3 libatk-bridge2.0-0 libdrm2 libxkbcommon0 \
    libgbm1 libasound2 libxrandr2 libpangocairo-1.0-0 \
    libxcomposite1 libxdamage1 libxfixes3 libxcursor1 \
    libgtk-3-0 libglib2.0-0 libdbus-1-3 libx11-xcb1 \
    # Fonts & locales
    fonts-liberation ca-certificates wget && \
    rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Install Playwright Chromium browser
RUN playwright install chromium --with-deps 2>/dev/null || playwright install chromium

# Create non-root app user (Cloud Run security best practice)
RUN groupadd -r project_umbra && useradd -r -g project_umbra project_umbra

WORKDIR /app

# Copy application source
COPY project_umbra/ ./project_umbra/
COPY pyproject.toml ./

# Create data directory for SQLite fallback
RUN mkdir -p /app/data && chown -R project_umbra:project_umbra /app

USER project_umbra

# Cloud Run uses PORT env var; default 8080
ENV PORT=8080
ENV HOST=0.0.0.0
ENV ENVIRONMENT=production
ENV PLAYWRIGHT_HEADLESS=true
ENV PLAYWRIGHT_SIMULATION_MODE=false
ENV PERSISTENCE_MODE=auto
ENV LOG_LEVEL=INFO

EXPOSE 8080

# Health check for Cloud Run readiness
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT}/api/v1/health')"

CMD ["sh", "-c", "uvicorn project_umbra.api.app:app --host ${HOST} --port ${PORT} --workers 1 --loop asyncio"]
