FROM python:3.12-slim-bookworm AS builder
COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /usr/local/bin/uv

ENV UV_PYTHON_DOWNLOADS=0 \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project --no-cache

FROM python:3.12-slim-bookworm AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
COPY --from=builder /opt/venv /opt/venv
RUN python -m playwright install --with-deps chromium && \
    chmod -R a+rX /ms-playwright

RUN groupadd -r project_umbra && useradd -r -g project_umbra project_umbra
WORKDIR /app
COPY project_umbra/ ./project_umbra/
COPY pyproject.toml ./
RUN mkdir -p /app/data && chown -R project_umbra:project_umbra /app
USER project_umbra

ENV PORT=8080 \
    HOST=0.0.0.0 \
    ENVIRONMENT=production \
    PLAYWRIGHT_HEADLESS=true \
    PLAYWRIGHT_SIMULATION_MODE=false \
    PERSISTENCE_MODE=auto \
    LOG_LEVEL=INFO

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT}/api/v1/health')"

CMD ["sh", "-c", "uvicorn project_umbra.api.app:app --host ${HOST} --port ${PORT} --workers 1 --loop asyncio"]
