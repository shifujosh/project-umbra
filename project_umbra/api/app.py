"""
Project Umbra FastAPI Application Factory & Lifespan Management.
Sets up CORS, error handling middleware, SSE broadcaster state, storage resolver,
and template/static mounts for the Cybernetic Dark Web UI.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging
from pathlib import Path
from typing import AsyncGenerator, Callable
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from project_umbra.api.routes import router
from project_umbra.api.sse import SSEBroadcaster
from project_umbra.config import settings
from project_umbra.core.mission_runner import MissionExecutionManager
from project_umbra.storage.resolver import get_storage_repository

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager initializing storage, state, and cleanup."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} ({settings.ENVIRONMENT})")

    if settings.ENVIRONMENT == "production":
        if not settings.UMBRA_ACCESS_SECRET:
            raise RuntimeError("UMBRA_ACCESS_SECRET is required for production startup.")
        if not (settings.UMBRA_OPERATOR_TOKEN or settings.JUDGE_ACCESS_TOKEN):
            raise RuntimeError(
                "UMBRA_OPERATOR_TOKEN is required for production startup "
                "(legacy JUDGE_ACCESS_TOKEN remains supported)."
            )

    # 1. Initialize Dual-Mode Storage
    repo = getattr(app.state, "repository", None) or getattr(app.state, "storage", None)
    if repo is None:
        repo = get_storage_repository()
        await repo.initialize()

    # 2. Initialize SSE Broadcaster & Mission Manager
    broadcaster = getattr(app.state, "broadcaster", None) or getattr(app.state, "sse_broadcaster", None)
    if broadcaster is None:
        broadcaster = SSEBroadcaster()

    manager = getattr(app.state, "mission_manager", None) or getattr(app.state, "manager", None)
    if manager is None:
        manager = MissionExecutionManager(repository=repo, sse_broadcaster=broadcaster)

    # Attach all aliases to app state
    app.state.repository = repo
    app.state.storage = repo
    app.state.broadcaster = broadcaster
    app.state.sse_broadcaster = broadcaster
    app.state.mission_manager = manager
    app.state.manager = manager
    app.state.active_missions = manager._task_metadata

    logger.info(f"Project Umbra initialized with storage backend: {repo.backend_type}")

    yield

    # 3. Shutdown: Cancel active tasks and close connections
    logger.info("Shutting down Project Umbra API...")
    if manager:
        await manager.shutdown()
    if repo:
        await repo.close()


def create_app() -> FastAPI:
    """Creates and configures the FastAPI application instance."""
    expose_api_docs = settings.ENVIRONMENT != "production"
    app = FastAPI(
        title="Project Umbra — Personal Privacy Agent",
        description=(
            "Turns an authorized identity profile into source-linked evidence, "
            "a current-risk report, and an approval-ready action plan."
        ),
        version=settings.APP_VERSION,
        lifespan=lifespan,
        docs_url="/docs" if expose_api_docs else None,
        redoc_url="/redoc" if expose_api_docs else None,
        openapi_url="/openapi.json" if expose_api_docs else None,
    )

    # 1. CORS Middleware Configuration. Same-origin is the production default;
    # explicit cross-origin allowlists can be configured without wildcard credentials.
    configured_origins = [
        origin.strip()
        for origin in settings.CORS_ALLOWED_ORIGINS.split(",")
        if origin.strip() and origin.strip() != "*"
    ]
    if settings.ENVIRONMENT != "production" and not configured_origins:
        configured_origins = ["http://localhost:8000", "http://127.0.0.1:8000"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=configured_origins,
        allow_credentials=bool(configured_origins),
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Location", "Content-Type"],
    )

    # 1b. BYOK Middleware — keeps the credential scoped to this request.
    class BYOKMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: Callable) -> Response:
            api_key = request.headers.get("X-Gemini-Api-Key", "").strip()
            if api_key:
                request.state.gemini_api_key = api_key
            response = await call_next(request)
            if (
                settings.ENVIRONMENT == "production"
                and request.url.path.startswith("/api/v1/")
                and "cache-control" not in response.headers
            ):
                response.headers["Cache-Control"] = "no-store"
            return response

    app.add_middleware(BYOKMiddleware)

    # 2. Global Exception Handlers
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "detail": exc.errors(),
                "error_type": "validation_error",
                "message": "Input validation failed. Please inspect request payload fields.",
            },
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "detail": exc.detail,
                "status_code": exc.status_code,
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        if settings.ENVIRONMENT == "production":
            logger.error(
                "Unhandled server exception type=%s path=%s",
                type(exc).__name__,
                request.url.path,
            )
        else:
            logger.error("Unhandled server exception: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error occurred.",
                "message": str(exc) if settings.ENVIRONMENT != "production" else "Internal server error.",
            },
        )

    # 3. Mount Static & Templates if available
    base_dir = Path(__file__).resolve().parent.parent
    static_dir = base_dir / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # 4. Include API Routers
    app.include_router(router)

    # 5. Controlled synthetic demo replay router
    from project_umbra.api.demo import demo_router
    app.include_router(demo_router)

    # 6. Serve web dashboard at root
    from project_umbra.api.dashboard import dashboard_router
    app.include_router(dashboard_router)

    return app


app = create_app()
