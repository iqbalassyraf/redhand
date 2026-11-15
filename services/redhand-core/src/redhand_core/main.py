"""
RedHand Core - FastAPI Application Factory & Lifespan Management
File: services/redhand-core/src/redhand_core/main.py

Initializes the Supabase `AsyncClient` (or the zero-config `LocalSupabaseAdapter`
in local dev mode) during startup, overrides `get_supabase_service_client` across
routers, and registers the Telemetry, HITL, Ephemeral IAM, and State/SSE routers.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from supabase import acreate_client

from redhand_core.config import Settings, get_settings
from redhand_core.middleware.body_limit import BodySizeLimitMiddleware
from redhand_core.middleware.security_headers import SecurityHeadersMiddleware
from redhand_core.routers.agent_auth import require_internal_service
from redhand_core.routers.agent_auth import router as agent_auth_router
from redhand_core.routers.dev import router as dev_router
from redhand_core.routers.hitl import router as hitl_router
from redhand_core.routers.passports import router as passports_router
from redhand_core.routers.iam_broker import get_sts_downscoper, router as iam_broker_router
from redhand_core.routers.scim import router as scim_router
from redhand_core.routers.state import router as state_router
from redhand_core.routers.blackbox import router as blackbox_router
from redhand_core.routers.honeytokens import router as honeytokens_router
from redhand_core.routers.mcp_scan import router as mcp_scan_router
from redhand_core.routers.radar import router as radar_router
from redhand_core.routers.destinations import router as destinations_router
from redhand_core.routers.risk import router as risk_router
from redhand_core.routers.tool_pins import router as tool_pins_router
from redhand_core.routers.events import router as events_router
from redhand_core.routers.telegram import router as telegram_router
from redhand_core.routers.usage import router as usage_router
from redhand_core.routers.telemetry import (
    get_supabase_service_client,
    router as telemetry_router,
)
from redhand_core.services.local_store import get_local_store
from redhand_core.services.metrics import get_metrics

logger = logging.getLogger("redhand.core.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Manages the startup and shutdown lifecycle of `redhand-core`:
    1. If a real `SUPABASE_URL` is configured, initializes `acreate_client`.
       Otherwise, binds the zero-config `LocalSupabaseAdapter` with SSE pub/sub.
    2. Cleanly closes outbound HTTPX connection pools on shutdown.
    """
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )

    supabase_client: Any

    if settings.uses_local_store:
        # The local store is seeded with a well-known dev API key and demo data. It must
        # never back a staging or production deployment (CLAUDE.md §5.2).
        if settings.ENVIRONMENT not in ("development", "test"):
            raise RuntimeError(
                "SUPABASE_URL is not configured; the in-memory local store is only allowed "
                "when ENVIRONMENT is 'development' or 'test'."
            )
        logger.info(
            "Starting %s v%s in Zero-Config Local Store + SSE Mode",
            settings.APP_NAME,
            settings.APP_VERSION,
        )
        supabase_client = get_local_store()
    else:
        logger.info(
            "Starting %s v%s connected to Supabase (%s)",
            settings.APP_NAME,
            settings.APP_VERSION,
            settings.SUPABASE_URL,
        )
        supabase_client = await acreate_client(
            settings.SUPABASE_URL,
            settings.SUPABASE_SERVICE_ROLE_KEY.get_secret_value(),
        )

    app.state.supabase_client = supabase_client

    try:
        yield
    finally:
        logger.info("Shutting down %s and closing connection pools...", settings.APP_NAME)
        if hasattr(supabase_client, "postgrest") and hasattr(
            supabase_client.postgrest, "aclose"
        ):
            await supabase_client.postgrest.aclose()
        downscoper = get_sts_downscoper()
        await downscoper.aclose()


def create_app(settings: Settings | None = None) -> FastAPI:
    """
    Constructs and configures the production FastAPI instance for `redhand-core`.
    """
    active_settings = settings or get_settings()

    app = FastAPI(
        title=active_settings.APP_NAME,
        description="Agentic Security Posture Management (ASPM) & Runtime Protection Engine",
        version=active_settings.APP_VERSION,
        lifespan=lifespan,
    )

    async def _provide_supabase_service_client(request: Request) -> Any:
        client = getattr(request.app.state, "supabase_client", None)
        if client is None:
            return get_local_store()
        return client

    app.dependency_overrides[get_supabase_service_client] = _provide_supabase_service_client

    # Added before CORS, so CORS wraps it and a refused body still carries the CORS headers the browser needs to read the 413.
    app.add_middleware(
        BodySizeLimitMiddleware,
        default_limit=active_settings.MAX_REQUEST_BYTES,
        path_limits={
            "/internal/v1/events": active_settings.MAX_INGEST_REQUEST_BYTES,
            "/v1/telemetry": active_settings.MAX_INGEST_REQUEST_BYTES,
        },
    )
    app.add_middleware(SecurityHeadersMiddleware)  # outside the body limit, so a 413 carries the headers too
    app.add_middleware(
        CORSMiddleware,
        allow_origins=active_settings.CORS_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(telemetry_router)
    app.include_router(hitl_router)
    app.include_router(iam_broker_router)
    app.include_router(state_router)
    app.include_router(scim_router)
    app.include_router(passports_router)
    app.include_router(agent_auth_router)
    app.include_router(telegram_router)
    app.include_router(usage_router)
    app.include_router(events_router)
    app.include_router(blackbox_router)
    app.include_router(honeytokens_router)
    app.include_router(mcp_scan_router)
    app.include_router(tool_pins_router)
    app.include_router(radar_router)
    app.include_router(destinations_router)
    app.include_router(risk_router)
    if (
        active_settings.ENVIRONMENT == "development"
        and active_settings.uses_local_store
        and not active_settings.OPERATOR_JWKS_URL
    ):
        app.include_router(dev_router)

    # Google Cloud Run's front end can intercept /healthz (it never reaches the app), so the
    # same check is also served at /health. Use /health on Cloud Run, either elsewhere.
    @app.get("/health", tags=["System"])
    @app.get("/healthz", tags=["System"])
    async def healthcheck() -> dict[str, str]:
        return {
            "status": "healthy",
            "service": "redhand-core",
            "version": active_settings.APP_VERSION,
            "environment": active_settings.ENVIRONMENT,
        }

    # Metrics reveal traffic volumes and internal names, so they need the same service token as
    # the other internal endpoints. Without a configured token the endpoint answers 503 (closed).
    @app.get("/metrics", tags=["Observability"], dependencies=[Depends(require_internal_service)])
    async def get_prometheus_metrics() -> Response:
        metrics_data = get_metrics().render_prometheus()
        return Response(
            content=metrics_data,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    return app


app = create_app()
