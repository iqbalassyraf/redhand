"""
FastAPI application entrypoint for AgentWall, the RedHand MCP gateway.

Public surface:
- POST /mcp/{server}   agents' MCP traffic (agent access token required)
- POST /v1/mcp/vet     static MCP manifest vetting (public, size- and rate-limited)
- GET  /health, /healthz   liveness (use /health on Cloud Run)
Operational endpoints (/v1/policies, /v1/audit/*, /metrics) require the internal
service token; operators reach audit data through redhand-core.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import hmac
import json
import math
import time
from typing import Annotated, Any, AsyncGenerator
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, Field
import structlog

from ..config.settings import Settings, get_settings
from .firewall.engine import FirewallPolicyEngine
from .firewall.mcp_vetting import MCPServerAuditor, MCPVettingReport
from .gateway.scan import ScanError, list_tools
from .gateway.budget import BudgetMeter, HttpUsageReporter
from .gateway.loops import LoopMeter
from .gateway.context import CoreContextClient
from .gateway.identity import AgentTokenVerifier
from .gateway.metrics import GatewayMetrics
from .gateway.pins import HttpPinReporter, PinCoordinator
from .gateway.radar_scan import HttpFindingsReporter, HttpScanCountsReporter, RadarScanner
from .gateway.selftest import BusyError, SelfTestError, SelfTestRunner
from .gateway.recorder import EventRecorder, HttpEventReporter
from .gateway.trips import HttpTripReporter, TripDispatcher
from .gateway.service import McpGateway
from .gateway.upstream import UpstreamForwarder
from .telemetry.audit_logger import TamperEvidentAuditLogger
from .telemetry.tracer import setup_telemetry

logger = structlog.get_logger(__name__)

SERVER_SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}$"
MAX_VET_BYTES = 256 * 1024
VET_REQUESTS_PER_MINUTE = 30


def build_gateway(settings: Settings, firewall: FirewallPolicyEngine, audit: TamperEvidentAuditLogger) -> McpGateway:
    core = settings.CORE_URL.rstrip("/")
    token = settings.CORE_SERVICE_TOKEN.get_secret_value() if settings.CORE_SERVICE_TOKEN else None
    instance_id = f"gw-{uuid4().hex}"  # identifies this process in usage reports; a restart gets a new one
    metrics = GatewayMetrics()
    return McpGateway(
        verifier=AgentTokenVerifier(
            public_key_pem=settings.AGENT_TOKEN_PUBLIC_KEY,
            jwks_url=f"{core}/v1/agent-auth/jwks",
        ),
        contexts=CoreContextClient(
            core_url=core, service_token=token, ttl_seconds=settings.CONTEXT_CACHE_TTL_SECONDS,
            instance_id=instance_id,
        ),
        forwarder=UpstreamForwarder(
            allow_insecure=settings.ALLOW_INSECURE_UPSTREAMS,
            max_response_bytes=settings.MAX_UPSTREAM_RESPONSE_BYTES,
            connect_timeout=settings.UPSTREAM_CONNECT_TIMEOUT_SECONDS,
            total_timeout=settings.UPSTREAM_TIMEOUT_SECONDS,
        ),
        firewall=firewall,
        audit_logger=audit,
        metrics=metrics,
        budget=BudgetMeter(
            instance_id=instance_id,
            reporter=HttpUsageReporter(core_url=core, service_token=token),
            flush_interval=settings.BUDGET_FLUSH_INTERVAL_SECONDS,
            max_keys=settings.BUDGET_MAX_TRACKED_KEYS,
            metrics=metrics,
        ),
        recorder=EventRecorder(
            instance_id=instance_id,
            reporter=HttpEventReporter(core_url=core, service_token=token, metrics=metrics),
            flush_interval=settings.RECORDER_FLUSH_INTERVAL_SECONDS,
            max_buffered=settings.RECORDER_MAX_BUFFERED_EVENTS,
            max_batch_size=settings.RECORDER_MAX_BATCH_SIZE,
            metrics=metrics,
        ),
        trips=TripDispatcher(reporter=HttpTripReporter(core_url=core, service_token=token), metrics=metrics),
        pins=PinCoordinator(reporter=HttpPinReporter(core_url=core, service_token=token), metrics=metrics),
        radar=RadarScanner(
            reporter=HttpFindingsReporter(core_url=core, service_token=token), metrics=metrics, use_model=settings.RADAR_MODEL_ENABLED,
            counts_reporter=HttpScanCountsReporter(core_url=core, service_token=token),
        ),
        loops=LoopMeter(),
        loop_detection_enabled=settings.LOOP_DETECTION_ENABLED,
    )


settings = get_settings()
firewall_engine = FirewallPolicyEngine(settings.POLICY_FILE_PATH)
audit_logger = TamperEvidentAuditLogger(log_file_path=settings.AUDIT_LOG_FILE)
gateway = build_gateway(settings, firewall_engine, audit_logger)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Starting AgentWall gateway", env=settings.ENVIRONMENT, port=settings.PORT)
    if settings.CORE_SERVICE_TOKEN is None:
        logger.error("AGENTWALL_CORE_SERVICE_TOKEN is not set: every agent call will be denied")
    if settings.AUDIT_LOG_FILE is None and settings.ENVIRONMENT not in ("development", "test"):
        logger.warning("AGENTWALL_AUDIT_LOG_FILE is not set: gateway audit records are in memory only")
    setup_telemetry(settings.OTEL_SERVICE_NAME)
    firewall_engine.load_policies()
    gateway.budget.start()
    gateway.recorder.start()
    yield
    logger.info("Shutting down AgentWall gateway")
    await gateway.budget.stop()
    await gateway.recorder.stop()
    await gateway.trips.aclose()
    await gateway.pins.aclose()
    await gateway.radar.aclose()
    await gateway.contexts.aclose()


app = FastAPI(
    title="AgentWall: RedHand MCP Gateway",
    version="0.2.0",
    description="Enforces Agent Passports on MCP tool traffic.",
    lifespan=lifespan,
)

# Browsers only need to reach the gateway from the dashboard origin (MCP vetting).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "Mcp-Session-Id", "Mcp-Protocol-Version"],
)


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or " " in token:
        return None
    return token


def require_service_token(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> None:
    expected = settings.CORE_SERVICE_TOKEN
    presented = _bearer(authorization)
    if expected is None or not presented or not hmac.compare_digest(presented, expected.get_secret_value()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Service credentials required.")


class _IpRateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str, limit: int, now: float) -> bool:
        recent = [t for t in self._hits.get(key, []) if now - t < 60.0]
        if len(recent) >= limit:
            self._hits[key] = recent
            return False
        recent.append(now)
        self._hits[key] = recent
        return True


_vet_limiter = _IpRateLimiter()
_scan_limiter = _IpRateLimiter()


def _reject_constant(name: str) -> Any:
    """`json.loads` accepts the tokens NaN, Infinity and -Infinity, which JSON (RFC 8259) does not have and which cannot be sent on."""
    raise ValueError(f"{name} is not valid JSON")


def _finite_float(text: str) -> float:
    """`1e999` is valid JSON text but parses to infinity, which cannot be sent on either: refuse it like the tokens above."""
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("number out of range")
    return value


async def _read_json_body(request: Request, limit: int) -> Any:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Request body too large.")
    body = await request.body()
    if len(body) > limit:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Request body too large.")
    try:
        return json.loads(body, parse_constant=_reject_constant, parse_float=_finite_float)
    except (ValueError, RecursionError):
        # ValueError covers a syntax error (JSONDecodeError), bad UTF-8 (UnicodeDecodeError), the refusals above and an integer of more than
        # 4,300 digits; RecursionError is a body nested too deep. All of them are an unusable body, answered after authentication.
        return None


# Google Cloud Run's front end can intercept /healthz (it never reaches the app), so the same
# check is also served at /health. Use /health on Cloud Run, either elsewhere.
@app.get("/health", status_code=status.HTTP_200_OK)
@app.get("/healthz", status_code=status.HTTP_200_OK)
async def healthz() -> dict[str, Any]:
    return {"status": "healthy", "service": "agentwall", "version": "0.2.0"}


@app.post("/mcp/{server}")
async def mcp_gateway(
    request: Request,
    server: Annotated[str, Path(pattern=SERVER_SLUG_PATTERN)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    upstream_authorization: Annotated[
        str | None, Header(alias="X-RedHand-Upstream-Authorization")
    ] = None,
) -> Response:
    """
    MCP Streamable HTTP endpoint for one registered server. The agent authenticates with
    its RedHand access token. If the upstream MCP server needs its own credential, the
    agent supplies it in `X-RedHand-Upstream-Authorization`; it is forwarded as
    `Authorization` and never logged. (Brokering upstream credentials is Phase 1.5.)
    """
    # JSON-RPC batches (arrays) and unparsable bodies are rejected by the gateway's
    # message-shape check after authentication.
    message = await _read_json_body(request, settings.MAX_REQUEST_BYTES)
    result = await gateway.handle(
        server=server,
        message=message,
        bearer_token=_bearer(authorization),
        client_headers={k.lower(): v for k, v in request.headers.items()},
        upstream_authorization=upstream_authorization,
    )
    if result.body is None:
        return Response(status_code=result.status_code, headers=result.headers)
    return JSONResponse(status_code=result.status_code, content=result.body, headers=result.headers)


@app.get("/mcp/{server}")
async def mcp_gateway_stream(server: str) -> Response:
    """Server-initiated SSE streams are not offered in Phase 1 (allowed by the MCP spec)."""
    return Response(status_code=status.HTTP_405_METHOD_NOT_ALLOWED, headers={"Allow": "POST"})


@app.post("/v1/mcp/vet", status_code=status.HTTP_200_OK, response_model=MCPVettingReport)
async def vet_mcp_manifest(request: Request) -> MCPVettingReport:
    """Static vetting of an MCP manifest supplied in the body. Fetches nothing."""
    client_ip = request.client.host if request.client else "unknown"
    if not _vet_limiter.allow(client_ip, VET_REQUESTS_PER_MINUTE, time.monotonic()):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests.")
    manifest = await _read_json_body(request, MAX_VET_BYTES)
    if not isinstance(manifest, dict):
        raise HTTPException(status_code=400, detail="Invalid JSON manifest payload")
    return MCPServerAuditor.audit_manifest(manifest)


class ScanRequest(BaseModel):
    """What redhand-core asks the gateway to scan. The URL is a server REGISTERED in the caller's organization; core checks
    that, the gateway re-checks the destination (https, public addresses, no redirects) before sending anything."""

    model_config = ConfigDict(extra="forbid")

    server_url: str = Field(min_length=8, max_length=2048)
    server_name: str = Field(default="server", max_length=128)


class ScanResponse(BaseModel):
    report: MCPVettingReport
    tool_count: int
    truncated: bool


SCAN_REQUESTS_PER_MINUTE = 20


@app.post("/internal/v1/scan", response_model=ScanResponse, dependencies=[Depends(require_service_token)], include_in_schema=False)
async def scan_registered_server(payload: ScanRequest) -> ScanResponse:
    """Lists a registered server's tools through the gateway's destination check and audits them. Service token only."""
    if not _scan_limiter.allow("scan", SCAN_REQUESTS_PER_MINUTE, time.monotonic()):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many scans; try again shortly.")
    try:
        tools, truncated = await list_tools(gateway.forwarder, payload.server_url)
    except ScanError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from None
    report = MCPServerAuditor.audit_manifest({"name": payload.server_name, "tools": tools})
    return ScanResponse(report=report, tool_count=len(tools), truncated=truncated)


class SelfTestCategory(BaseModel):
    category: str
    malicious: int
    benign: int
    detected: int
    false_alarms: int
    detection_low: float
    detection_high: float
    false_alarm_low: float
    false_alarm_high: float
    hard_benign: int
    hard_false_alarms: int


class SelfTestResponse(BaseModel):
    corpus: str
    model_enabled: bool
    samples: int
    duration_ms: float
    categories: list[SelfTestCategory]
    limits: str


_self_test = SelfTestRunner(model_enabled=settings.RADAR_MODEL_ENABLED)


@app.post("/internal/v1/radar/self-test", response_model=SelfTestResponse, dependencies=[Depends(require_service_token)], include_in_schema=False)
async def radar_self_test() -> SelfTestResponse:
    """Runs the Radar over the bundled held-out samples and returns counts only. Takes no input. Service token only."""
    try:
        return SelfTestResponse.model_validate(await _self_test.run())
    except BusyError:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="A self-test is already running.") from None
    except (SelfTestError, ValueError) as exc:
        logger.error("Radar self-test failed", error_type=type(exc).__name__)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="The self-test could not be completed.") from None


@app.get("/v1/policies", dependencies=[Depends(require_service_token)])
async def get_policies() -> dict[str, Any]:
    return firewall_engine.policies


@app.get("/v1/audit/logs", dependencies=[Depends(require_service_token)])
async def get_audit_logs(limit: int = Query(default=50, ge=1, le=1000)) -> list[dict[str, Any]]:
    return audit_logger.get_recent(limit=limit)


@app.get("/v1/audit/verify", dependencies=[Depends(require_service_token)])
async def verify_audit_chain() -> dict[str, Any]:
    is_valid, reason = audit_logger.verify_chain_integrity()
    return {
        "tamper_evident_chain_intact": is_valid,
        "scope": "records held by this gateway process since start",
        "details": reason or "All records verified.",
    }


@app.get("/metrics", dependencies=[Depends(require_service_token)])
async def metrics() -> PlainTextResponse:
    return PlainTextResponse(gateway.metrics.render(), media_type="text/plain; version=0.0.4")
