"""
FastAPI application entrypoint for AgentWall Zero-Trust Proxy.
"""

from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog

from ..config.settings import get_settings
from .firewall.engine import FirewallPolicyEngine
from .firewall.mcp_vetting import MCPServerAuditor, MCPVettingReport
from .proxy.handler import ProxyDispatcher
from .telemetry.audit_logger import get_audit_logger
from .telemetry.tracer import setup_telemetry

logger = structlog.get_logger(__name__)

settings = get_settings()
firewall_engine = FirewallPolicyEngine(settings.POLICY_FILE_PATH)
dispatcher = ProxyDispatcher(firewall_engine=firewall_engine)
audit_logger = get_audit_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info(
        "Starting AgentWall Zero-Trust Proxy",
        env=settings.ENVIRONMENT,
        port=settings.PORT,
    )
    setup_telemetry(settings.OTEL_SERVICE_NAME)
    firewall_engine.load_policies()
    yield
    logger.info("Shutting down AgentWall Proxy")


app = FastAPI(
    title="AgentWall Zero-Trust Agent Tool Firewall & Ephemeral IAM Broker",
    version="0.1.0",
    description="Inline Zero-Trust containment gateway for Anthropic MCP and OpenAI tool calling.",
    lifespan=lifespan,
)

# Browsers only need to reach the gateway from the dashboard origin. Wildcard origins
# combined with credentials would let any website drive the gateway from a victim's browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "Mcp-Session-Id", "Mcp-Protocol-Version"],
)


@app.get("/healthz", status_code=status.HTTP_200_OK)
async def healthz() -> dict[str, Any]:
    return {
        "status": "healthy",
        "service": "agentwall",
        "version": "0.1.0",
        "policies_loaded": len(firewall_engine.policies.get("tools", {})),
    }


@app.get("/v1/policies", status_code=status.HTTP_200_OK)
async def get_policies() -> dict[str, Any]:
    return firewall_engine.policies


@app.get("/v1/audit/logs", status_code=status.HTTP_200_OK)
async def get_audit_logs(limit: int = 50) -> list[dict[str, Any]]:
    return audit_logger.get_recent(limit=limit)


@app.get("/v1/audit/verify", status_code=status.HTTP_200_OK)
async def verify_audit_chain() -> dict[str, Any]:
    is_valid, reason = audit_logger.verify_chain_integrity()
    return {
        "tamper_evident_chain_intact": is_valid,
        "details": reason or "All records cryptographically verified with zero hash discrepancies.",
    }


@app.post("/v1/mcp/vet", status_code=status.HTTP_200_OK, response_model=MCPVettingReport)
async def vet_mcp_manifest(request: Request) -> MCPVettingReport:
    """Pre-install static security vetting of MCP server manifest or tools list."""
    try:
        manifest = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON manifest payload")
    return MCPServerAuditor.audit_manifest(manifest)


@app.post("/mcp", status_code=status.HTTP_200_OK)
@app.post("/mcp/rpc", status_code=status.HTTP_200_OK)
async def handle_mcp_endpoint(
    request: Request,
    x_agent_id: str = Header(default="agent-mcp-client", alias="X-Agent-ID"),
    x_caller_identity: str = Header(default="corp-ai-agent", alias="X-Caller-Identity"),
    x_user_id: str | None = Header(default=None, alias="X-User-ID"),
    x_user_roles: str | None = Header(default=None, alias="X-User-Roles"),
) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    parsed_roles = [r.strip() for r in x_user_roles.split(",") if r.strip()] if x_user_roles else None

    response = await dispatcher.handle_mcp_call(
        body=body,
        agent_id=x_agent_id,
        caller_identity=x_caller_identity,
        user_id=x_user_id,
        user_roles=parsed_roles,
    )
    return response


@app.post("/v1/tools/execute", status_code=status.HTTP_200_OK)
async def handle_rest_execute_endpoint(
    request: Request,
    x_agent_id: str = Header(default="agent-rest-client", alias="X-Agent-ID"),
    x_caller_identity: str = Header(default="corp-ai-agent", alias="X-Caller-Identity"),
    x_user_id: str | None = Header(default=None, alias="X-User-ID"),
    x_user_roles: str | None = Header(default=None, alias="X-User-Roles"),
) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    parsed_roles = [r.strip() for r in x_user_roles.split(",") if r.strip()] if x_user_roles else None

    response = await dispatcher.handle_rest_call(
        body=body,
        agent_id=x_agent_id,
        caller_identity=x_caller_identity,
        user_id=x_user_id,
        user_roles=parsed_roles,
    )
    
    # Return 403 Forbidden on policy violation
    if response.get("status") == "blocked":
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=response)
    if response.get("status") == "error":
        return JSONResponse(status_code=status.HTTP_502_BAD_GATEWAY, content=response)

    return JSONResponse(status_code=status.HTTP_200_OK, content=response)

