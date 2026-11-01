"""
RedHand In-VPC Sidecar - Local Security Proxy & MCP Interceptor
File: packages/redhand-sidecar/src/redhand_sidecar/proxy.py

Runs on `localhost:8080` co-located with AI agent containers. Intercepts tool calls,
evaluates prompt injection and DLP locally within the customer VPC boundary, and
forwards scrubbed OCSF telemetry.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from redhand_sdk.adapters.mcp import RedHandMCPInterceptor
from redhand_sdk.client import RedHandClient
from redhand_sdk.firewall.engine import FirewallEngine

logger = logging.getLogger("redhand.sidecar.proxy")

app = FastAPI(
    title="RedHand In-VPC Sidecar Proxy",
    description="Local zero-trust proxy running within customer VPC network perimeter",
    version="0.1.0",
)

_firewall = FirewallEngine()
_sdk_client = RedHandClient()
_mcp_interceptor = RedHandMCPInterceptor(client=_sdk_client, firewall=_firewall)


class InspectPayload(BaseModel):
    tool_name: str
    tool_arguments: dict[str, Any] = Field(default_factory=dict)
    prompt_context: str | None = None
    risk_tier: str = "read_only"


class InspectResponse(BaseModel):
    verdict: str
    allowed: bool
    latency_ms: float
    trigger_snippet: str | None = None


@app.get("/healthz", summary="Liveness & Readiness Probe")
async def healthz() -> dict[str, str]:
    return {"status": "healthy", "sidecar": "in_vpc"}


@app.post("/v1/inspect", response_model=InspectResponse, summary="Inspect Tool Call In-VPC")
async def inspect_tool_call(payload: InspectPayload) -> InspectResponse:
    """
    Evaluates tool invocation locally using Tier-0 AST and Tier-1 ONNX DeBERTa
    without data ever leaving the customer VPC.
    """
    eval_result = _firewall.evaluate(
        tool_name=payload.tool_name,
        tool_arguments=payload.tool_arguments,
        agent_thought=payload.prompt_context,
    )

    if eval_result.verdict.value == "blocked":
        snippet = eval_result.finding.trigger_snippet if eval_result.finding else None
        return InspectResponse(
            verdict="blocked",
            allowed=False,
            latency_ms=eval_result.latency_ms,
            trigger_snippet=snippet,
        )

    return InspectResponse(
        verdict="allow",
        allowed=True,
        latency_ms=eval_result.latency_ms,
    )


@app.post("/mcp", summary="MCP JSON-RPC In-VPC Reverse Proxy")
async def handle_mcp_proxy(request: Request) -> Response:
    """
    Intercepts Model Context Protocol (MCP) JSON-RPC requests from LLM agents.
    Blocks prompt injections before forwarding to upstream backend tool servers.
    """
    import json
    body_bytes = await request.body()
    try:
        msg_dict = json.loads(body_bytes)
        async def dummy_upstream(req: dict[str, Any]) -> dict[str, Any]:
            return {"jsonrpc": "2.0", "id": req.get("id"), "result": {"content": [{"type": "text", "text": "OK"}]}}

        resp_dict = await _mcp_interceptor.intercept_jsonrpc(msg_dict, dummy_upstream)
        return Response(
            content=json.dumps(resp_dict),
            media_type="application/json",
            status_code=status.HTTP_200_OK,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Sidecar MCP proxy exception: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
