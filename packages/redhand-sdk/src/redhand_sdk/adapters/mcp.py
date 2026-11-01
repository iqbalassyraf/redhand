"""
RedHand SDK - Model Context Protocol (MCP) Security Proxy Interceptor
File: packages/redhand-sdk/src/redhand_sdk/adapters/mcp.py

Intercepts MCP JSON-RPC `tools/call` requests before they reach an underlying
MCP server (stdio or SSE), enforcing RedHand's `<50ms` Semantic Firewall and
HITL blast-radius containment with zero changes to the MCP server code.
"""

from __future__ import annotations

import secrets
from typing import Any, Awaitable, Callable
from uuid import uuid4

from redhand_sdk.client import RedHandClient, get_default_client
from redhand_sdk.firewall.engine import FirewallEngine, get_default_firewall
from redhand_sdk.models import (
    FirewallVerdict,
    RiskTier,
    StepType,
    TraceSpanItem,
)


class RedHandMCPInterceptor:
    """
    Wraps any MCP JSON-RPC message dispatcher to inspect `tools/call` invocations
    through RedHand's `<50ms` Semantic Firewall.
    """

    def __init__(
        self,
        *,
        tool_risk_tiers: dict[str, RiskTier] | None = None,
        firewall: FirewallEngine | None = None,
        client: RedHandClient | None = None,
    ) -> None:
        self.tool_risk_tiers = tool_risk_tiers or {}
        self.firewall = firewall or get_default_firewall()
        self.client = client or get_default_client()
        self.session_id = uuid4()

    async def intercept_jsonrpc(
        self,
        request_msg: dict[str, Any],
        forward_handler: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        """
        Inspects an incoming MCP JSON-RPC 2.0 request. If `method == "tools/call"`,
        evaluates `params.arguments` through the Semantic Firewall before forwarding.
        """
        method = request_msg.get("method")
        msg_id = request_msg.get("id")

        if method != "tools/call":
            return await forward_handler(request_msg)

        params = request_msg.get("params") or {}
        tool_name = str(params.get("name", "unknown_mcp_tool"))
        tool_args = params.get("arguments") or {}
        if not isinstance(tool_args, dict):
            tool_args = {"raw": str(tool_args)}

        trace_id = secrets.token_hex(16)
        span_id = secrets.token_hex(8)
        risk_tier = self.tool_risk_tiers.get(tool_name, RiskTier.READ_ONLY)

        fw_res = self.firewall.evaluate(
            tool_name=tool_name,
            tool_arguments=tool_args,
        )

        if fw_res.verdict == FirewallVerdict.BLOCKED and fw_res.finding is not None:
            blocked_span = TraceSpanItem(
                session_id=self.session_id,
                trace_id=trace_id,
                span_id=span_id,
                step_type=StepType.ACTION,
                tool_name=tool_name,
                tool_arguments=tool_args,
                tool_risk_tier=risk_tier,
                firewall_verdict=FirewallVerdict.BLOCKED,
                firewall_latency_ms=fw_res.latency_ms,
                security_finding=fw_res.finding,
            )
            await self.client.flush_spans([blocked_span])

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32001,
                    "message": f"[REDHAND_MCP_FIREWALL_BLOCKED] {fw_res.finding.mitigation_action}",
                    "data": {
                        "span_id": span_id,
                        "event_type": fw_res.finding.event_type.value,
                        "firewall_latency_ms": fw_res.latency_ms,
                    },
                },
            }

        response = await forward_handler(request_msg)

        allow_span = TraceSpanItem(
            session_id=self.session_id,
            trace_id=trace_id,
            span_id=span_id,
            step_type=StepType.ACTION,
            tool_name=tool_name,
            tool_arguments=tool_args,
            tool_risk_tier=risk_tier,
            firewall_verdict=fw_res.verdict,
            firewall_latency_ms=fw_res.latency_ms,
            security_finding=fw_res.finding,
        )
        self.client.enqueue_span(allow_span)
        return response

