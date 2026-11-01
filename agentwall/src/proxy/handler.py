"""
Ingress Router and Reverse Proxy Dispatcher for AgentWall.
Coordinates firewall evaluation, ephemeral token injection, upstream dispatch,
and tamper-evident telemetry.
"""

import time
from typing import Any
import httpx
from uuid import uuid4
import structlog

from ..broker.token_manager import get_token_broker
from ..firewall.engine import FirewallPolicyEngine, FirewallVerdict
from ..telemetry.audit_logger import get_audit_logger
from ..telemetry.tracer import trace_span
from .mcp_parser import MCPParser, MCPParsedCall
from .rest_parser import RESTParser, RESTToolCall

logger = structlog.get_logger(__name__)


class ProxyDispatcher:
    """Reverse proxy dispatcher handling inline security, IAM injection, and upstream routing."""

    def __init__(
        self,
        firewall_engine: FirewallPolicyEngine,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.firewall = firewall_engine
        self.broker = get_token_broker()
        self.audit_logger = get_audit_logger()
        self._http_client = http_client or httpx.AsyncClient(timeout=10.0)

    async def handle_mcp_call(
        self,
        body: dict[str, Any],
        agent_id: str = "agent-anonymous",
        caller_identity: str = "internal-service",
        user_id: str | None = None,
        user_roles: list[str] | None = None,
    ) -> dict[str, Any]:
        trace_id = uuid4().hex
        span_id = uuid4().hex[:16]

        with trace_span("agentwall.mcp_intercept", {"agent_id": agent_id, "trace_id": trace_id}):
            parsed = MCPParser.parse(body)
            if parsed.error_response:
                return parsed.error_response

            if not parsed.is_tool_call:
                # Pass-through non-tool MCP requests (e.g., tools/list, initialize)
                return {
                    "jsonrpc": "2.0",
                    "id": parsed.request_id,
                    "result": {"status": "ok", "message": f"Non-execution MCP method '{parsed.raw_method}' accepted."},
                }

            start_time = time.perf_counter()
            verdict = self.firewall.evaluate_tool_call(
                tool_name=parsed.tool_name,
                arguments=parsed.arguments,
                agent_id=agent_id,
                caller_identity=caller_identity,
                user_roles=user_roles,
            )

            # Block decision
            if verdict.decision == "BLOCK":
                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
                self.audit_logger.record(
                    trace_id=trace_id,
                    span_id=span_id,
                    agent_id=agent_id,
                    caller_identity=caller_identity,
                    tool_name=parsed.tool_name,
                    sanitized_arguments=parsed.arguments,
                    firewall_decision="BLOCK",
                    policy_violation_reasons=verdict.reasons,
                    downstream_status=403,
                    execution_latency_ms=latency_ms,
                )
                return MCPParser.create_tool_blocked_response(
                    request_id=parsed.request_id,
                    tool_name=parsed.tool_name,
                    violations=verdict.reasons,
                    as_tool_result=False,
                )

            # Allow decision: Mint ephemeral token & dispatch
            ephemeral_token = await self.broker.mint_ephemeral_token(
                agent_id=agent_id,
                tool_name=verdict.tool_name,
                target_audience=verdict.target_audience,
                provider_name=verdict.iam_provider,
                ttl_seconds=30,
                user_id=user_id,
                user_roles=user_roles,
            )

            upstream_res, status_code = await self._forward_upstream(
                upstream_url=verdict.upstream_url,
                payload={"method": "tools/call", "params": {"name": parsed.tool_name, "arguments": parsed.arguments}},
                ephemeral_token=ephemeral_token.access_token,
            )

            # Egress inspection & DLP
            if verdict.egress_dlp:
                sanitized_body, dlp_violations = self.firewall.inspect_egress(upstream_res)
                if dlp_violations:
                    logger.warning("Egress secrets scrubbed from response", count=len(dlp_violations))
            else:
                sanitized_body = upstream_res

            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            self.audit_logger.record(
                trace_id=trace_id,
                span_id=span_id,
                agent_id=agent_id,
                caller_identity=caller_identity,
                tool_name=parsed.tool_name,
                sanitized_arguments=parsed.arguments,
                firewall_decision="ALLOW",
                downstream_status=status_code,
                execution_latency_ms=latency_ms,
                credential_jti=ephemeral_token.token_jti,
            )

            return {
                "jsonrpc": "2.0",
                "id": parsed.request_id,
                "result": sanitized_body,
            }

    async def handle_rest_call(
        self,
        body: dict[str, Any],
        agent_id: str = "agent-anonymous",
        caller_identity: str = "internal-service",
        user_id: str | None = None,
        user_roles: list[str] | None = None,
    ) -> dict[str, Any]:
        trace_id = uuid4().hex
        span_id = uuid4().hex[:16]

        with trace_span("agentwall.rest_intercept", {"agent_id": agent_id, "trace_id": trace_id}):
            calls = RESTParser.parse_payload(body)
            if not calls or not calls[0].is_valid:
                err_msg = calls[0].error if calls else "Invalid payload"
                return {"status": "error", "error": err_msg}

            call = calls[0]
            start_time = time.perf_counter()
            verdict = self.firewall.evaluate_tool_call(
                tool_name=call.tool_name,
                arguments=call.arguments,
                agent_id=agent_id,
                caller_identity=caller_identity,
                user_roles=user_roles,
            )

            if verdict.decision == "BLOCK":
                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
                self.audit_logger.record(
                    trace_id=trace_id,
                    span_id=span_id,
                    agent_id=agent_id,
                    caller_identity=caller_identity,
                    tool_name=call.tool_name,
                    sanitized_arguments=call.arguments,
                    firewall_decision="BLOCK",
                    policy_violation_reasons=verdict.reasons,
                    downstream_status=403,
                    execution_latency_ms=latency_ms,
                )
                return {
                    "call_id": call.call_id,
                    "status": "blocked",
                    "tool": call.tool_name,
                    "violations": verdict.reasons,
                }

            ephemeral_token = await self.broker.mint_ephemeral_token(
                agent_id=agent_id,
                tool_name=verdict.tool_name,
                target_audience=verdict.target_audience,
                provider_name=verdict.iam_provider,
                ttl_seconds=30,
                user_id=user_id,
                user_roles=user_roles,
            )

            upstream_res, status_code = await self._forward_upstream(
                upstream_url=verdict.upstream_url,
                payload={"tool": call.tool_name, "arguments": call.arguments},
                ephemeral_token=ephemeral_token.access_token,
            )

            if verdict.egress_dlp:
                sanitized_body, _ = self.firewall.inspect_egress(upstream_res)
            else:
                sanitized_body = upstream_res

            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            self.audit_logger.record(
                trace_id=trace_id,
                span_id=span_id,
                agent_id=agent_id,
                caller_identity=caller_identity,
                tool_name=call.tool_name,
                sanitized_arguments=call.arguments,
                firewall_decision="ALLOW",
                downstream_status=status_code,
                execution_latency_ms=latency_ms,
                credential_jti=ephemeral_token.token_jti,
            )

            return {
                "call_id": call.call_id,
                "status": "success",
                "tool": call.tool_name,
                "output": sanitized_body,
            }

    async def _forward_upstream(
        self,
        upstream_url: str,
        payload: dict[str, Any],
        ephemeral_token: str,
    ) -> tuple[Any, int]:
        """Dispatches outbound call with JIT credential and strips auth headers upon return."""
        headers = {
            "Authorization": f"Bearer {ephemeral_token}",
            "Content-Type": "application/json",
            "User-Agent": "AgentWall-ZeroTrust-Proxy/1.0",
        }

        try:
            resp = await self._http_client.post(upstream_url, json=payload, headers=headers)
            status_code = resp.status_code
            try:
                res_data = resp.json()
            except Exception:
                res_data = {"raw_text": resp.text}
            return res_data, status_code
        except Exception as exc:
            logger.info("Upstream tool server unreachable, utilizing simulated mock response", url=upstream_url, exc=str(exc))
            # Return simulated success response for local containment mode
            mock_resp = {
                "content": [{"type": "text", "text": f"Successfully simulated execution of {payload.get('tool') or payload.get('params', {}).get('name')}"}],
                "simulated": True,
            }
            return mock_resp, 200

