"""
The RedHand MCP gateway: the enforcement point for Agent Passports.

For every JSON-RPC message an agent sends to `/mcp/{server}`:
  1. authenticate the agent's access token (signature, audience, expiry)
  2. load the passport context from core (status, scopes, upstream URL; cached <= 2 s)
  3. deny unless the passport is active and the server is registered in the tenant
  4. allow only the MCP methods Phase 1 governs; for tools/call require a matching scope
     and pass the optional argument guardrails
  5. forward to the customer's MCP server, filter tools/list to permitted tools, redact
     secrets from tool results, and record the decision

Every error path denies. Nothing here calls an LLM or does unbounded work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any
from uuid import UUID, uuid4

import structlog

from ..firewall.engine import FirewallPolicyEngine
from ..telemetry.audit_logger import TamperEvidentAuditLogger
from .context import AgentUnknownError, ContextUnavailableError, CoreContextClient, GatewayContext
from .identity import AgentAuthError, AgentIdentity, AgentTokenVerifier, KeyUnavailableError
from .budget import BudgetMeter
from .metrics import GatewayMetrics
from .upstream import DestinationBlockedError, UpstreamError, UpstreamForwarder

logger = structlog.get_logger(__name__)

# Methods the Phase 1 gateway forwards. Resources and prompts can expose data outside the
# tool scopes a passport describes, so they are refused until scopes cover them.
ALLOWED_METHODS = frozenset(
    {
        "initialize",
        "ping",
        "tools/list",
        "tools/call",
        "notifications/initialized",
        "notifications/cancelled",
    }
)

BUDGET_REFUSAL_LOG_INTERVAL_SECONDS = 60.0

JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_POLICY_VIOLATION = -32000
JSONRPC_PASSPORT_INACTIVE = -32001
JSONRPC_UPSTREAM_UNAVAILABLE = -32002
JSONRPC_GATEWAY_UNAVAILABLE = -32003
JSONRPC_UNKNOWN_SERVER = -32004
JSONRPC_UNAUTHORIZED = -32005


@dataclass(slots=True)
class GatewayResponse:
    status_code: int
    body: dict[str, Any] | None
    headers: dict[str, str] = field(default_factory=dict)


def _error(request_id: Any, code: int, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


class McpGateway:
    def __init__(
        self,
        *,
        verifier: AgentTokenVerifier,
        contexts: CoreContextClient,
        forwarder: UpstreamForwarder,
        firewall: FirewallPolicyEngine,
        audit_logger: TamperEvidentAuditLogger,
        metrics: GatewayMetrics,
        budget: BudgetMeter,
    ) -> None:
        self.verifier = verifier
        self.contexts = contexts
        self.forwarder = forwarder
        self.firewall = firewall
        self.audit = audit_logger
        self.metrics = metrics
        self.budget = budget
        self._budget_refusal_logged: dict[UUID, float] = {}

    def _record_budget_refusal(
        self, identity: AgentIdentity, context: GatewayContext, method: str | None, message: Any,
        reasons: list[str], tool_name: str, arguments: dict[str, Any],
    ) -> None:
        """
        One audit record per agent per minute for repeated refusals over the limit: a runaway agent retrying
        in a loop must not flood the ledger and the logs. Every refusal is still counted in the metrics.
        """
        now = time.monotonic()
        last = self._budget_refusal_logged.get(identity.agent_id)
        if last is not None and now - last < BUDGET_REFUSAL_LOG_INTERVAL_SECONDS:
            return
        self._budget_refusal_logged[identity.agent_id] = now
        self._record(identity, context, method, message, "BLOCK", reasons, 403, tool_name, arguments)

    async def handle(
        self,
        *,
        server: str,
        message: Any,
        bearer_token: str | None,
        client_headers: dict[str, str],
        upstream_authorization: str | None,
    ) -> GatewayResponse:
        started = time.perf_counter()
        request_id = message.get("id") if isinstance(message, dict) else None
        method = message.get("method") if isinstance(message, dict) else None
        method_label = method if method in ALLOWED_METHODS else "other"

        def deny(status: int, code: int, text: str, reason: str, data: dict[str, Any] | None = None) -> GatewayResponse:
            self.metrics.record(
                method=method_label, outcome="deny", reason=reason,
                overhead_ms=(time.perf_counter() - started) * 1000,
            )
            headers = {"WWW-Authenticate": 'Bearer realm="redhand-gateway"'} if status == 401 else {}
            return GatewayResponse(status, _error(request_id, code, text, data), headers)

        # 1. Agent authentication
        if not bearer_token:
            return deny(401, JSONRPC_UNAUTHORIZED, "Agent access token required.", "missing_token")
        try:
            identity = await self.verifier.verify(bearer_token)
        except KeyUnavailableError:
            return deny(503, JSONRPC_GATEWAY_UNAVAILABLE, "Gateway cannot verify tokens right now.", "keys_unavailable")
        except AgentAuthError:
            return deny(401, JSONRPC_UNAUTHORIZED, "Invalid or expired agent access token.", "invalid_token")

        # 2. Message shape
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return deny(400, JSONRPC_INVALID_REQUEST, "Invalid JSON-RPC 2.0 message.", "invalid_message")

        # 3. Passport and server context
        try:
            context = await self.contexts.get(identity.agent_id, identity.organization_id, server)
        except AgentUnknownError:
            return deny(401, JSONRPC_UNAUTHORIZED, "Agent is not registered.", "unknown_agent")
        except ContextUnavailableError:
            return deny(503, JSONRPC_GATEWAY_UNAVAILABLE, "Passport service unavailable; request denied.", "context_unavailable")

        if context.status != "active":
            self._record(identity, context, method, message, "BLOCK", [f"passport_{context.status}"], 403)
            return deny(
                403, JSONRPC_PASSPORT_INACTIVE, f"Agent passport is {context.status}.",
                f"passport_{context.status}", {"passport_status": context.status},
            )
        if context.server_url is None:
            return deny(404, JSONRPC_UNKNOWN_SERVER, f"Unknown MCP server '{server}'.", "unknown_server")
        if method not in ALLOWED_METHODS:
            return deny(200, JSONRPC_METHOD_NOT_FOUND, f"Method '{method}' is not permitted through the RedHand gateway.", "method_not_allowed")

        # 4. Tool authorization
        tool_name = ""
        arguments: dict[str, Any] = {}
        if method == "tools/call":
            params = message.get("params")
            if not isinstance(params, dict) or not isinstance(params.get("name"), str) or not params["name"]:
                return deny(200, JSONRPC_INVALID_PARAMS, "tools/call requires params.name.", "invalid_params")
            raw_args = params.get("arguments", {})
            if not isinstance(raw_args, dict):
                return deny(200, JSONRPC_INVALID_PARAMS, "tools/call arguments must be an object.", "invalid_params")
            tool_name, arguments = params["name"], raw_args

            if not context.allows_tool(tool_name):
                if context.safe_mode and context.covers_tool(tool_name):
                    reasons = [f"Safe Mode is on: tool '{tool_name}' on server '{server}' is not declared read-only."]
                    self._record(identity, context, method, message, "BLOCK", reasons, 403, tool_name, arguments)
                    return deny(200, JSONRPC_POLICY_VIOLATION, f"PolicyViolation: Safe Mode is on and tool '{tool_name}' is not read-only.",
                                "safe_mode", {"tool_name": tool_name, "violations": reasons})
                reasons = [f"Tool '{tool_name}' on server '{server}' is not in this agent's passport scopes."]
                self._record(identity, context, method, message, "BLOCK", reasons, 403, tool_name, arguments)
                return deny(200, JSONRPC_POLICY_VIOLATION, f"PolicyViolation: tool '{tool_name}' is out of scope.",
                            "out_of_scope", {"tool_name": tool_name, "violations": reasons})

            violations = self.firewall.inspect_arguments(tool_name, arguments)
            if violations:
                self._record(identity, context, method, message, "BLOCK", violations, 403, tool_name, arguments)
                return deny(200, JSONRPC_POLICY_VIOLATION, f"PolicyViolation: tool '{tool_name}' blocked by guardrails.",
                            "guardrail", {"tool_name": tool_name, "violations": violations})

            # 4b. Budget Guard: a call that is otherwise allowed consumes one unit of the agent's daily
            # limit, or is refused. Refused calls above never reach this point, so they never consume.
            decision = self.budget.try_consume(identity.agent_id, context.budget)
            if not decision.allowed:
                limit = context.budget.daily_call_limit
                resets = context.budget.resets_at.isoformat()
                if decision.reason == "meter_full":
                    reasons = ["The gateway cannot track this agent's usage right now; the call was refused."]
                    text = "PolicyViolation: the gateway cannot track this agent's usage right now."
                    why = "budget_untracked"
                else:
                    reasons = [f"Daily limit of {limit} tool calls reached ({decision.used} used); resets at {resets}."]
                    text = f"PolicyViolation: daily limit of {limit} tool calls reached; it resets at {resets}."
                    why = "budget_exceeded"
                self._record_budget_refusal(identity, context, method, message, reasons, tool_name, arguments)
                return deny(
                    200, JSONRPC_POLICY_VIOLATION, text, why,
                    {"tool_name": tool_name, "daily_call_limit": limit, "used": decision.used, "resets_at": resets},
                )
            self.budget.schedule_flush_if_due()
            if decision.urgent:
                await self.budget.flush_now()

        overhead_ms = (time.perf_counter() - started) * 1000

        # 5. Forward
        try:
            result = await self.forwarder.send(
                url=context.server_url,
                message=message,
                client_headers=client_headers,
                upstream_authorization=upstream_authorization,
            )
        except UpstreamError as exc:
            reason = "destination_blocked" if isinstance(exc, DestinationBlockedError) else "upstream_error"
            if method == "tools/call":
                self._record(identity, context, method, message, "ERROR", [str(exc)], 502, tool_name, arguments)
            self.metrics.record(method=method_label, outcome="error", reason=reason, overhead_ms=overhead_ms)
            if request_id is None:
                return GatewayResponse(502, None)
            return GatewayResponse(502, _error(request_id, JSONRPC_UPSTREAM_UNAVAILABLE, str(exc)))

        body = result.message
        if body is not None and "result" in body:
            if method == "tools/list":
                body = self._filter_tool_list(body, context)
            elif method == "tools/call":
                redacted, findings = self.firewall.inspect_egress(body["result"])
                if findings:
                    logger.warning("Secrets redacted from tool result", count=len(findings), tool=tool_name)
                body = {**body, "result": redacted}

        if method == "tools/call":
            self._record(identity, context, method, message, "ALLOW", [], result.status_code, tool_name, arguments)
        self.metrics.record(method=method_label, outcome="allow", reason="ok", overhead_ms=overhead_ms)
        if body is None:
            return GatewayResponse(202, None, result.headers)
        return GatewayResponse(200, body, result.headers)

    @staticmethod
    def _filter_tool_list(body: dict[str, Any], context: GatewayContext) -> dict[str, Any]:
        result = body.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return body
        permitted = [
            t for t in result["tools"]
            if isinstance(t, dict) and isinstance(t.get("name"), str) and context.allows_tool(t["name"])
        ]
        return {**body, "result": {**result, "tools": permitted}}

    def _record(
        self,
        identity: AgentIdentity,
        context: GatewayContext,
        method: str | None,
        message: Any,
        decision: str,
        reasons: list[str],
        status: int,
        tool_name: str = "",
        arguments: dict[str, Any] | None = None,
    ) -> None:
        self.audit.record(
            trace_id=uuid4().hex,
            span_id=uuid4().hex[:16],
            agent_id=str(identity.agent_id),
            caller_identity=f"agent:{identity.agent_id}",
            organization_id=str(identity.organization_id),
            server=context.server_slug,
            tool_name=tool_name or str(method or ""),
            arguments=arguments or {},
            firewall_decision=decision,  # type: ignore[arg-type]  # validated Literal by the model
            policy_violation_reasons=reasons,
            downstream_status=status,
            credential_jti=identity.token_id,
        )
