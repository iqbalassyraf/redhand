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

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import json
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
from .capture import build_excerpt
from .honeytokens import scan as scan_honeytokens
from .pins import PinCoordinator
from .radar_scan import RadarScanner, kinds_for
from .recorder import EventRecorder, GatewayEvent
from .trips import Trip, TripDispatcher
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
        recorder: EventRecorder,
        trips: TripDispatcher,
        pins: PinCoordinator,
        radar: RadarScanner,
    ) -> None:
        self.verifier = verifier
        self.contexts = contexts
        self.forwarder = forwarder
        self.firewall = firewall
        self.audit = audit_logger
        self.metrics = metrics
        self.budget = budget
        self.recorder = recorder
        self.trips = trips
        self.pins = pins
        self.radar = radar
        contexts.attach_metrics(metrics)
        verifier.attach_metrics(metrics)
        self._budget_refusal_logged: dict[UUID, float] = {}

    def _record_budget_refusal(
        self, identity: AgentIdentity, context: GatewayContext, method: str | None, message: Any,
        reasons: list[str], tool_name: str, arguments: dict[str, Any], started: float,
    ) -> None:
        """
        The in-process ledger gets one audit record per agent per minute for repeated refusals over
        the limit, so a runaway agent retrying in a loop cannot flood it; every refusal is still
        counted in the metrics AND still reaches the Black Box (`_record` always pushes to
        `self.recorder`, uncoalesced): the ledger's once-a-minute throttle is only about keeping the
        gateway's own forensic log short, not about the durable record owners see on the dashboard.
        """
        now = time.monotonic()
        last = self._budget_refusal_logged.get(identity.agent_id)
        if last is None or now - last >= BUDGET_REFUSAL_LOG_INTERVAL_SECONDS:
            self._budget_refusal_logged[identity.agent_id] = now
            self._record(identity, context, method, message, "BLOCK", reasons, 403, tool_name, arguments, started)
        else:
            self.recorder.record(self._event(identity, context, method, "BLOCK", reasons, 403, tool_name, started))

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
        self.recorder.schedule_flush_if_due()  # synchronous, no I/O: starts a background flush at most
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
        verify_timer = time.perf_counter()
        try:
            identity = await self.verifier.verify(bearer_token)
        except KeyUnavailableError:
            return deny(503, JSONRPC_GATEWAY_UNAVAILABLE, "Gateway cannot verify tokens right now.", "keys_unavailable")
        except AgentAuthError:
            return deny(401, JSONRPC_UNAUTHORIZED, "Invalid or expired agent access token.", "invalid_token")
        self.metrics.record_stage("verify", (time.perf_counter() - verify_timer) * 1000)

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
            self._record(identity, context, method, message, "BLOCK", [f"passport_{context.status}"], 403, started=started)
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

            # 4a. Honeytokens and decoy tools come first: a call carrying planted bait, or to a decoy, is a trip
            # however the passport is scoped, and neither is ever forwarded upstream. The tool NAME is scanned
            # along with the arguments (names and argument keys can carry bait too), and a trip is recorded,
            # logged and reported with the redacted copies, so the bait itself never reaches an event or a log.
            bait_timer = time.perf_counter()
            try:
                bait = scan_honeytokens({"tool": tool_name, "arguments": arguments}, context.honeytokens)
                self.metrics.record_stage("honeytoken_scan", (time.perf_counter() - bait_timer) * 1000)
            except Exception as exc:  # noqa: BLE001  enforcement path: a scanner error denies
                logger.error("Honeytoken scan failed", error_type=type(exc).__name__)
                self._record(identity, context, method, message, "BLOCK", ["honeytoken scan failed"], 403, "", {}, started, capture=False)
                return deny(200, JSONRPC_POLICY_VIOLATION, "PolicyViolation: request could not be checked.", "honeytoken_scan_error")
            if bait.truncated:
                self.metrics.record_honeytoken_scan_truncated()
            if bait.matched:
                safe_tool, safe_arguments = bait.value["tool"], bait.value["arguments"]
                for honeytoken_id in bait.matched:
                    self._trip(identity, context, "honeytoken", honeytoken_id, "arguments", safe_tool)
                self._record(identity, context, method, message, "BLOCK", ["honeytoken"], 403, safe_tool, safe_arguments, started, capture=False)
                return deny(200, JSONRPC_POLICY_VIOLATION, "PolicyViolation: request blocked.", "honeytoken")
            decoy = context.honey_tool(tool_name)
            if decoy is not None:
                self._trip(identity, context, "honey_tool", decoy.id, "call", tool_name)
                self._record(identity, context, method, message, "BLOCK", ["honey_tool"], 403, tool_name, arguments, started, capture=False)
                self.metrics.record(
                    method=method_label, outcome="deny", reason="honey_tool",
                    overhead_ms=(time.perf_counter() - started) * 1000,
                )
                # Plausible, so an attacker does not learn the tool is bait: a generic tool error.
                return GatewayResponse(200, {
                    "jsonrpc": "2.0", "id": request_id,
                    "result": {"content": [{"type": "text", "text": "The service is temporarily unavailable. Try again later."}], "isError": True},
                })

            if not context.allows_tool(tool_name):
                if context.safe_mode and context.covers_tool(tool_name):
                    reasons = [f"Safe Mode is on: tool '{tool_name}' on server '{server}' is not declared read-only."]
                    self._record(identity, context, method, message, "BLOCK", reasons, 403, tool_name, arguments, started)
                    return deny(200, JSONRPC_POLICY_VIOLATION, f"PolicyViolation: Safe Mode is on and tool '{tool_name}' is not read-only.",
                                "safe_mode", {"tool_name": tool_name, "violations": reasons})
                reasons = [f"Tool '{tool_name}' on server '{server}' is not in this agent's passport scopes."]
                self._record(identity, context, method, message, "BLOCK", reasons, 403, tool_name, arguments, started)
                return deny(200, JSONRPC_POLICY_VIOLATION, f"PolicyViolation: tool '{tool_name}' is out of scope.",
                            "out_of_scope", {"tool_name": tool_name, "violations": reasons})

            if context.pin_mode == "enforce" and not self._pin_allows(identity, context, tool_name):
                reasons = [f"Tool '{tool_name}' on server '{server}' is not approved: its current version has not been reviewed."]
                self.metrics.record_pin_event("refused")
                self._record(identity, context, method, message, "BLOCK", reasons, 403, tool_name, arguments, started)
                return deny(200, JSONRPC_POLICY_VIOLATION, f"PolicyViolation: tool '{tool_name}' is not approved.",
                            "tool_unapproved", {"tool_name": tool_name, "violations": reasons})

            guard_timer = time.perf_counter()
            violations = self.firewall.inspect_arguments(tool_name, arguments)
            self.metrics.record_stage("guardrails", (time.perf_counter() - guard_timer) * 1000)
            if violations:
                self._record(identity, context, method, message, "BLOCK", violations, 403, tool_name, arguments, started)
                return deny(200, JSONRPC_POLICY_VIOLATION, f"PolicyViolation: tool '{tool_name}' blocked by guardrails.",
                            "guardrail", {"tool_name": tool_name, "violations": violations})

            # 4b. Budget Guard: a call that is otherwise allowed consumes one unit of the agent's daily
            # limit, or is refused. Refused calls above never reach this point, so they never consume.
            budget_timer = time.perf_counter()
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
                self._record_budget_refusal(identity, context, method, message, reasons, tool_name, arguments, started)
                return deny(
                    200, JSONRPC_POLICY_VIOLATION, text, why,
                    {"tool_name": tool_name, "daily_call_limit": limit, "used": decision.used, "resets_at": resets},
                )
            self.budget.schedule_flush_if_due()
            self.metrics.record_stage("budget", (time.perf_counter() - budget_timer) * 1000)
            if decision.urgent:
                flush_timer = time.perf_counter()
                await self.budget.flush_now()
                self.metrics.record_stage("budget_flush_now", (time.perf_counter() - flush_timer) * 1000)

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
                self._record(identity, context, method, message, "ERROR", [str(exc)], 502, tool_name, arguments, started)
            self.metrics.record(method=method_label, outcome="error", reason=reason, overhead_ms=overhead_ms)
            if request_id is None:
                return GatewayResponse(502, None)
            return GatewayResponse(502, _error(request_id, JSONRPC_UPSTREAM_UNAVAILABLE, str(exc)))

        body = result.message
        findings: list[str] = []
        trip_reasons: list[str] = []
        result_size_bytes: int | None = None
        captured_result: Any = None
        if body is not None and "result" in body:
            if method == "tools/list":
                body = self._filter_tool_list(body, context)
                if context.pin_mode != "off":
                    pinned = self._apply_pins(identity, context, body)
                    if pinned is None:  # enforce mode could not check the list: show nothing rather than unchecked tools
                        return deny(200, JSONRPC_GATEWAY_UNAVAILABLE, "The tool list could not be checked.", "pin_check_failed")
                    body = pinned
                body = self._add_honey_tools(body, context)
            elif method == "tools/call":
                upstream_result = body["result"]
                try:
                    bait = scan_honeytokens(upstream_result, context.honeytokens)
                except Exception as exc:  # noqa: BLE001  the call already ran; a scanner error must not leak the result
                    logger.error("Honeytoken scan failed", error_type=type(exc).__name__)
                    self._record(identity, context, method, message, "BLOCK", ["honeytoken scan failed"], 403, tool_name, arguments, started, capture=False)
                    return deny(200, JSONRPC_POLICY_VIOLATION, "PolicyViolation: result could not be checked.", "honeytoken_scan_error")
                if bait.truncated:
                    self.metrics.record_honeytoken_scan_truncated()
                if bait.matched:
                    # The agent READ planted bait. The result goes back with the bait redacted (refusing would
                    # tip off an attacker that this record is special); core alerts or freezes per the stored action.
                    for honeytoken_id in bait.matched:
                        self._trip(identity, context, "honeytoken", honeytoken_id, "result", tool_name)
                    upstream_result = bait.value
                    trip_reasons = ["honeytoken"]
                redacted, findings = self.firewall.inspect_egress(upstream_result)
                if findings:
                    logger.warning("Secrets redacted from tool result", count=len(findings), tool=tool_name)
                self._observe_result(identity, context, tool_name, redacted)
                body = {**body, "result": redacted}
                captured_result = redacted
                try:
                    result_size_bytes = len(json.dumps(redacted, default=str))
                except (TypeError, ValueError):
                    result_size_bytes = None

        if method == "tools/call":
            self._record(
                identity, context, method, message, "ALLOW", trip_reasons, result.status_code, tool_name, arguments, started,
                result_size_bytes=result_size_bytes, redaction_count=len(findings), result=captured_result,
                capture=not trip_reasons,
            )
        self.metrics.record(method=method_label, outcome="allow", reason="ok", overhead_ms=overhead_ms)
        if body is None:
            return GatewayResponse(202, None, result.headers)
        return GatewayResponse(200, body, result.headers)

    def _observe_result(self, identity: AgentIdentity, context: GatewayContext, tool_name: str, result: Any) -> None:
        """
        Hands the (already redacted) result to the Radar's background queue. Observe only: this never changes the result, never
        waits and never raises, so a scanner problem cannot affect the call (docs/adr/0015-radar-in-the-gateway.md).
        """
        kinds = kinds_for(context.radar_mode, context.output_check_mode)
        if not kinds:
            return
        self.radar.submit(
            organization_id=identity.organization_id, agent_id=identity.agent_id, server=context.server_slug, tool=tool_name,
            tool_names=frozenset(s.tool for s in context.scopes if s.server == context.server_slug and s.tool != "*"),
            kinds=kinds, result=result,
        )

    def _trip(
        self, identity: AgentIdentity, context: GatewayContext, kind: str, ref_id: UUID, seen_in: str, tool_name: str
    ) -> None:
        """Counts a trip and reports it to core without waiting. Never logs the value (there is none here)."""
        self.metrics.record_trip(kind, seen_in)
        logger.warning("Trip", kind=kind, seen_in=seen_in, agent_id=str(identity.agent_id), tool=tool_name)
        self.trips.report(Trip(
            organization_id=identity.organization_id, trip_id=uuid4(), agent_id=identity.agent_id,
            kind=kind,  # type: ignore[arg-type]  # one of two literals chosen by the callers above
            ref_id=ref_id,
            seen_in=seen_in,  # type: ignore[arg-type]  # one of three literals chosen by the callers above
            tool_name=tool_name, server=context.server_slug,
        ))

    def _apply_pins(self, identity: AgentIdentity, context: GatewayContext, body: dict[str, Any]) -> dict[str, Any] | None:
        """Hashes the listed tools, reports versions not yet reported, and in enforce mode keeps only tools whose current
        version is approved. In alert mode a failure only counts (pinning is a side effect there); in enforce mode it
        returns None so the caller shows no tools."""
        result = body.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return body
        try:
            tools = [t for t in result["tools"] if isinstance(t, dict) and isinstance(t.get("name"), str) and t["name"]]
            digests = self.pins.observe(identity.organization_id, context.server_slug, tools)
            if context.pin_mode != "enforce":
                return body
            kept = [t for t in result["tools"] if isinstance(t, dict) and (t.get("name"), digests.get(str(t.get("name")))) in context.approved_tools]
            hidden = len(result["tools"]) - len(kept)
            if hidden:
                self.metrics.record_pin_event("hidden", hidden)
            return {**body, "result": {**result, "tools": kept}}
        except Exception as exc:  # noqa: BLE001
            logger.error("Tool pin check failed", error_type=type(exc).__name__)
            self.metrics.record_pin_event("error")
            return body if context.pin_mode != "enforce" else None

    def _pin_allows(self, identity: AgentIdentity, context: GatewayContext, tool_name: str) -> bool:
        """Enforce mode: a tool may be called if its name is approved and the version this gateway last saw for it (if it
        has seen one) is the approved one. A tool never listed through this process is judged by name alone."""
        if tool_name not in {name for name, _ in context.approved_tools}:
            return False
        last = self.pins.last_digest(identity.organization_id, context.server_slug, tool_name)
        return last is None or (tool_name, last) in context.approved_tools

    @staticmethod
    def _add_honey_tools(body: dict[str, Any], context: GatewayContext) -> dict[str, Any]:
        """Appends this agent's decoy tools to a tools/list result (never a duplicate of a real tool's name)."""
        result = body.get("result")
        if not context.honey_tools or not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return body
        names = {t.get("name") for t in result["tools"] if isinstance(t, dict)}
        decoys = [
            {"name": t.name, "description": t.description, "inputSchema": {"type": "object", "additionalProperties": True}}
            for t in context.honey_tools if t.name not in names
        ]
        return {**body, "result": {**result, "tools": [*result["tools"], *decoys]}}

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

    def _event(
        self,
        identity: AgentIdentity,
        context: GatewayContext,
        method: str | None,
        decision: str,
        reasons: list[str],
        status: int,
        tool_name: str,
        started: float,
        *,
        result_size_bytes: int | None = None,
        redaction_count: int = 0,
    ) -> GatewayEvent:
        """Builds the Black Box Recorder event for one decision. Never raises: every field here is
        already validated or bounded upstream (CLAUDE.md §5.4), so building it is pure computation."""
        return GatewayEvent(
            agent_id=identity.agent_id,
            organization_id=identity.organization_id,
            occurred_at=datetime.now(timezone.utc).isoformat(),
            server=context.server_slug,
            method=str(method or ""),
            tool_name=tool_name,
            decision=decision,
            reasons=reasons[:10],
            upstream_status=status,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            argument_keys=[],  # filled in by _record, which reuses the ledger record's own digest
            result_size_bytes=result_size_bytes,
            redaction_count=redaction_count,
            credential_jti=identity.token_id,
        )

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
        started: float | None = None,
        *,
        result_size_bytes: int | None = None,
        redaction_count: int = 0,
        result: Any = None,
        capture: bool = True,
    ) -> None:
        record_obj = self.audit.record(
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
            execution_latency_ms=0.0 if started is None else (time.perf_counter() - started) * 1000,
            credential_jti=identity.token_id,
        )
        if started is not None:
            event = self._event(
                identity, context, method, decision, reasons, status, tool_name or str(method or ""), started,
                result_size_bytes=result_size_bytes, redaction_count=redaction_count,
            )
            # Reuse the ledger record's own digest: raw arguments are never stored (CLAUDE.md §10),
            # and the audit logger already computed the name list and the SHA-256 the same way.
            event = replace(event, argument_keys=record_obj.argument_keys, arguments_sha256=record_obj.arguments_sha256)
            # Never capture the payload of a trip: it may hold the bait itself, and the password format is
            # not something the redaction patterns can recognise.
            if context.payload_capture and capture:
                event = self._with_payloads(event, arguments, result)
            self.recorder.record(event)

    def _with_payloads(self, event: GatewayEvent, arguments: dict[str, Any] | None, result: Any) -> GatewayEvent:
        """Adds redacted, size-capped excerpts of the arguments and the (already secret-scrubbed) result.
        Only called when the organization turned payload capture on. Never raises into the decision path:
        a failure only means this event is recorded without a payload, and the failure is counted, not
        logged with values (CLAUDE.md §5.2)."""
        try:
            args_excerpt = build_excerpt(arguments).as_dict() if arguments else None
            result_excerpt = build_excerpt(result).as_dict() if result is not None else None
        except Exception as exc:  # noqa: BLE001  capture is a side effect and must not affect enforcement
            logger.warning("Payload capture failed", error_type=type(exc).__name__)
            self.metrics.record_payload_capture("failed")
            return event
        self.metrics.record_payload_capture("ok")
        return replace(event, arguments_redacted=args_excerpt, result_excerpt=result_excerpt)
