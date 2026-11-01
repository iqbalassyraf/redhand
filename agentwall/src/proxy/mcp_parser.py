"""
Anthropic Model Context Protocol (MCP) JSON-RPC 2.0 message parser and response generator.
"""

from typing import Any
from pydantic import BaseModel, Field


class MCPParsedCall(BaseModel):
    request_id: Any
    is_tool_call: bool
    tool_name: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)
    raw_method: str = ""
    error_response: dict[str, Any] | None = None


class MCPParser:
    """Parses incoming JSON-RPC 2.0 MCP requests and serializes compliant responses."""

    @classmethod
    def parse(cls, body: dict[str, Any]) -> MCPParsedCall:
        if not isinstance(body, dict):
            return MCPParsedCall(
                request_id=None,
                is_tool_call=False,
                error_response=cls.create_jsonrpc_error(None, -32600, "Invalid Request: Payload must be a JSON object."),
            )

        jsonrpc_ver = body.get("jsonrpc")
        if jsonrpc_ver != "2.0":
            return MCPParsedCall(
                request_id=body.get("id"),
                is_tool_call=False,
                error_response=cls.create_jsonrpc_error(body.get("id"), -32600, "Invalid JSON-RPC version: must be '2.0'."),
            )

        req_id = body.get("id")
        method = body.get("method", "")
        params = body.get("params", {})

        if method == "tools/call":
            if not isinstance(params, dict):
                return MCPParsedCall(
                    request_id=req_id,
                    is_tool_call=False,
                    error_response=cls.create_jsonrpc_error(req_id, -32602, "Invalid params: must be a JSON object."),
                )
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            if not isinstance(arguments, dict):
                return MCPParsedCall(
                    request_id=req_id,
                    is_tool_call=False,
                    error_response=cls.create_jsonrpc_error(req_id, -32602, "Invalid arguments: must be an object."),
                )
            return MCPParsedCall(
                request_id=req_id,
                is_tool_call=True,
                tool_name=tool_name,
                arguments=arguments,
                raw_method=method,
            )

        # For non-tool calls (e.g., tools/list, initialize)
        return MCPParsedCall(
            request_id=req_id,
            is_tool_call=False,
            raw_method=method,
        )

    @classmethod
    def create_jsonrpc_error(
        cls,
        request_id: Any,
        code: int,
        message: str,
        data: Any = None,
    ) -> dict[str, Any]:
        resp: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": code,
                "message": message,
            },
        }
        if data is not None:
            resp["error"]["data"] = data
        return resp

    @classmethod
    def create_tool_blocked_response(
        cls,
        request_id: Any,
        tool_name: str,
        violations: list[str],
        as_tool_result: bool = False,
    ) -> dict[str, Any]:
        """Creates either a JSON-RPC error or an MCP tool result indicating execution failure."""
        if as_tool_result:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"AgentWall Policy Violation: Execution of '{tool_name}' blocked.\nReasons:\n"
                            + "\n".join(f"- {r}" for r in violations),
                        }
                    ],
                    "isError": True,
                },
            }
        return cls.create_jsonrpc_error(
            request_id=request_id,
            code=-32000,
            message=f"PolicyViolation: Tool call '{tool_name}' blocked by AgentWall policy.",
            data={"tool_name": tool_name, "error_type": "PolicyViolation", "violations": violations},
        )

