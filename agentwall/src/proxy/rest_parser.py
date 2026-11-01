"""
REST & OpenAI/Gemini-compatible function call payload parser.
"""

import json
from typing import Any
from pydantic import BaseModel, Field


class RESTToolCall(BaseModel):
    call_id: str = "default_call"
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    is_valid: bool = True
    error: str | None = None


class RESTParser:
    """Parses OpenAI function calling and generic REST tool call payloads."""

    @classmethod
    def parse_payload(cls, body: dict[str, Any]) -> list[RESTToolCall]:
        results: list[RESTToolCall] = []

        if not isinstance(body, dict):
            return [RESTToolCall(tool_name="", is_valid=False, error="Payload must be a JSON dictionary.")]

        # Format 1: OpenAI tool_calls structure
        if "tool_calls" in body and isinstance(body["tool_calls"], list):
            for idx, tc in enumerate(body["tool_calls"]):
                if not isinstance(tc, dict):
                    results.append(RESTToolCall(tool_name="", is_valid=False, error=f"tool_calls[{idx}] not a dict"))
                    continue
                call_id = tc.get("id", f"call_{idx}")
                fn_obj = tc.get("function", {})
                if not isinstance(fn_obj, dict):
                    results.append(RESTToolCall(call_id=call_id, tool_name="", is_valid=False, error="Invalid function object"))
                    continue
                name = fn_obj.get("name", "")
                raw_args = fn_obj.get("arguments", {})
                if isinstance(raw_args, str):
                    try:
                        args = json.loads(raw_args)
                    except Exception as exc:
                        results.append(RESTToolCall(call_id=call_id, tool_name=name, is_valid=False, error=f"Invalid arguments JSON string: {exc}"))
                        continue
                elif isinstance(raw_args, dict):
                    args = raw_args
                else:
                    args = {}
                results.append(RESTToolCall(call_id=call_id, tool_name=name, arguments=args, is_valid=True))
            return results

        # Format 2: Direct single tool execution endpoint
        tool_name = body.get("tool") or body.get("tool_name")
        if tool_name and isinstance(tool_name, str):
            raw_args = body.get("arguments", {})
            if isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args)
                except Exception as exc:
                    return [RESTToolCall(tool_name=tool_name, is_valid=False, error=f"Invalid arguments JSON: {exc}")]
            elif isinstance(raw_args, dict):
                args = raw_args
            else:
                args = {}
            call_id = body.get("call_id", "direct_call")
            return [RESTToolCall(call_id=call_id, tool_name=tool_name, arguments=args, is_valid=True)]

        return [RESTToolCall(tool_name="", is_valid=False, error="Unrecognized tool call payload structure.")]

