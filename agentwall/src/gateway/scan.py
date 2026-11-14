"""
Live scan of a registered MCP server (Phase 4 M2): asks the server for its tool list the way an agent would, then
audits what it returned. The URL comes from redhand-core (which only passes servers registered in the caller's
organization), and every request goes through the same destination check as agent traffic: https only, public
addresses only, no redirects, bounded size and time.

Everything the server returns is untrusted. It is size-capped here, never executed, and the report built from it
carries rule wording, not the server's text.
"""

from __future__ import annotations

from typing import Any

import structlog

from .upstream import UpstreamError, UpstreamForwarder

logger = structlog.get_logger(__name__)

MAX_PAGES = 5
MAX_TOOLS = 500
MAX_NAME_CHARS = 128
PROTOCOL_VERSION = "2025-06-18"


class ScanError(Exception):
    """The scan could not be completed. The message is safe to show: it never repeats server-supplied text."""


async def list_tools(
    forwarder: UpstreamForwarder, url: str, upstream_authorization: str | None = None
) -> tuple[list[dict[str, Any]], bool]:
    """Returns (tools, truncated). `truncated` is True when the server had more than MAX_TOOLS tools or MAX_PAGES pages.
    `upstream_authorization` is the credential an agent supplied for the server (tool pinning's first-use check); a registered-server scan has none."""
    headers: dict[str, str] = {}
    try:
        init = await forwarder.send(
            url=url,
            message={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "redhand-scanner", "version": "1.0"}}},
            client_headers=headers, upstream_authorization=upstream_authorization,
        )
        if init.message is None or "result" not in init.message:
            raise ScanError("The server did not accept an initialize request.")
        if "mcp-session-id" in init.headers:
            headers["mcp-session-id"] = init.headers["mcp-session-id"]
        await forwarder.send(
            url=url, message={"jsonrpc": "2.0", "method": "notifications/initialized"},
            client_headers=headers, upstream_authorization=upstream_authorization,
        )
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for page in range(MAX_PAGES):
            params = {"cursor": cursor} if cursor else {}
            reply = await forwarder.send(
                url=url, message={"jsonrpc": "2.0", "id": 2 + page, "method": "tools/list", "params": params},
                client_headers=headers, upstream_authorization=upstream_authorization,
            )
            result = reply.message.get("result") if reply.message else None
            if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                raise ScanError("The server did not return a tool list (it may require credentials).")
            for tool in result["tools"]:
                if isinstance(tool, dict):
                    tools.append(tool)
                if len(tools) >= MAX_TOOLS:
                    return _clean(tools), bool(result.get("nextCursor")) or len(result["tools"]) > MAX_TOOLS
            next_cursor = result.get("nextCursor")
            if not isinstance(next_cursor, str) or not next_cursor:
                return _clean(tools), False
            cursor = next_cursor
        return _clean(tools), True
    except UpstreamError as exc:
        # The forwarder's messages describe OUR side of the failure (blocked destination, unreachable, too large).
        raise ScanError(str(exc)) from exc


def _clean(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keeps only what the auditor reads, with a bounded name; nothing else the server sent is carried forward."""
    cleaned: list[dict[str, Any]] = []
    for tool in tools[:MAX_TOOLS]:
        name = tool.get("name")
        if not isinstance(name, str) or not name:
            continue
        schema = tool.get("inputSchema")
        cleaned.append({
            "name": name[:MAX_NAME_CHARS],
            "description": tool.get("description") if isinstance(tool.get("description"), str) else "",
            "inputSchema": schema if isinstance(schema, dict) else {},
        })
    return cleaned
