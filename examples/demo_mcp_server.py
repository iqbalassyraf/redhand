"""
A tiny MCP server (Streamable HTTP, JSON responses) for local demos and end-to-end tests.

Tools: list_invoices (read), send_reminder (write), delete_invoice (destructive).
It does nothing real; it returns canned text so you can watch the RedHand gateway allow
or block calls.

Run:  uv run uvicorn examples.demo_mcp_server:app --port 9100
Then register it in the dashboard as slug "xero", URL http://localhost:9100/mcp
(requires ALLOW_INSECURE_MCP_URLS / AGENTWALL_ALLOW_INSECURE_UPSTREAMS in development).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_invoices",
        "description": "List unpaid invoices.",
        "inputSchema": {"type": "object", "properties": {"month": {"type": "string"}}},
    },
    {
        "name": "send_reminder",
        "description": "Email a payment reminder for an invoice.",
        "inputSchema": {"type": "object", "properties": {"invoice_id": {"type": "string"}}},
    },
    {
        "name": "delete_invoice",
        "description": "Delete an invoice.",
        "inputSchema": {"type": "object", "properties": {"invoice_id": {"type": "string"}}},
    },
]

app = FastAPI(title="Demo MCP server (not a real integration)")
calls: list[dict[str, Any]] = []


@app.post("/mcp")
async def mcp(request: Request) -> Response:
    message = await request.json()
    if "id" not in message:
        return Response(status_code=202)
    method = message.get("method")
    calls.append(message)
    if method == "initialize":
        result: dict[str, Any] = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "demo-invoices", "version": "0.1.0"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        name = message.get("params", {}).get("name")
        if name not in {t["name"] for t in TOOLS}:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32602, "message": "Unknown tool"}}
            )
        result = {"content": [{"type": "text", "text": f"demo: {name} executed"}], "isError": False}
    else:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "Method not found"}}
        )
    return JSONResponse(
        {"jsonrpc": "2.0", "id": message["id"], "result": result},
        headers={"Mcp-Session-Id": "demo-session"},
    )
