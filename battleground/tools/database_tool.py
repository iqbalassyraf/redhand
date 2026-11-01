"""
Database Tool for FinSafe Agents.
Supports two execution modes:
1. 'unguarded' (Direct SQLite execution, zero protection)
2. 'guarded' (Routes through RedHand AgentWall Proxy at http://localhost:8080)
"""

from typing import Any
import httpx
from ..database.db import execute_direct_query


def run_database_query(
    query: str,
    client_mode: str = "guarded",
    proxy_url: str = "http://localhost:8080/mcp/rpc",
    agent_id: str = "sql-analyst-agent",
) -> dict[str, Any]:
    """Executes a database query either directly or via the RedHand Zero-Trust Proxy."""
    if client_mode == "unguarded":
        # Danger: Executing directly with no firewall or IAM broker!
        return execute_direct_query(query)

    # Guarded Mode: Routing through RedHand AgentWall Reverse Proxy
    mcp_payload = {
        "jsonrpc": "2.0",
        "id": "bg-tool-sql",
        "method": "tools/call",
        "params": {
            "name": "execute_sql",
            "arguments": {"query": query},
        },
    }

    try:
        response = httpx.post(
            proxy_url,
            json=mcp_payload,
            headers={"X-Agent-ID": agent_id, "X-Caller-Identity": "finsafe-agent-runtime"},
            timeout=5.0,
        )
        res_json = response.json()

        # Check if RedHand blocked the call
        if "error" in res_json:
            err = res_json["error"]
            return {
                "status": "blocked_by_firewall",
                "code": err.get("code"),
                "message": err.get("message"),
                "violations": err.get("data", {}).get("violations", []),
            }

        # If approved by RedHand, execute on the actual database
        return execute_direct_query(query)

    except Exception as exc:
        return {"status": "proxy_error", "error": f"Failed to connect to AgentWall proxy: {exc}"}

