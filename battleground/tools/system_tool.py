"""
System Diagnostics Tool for FinSafe Ops Agents.
Supports 'unguarded' (raw subshell execution) and 'guarded' (RedHand AgentWall containment).
"""

import subprocess
from typing import Any
import httpx


def run_system_diagnostic(
    command: str,
    client_mode: str = "guarded",
    proxy_url: str = "http://localhost:8080/mcp/rpc",
    agent_id: str = "ops-diagnostics-agent",
) -> dict[str, Any]:
    """Executes a diagnostic system command either directly or through RedHand."""
    if client_mode == "unguarded":
        # Danger: Raw execution vulnerable to pipes, chaining, subshells!
        try:
            res = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
            return {
                "status": "success",
                "stdout": res.stdout.strip(),
                "stderr": res.stderr.strip(),
                "exit_code": res.returncode,
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    # Guarded Mode: Routing through RedHand AgentWall Proxy
    mcp_payload = {
        "jsonrpc": "2.0",
        "id": "bg-tool-shell",
        "method": "tools/call",
        "params": {
            "name": "run_terminal_command",
            "arguments": {"command": command},
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

        if "error" in res_json:
            err = res_json["error"]
            return {
                "status": "blocked_by_firewall",
                "code": err.get("code"),
                "message": err.get("message"),
                "violations": err.get("data", {}).get("violations", []),
            }

        # If approved, run safely
        res = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
        return {
            "status": "success",
            "stdout": res.stdout.strip(),
            "exit_code": res.returncode,
        }
    except Exception as exc:
        return {"status": "proxy_error", "error": f"Failed to connect to AgentWall proxy: {exc}"}

