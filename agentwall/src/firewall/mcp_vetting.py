"""
MCP Server Manifest & Capability Auditor.
Performs pre-install static security vetting of Model Context Protocol (MCP) servers,
analyzing binary commands, environment secrets, tool permissions, and schema constraints.
"""

import os
import re
from typing import Any, Literal
from pydantic import BaseModel, Field
import structlog

from .description_rules import scan_description

logger = structlog.get_logger(__name__)


class MCPFinding(BaseModel):
    id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    category: Literal[
        "EXECUTION_RISK",
        "CREDENTIAL_EXPOSURE",
        "FILESYSTEM_RISK",
        "SCHEMA_RISK",
        "NETWORK_RISK",
        "DESCRIPTION_RISK",
    ]
    tool_name: str | None = None
    title: str
    description: str
    remediation: str


class MCPVettingReport(BaseModel):
    server_name: str
    risk_score: int = Field(ge=0, le=100)
    verdict: Literal["PASS", "WARN", "FAIL"]
    total_tools_scanned: int
    findings: list[MCPFinding] = Field(default_factory=list)
    recommended_policy: dict[str, Any] = Field(default_factory=dict)


_WORDS = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    """Lower-case word tokens of a name, splitting on punctuation, underscores and camelCase, so 'seashell_lookup' is
    {'seashell', 'lookup'} and does not contain 'shell' (substring matching flagged harmless names)."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return set(_WORDS.findall(spaced.lower()))


def _keyword_hit(keywords: set[str], tokens: set[str]) -> bool:
    """A keyword like 'write_file' hits when all of its words are tokens; 'bash' hits when 'bash' is a token."""
    return any(set(k.split("_")) <= tokens for k in keywords)


class MCPServerAuditor:
    """
    Audits MCP server configuration manifests and tool definitions prior to installation.
    Prevents untrusted or overprivileged tool extensions from compromising the host environment.
    """

    DANGEROUS_COMMANDS = {"bash", "sh", "zsh", "cmd.exe", "powershell", "python -c", "perl"}
    RAW_EXEC_KEYWORDS = {"bash", "shell", "exec", "terminal", "eval", "system", "command", "run_cmd"}
    FILESYSTEM_KEYWORDS = {"write_file", "delete_file", "overwrite", "read_all", "filesystem"}
    DATABASE_KEYWORDS = {"execute_sql", "query_db", "run_query", "raw_sql", "db_execute"}
    NETWORK_KEYWORDS = {"fetch", "http_request", "curl", "webhook", "send_request", "download"}

    SECRET_ENV_PATTERNS = [
        re.compile(r"sk-[a-zA-Z0-9_-]{20,}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"gh[pousr]_[a-zA-Z0-9]{36}"),
        re.compile(r"ya29\.[0-9a-zA-Z_.-]{20,}"),
    ]

    @classmethod
    def audit_manifest(cls, manifest: dict[str, Any]) -> MCPVettingReport:
        server_name = manifest.get("name") or manifest.get("server_name") or "unnamed-mcp-server"
        findings: list[MCPFinding] = []
        score = 0

        command = str(manifest.get("command", "")).lower()
        args = [str(a).lower() for a in manifest.get("args", [])]
        env_vars = manifest.get("env", {})
        tools = manifest.get("tools", [])

        # 1. Audit Server Binary & Invocation Arguments. Matches whole program names and argument tokens, not substrings,
        # so 'dist/shellfish.js' is not a shell.
        program = os.path.basename(command.split()[0]) if command.strip() else ""
        program = program[:-4] if program.endswith(".exe") else program
        arg_tokens = {t for a in args for t in _WORDS.findall(a)}
        for d_cmd in cls.DANGEROUS_COMMANDS:
            head, _, flag = d_cmd.partition(" ")
            if flag:  # an interpreter run with an inline-code flag, such as 'python -c'
                matched = program.startswith(head) and flag in args
            else:
                matched = program == d_cmd or program == d_cmd.replace(".exe", "") or d_cmd in arg_tokens
            if matched:
                score += 40
                findings.append(
                    MCPFinding(
                        id="MCP-SEC-001",
                        severity="CRITICAL",
                        category="EXECUTION_RISK",
                        title=f"Direct Shell or Interpreter Execution Detected ({d_cmd})",
                        description=f"Server launches via interactive shell or dynamic interpreter '{d_cmd}', exposing arbitrary code execution vectors.",
                        remediation="Package MCP server as a standalone compiled binary or containerized service without shell wrappers.",
                    )
                )

        # 2. Audit Environment Variables for Static Secrets
        for env_key, env_val in env_vars.items():
            str_val = str(env_val)
            for pat in cls.SECRET_ENV_PATTERNS:
                if pat.search(str_val):
                    score += 35
                    findings.append(
                        MCPFinding(
                            id="MCP-SEC-002",
                            severity="CRITICAL",
                            category="CREDENTIAL_EXPOSURE",
                            title=f"Hardcoded Static Secret in Environment Variable '{env_key}'",
                            description=f"Environment variable '{env_key}' contains a high-entropy cloud or API secret key.",
                            remediation="Do not pass static long-lived credentials. Utilize AgentWall JIT Ephemeral STS broker instead.",
                        )
                    )

        # 3. Audit Tool Definitions & Schemas
        recommended_tools_policy: dict[str, Any] = {}

        for tool in tools:
            tool_name = tool.get("name", "unnamed_tool")
            raw_desc = tool.get("description", "")
            raw_desc = raw_desc if isinstance(raw_desc, str) else ""
            tool_desc = raw_desc.lower()
            input_schema = tool.get("inputSchema") or tool.get("schema") or {}
            properties = input_schema.get("properties", {})
            required_props = input_schema.get("required", [])
            tool_lower = tool_name.lower()
            name_tokens, desc_tokens = _tokens(str(tool_name)), _tokens(tool_desc)

            # Check arbitrary command execution
            if _keyword_hit(cls.RAW_EXEC_KEYWORDS, name_tokens | desc_tokens):
                score += 30
                findings.append(
                    MCPFinding(
                        id="MCP-SEC-003",
                        severity="HIGH",
                        category="EXECUTION_RISK",
                        tool_name=tool_name,
                        title=f"Arbitrary Command/Script Execution Tool: '{tool_name}'",
                        description=f"Tool '{tool_name}' provides direct execution access to terminal or system shell primitives.",
                        remediation="Constrain tool with ShellASTGuardrail positive allowlist or replace with intent-specific micro-tools.",
                    )
                )

            # Check destructive filesystem capabilities
            if _keyword_hit(cls.FILESYSTEM_KEYWORDS, name_tokens):
                score += 25
                findings.append(
                    MCPFinding(
                        id="MCP-SEC-004",
                        severity="HIGH",
                        category="FILESYSTEM_RISK",
                        tool_name=tool_name,
                        title=f"Potentially Destructive Filesystem Access: '{tool_name}'",
                        description=f"Tool '{tool_name}' exhibits broad filesystem read/write or deletion privileges.",
                        remediation="Enforce chroot/path jail regex constraints in input schema and disallow traversal sequences.",
                    )
                )

            # Check SQL / database tools
            if _keyword_hit(cls.DATABASE_KEYWORDS, name_tokens):
                score += 20
                findings.append(
                    MCPFinding(
                        id="MCP-SEC-005",
                        severity="MEDIUM",
                        category="SCHEMA_RISK",
                        tool_name=tool_name,
                        title=f"Database Access Tool Detected: '{tool_name}'",
                        description=f"Tool '{tool_name}' connects to persistent database. Full table dump or data poisoning risks exist.",
                        remediation="Apply SQLASTGuardrail with mandatory LIMIT clauses and column-level exfiltration restrictions.",
                    )
                )

            # Check network-capable tools (name only, like the filesystem and database checks)
            if _keyword_hit(cls.NETWORK_KEYWORDS, name_tokens):
                score += 15
                findings.append(
                    MCPFinding(
                        id="MCP-SEC-009",
                        severity="MEDIUM",
                        category="NETWORK_RISK",
                        tool_name=tool_name,
                        title=f"Network-Capable Tool: '{tool_name}'",
                        description=f"Tool '{tool_name}' can send requests to outside addresses, which can carry data out.",
                        remediation="Restrict destinations with an allowlist and review what data the tool can send.",
                    )
                )

            # Check the description for hidden instructions, concealment, exfiltration and cross-tool coercion. The
            # description text is untrusted: findings carry the rule's fixed wording and never repeat it.
            for rule in scan_description(raw_desc):
                score += 35 if rule.severity == "HIGH" else 15
                findings.append(
                    MCPFinding(
                        id=rule.rule_id,
                        severity="HIGH" if rule.severity == "HIGH" else "MEDIUM",
                        category="DESCRIPTION_RISK",
                        tool_name=tool_name,
                        title=rule.title,
                        description=rule.description,
                        remediation=rule.remediation,
                    )
                )

            # Check schema robustness
            if not input_schema:
                score += 20
                findings.append(
                    MCPFinding(
                        id="MCP-SEC-006",
                        severity="HIGH",
                        category="SCHEMA_RISK",
                        tool_name=tool_name,
                        title=f"Missing Input Schema in Tool '{tool_name}'",
                        description=f"Tool '{tool_name}' specifies no parameter schema, accepting unbounded payload injection.",
                        remediation="Define strict JSON schema with type constraints and maxLength boundaries.",
                    )
                )
            else:
                if input_schema.get("additionalProperties") is True:
                    score += 10
                    findings.append(
                        MCPFinding(
                            id="MCP-SEC-007",
                            severity="MEDIUM",
                            category="SCHEMA_RISK",
                            tool_name=tool_name,
                            title=f"Permissive additionalProperties in Tool '{tool_name}'",
                            description="Tool schema allows arbitrary additional fields to pass unvalidated.",
                            remediation="Set 'additionalProperties: false' in tool JSON schema.",
                        )
                    )
                # Check for unbounded strings
                for prop_name, prop_def in properties.items():
                    if isinstance(prop_def, dict) and prop_def.get("type") == "string":
                        if "maxLength" not in prop_def and "pattern" not in prop_def:
                            score += 5
                            findings.append(
                                MCPFinding(
                                    id="MCP-SEC-008",
                                    severity="LOW",
                                    category="SCHEMA_RISK",
                                    tool_name=tool_name,
                                    title=f"Unbounded String Field '{prop_name}' in Tool '{tool_name}'",
                                    description=f"Parameter '{prop_name}' does not specify maxLength or regex pattern, enabling prompt injection delivery.",
                                    remediation=f"Add 'maxLength: 256' or specific regex constraint to '{prop_name}'.",
                                )
                            )

            # Auto-generate recommended sandboxed AgentWall policy snippet
            recommended_tools_policy[tool_name] = {
                "type": "shell" if any(k in tool_lower for k in cls.RAW_EXEC_KEYWORDS) else "generic",
                "description": f"Sandboxed definition for {tool_name}",
                "upstream_url": f"http://localhost:8080/mcp/tools/{tool_name}",
                "iam_provider": "local_sts",
                "target_audience": f"https://mcp.{server_name}.internal",
                "schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required_props,
                    "additionalProperties": False,
                },
            }

        # Calculate final verdict
        clamped_score = min(score, 100)
        if clamped_score > 60:
            verdict: Literal["PASS", "WARN", "FAIL"] = "FAIL"
        elif clamped_score > 20:
            verdict = "WARN"
        else:
            verdict = "PASS"

        recommended_policy = {
            "version": "1.0",
            "server": server_name,
            "settings": {"fail_mode": "fail_closed", "egress_dlp_enabled": True},
            "tools": recommended_tools_policy,
        }

        return MCPVettingReport(
            server_name=server_name,
            risk_score=clamped_score,
            verdict=verdict,
            total_tools_scanned=len(tools),
            findings=findings,
            recommended_policy=recommended_policy,
        )

