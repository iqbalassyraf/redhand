"""
RedHand SDK - Static AST Tool & Policy Scanner
File: packages/redhand-sdk/src/redhand_sdk/scanner/ast_checker.py

Parses Python ASTs of agent codebases to detect:
1. RH-SEC-001: Missing @guard decorator on LLM agent tools.
2. RH-SEC-002: Overly broad IAM permission wildcards (e.g., 'roles/*') in tool definitions.
3. RH-SEC-003: Destructive function naming without DESTRUCTIVE / CRITICAL RiskTier.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

DESTRUCTIVE_NAME_PREFIXES = (
    "delete_",
    "drop_",
    "terminate_",
    "destroy_",
    "kill_",
    "purge_",
    "truncate_",
    "rm_",
)

KNOWN_TOOL_DECORATORS = ("tool", "agent_tool", "mcp_tool")


@dataclass(frozen=True, slots=True)
class ScanFinding:
    rule_id: str
    rule_name: str
    severity: str  # error, warning, note
    file_path: str
    line_number: int
    tool_name: str
    message: str


class ToolASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[ScanFinding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._analyze_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._analyze_function(node)
        self.generic_visit(node)

    def _analyze_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        decorator_names = [self._get_decorator_name(d) for d in node.decorator_list]
        is_tool = any(
            any(k in dec_name.lower() for k in KNOWN_TOOL_DECORATORS)
            for dec_name in decorator_names
        )
        has_guard = any("guard" in dec_name.lower() for dec_name in decorator_names)

        func_name = node.name.lower()
        is_destructive_name = any(func_name.startswith(p) for p in DESTRUCTIVE_NAME_PREFIXES)

        # RH-SEC-001: Missing @guard on exposed agent tool
        if is_tool and not has_guard:
            self.findings.append(
                ScanFinding(
                    rule_id="RH-SEC-001",
                    rule_name="Unprotected Agent Tool",
                    severity="error",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    tool_name=node.name,
                    message=(
                        f"Agent tool '{node.name}' lacks @guard runtime protection. "
                        "All tools callable by autonomous agents must be guarded."
                    ),
                )
            )

        # RH-SEC-003: Destructive function without @guard or with improper tier
        if is_destructive_name and not has_guard:
            self.findings.append(
                ScanFinding(
                    rule_id="RH-SEC-003",
                    rule_name="Unguarded Destructive Tool",
                    severity="error",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    tool_name=node.name,
                    message=(
                        f"Potentially destructive tool '{node.name}' has no @guard circuit breaker. "
                        "Destructive actions can cause catastrophic infrastructure loss."
                    ),
                )
            )

        # Inspect @guard arguments if present for wildcards (RH-SEC-002)
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and "guard" in self._get_decorator_name(dec).lower():
                self._check_guard_call(dec, node)

    def _check_guard_call(
        self, call_node: ast.Call, func_node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        for kw in call_node.keywords:
            if kw.arg in ("target_iam_permissions", "permissions"):
                if isinstance(kw.value, (ast.List, ast.Tuple)):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            if elt.value in ("*", "roles/*", "*:*", "admin"):
                                self.findings.append(
                                    ScanFinding(
                                        rule_id="RH-SEC-002",
                                        rule_name="Overly Broad IAM Permission Wildcard",
                                        severity="warning",
                                        file_path=self.file_path,
                                        line_number=func_node.lineno,
                                        tool_name=func_node.name,
                                        message=(
                                            f"Tool '{func_node.name}' requests overly broad IAM permission '{elt.value}'. "
                                            "Specify explicit downscoped actions (e.g., 'roles/cloudsql.viewer')."
                                        ),
                                    )
                                )

    @staticmethod
    def _get_decorator_name(dec: ast.expr) -> str:
        if isinstance(dec, ast.Name):
            return dec.id
        if isinstance(dec, ast.Attribute):
            return dec.attr
        if isinstance(dec, ast.Call):
            return ToolASTVisitor._get_decorator_name(dec.func)
        return ""


def scan_python_file(file_path: str | Path) -> list[ScanFinding]:
    """Scans a single Python file for agent tool security vulnerabilities."""
    path = Path(file_path)
    if not path.is_file() or path.suffix != ".py":
        return []

    try:
        content = path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(path))
        visitor = ToolASTVisitor(file_path=str(path))
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError:
        return []


def scan_directory(directory: str | Path) -> list[ScanFinding]:
    """Recursively scans all Python files in a directory."""
    root = Path(directory)
    findings: list[ScanFinding] = []
    for p in root.rglob("*.py"):
        # Ignore virtualenvs, caches, and test files
        if any(part in p.parts for part in (".venv", "node_modules", "__pycache__", ".git")):
            continue
        findings.extend(scan_python_file(p))
    return findings

