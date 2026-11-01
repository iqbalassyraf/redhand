"""
AST-based semantic guardrails for SQL and Shell tools, plus Egress DLP Taint inspection.
"""

import re
import shlex
from typing import Any
import sqlglot
from sqlglot import exp


class SQLASTGuardrail:
    """Enforces strict read-only SQL semantics via Abstract Syntax Tree traversal."""

    DESTRUCTIVE_EXPRESSION_TYPES = (
        exp.Drop,
        exp.Delete,
        exp.Update,
        exp.Alter,
        exp.Insert,
        exp.TruncateTable if hasattr(exp, "TruncateTable") else exp.Truncate,
        exp.Create,
        exp.Command,
    )

    FORBIDDEN_KEYWORDS = [
        "INTO OUTFILE",
        "INTO DUMPFILE",
        "LOAD_FILE",
        "XP_CMDSHELL",
        "SP_EXECUTESQL",
        "SHUTDOWN",
    ]

    @classmethod
    def evaluate(
        cls,
        query: str,
        allowed_statements: list[str] | None = None,
        forbidden_clauses: list[str] | None = None,
        forbidden_columns: list[str] | None = None,
        max_rows_limit: int | None = None,
    ) -> tuple[bool, list[str]]:
        violations: list[str] = []
        if not query or not query.strip():
            return False, ["SQL query cannot be empty."]

        # Check raw string forbidden clauses
        upper_query = query.upper()
        clauses_to_check = (forbidden_clauses or []) + cls.FORBIDDEN_KEYWORDS
        for clause in clauses_to_check:
            if clause.upper() in upper_query:
                violations.append(f"SQL contains prohibited clause or keyword: '{clause}'")

        # Parse with sqlglot
        try:
            parsed_expressions = sqlglot.parse(query)
        except Exception as exc:
            violations.append(f"Failed to parse SQL query AST: {exc}")
            return False, violations

        if not parsed_expressions or all(e is None for e in parsed_expressions):
            violations.append("Query resulted in empty AST.")
            return False, violations

        allowed = [s.upper() for s in (allowed_statements or ["SELECT"])]
        forbidden_col_set = {c.lower() for c in (forbidden_columns or [])}

        for idx, expression in enumerate(parsed_expressions):
            if expression is None:
                continue

            # Verify statement root type
            expr_name = expression.key.upper() if hasattr(expression, "key") else type(expression).__name__.upper()
            if expr_name not in allowed:
                violations.append(
                    f"Statement {idx + 1} '{expr_name}' is not in allowed statements list: {allowed}"
                )

            # Walk all subnodes in AST to detect hidden destructive nodes
            for node in expression.walk():
                if isinstance(node, cls.DESTRUCTIVE_EXPRESSION_TYPES):
                    violations.append(
                        f"Prohibited destructive AST node detected: '{type(node).__name__}'"
                    )

            # Column-level policy enforcement (Data Exfiltration Prevention)
            if forbidden_col_set:
                for col_node in expression.find_all(exp.Column):
                    col_name = col_node.name.lower()
                    if col_name in forbidden_col_set:
                        violations.append(
                            f"Access to sensitive column '{col_node.name}' is prohibited by data governance policy."
                        )

            # Hard row limit enforcement (Preventing Full Table Dump Exfiltration)
            if max_rows_limit is not None and expr_name == "SELECT":
                limit_node = expression.find(exp.Limit)
                if not limit_node:
                    violations.append(
                        f"Query lacks mandatory LIMIT clause (enforced maximum: {max_rows_limit} rows)."
                    )
                else:
                    try:
                        limit_val = int(str(limit_node.expression).strip("'\""))
                        if limit_val > max_rows_limit:
                            violations.append(
                                f"Requested LIMIT {limit_val} exceeds maximum allowed row limit of {max_rows_limit}."
                            )
                    except Exception:
                        violations.append("Invalid or unparseable LIMIT clause in SQL query.")

        return len(violations) == 0, violations


class ShellASTGuardrail:
    """
    POSIX-compliant shell command lexer & AST guardrail.
    Enforces positive binary allowlists and anti-evasion checks over fragile denylists.
    """

    CHAINING_OPERATORS = {"&&", "||", ";", "&"}
    SUBSHELL_PATTERNS = [
        re.compile(r"\$\(.*\)"),          # $(command)
        re.compile(r"`.*`"),              # `command`
        re.compile(r"<\(.*\)"),           # <(process substitution)
        re.compile(r">\(.*\)"),           # >(process substitution)
        re.compile(r"\$\{.*\}"),          # ${VAR} expansion evasion
    ]
    EVASION_PATTERNS = [
        re.compile(r"\\x[0-9a-fA-F]{2}"), # Hex escape evasion
        re.compile(r"\\u[0-9a-fA-F]{4}"), # Unicode escape evasion
        re.compile(r"base64\s+(?:-d|--decode)", re.IGNORECASE), # Base64 decoded execution
        re.compile(r"(?:python|perl|ruby|node|sh|bash)\s+-c", re.IGNORECASE), # Dynamic inline execution
    ]
    DANGEROUS_PRIMITIVES = {
        "sudo", "su", "eval", "exec", "curl", "wget", "nc", "netcat", "ncat",
        "mkfifo", "bash", "sh", "zsh", "chmod", "chown", "rm", "kill", "pkill",
        "shutdown", "reboot", "dd", "env", "export",
    }

    @classmethod
    def evaluate(
        cls,
        command_str: str,
        allowed_binaries: list[str] | None = None,
        block_chaining: bool = True,
        block_subshells: bool = True,
        block_dangerous_primitives: bool = True,
    ) -> tuple[bool, list[str]]:
        violations: list[str] = []
        if not command_str or not command_str.strip():
            return False, ["Shell command cannot be empty."]

        # 1. Anti-evasion & Obfuscation Detection
        for evasion_pat in cls.EVASION_PATTERNS:
            if evasion_pat.search(command_str):
                violations.append(f"Command obfuscation or dynamic code evaluation detected: '{evasion_pat.pattern}'")

        # 2. Subshell & command substitution detection
        if block_subshells:
            for pattern in cls.SUBSHELL_PATTERNS:
                if pattern.search(command_str):
                    violations.append(f"Subshell or command substitution syntax detected: {pattern.pattern}")

        # 3. Command chaining detection via raw string & lexer
        if block_chaining:
            for op in cls.CHAINING_OPERATORS:
                if op in command_str:
                    violations.append(f"Command chaining operator '{op}' is prohibited.")

        # 4. Lexical tokenization using shlex
        try:
            tokens = shlex.split(command_str, posix=True)
        except Exception as exc:
            return False, [f"Failed to tokenize shell command: {exc}"]

        if not tokens:
            return False, ["Shell command parsed into empty token list."]

        base_cmd = tokens[0].lower()
        if "/" in base_cmd:
            base_cmd = base_cmd.split("/")[-1]

        # 5. Positive Allowlist Enforcement (Deny-by-default)
        if allowed_binaries is not None:
            allowed_set = {b.lower() for b in allowed_binaries}
            if base_cmd not in allowed_set:
                violations.append(
                    f"Executable '{base_cmd}' is not in the positive security allowlist: {allowed_binaries}. Deny-by-default enforced."
                )
        else:
            violations.append("Shell execution blocked: zero-trust policy mandates an explicit allowed_binaries allowlist.")

        # 6. Check dangerous primitives anywhere in arguments
        if block_dangerous_primitives:
            for token in tokens:
                clean_tok = token.lower().strip()
                if clean_tok in cls.DANGEROUS_PRIMITIVES and clean_tok != base_cmd:
                    violations.append(f"Dangerous primitive found in arguments: '{clean_tok}'")
                if "169.254.169.254" in clean_tok or "/dev/tcp" in clean_tok:
                    violations.append(f"Network exfiltration or SSRF target detected: '{clean_tok}'")

        # 7. Pipe redirection check
        if "|" in command_str:
            violations.append("Pipe operator '|' is prohibited in containment mode.")

        return len(violations) == 0, violations


class EgressTaintGuardrail:
    """Detects high-entropy credential leakage, private keys, and exfiltration targets."""

    PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("OPENAI_KEY", re.compile(r"sk-[a-zA-Z0-9_-]{20,}")),
        ("ANTHROPIC_KEY", re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}")),
        ("AWS_KEY", re.compile(r"(?:A3T[A-Z0-9]|AKIA[0-9A-Z]{16})")),
        ("GCP_BEARER", re.compile(r"ya29\.[0-9a-zA-Z_.-]{16,}")),
        ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:[A-Z ]* )?PRIVATE KEY-----")),
        ("METADATA_SSRF", re.compile(r"http://169\.254\.169\.254")),
        ("EXFIL_WEBHOOK", re.compile(r"(?:webhook\.site|requestbin\.com|pipedream\.net)")),
    ]

    @classmethod
    def scan_and_redact(cls, data: Any) -> tuple[Any, list[str]]:
        """Recursively scans data structure and redacts matched secrets."""
        detections: list[str] = []

        def _clean_str(text: str) -> str:
            cleaned = text
            for name, pattern in cls.PATTERNS:
                matches = pattern.findall(cleaned)
                if matches:
                    for m in matches:
                        detections.append(f"Detected secret '{name}'")
                        cleaned = cleaned.replace(m, f"[REDACTED_SECRET:{name}]")
            return cleaned

        def _traverse(obj: Any) -> Any:
            if isinstance(obj, str):
                return _clean_str(obj)
            elif isinstance(obj, dict):
                return {k: _traverse(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [_traverse(item) for item in obj]
            return obj

        sanitized_data = _traverse(data)
        return sanitized_data, detections
