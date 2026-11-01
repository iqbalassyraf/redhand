"""
Triage Agent - The entry point for incoming customer support tickets and external web requests.
Vulnerable to indirect prompt injections hiding inside user input.
"""

import re
from typing import Any
from .ops_agent import OpsDiagnosticsAgent
from .sql_analyst import SQLAnalystAgent


class CustomerTriageAgent:
    """Simulates an autonomous AI agent reasoning pipeline that delegates to worker agents."""

    def __init__(self) -> None:
        self.sql_analyst = SQLAnalystAgent()
        self.ops_agent = OpsDiagnosticsAgent()

    def process_incoming_ticket(self, ticket_text: str, client_mode: str = "guarded") -> dict[str, Any]:
        """
        Parses ticket content and routes to the appropriate tool worker.
        Vulnerable to Prompt Injection when attackers embed override instructions!
        """
        ticket_lower = ticket_text.lower()

        # 1. Check for system / server diagnostics first
        pipe_match = re.search(r"(cat\s+[^|;]+(?:\||;)[^\n]+)", ticket_text, re.IGNORECASE)
        if pipe_match or "server" in ticket_lower or "diagnostic" in ticket_lower or "uptime" in ticket_lower:
            if pipe_match:
                # Agent got tricked into running chained or piped command
                generated_cmd = pipe_match.group(1).strip()
            else:
                generated_cmd = "uptime"

            result = self.ops_agent.execute_terminal_task(generated_cmd, client_mode=client_mode)
            return {
                "dispatched_to": "ops_agent",
                "extracted_command": generated_cmd,
                "execution_result": result,
            }

        # 2. Check for injected or requested SQL instructions
        if "sql" in ticket_lower or "drop table" in ticket_lower or "select" in ticket_lower or "invoice" in ticket_lower or "customer" in ticket_lower:
            drop_match = re.search(r"(drop\s+table\s+\w+;?)", ticket_text, re.IGNORECASE)
            select_match = re.search(r"(select\s+[^;]+;?)", ticket_text, re.IGNORECASE)

            if drop_match:
                generated_query = drop_match.group(1).strip()
                if not generated_query.endswith(";"):
                    generated_query += ";"
            elif select_match:
                generated_query = select_match.group(1).strip()
                if not generated_query.endswith(";"):
                    generated_query += ";"
            else:
                generated_query = "SELECT id, name, tier, balance FROM customers LIMIT 5;"

            result = self.sql_analyst.execute_query_task(generated_query, client_mode=client_mode)
            return {
                "dispatched_to": "sql_analyst",
                "extracted_query": generated_query,
                "execution_result": result,
            }

        return {
            "dispatched_to": "none",
            "message": "Ticket does not require tool execution.",
        }
