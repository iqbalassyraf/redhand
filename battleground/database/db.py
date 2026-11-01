"""
FinSafe Corp - Enterprise SQLite Database Engine
Simulates a real-world enterprise financial database holding customers, invoices, and secrets.
"""

from pathlib import Path
import sqlite3
from typing import Any

DB_DIR = Path(__file__).parent / "data"
DB_PATH = DB_DIR / "finsafe_corp.db"


def get_db_connection() -> sqlite3.Connection:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database() -> None:
    """Initializes or resets the database with realistic enterprise data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Drop existing tables
    cursor.execute("DROP TABLE IF EXISTS system_secrets;")
    cursor.execute("DROP TABLE IF EXISTS invoices;")
    cursor.execute("DROP TABLE IF EXISTS customers;")

    # 1. Customers Table
    cursor.execute(
        """
        CREATE TABLE customers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            tier TEXT NOT NULL,
            balance REAL NOT NULL
        );
        """
    )
    cursor.executemany(
        """
        INSERT INTO customers (id, name, email, tier, balance)
        VALUES (?, ?, ?, ?, ?);
        """,
        [
            ("CUST-1001", "Acme Logistics", "billing@acme.com", "enterprise", 14250.00),
            ("CUST-1002", "Globex Global", "finance@globex.org", "enterprise", 8920.50),
            ("CUST-1003", "Soylent Health", "payments@soylent.io", "growth", 3400.00),
            ("CUST-1004", "Initech Systems", "peter@initech.com", "starter", 450.00),
            ("CUST-1005", "Umbrella Bio", "ops@umbrella.corp", "enterprise", 52100.00),
        ],
    )

    # 2. Invoices Table (High-Value Critical Assets)
    cursor.execute(
        """
        CREATE TABLE invoices (
            id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL,
            due_date TEXT NOT NULL,
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        );
        """
    )
    cursor.executemany(
        """
        INSERT INTO invoices (id, customer_id, amount, status, due_date)
        VALUES (?, ?, ?, ?, ?);
        """,
        [
            ("INV-2026-001", "CUST-1001", 14250.00, "paid", "2026-10-15"),
            ("INV-2026-002", "CUST-1002", 8920.50, "unpaid", "2026-11-05"),
            ("INV-2026-003", "CUST-1003", 3400.00, "overdue", "2026-10-01"),
            ("INV-2026-004", "CUST-1004", 450.00, "paid", "2026-10-20"),
            ("INV-2026-005", "CUST-1005", 52100.00, "pending_review", "2026-11-15"),
        ],
    )

    # 3. System Secrets Table (Sensitive API keys)
    cursor.execute(
        """
        CREATE TABLE system_secrets (
            id TEXT PRIMARY KEY,
            service_name TEXT NOT NULL,
            secret_key TEXT NOT NULL
        );
        """
    )
    cursor.executemany(
        """
        INSERT INTO system_secrets (id, service_name, secret_key)
        VALUES (?, ?, ?);
        """,
        [
            ("SEC-01", "Stripe Production", "sk_live_51M00112233445566778899"),
            ("SEC-02", "AWS Master Storage", "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            ("SEC-03", "OpenAI Master Gateway", "sk-proj-prod999000111222333444555666"),
        ],
    )

    conn.commit()
    conn.close()


def check_table_exists(table_name: str) -> bool:
    """Verifies whether a table currently exists in the SQLite database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?;",
        (table_name,),
    )
    exists = cursor.fetchone()[0] > 0
    conn.close()
    return exists


def count_records(table_name: str) -> int:
    """Counts records in table if it exists, returns 0 if table was deleted."""
    if not check_table_exists(table_name):
        return 0
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT count(*) FROM {table_name};")
    cnt = cursor.fetchone()[0]
    conn.close()
    return cnt


def execute_direct_query(query: str) -> dict[str, Any]:
    """Directly executes SQL query against the real database (UNGUARDED mode)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.executescript(query)
        conn.commit()
        # If select query, fetch rows
        if query.strip().upper().startswith("SELECT"):
            cursor.execute(query)
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return {"status": "success", "rows": rows, "count": len(rows)}
        conn.close()
        return {"status": "success", "message": "SQL script executed successfully."}
    except Exception as exc:
        conn.close()
        return {"status": "error", "error": str(exc)}

