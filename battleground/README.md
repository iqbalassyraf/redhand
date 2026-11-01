# FinSafe Battleground: AI Agent Red-Team Attack Simulation

This directory is an **independent, self-contained multi-agent environment** simulating a customer's production system (FinSafe Corp). It operates completely separated from RedHand.

---

## 1. Architecture

```
battleground/
├── database/
│   ├── db.py                 # Real SQLite database engine (customers, invoices, secrets)
│   └── data/                 # SQLite storage (finsafe_corp.db)
├── tools/
│   ├── database_tool.py      # Database query tool (supports Direct or RedHand MCP Proxy)
│   └── system_tool.py        # System diagnostics tool (supports Direct or RedHand MCP Proxy)
├── agents/
│   ├── triage_agent.py       # Ingests user tickets & delegates to worker agents
│   ├── sql_analyst.py        # Generates & runs database queries
│   └── ops_agent.py          # Runs diagnostic shell commands
├── attacker/
│   └── attacks.py            # Weaponized indirect prompt injections & exploits
├── run_battle.py             # Interactive Red-Team vs. Blue-Team showdown runner
└── README.md
```

---

## 2. How to Run the Battle

Make sure the RedHand AgentWall Proxy is running on port 8080:
```bash
uv run uvicorn agentwall.src.main:app --port 8080 --reload
```

Then run the battle simulation:
```bash
python battleground/run_battle.py
```

---

## 3. What the Battle Proves

- **Round 1 (Unguarded):**  
  The agent is tricked by an indirect prompt injection. It calls `DROP TABLE invoices;` directly on SQLite. **The real invoices table is destroyed** and $79,120.50 in tracked customer revenue is wiped out.
  
- **Round 2 (Guarded by RedHand):**  
  The agent is hit with the exact same attack. The call is routed through `http://localhost:8080/mcp/rpc`. RedHand's AST firewall intercepts and halts the `DROP` statement in **0.16 milliseconds**. **Zero data loss**, and the incident is recorded in the immutable WORM ledger.

