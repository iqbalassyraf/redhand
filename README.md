# RedHand: Agentic Security Posture Management (ASPM) & Runtime Protection

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Next.js 15](https://img.shields.io/badge/Next.js-15.0+-black.svg)](https://nextjs.org/)
[![Zero Trust](https://img.shields.io/badge/architecture-NIST%20SP%20800--207-green.svg)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
[![Compliance](https://img.shields.io/badge/compliance-ISO%2FIEC%2042001%20%7C%20NIST%20AI%20600--1-orange.svg)](https://www.iso.org/standard/81230.html)

**RedHand** is an enterprise-grade **Agentic Security Posture Management (ASPM)** and **Runtime Protection Platform** for autonomous AI agents. 

It provides an inline Zero-Trust reverse proxy (`AgentWall`), a sub-millisecond semantic firewall, ephemeral cloud IAM credential brokering (AWS STS & Google Cloud STS), and Four-Eyes human-in-the-loop circuit breakers to permanently solve the **Lethal Trifecta** in multi-agent workflows.

---

## 1. The Problem: The "Lethal Trifecta"

Autonomous AI agents (built on LangGraph, CrewAI, AutoGen, or Vertex AI) create unprecedented enterprise risk when three vulnerabilities intersect:

```
[Untrusted Inputs]         +  [Broad Ambient IAM]       +  [Autonomous Execution]    =  Catastrophic Breach
(Indirect Prompt Injection)   (Static 24/7 Admin Keys)     (Unchecked Tool Invocation)   (Data Drop / Exfiltration)
```

1. **Untrusted Inputs (Prompt Injections):** Malicious instructions embedded in customer emails, RAG databases, or support tickets hijack the agent's reasoning loop.
2. **Broad Ambient IAM (Standing Privileges):** Agents are provisioned with static, long-lived cloud keys (e.g., `s3:*` or full BigQuery access) mounted directly in container environments.
3. **Autonomous Execution (Unchecked Agency):** Agents execute destructive actions (database drops, cloud infrastructure deletion, fund transfers) without human verification or cryptographic audit trails.

**RedHand eliminates all three attack vectors at the tool-execution boundary.**

---

## 2. Architecture & Data Plane Flow

RedHand operates both as a Python SDK decorator (`@guard`), an in-VPC Kubernetes sidecar proxy, and an inline Model Context Protocol (MCP) gateway:

```mermaid
flowchart LR
    A["AI Agent Runtime<br/>(LangGraph / CrewAI / Claude)"] -->|"1. Inbound Tool Call"| B["RedHand / AgentWall<br/>(:8080 or SDK @guard)"]

    subgraph RedHand ["RedHand Zero-Trust Control & Data Plane"]
        B --> C{"<50ms Semantic Firewall<br/>AST & Lexer Inspection"}
        C -->|"Attack Detected (0.16ms)<br/>DROP / Chaining / Injection"| D["🛑 Block & Alert<br/>(HTTP 403 / JSON-RPC -32000)"]
        C -->|"Policy-as-Code<br/>RH-PAC-002: Cost >$500"| E["🚨 Four-Eyes HITL<br/>Slack / Web UI Dual Signoff"]
        C -->|"Clean Intent"| F["JIT Multi-Cloud STS Broker<br/>AWS Session Policy / GCP CAB"]
        F -->|"2. Scoped Ephemeral Token<br/>(TTL &le; 30-60s)"| G["Upstream Cloud / DB<br/>(S3 / BigQuery / Postgres)"]
        G -->|"3. Raw Response"| H["Egress DLP Secret Scrubber<br/>(Removes API Keys / Tokens)"]
    end

    H -->|"4. Sanitized Output (No Token)"| A
    D --> I[("Immutable WORM Audit Ledger<br/>Merkle Tree Hash Chain (OCSF v1.1)")]
    H --> I
    E -.->|"Approved by 2 Humans"| F
```

---

## 3. Core Capabilities

### 🛡️ Sub-Millisecond Semantic Firewall (`< 0.2ms p99`)
- **SQL AST Inspection (`sqlglot`):** Evaluates query syntax trees in real-time. Permits strictly read-only operations (`SELECT`). Automatically halts `DROP`, `DELETE`, `UPDATE`, `ALTER`, `TRUNCATE`, `INSERT`, `EXEC`, and semicolon-separated multi-statement injections.
- **POSIX Shell Guardrail (`shlex`):** Detects and halts command chaining (`&&`, `||`, `;`, `&`), pipes (`| curl evil.com`), subshells (`$()`, ````), and dangerous primitives (`sudo`, `eval`, `rm -rf`, `nc`).
- **Strict JSON Schema Validation:** Rejects parameter pollution and unexpected fields (`additionalProperties: false`).

### 🔑 Ephemeral Cloud IAM Brokering (Zero Static Credentials)
- **AWS STS AssumeRole with Inline Session Policies:** Mints ephemeral session tokens bound strictly to the target ARN (e.g., a single S3 bucket) with a **30-second TTL**.
- **Google Cloud STS Credential Access Boundaries (CAB):** Computes least-privilege CEL rules dynamically at runtime.
- **Secretless Execution:** The proxy injects `Authorization: Bearer <token>` into outbound requests and strips it from responses before the agent sees it.

### 👥 "Four-Eyes" Human-in-the-Loop (HITL) Circuit Breakers
- **Declarative Policy-as-Code (`RH-PAC-001/002/003`):** High-blast-radius actions (instance terminations, table drops, spend >$500) are automatically frozen in mid-air.
- **Dual-Approval State Machine:** Requires **two distinct operator signatures** via Slack Block Kit interactive buttons or the Web Command Center. Prevents self-approval or duplicate signatures.

### 🧹 Egress Data Loss Prevention (DLP)
- Recursively inspects tool outputs before returning data to the agent.
- Automatically redacts OpenAI keys (`sk-...`), Anthropic keys (`sk-ant-...`), AWS access keys (`AKIA...`), GCP bearer tokens (`ya29...`), and private keys (`-----BEGIN PRIVATE KEY-----`).

### 📜 Tamper-Proof WORM Audit Ledger (ISO 42001 / NIST AI 600-1)
- Structured JSON audit records containing `trace_id`, `span_id`, `agent_id`, `tool_name`, decision, and latency.
- Linked via rolling cryptographic SHA-256 block hash chaining (`record_hash = sha256(prev_hash + canonical_json)`). Verifiable on-demand via `GET /v1/audit/verify`.

### 🔍 Static CI/CD Guard Scanner (`redhand scan`)
- Analyzes agent code in pull requests.
- Detects unguarded tools (`RH-SEC-001`), wildcard IAM scopes (`RH-SEC-002`), and dangerous system builtins (`RH-SEC-003`).
- Outputs standard **OASIS SARIF v2.1.0** reports for GitHub Advanced Security and GitLab CI.

---

## 4. Monorepo Structure

```
project-redhand/
├── apps/
│   └── redhand-ui/              # Next.js 15 Command Center (Flow Canvas, HITL Queue, WORM Ledger)
├── services/
│   └── redhand-core/            # FastAPI Control Plane, Policy Engine, SCIM 2.0, Prometheus /metrics
├── packages/
│   ├── redhand-sdk/             # Python Client SDK (@guard decorator, AST checker, attack fuzzer)
│   └── redhand-sidecar/         # In-VPC Sidecar Proxy container & Kubernetes Helm chart
├── agentwall/                   # Inline Zero-Trust Reverse Proxy for Anthropic MCP and REST
├── battleground/                # Independent Red Team vs. Blue Team simulation with real SQLite database
├── deploy/
│   ├── dashboards/              # Pre-configured Grafana ASPM Dashboard JSON
│   └── helm/                    # Kubernetes Helm charts with Horizontal Pod Autoscalers (HPA)
├── examples/                    # Live FinOps, SecOps, and DevOps multi-agent scripts
├── pyproject.toml               # uv root workspace configuration
└── package.json                 # Next.js & Turborepo workspace configuration
```

---

## 5. Quickstart & Installation

### Prerequisites
- Python 3.11+
- [uv](https://github.com/astral-sh/uv) (ultra-fast Python package runner)
- Node.js 18+ & npm

### 1. Clone & Install
```bash
git clone https://github.com/iqbalassyraf/redhand.git
cd redhand

# Install all Python workspace packages via uv
uv sync

# Install frontend dependencies
npm install
```

### 2. Run the Full Test Suite (57 Tests)
```bash
uv run pytest -v
```
*Expected: 57 passed in <1 second.*

---

## 6. How to Run & Experience RedHand

### Option A: The Live Red-Team Attack Battleground
Run an end-to-end simulation where an attacker attempts destructive SQL drops and shell exfiltration against an autonomous multi-agent financial operations app:

```bash
uv run python battleground/run_battle.py
```

**What you will observe:**
1. **Round 1 (Unguarded):** Attacker injects a prompt injection $\rightarrow$ agent drops the real `invoices` table directly on disk $\rightarrow$ **100% data loss**.
2. **Round 2 (Guarded by RedHand):** Same attack executed $\rightarrow$ RedHand intercepts in **0.16ms** $\rightarrow$ **Attack halted with HTTP 403 / `-32000`** $\rightarrow$ Database remains 100% intact.

---

### Option B: The Multi-Agent Enterprise Simulation (`redhand demo`)
Simulates 3 concurrent enterprise agents (FinOps on LangGraph, SecOps on Vertex ADK, and DevOps on CrewAI):

```bash
uv run redhand demo
```
- Halts prompt injection strikes in **1.25ms**.
- Redacts raw bearer tokens from observation payloads with DLP.
- Trips the **HITL Circuit Breaker** on database termination, pausing the action until approved.

---

### Option C: The Adversarial Attack Fuzzer (`redhand fuzz`)
Stress-tests the Semantic Firewall against synthetic prompt injection, SSRF, jailbreaks, and credential leaks:

```bash
uv run redhand fuzz
```
*Output: 100% Attack Block Rate, 0.16ms p99 latency SLA.*

---

### Option D: The Web Command Center (`http://localhost:3000`)
Launch the Next.js Command Center locally:

```bash
# Terminal 1: Start RedHand Core Control Plane
uv run uvicorn redhand_core.main:app --port 8000 --reload

# Terminal 2: Start AgentWall Proxy
uv run uvicorn agentwall.src.main:app --port 8080 --reload

# Terminal 3: Start Web Command Center
npm run dev
```

Open **`http://localhost:3000`** in your browser:
- **Interactive Flow Canvas:** Visual radar tracking agent-to-tool connections.
- **Review Queue:** Dual-signature approval for high-risk actions.
- **Flight Recorder Dock:** Deep-dive inspection of blocked security events.
- **WORM Ledger:** Live cryptographic block verification and Merkle tree roots.
- **Prometheus Metrics:** Live OpenMetrics scraped at `http://localhost:8000/metrics`.

---

## 7. Integration Guide: Connecting Your Own Agents

### Method 1: The Zero-Code Proxy Route (Anthropic MCP)
If your agents communicate via Anthropic Model Context Protocol (MCP) or OpenAI function calling, point your tool server endpoint to AgentWall:

```json
{
  "mcpServers": {
    "secure-tools": {
      "url": "http://localhost:8080/mcp/rpc"
    }
  }
}
```

### Method 2: The Python SDK Route (`@guard`)
Wrap any existing Python tool function with the `@guard` decorator:

```python
from redhand_sdk import guard

@guard(
    tool_name="execute_sql",
    cloud="gcp",
    target_resource="//bigquery.googleapis.com/projects/prod-data/datasets/warehouse",
    permissions=["bigquery.tables.getData"],
)
async def query_warehouse(query: str):
    # Safe execution: RedHand handles firewall inspection & STS credential injection
    return await db.execute(query)
```

---

## 8. Benchmark & Verification Matrix

| Metric / Capability | Measured Performance | Industry Standard | Status |
| :--- | :--- | :--- | :--- |
| **Semantic Firewall Latency (p99)** | **0.16 ms** | < 50.0 ms | `PASS (300x faster)` |
| **Prompt Injection Block Rate** | **100.0%** (7/7 Attack Vectors) | > 95% | `PASS` |
| **Benign Payload False Positive Rate** | **0.0%** (100% Pass Rate) | < 2% | `PASS` |
| **JIT Cloud STS Mint Latency** | **1.20 ms** | < 100.0 ms | `PASS` |
| **Token Cache Hit Latency** | **0.02 ms** | < 1.0 ms | `PASS` |
| **Automated Test Coverage** | **57 / 57 Tests Passed** | 100% | `PASS` |

---

## 9. Security Governance & Compliance Standards

- **NIST SP 800-207:** Zero Trust Architecture (explicit, continuous per-request validation).
- **ISO/IEC 42001:** Artificial Intelligence Management System (AIMS) governance and auditable tool containment.
- **NIST AI 600-1:** Managing Risks of Generative AI (preventing autonomous runaway actions).
- **OWASP Top 10 for LLMs & AI Agents:** Directly mitigates LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM07 (System Prompt Leakage), and LLM08 (Excessive Agency).

---

## 10. License

RedHand is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for details.
