# RedHand

**Agentic Security Posture Management (ASPM) & Runtime Protection Platform**

## Monorepo Architecture

- [`packages/redhand-sdk`](./packages/redhand-sdk): Python tool interceptor (`@guard`) and `<50ms` in-memory tiered Semantic Firewall (AST + ONNX DeBERTa-v3).
- [`services/redhand-core`](./services/redhand-core): FastAPI Control Plane on GCP Cloud Run handling STS Credential Access Boundary downscoping, durable HITL checkpointing, and OCSF SIEM telemetry ingestion.
- [`apps/redhand-ui`](./apps/redhand-ui): Next.js (App Router) + React Flow real-time topological radar and Human-in-the-Loop circuit breaker command center.
- [`supabase`](./supabase): Multi-tenant PostgreSQL schema, Row Level Security (RLS) policies, and Realtime publications.

