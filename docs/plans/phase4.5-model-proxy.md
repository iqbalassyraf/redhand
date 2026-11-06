> **Status (2026-11-06):** the owner asked for Phase 4.5 to be built as well as possible. This document is the
> original go/no-go evaluation (drafted by a cloud session on 2026-11-06). The approved build plan that
> supersedes its open decisions is `phase4.5-build-plan.md`.
> Section 3 below also uses older OWASP numbering in places; verify against the current OWASP list before anything
> is published.

# Phase 4.5 evaluation: model proxy (go / no-go)

**Status:** Evaluation, not approved. No code. This document exists so the decision is made on an
honest latency/cost/uptime model rather than enthusiasm. If approved, it becomes an ADR and a full
plan in the §3.2 format; if declined, it stays as the record of why.

**One-line framing:** today RedHand sits between an agent and its *tools* (the MCP gateway). A model
proxy would also put RedHand between an agent and its *model* (Anthropic / OpenAI / Gemini). That one
change is what unlocks a cluster of otherwise-impossible features — and it is also the single biggest
commitment RedHand could make, because it would then carry the agent's *thinking*, not just its
*doing*.

---

## 1. Why this is separate from Phase 4

Phase 4 ("Check inputs") is deterministic, local, and adds no new uptime dependency. The model proxy
is the opposite on all three counts, and it touches principles we set on purpose:

- **CLAUDE.md §4.6 — hot path is lean:** "The gateway does lookups and rule evaluation only. No LLM
  calls, no synchronous calls to slow external services." A model proxy *is* a synchronous call to a
  slow external service, on every turn, including streaming. It is a different kind of system from the
  MCP gateway, not a bigger version of it.
- **§1 / briefing — cost to serve:** must stay a small fraction of the per-agent price. Proxying model
  traffic means paying for bytes in/out and holding open streaming connections for the length of every
  completion. This is a per-token-ish cost profile, the exact thing the cost constraint warns about.
- **§8 — availability:** the 99.9% target currently covers tool routing. Behind a model proxy, a
  RedHand outage stops the agent from *thinking*, not just from calling a tool. The blast radius of
  downtime grows by an order of magnitude.
- **Product truth:** "RedHand only controls what flows through RedHand." A model proxy is *consistent*
  with this (it widens what flows through), but it widens the promise enormously and must be matched by
  real reliability, or the copy overclaims.

None of this makes it wrong — it makes it a deliberate, separately-owned decision.

## 2. What it unlocks (the upside, concretely)

Each of these is impossible or partial without the proxy, and becomes clean with it:

- **Dollar / token budgets.** Budget Guard counts *calls* today, explicitly because "dollar budgets
  would need model traffic routed through RedHand" (ADR 0010). The proxy turns Budget Guard into a
  real spend cap and real token-rate limiting.
- **Injection Radar on user inputs (OWASP LLM01).** RedHand can only inspect the prompt actually sent
  to the model if it sits in front of the model. Phase 4 covers tool results and RAG ingest; the proxy
  adds the user-input leg.
- **Insecure output handling at the source (LLM02).** Inspect/redact the model's *output stream*
  before the agent acts on it, not just tool results.
- **System-prompt leakage detection (LLM07).** See the actual system prompt and detect it (or its
  canary) appearing in output — directly, not only via the tool path.
- **Unbounded consumption (LLM10).** Token-level rate and concurrency limits, loop detection on
  generation, not just on tool calls.
- **Approved-model enforcement with teeth.** Phase 4's provider allowlist becomes an enforced routing
  decision rather than a check on a tool name.

## 3. The costs (the downside, concretely)

- **Latency.** Every token round-trips through RedHand. Streaming must be transparent (first-token
  latency and inter-token gaps are what users feel). Any per-token inspection competes with that
  budget. This is a new, hard SLO we do not have today.
- **Uptime.** RedHand becomes in-path for generation. Needs multi-instance, health-checked, probably
  multi-region eventually — a bigger operational surface than the scale-to-zero Cloud Run setup now.
- **Cost to serve.** Bandwidth + long-lived connections per agent. Must be modelled per-agent and kept
  a small fraction of price (§1). This is the number that decides viability.
- **Credential custody.** RedHand would hold or broker customer model-provider API keys — envelope
  encryption, never returned, rotation (§5.2/§5.5). A new, sensitive secret store.
- **Provider surface.** Each provider (Anthropic, OpenAI, Gemini) has its own streaming format, tool
  format, error taxonomy. Transparent proxying across all three is real, ongoing work.
- **Data residency / PDPA.** Prompts and completions are the most sensitive payloads of all; carrying
  them raises the same lawful-basis questions as Phase 3 payload capture, but always-on.

## 4. Architecture options (to be costed before any commit)

| Option | Shape | Trade-off |
|---|---|---|
| A. Hosted transparent proxy | RedHand runs an OpenAI/Anthropic/Gemini-compatible endpoint; agents point their base_url at it | Most control, most uptime/latency/cost owned by us |
| B. In-VPC sidecar proxy | The existing `redhand-sidecar` carries model traffic inside the customer's network | Customer owns uptime/egress; RedHand sees traffic without holding keys centrally; fits higher tier |
| C. Metadata-only (no body relay) | SDK reports token counts/model used to core out-of-band; RedHand never carries the stream | Cheap, keeps §4.6, but no input/output inspection or redaction — a much weaker version |
| D. Async copy | Proxy streams straight through; a copy is inspected off the hot path | Preserves latency; detection is after-the-fact, not blocking |

Recommendation to evaluate first: **C or B**. C (metadata-only) delivers dollar budgets and
approved-model enforcement — the highest-value, lowest-risk subset — without taking on the stream. B
(sidecar) suits the self-hosted/higher tier already in the roadmap. A (hosted full proxy) is the
biggest bet and should not be first.

## 5. What would have to be true to say "go"

1. A per-agent cost-to-serve estimate for the chosen option that stays a small fraction of price (§1).
2. A latency budget for transparent streaming (first-token + inter-token overhead) with a measured
   prototype, not a guess.
3. An uptime plan that credibly meets or revises §8 for in-path generation.
4. A credential-custody design (envelope encryption, rotation) reviewed against §5.
5. A data-residency/PDPA position for carrying prompts and completions.
6. Evidence of customer pull from the 5–10 SME validation already open in the briefing — this is a
   buyer-shaped decision, not only a technical one.

## 6. Open decisions for you

- **D1 — pursue at all?** Or keep RedHand tool-only and deliver dollar budgets via option C
  (metadata-only) without a true proxy? Rec: do C's metadata path regardless (cheap, high value);
  treat A/B as a later, customer-validated bet.
- **D2 — which option to prototype** if we proceed (A/B/C/D).
- **D3 — tier/positioning.** Proxy as a higher-tier / self-hosted feature (fits the parked
  enterprise items) rather than Starter? Rec: yes — Starter stays tool-only and cheap.
- **D4 — timing.** After Phase 4 ships and SME validation is in, not before.

**Nothing here is committed.** The recommendation is: finish Phase 3, ship Phase 4 (deterministic,
cheap, no new uptime risk), deliver dollar budgets via the metadata path, and revisit a true model
proxy only with a costed prototype and customer evidence in hand.
