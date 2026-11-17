# ADR 0025: Model proxy prototype in the gateway (Phase 4.5 B5): measured, off by default, not approved for release

**Status:** Proposed (2026-11-17). A **prototype** built at the owner's request to produce numbers for a go/no-go decision. It is behind a kill switch that is off, it is a
draft pull request, and nothing in this ADR is approved. Earlier analysis: `docs/plans/phase4.5-model-proxy.md` (options A to D) and `docs/plans/phase4.5-build-plan.md`.

## Context
Today RedHand sits between an agent and its tools. B4a/B4b report model use from the agent's own SDK, so the numbers are self-reported and nothing can be refused.
Only a proxy in front of the model API makes spend authoritative and lets RedHand refuse a model call. The standing gate (owner, 2026-11-16) was "no proxy before a
measured prototype". This is that prototype, built before the production-hosting decision by the owner's choice on 2026-11-17.

## What was built (option A-lite: a hosted transparent proxy for one provider)
`agentwall/src/gateway/model_proxy.py`, mounted at `POST /v1/model/anthropic/v1/messages` **only when `AGENTWALL_MODEL_PROXY_ENABLED=true`** (otherwise the path does not exist).
An agent sets its Anthropic SDK base URL to `<gateway>/v1/model/anthropic` and uses its RedHand agent token as the credential. For each call:
1. **Fail closed first:** no provider key configured means every call is refused (503).
2. **Authenticate** with the tool route's verifier (the same token, the same key set).
3. **Validate** the body before anything leaves: a JSON object, a plain `model` name, a whole `max_tokens` inside a cap (default 32,000), a boolean `stream`, at most 1 MiB; NaN and other non-JSON constants refused.
4. **Authorize** through the existing passport lookup and its short cache (server name `model`): the passport must be active, the token not older than the passport, and one of its
   scopes must cover the model (`server: model`, `tool: <model id>` or `*`). Approved models are therefore enforced **per agent with the scope editor that already exists**; an
   optional deployment-wide list narrows it further.
5. **Forward** the original bytes with the deployment's provider key; the agent's token, cookies and any `x-api-key` it sent are never forwarded; the answer comes back through a response-header allowlist.
   Provider 401/403 (the gateway's own key refused) become a 502 that says nothing else; other provider errors pass through.
6. **Bound everything:** request size, response size (8 MiB), stream size (32 MiB), an idle timeout on streams, connect and total timeouts; no unbounded buffer (a stream is relayed chunk by chunk,
   and only the current partial event line, up to 64 KiB, is kept to read token counts).
7. **Record usage** from what the PROVIDER reported (non-stream `usage`, stream `message_start` and `message_delta`), exactly once per call, with an outcome (`ok`, `usage_not_reported`,
   `provider_error`, `stream_interrupted`, ...). A call with no usage is "not reported", never "free". Prometheus counters: requests by outcome, tokens in and out, proxy overhead.

No prompt or completion text is read for any purpose except counting tokens in event metadata; none is stored or logged.

## Measured (local loopback, fake provider: `docs/security/measurements/2026-11-17-model-proxy-prototype.md`)
See that file for the full table. In summary the gateway adds about **2 to 3 ms (p50) and under 10 ms (p99)** to a non-stream call and about **7 ms to the first byte** of a stream; the gaps between stream
events are unchanged and the stream arrives byte for byte identical; 100 concurrent streams completed with no errors and the gateway grew by about 7 MB (97 to 104 MB, transient). This is inside the 10 ms / 50 ms budget CLAUDE.md section 8 sets
for the tool route. It says nothing about a real provider or network, which add their own time and dominate.

## What is NOT built (each is a decision, not a detail)
- **Provider-key custody.** The prototype holds ONE deployment-level key in an environment variable. A customer product needs per-tenant keys, envelope-encrypted, never returned, with rotation (CLAUDE.md 5.2, 5.5):
  a new secret store, its own ADR and threat-model section. Until then the proxy can only serve one operator's own key.
- **Reporting usage to core.** The sink is in memory. The next step reuses the B4a roll-up (`agent_model_daily`) through a service-token ingest route and then the spend limit, the approved-model finding and the Risk signals can use authoritative numbers.
- **Spend limits that refuse.** The data to refuse over a daily dollar limit exists after the step above; the prototype refuses only by passport and model.
- **Inspection and redaction of prompts and completions** (OWASP LLM01, LLM02, LLM07): the reason to be in the path, and the expensive part (per-token latency, PDPA position, what is stored).
- **Other providers** (OpenAI, Gemini: each has its own streaming and error format), request caching, retries, regional failover.
- **Several gateway instances:** the passport cache and stats are per instance (the revocation bound is the same per instance).

## Go / no-go criteria (from `docs/plans/phase4.5-model-proxy.md` section 5), with where this stands
| # | Criterion | Status |
|---|---|---|
| 1 | Per-agent cost-to-serve estimate stays a small fraction of the price | **Partly.** Compute per call is about one gateway call (a few ms of CPU); bytes in and out are pass-through; no LLM call by RedHand. Long-lived stream connections (one per in-flight completion) are the real cost driver: measure at Cloud Run pricing before pricing the tier. |
| 2 | Measured latency budget for transparent streaming | **Met locally** (numbers above); to repeat against a real provider and on Cloud Run. |
| 3 | An uptime plan for in-path generation (section 8 says 99.9% for tool routing) | **Not done.** An outage of the proxy stops the agent from thinking, not just from calling tools. Needs at least two instances, health checks, a documented bypass decision (the customer can always point the SDK straight at the provider; RedHand must not pretend otherwise), and probably the in-VPC sidecar option B for the higher tier. |
| 4 | Credential-custody design reviewed against CLAUDE.md section 5 | **Not done** (see above). |
| 5 | Data-residency and PDPA position for carrying prompts and completions | **Not done.** Carrying content in transit is not the same as storing it; the position must say so and say what is logged (counts only, today). |
| 6 | Evidence of customer pull | **Not available to me.** The owner's call. |

## Security impact
- **New trust boundaries:** an outbound call to a model provider carrying customer prompts; a provider credential in the gateway process; a new authenticated inbound route.
- **Failure behaviour:** every failure before the provider call refuses; a provider failure is a 502 or the provider's own error; a stream failure closes the connection and records the outcome. There is no path that allows because something could not be checked.
- **Attacks considered and tested:** a stolen or stale token (401), a frozen/revoked/expired passport (403), a model outside the passport (403), a hostile body (non-JSON, NaN, wrong types, oversized, absurd `max_tokens`), a hostile provider (huge answer, endless stream, stalled stream, over-long event lines, non-JSON answer), the agent's own token or cookies leaking to the provider, the provider key leaking to an agent or a log.
- **Not covered:** an agent that already has the provider's key can bypass the proxy entirely. As with the tool gateway, RedHand controls only what flows through it.

## Cost and performance
No LLM call by RedHand. Overhead per call as measured; memory per in-flight stream is a few KiB (the buffer is one event line, capped). Recurring cost per agent is bandwidth and connection time, to be modelled with real traffic.

## Consequences if adopted later
A proxy tier is a different product commitment (availability, key custody, content in transit), and should be priced and operated as one. Recommendation unchanged from the evaluation: ship it, if at all, as a higher-tier or self-hosted
(sidecar) feature after the key-custody design and an uptime plan, and keep the Starter tier tool-only.
