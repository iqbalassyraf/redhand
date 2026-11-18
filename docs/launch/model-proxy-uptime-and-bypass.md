# Model proxy: uptime and bypass (DRAFT for the owner's go/no-go, not a decision)

Written 2026-11-18 for ADR 0025 go/no-go item 3. Nothing here is built or measured on production.

## Why it is different from the tool gateway
If the tool gateway is down, an agent cannot call its tools. If the model proxy is down, an agent cannot **think**: every model call fails. The proxy also holds long connections (one per call in flight, streams last seconds to minutes), so a restart cuts calls off mid-answer.

## What an uptime plan would need
- **At least two instances** of the gateway for the proxy path, and `--min-instances 1` or more (a cold start adds time to the first call; ADR 0028).
- **Health checks** that reflect the real dependencies (core reachable for passport lookups, provider reachable), and an alert to a person.
- **Graceful shutdown** that lets in-flight streams finish within a stated limit, and a clear error to the agent for the rest.
- **Known limits:** the passport cache and usage counters are per instance (ADR 0025), so the spend limit's overshoot bound is per instance.
- **A target.** Section 8 of CLAUDE.md sets 99.9% monthly for the gateway. This paper does not claim the proxy meets it: it has not been measured on production.

## What the customer does if the proxy is down (the bypass)
The customer can always point the agent's SDK straight back at the model provider with their own key. That restores the agent and **removes RedHand from the path**: no model-spend refusals, no measured usage and no model-scope check until the proxy is used again.
RedHand must say so plainly in the status page, the runbook and any customer copy. It must never imply that model calls are controlled while the agent is configured to bypass the proxy. Likewise an agent that holds the provider key can bypass the proxy at any time, so the proxy is a control only for the agents that are made to use it.

## Open questions for the owner
1. Is a proxy outage something the product promises to prevent, or only to report? (This sets the price.)
2. Is the customer allowed to configure automatic fallback to the provider, knowing it removes control? (Recommended: no; the bypass is a manual, visible decision.)
3. For customers who need strong uptime or custody, is the answer the in-VPC sidecar (higher tier) rather than the hosted proxy?
