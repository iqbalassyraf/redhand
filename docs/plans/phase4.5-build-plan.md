# Phase 4.5 build plan: the "brain" (decision layer and Model Gateway)

**Status:** Approved by the owner as recommended (2026-11-06). Part 1 (B1 to B3) and B4 may be built after Phase 4's
M4; B5 and B6 (the proxy) are gated on a measured prototype and a key-custody review (B-D3). Nothing here is built yet.
Supersedes the open decisions in `phase4.5-model-proxy.md` (the original go/no-go evaluation).

**Goal:** RedHand turns the signals it already has into one explainable picture per agent and a configurable response
ladder, and (gated) sits in front of model calls so spend, approved models and input checks are enforced rather than
guessed, at a cost per agent that stays a small fraction of price.

**Product truth:** RedHand only sees what flows through RedHand. An agent that does not use the gateway or the proxy
is not covered, and the product says so.

## Part 1: decision layer (no proxy needed)
- **B1 Risk Engine.** A deterministic score per agent from honeytoken trips, Radar findings, tool-pin changes, loop
  detections, budget events and Safe Mode state, with an explanation (which signals, how much). An owner-defined
  response ladder: observe, alert, throttle, Safe Mode, freeze. Every rung is configurable, audited and
  reversible only by an admin. Auto-freeze is off by default and opt-in per organization (B-D4). No model, no network.
- **B2 Behaviour baseline.** A rolling per-agent profile of which tools it calls and how often, with a simple
  statistical rule (moving average and threshold) for sudden spikes and never-seen tools. Needs a warm-up; its false
  alarm rate is measured before it is offered as more than a warning.
- **B3 Incident view.** One timeline per agent stitching Black Box events, findings, trips and control actions, with a
  one-click "freeze and review". No new data collection.

## Part 2: Model Gateway
- **B4 Spend and model metadata (Option C).** The SDK reports provider, model and token counts. Dollar budgets,
  alerts and an approved-model list are checked against what was reported. Detective, not preventive.
- **B5 Transparent proxy.** OpenAI- and Anthropic-compatible endpoint (`/llm/{provider}`) on the gateway; the agent
  only changes its base URL. RedHand injects the customer's provider key from a store with envelope encryption under a
  cloud key service (never returned, never logged). Approved models are enforced. Dollar caps are enforced BEFORE the
  call (projected worst case: estimated input plus maximum output must fit the remaining budget) and exact cost is
  recorded after from the provider's own usage report. Streaming passes through; first-token delay is a hard SLO.
  Refuses a hard cap for a model with no price. The price table is versioned and shows its date.
- **B6 Input and output checks in the proxy.** Radar on the request (user inputs for the first time); optional
  output scanning; system-prompt canaries matched in output.

## Refusals (decided)
No prompt storage by default (metadata only; opt-in redacted excerpts as in Phase 3). No LLM judge on the request
path. No claim of protection for traffic that does not use the proxy.

## Costs and risks
- **Cost:** no reliable per-agent number yet. Streaming holds connections open; a prototype measures cost per 1,000
  calls before B5 goes beyond a prototype.
- **Latency:** our own overhead stays inside the 10 ms p50 rule, excluding the model's time; first-token delay is
  measured, not estimated.
- **Custody:** holding customer model keys raises RedHand's value as a target. B5 gets its own threat model and an
  owner review before launch.
- **Provider surface:** each provider differs in streaming and errors. Anthropic and OpenAI first (B-D5).
- **Data protection:** prompts and completions are the most sensitive payloads; the lawful-basis question from Phase 3
  applies, always-on. No compliance claims.

## Order
B1 to B3 after Phase 4 M4, then B4. B5 and B6 only after the prototype shows acceptable cost and latency.

## Decisions (owner approved as recommended)
B-D1 build Part 1. B-D2 build B4. B-D3 build the proxy gated on a measured prototype and the custody review. B-D4
auto-freeze off by default, opt-in. B-D5 Anthropic and OpenAI first. B-D6 proxy on our gateway for Starter, the in-VPC
sidecar for higher tiers later. B-D7 metadata only, opt-in redacted excerpts.
