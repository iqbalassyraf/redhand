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

## Part 3: Threat intelligence (CTI), decided 2026-11-08
**Owner direction:** connect RedHand to external threat intelligence (STIX and TAXII) and add an LLM reasoning layer, in the way
enterprise tools do. After a design discussion the owner **agreed to split it into three pieces** that differ in value, cost and
risk. Nothing here is built. Where this part is not marked decided, it is proposed.

**What the feeds can and cannot give us.** Feeds are mostly indicators of compromise (bad domains, URLs, IPs, file hashes), not
prompt-injection phrases, so the useful cache for RedHand is destinations, plus technique labels. ATT&CK and ATLAS describe
techniques and are for labelling, not for matching live traffic. No verifiable STIX feed of injection patterns was found; those
come from research datasets with their own licences (P4-D10).

| Piece | What it is | Placement | Status |
|---|---|---|---|
| **A. Technique labels** | Map each Radar and scanner rule to ATLAS and ATT&CK technique IDs from a vendored snapshot, with attribution; a test checks every ID exists in the snapshot | M4.4 / M4.5 (finding explanations, coverage page) | decided: do soon |
| **B. Indicator cache** | A cached set of known-bad domains, URLs and IPs, matched deterministically; an input to the Risk Engine (B1) | Phase 4.5, after M4, one or two feeds that pass the licence check | decided: after M4 |
| **C. LLM triage** | An LLM reviews already-flagged events and recommends an action | Last in 4.5, behind an offline prototype, tenant opt-in and owner approval | decided: gated, separate decision |

### Architecture (B and C)
- **Store:** a global table `threat_indicators` (type, value, source, confidence, expiry) holding public data only, so no tenant
  data; per-source kill switch, freshness and counts; ingest by a scheduled core job. Matches are per-tenant and flow through the
  existing finding pipeline (shared reporter, Black Box reasons `ioc:<source>`).
- **Fast path:** the gateway loads a versioned snapshot into memory (sets for domains and hashes, a CIDR structure for IPs) and
  refreshes it every few minutes from an internal core endpoint; lookups are O(1) with no network call and a memory cap. It plugs
  into the Radar's `Detector` interface and reuses the hosts and URLs the output checks already extract.
- **Matches are signals, not blocks.** A stale or failed feed means less detection, a metric, and an alert after 24 hours; it
  never affects enforcement. Observe is the default, because a wrong or poisoned indicator could flag a legitimate domain.
- **Fetching:** an SSRF-safe fetcher (scheme allowlist, private ranges blocked, resolve then check, redirect cap, size and time
  caps); STIX parsing limited to simple indicator types (domain, URL, IP, file hash); unsupported patterns are counted and skipped.
  A small `FeedSource` interface: a file or JSON adapter first, a TAXII 2.1 adapter second (TAXII only matters for ATT&CK, OTX and AIS).
- **LLM triage lives in core, asynchronous, on flagged events only** (the gateway stays at zero LLM calls). It dedupes repeats by
  fingerprint and has per-tenant daily and monthly caps. Cost is flagged events times tokens times price and is **not claimed until
  measured** in the prototype.

### Rules for the LLM layer (proposed, to confirm)
1. **The LLM advises, a deterministic policy decides.** Flagged content is attacker-controlled; feeding it to a model creates a new
   injection target. The model may recommend, explain and **tighten** (escalate to a human, freeze); it can never relax or override
   a block. The action ladder is the owner's (B1), and auto-isolation stays opt-in (B-D4).
2. **Metadata only:** rule ids, tool name, destination host, counts; no payloads by default (CLAUDE.md section 10: no customer data
   to an LLM without an approved design and tenant consent). Opt-in per tenant.
3. The triage model gets no tools, returns schema-validated JSON with an enum of actions, and its output is rendered as plain text.

### Feeds (checked 2026-11-08; verify the live terms before use; redistribution unverified for all)
| Feed | Finding | Use |
|---|---|---|
| MITRE ATT&CK | official STIX data and a TAXII server | labels (piece A) |
| MITRE ATLAS | a STIX 2.1 bundle on GitHub (`mitre-atlas/atlas-navigator-data`); no TAXII server found | labels (piece A), the best fit for agents |
| abuse.ch | Feodo Tracker, SSL Blacklist and YARAify stated as CC0; **URLhaus and ThreatFox are not**: commercial users may need a paid subscription | do not use URLhaus or ThreatFox without clearing it |
| CISA AIS | free, with eligibility rules and a data-aggregator addendum; Federal and CISCP feeds restricted | needs a legal read |
| AlienVault OTX | a free STIX/TAXII server exists; commercial and redistribution terms not verified | candidate |
| Pulsedive | TAXII 2.1 bulk export needs a paid plan | not free |
Rule: no feed is built in before a human reads its terms (CLAUDE.md section 13: licences must allow commercial closed-source use).

### Plan
0. ADR (0016) and a licence audit of each candidate feed by the owner or a lawyer. No code.
1. **Piece A:** vendored ATT&CK and ATLAS snapshot with attribution; rule to technique IDs; a test that every ID exists.
2. **Indicator store:** migration with rollback, SSRF-safe ingest job, per-source kill switch and freshness, SQL tests.
3. **Gateway:** snapshot loader and `IocDetector` in observe mode; metrics; findings through the shared reporter; the benchmark reports
   it separately as reputation, never as injection coverage.
4. **Dashboard:** source status and freshness, matches, per-organization toggle.
5. **LLM triage prototype, offline first:** replay synthetic flagged events, measure cost and agreement with a deterministic baseline,
   and test whether the triage model itself can be injected. Only then build the asynchronous worker, with caps, audit records and
   tighten-only authority, after the owner approves the cost and consent design.
6. **Staging tests** by Antigravity per `docs/testing/README.md`.
**Done tests:** a known-bad domain in a tool result raises a finding and a Black Box record; a stale or failed feed degrades without
an outage and raises a metric; a wrongly listed legitimate domain only alerts in observe mode; the triage cannot loosen a block; the
cost cap holds.

### Risks
New outbound dependency and trust boundary (the fetcher); feed poisoning and false positives; licence terms; memory and refresh
cost of the snapshot; alert noise; an LLM that is fooled by flagged content (hence rule 1); cost per agent unknown until measured.
Value is modest for prompt-level attacks, which are the main agent threat: indicators mostly help with exfiltration destinations and
MCP server supply chain. This part is a strengthening of the product and its story, not the core of Phase 4.5.

### Decisions
- **Decided (owner, 2026-11-08):** C-D1 split CTI into pieces A, B and C as above, with C gated.
- **Open, to confirm:** C-D2 the LLM rule (advises, deterministic policy decides, tighten-only, metadata only, opt-in). C-D3 who reads and
  clears each feed's terms. C-D4 whether the goal is mainly the product or the sales story (if the story, piece A plus this roadmap
  may be enough for now).
