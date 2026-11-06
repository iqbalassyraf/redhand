# ADR 0013: MCP Scanner (description rules and live scan)

**Status:** Accepted (2026-11-07). Phase 4 M2. Plan: `docs/plans/phase4-plan.md`.

## Context
An MCP server describes its tools in text that the AGENT reads. A poisoned description (hidden instructions, "do not tell the
user", requests to read credentials or call other tools) is one of the cheapest ways to hijack an agent, and the existing
manifest auditor looked only at tool names, commands and schemas. The auditor also matched by substring, which flagged
harmless names (`shellfish.js`, `seashell_lookup`). The plan also needs a live scan, without creating an open fetcher.

## Decision
- **Description rules** (`agentwall/src/firewall/description_rules.py`): deterministic patterns, English and Bahasa
  Malaysia, for concealment, instruction override, hidden-instruction markers, reading sensitive data, sending data to
  outside destinations, cross-tool coercion, invisible characters, manipulation of tool choice and commands run without
  approval. Text is normalised first (NFKC, lookalike letters mapped, invisible characters removed, case folded). A negation
  guard ignores text that warns AGAINST a behaviour ("do not include passwords"). At most 8 KiB is read; a description over
  1,200 characters is a finding in itself. **Findings carry the rule's fixed wording and never repeat the description**, so a
  scan result cannot carry an attack to whoever reads it.
- **Auditor hardening:** commands, tool names and descriptions are matched by whole word tokens (camelCase and underscores
  split), not substrings; network-capable tools are reported (MCP-SEC-009).
- **Live scan of registered servers only.** `POST /v1/mcp-servers/{id}/scan` (admin) in core: the server must be registered,
  active and in the caller's organization, and its URL comes from the database, never from the request. Core asks the gateway
  (`POST /internal/v1/scan`, service token) to run `initialize` and `tools/list` through the same destination check as agent
  traffic (https only, public addresses only, no redirects, size and time limits, at most 5 pages and 500 tools) and audit
  the result. The server's reply is reduced to name, description and schema. Core strips control and invisible characters
  from everything that came from the server and caps lengths; the dashboard shows it as plain text. Results are returned,
  not stored.
- **Pasted manifests** go to the existing public, rate-limited `/v1/mcp/vet`, which fetches nothing.
- **Measured, not claimed.** The benchmark (`python -m agentwall.src.bench`, ADR-less runbook `docs/runbooks/bench.md`)
  reports detection and false-alarm rates. Rules are written against the **dev** samples and rated on a **held-out** set that
  is never tuned on. First held-out result for tool poisoning: 12 of 20 detected before any fix; 13 of 20 after one rule
  pattern was added for a miss on the dev samples (seen after the first held-out run, so disclosed), 0 of 20 false alarms.
  The dev set reads 20 of 20, which is the flattering number.

## Alternatives considered
- **Scan any URL from the public endpoint:** an open fetcher (SSRF and amplification) for little benefit. Rejected.
- **Core fetches the server itself:** core holds the database service-role key; adding outbound fetching there widens its
  attack surface. The gateway already owns the destination check. Rejected.
- **An LLM judging descriptions:** cost and latency rules; non-deterministic. Rejected for Phase 4.
- **Storing scan results:** useful history, but a new data type with retention duties. Deferred to M3 (tool pinning).

## Consequences and limits
- Pattern rules catch known phrasings and miss rephrased attacks; the UI and docs say so. A pass is not a guarantee.
- A server that needs credentials to list its tools cannot be scanned; the scan cannot see what a tool does when called.
- The gateway needs `GATEWAY_URL` set on core for live scans (otherwise 503); this is a deploy setting, see the runbook.
- Phrases past the first 8 KiB are not read (the length is flagged instead).
