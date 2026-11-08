# ADR 0015: The Radar inside the gateway (observe only)

**Status:** Accepted (2026-11-08). Phase 4 M4.3. Plan: `docs/plans/phase4-m4-plan.md`. Builds on ADR 0014 and the M4.2 findings API.

## Context
The Radar rules (`agentwall/src/firewall/radar.py`) and the findings store (M4.2) exist but nothing connects them: a tool result
passing through the gateway is never scanned. Measured quality is modest (blind round 2: injection 41% with 8% false alarms on hard
benign documents; markup about 92%; addresses and files about 62 to 64%), so the first connection must be observe-only.

## Decision
- **Observe only.** After the gateway has built the result it will return (secrets and honeytokens already redacted), it hands the
  result to `RadarScanner.submit()` (`agentwall/src/gateway/radar_scan.py`). The result is never changed, delayed or refused
  because of the scan. Block mode does not exist anywhere (refused by the API, SQL and the gateway context).
- **Off the call's path.** `submit()` is synchronous, does no I/O and never raises. A bounded queue (16) feeds one worker that
  scans on a thread (`asyncio.to_thread`). A full queue drops the work and counts it. Any scanner or reporting error is counted and
  swallowed. The scan time is not part of the call, but it shares CPU with the gateway, so it is measured (see Consequences).
- **Modes come from core, per organization, per call.** The gateway context carries `radar_mode` and `output_check_mode`, each
  `off` or `observe`. Core sends `observe` only when the stored value is exactly `observe`; anything else is `off`. The gateway
  requires both fields and denies if they are missing or hold another value (an older core, or `block`). **Deploy core before the
  gateway.** With both off, nothing is queued.
- **Findings go to core** (`POST /internal/v1/findings`, service token) through the shared `ReportDispatcher`: non-blocking,
  retried with backoff, 4xx dropped, at most 20 in flight. A report holds only fixed fields (rule id, family, severity, confidence,
  place, evasion tags, tool name, server slug, `would_block`). **`would_block` means "this finding was not low confidence"**, the
  same rule that decides what alerts; it does not mean anything was blocked.
- **Suppressions and daily caps stay in the database** (`record_security_findings`): one place, tenant-checked, so the gateway
  carries no suppression list. The gateway adds a repeat limit: the same (agent, rule, tool, place, server) is reported at most once
  per 30 seconds per process, so a hostile tool returning the same text every call cannot make a request per call. Core coalesces
  further; `occurrences` therefore counts reports, not calls.
- **The second-stage model is optional** (`AGENTWALL_RADAR_MODEL_ENABLED`, default off): same worker, about 8 ms more CPU at the
  largest scan size. It is not part of the quality claims until a blind round measures the final model.

## Alternatives considered
- Scan inline before returning the result: simplest, but adds up to ~17 ms (p50 at 16 KiB) to calls and breaks the 10 ms budget for
  large results. Rejected for observe mode; it may return for block mode if the measured gate is passed (M4.6).
- A process pool or a separate scanner service: isolates CPU but adds a deployment unit and cost for no measured need. Deferred.
- Suppression list in the gateway context: more fields in the hot lookup and a second place to enforce tenancy. Rejected.

## Consequences
- Staleness: a mode change reaches the gateway within the context cache (at most 4 seconds, 2 by default).
- The latency histogram (`redhand_gateway_overhead_ms`) is taken before the call goes upstream, so it does **not** include the work
  done on the result (egress redaction, honeytoken scan, queueing for the Radar). Gateway cost on staging for the whole call has not
  been measured end to end; `redhand_gateway_radar_scan_ms` shows the background scan time, and `scripts/latency_baseline.py`
  measures the pre-upstream part only. Do not claim a latency figure for the Radar from these.
- Memory: up to 16 queued results are held beyond their request (each is already in memory for its own request; the upstream cap is
  5 MiB).
- Metrics: `redhand_gateway_radar_scans_total{outcome}`, `_findings_total{kind}`, `_reports_total{outcome}`, `_scan_ms_sum/_count`.
- Failure behaviour: core down or refusing, a full queue, a scanner crash: calls are unaffected, findings are lost or late and
  counted. Nothing here can turn a deny into an allow, because the Radar makes no decision.
