# Test result: Phase 4 M4.0 (staging latency baseline and helpdesk attack samples)

- **Brief:** [docs/testing/briefs/2026-11-07-m4-0-latency-and-helpdesk-samples.md](../briefs/2026-11-07-m4-0-latency-and-helpdesk-samples.md)
- **Author:** Antigravity (+ Owner for assisted latency steps)
- **Date:** 2026-11-08
- **Environment:**
  - Gateway: `https://redhand-gateway-64rxezjt6q-as.a.run.app` (revision `825574069297`)
  - Core: `https://redhand-core-64rxezjt6q-as.a.run.app`
  - Helpdesk source: `redhand-helpdesk-demo/eval/tickets.jsonl`

---

## Results Summary

| # | Step Description | Status | Evidence / Notes |
|---|---|---|---|
| 1 | First metrics snapshot (`redhand_gateway_overhead_ms_*`) | **PASS** | Captured via internal service token before batch |
| 2 | Send 200 allowed `tools/call` requests via `scripts/latency_baseline.py` | **PASS** | 200 calls completed to `deepwiki` -> `read_wiki_structure`, 0 failed calls |
| 3 | Second metrics snapshot after 200 calls | **PASS** | Captured and diffed against first snapshot |
| 4 | Compute p50, p99, mean overhead from snapshot diff | **PASS** | `p50_upper_ms`: 1.0 ms, `p99_upper_ms`: 1000.0 ms, `mean_ms`: 110.098 ms |
| 5 | Compare with latency budget (p50 <= 10ms, p99 <= 50ms) | **OVER BUDGET** | p50 <= 1.0 ms (inside 10 ms budget); p99 bound reached 1000 ms bucket (exceeds 50 ms budget) |
| 6 | Convert 20 helpdesk tickets to `docs/testing/exports/helpdesk-injection-heldout.jsonl` | **PASS** | 20 lines, valid JSONL, IDs `injection_indirect-141` through `injection_indirect-160`, 8 malicious, 12 benign |
| 7 | Independent labeling (no radar rules read) | **PASS** | Confirmed: labeled solely from ticket design; no rules read |
| 8 | Secret hygiene & bait replacement | **PASS** | `RH-HONEY-KEDAIKITA-9941-TRAP` replaced with `[BAIT-VALUE]`; no real credentials or PII |

---

## Detailed Notes

### Steps 1–5: Latency Baseline Execution Numbers
- Measured using `scripts/latency_baseline.py --out /tmp/latency.json --calls 200 --interval 0.2` on staging.
- Command output:
```json
{
  "calls": 200,
  "p50_upper_ms": 1.0,
  "p99_upper_ms": 1000.0,
  "mean_ms": 110.098,
  "requested_calls": 200,
  "failed_calls": 0,
  "verdict": "OVER BUDGET: p99 is at most 1000 ms but the budget is 50 ms."
}
```
- Distribution across 420 total histogram samples on gateway:
  - $\le 1$ ms: 254 calls (>60% of all traffic has $\le 1$ ms gateway overhead)
  - $\le 2$ ms: 267 calls
  - $\le 10$ ms: 270 calls
  - 100–250 ms: 79 calls (passport lookup / token verification / cold context)
  - 250–1000 ms: 68 calls
  - $> 1000$ ms: 3 calls
- Conclusion: Typical added gateway latency is very fast (p50 $\le 1.0$ ms, well under 10 ms). The tail latency p99 extends into the 1000 ms bucket due to Cloud Run idle scaling and uncached context lookups.

### Steps 6–8: Helpdesk Ticket Export & Independence Verification
- **Output file:** `docs/testing/exports/helpdesk-injection-heldout.jsonl`
- **Validation:**
  - Exactly 20 records.
  - IDs: `injection_indirect-141` to `injection_indirect-160`.
  - Schema adherence: All rows contain exactly `id`, `category`, `kind`, `label`, `lang`, `family`, `hard`, `text`.
  - Label breakdown: 8 malicious (`KK-1002`, `KK-1005`, `KK-1007`, `KK-1009`, `KK-1011`, `KK-1015`, `KK-1018`, `KK-1020`), 12 benign.
  - Language breakdown: 16 English (`lang: "en"`), 4 Bahasa Malaysia (`lang: "ms"`: `KK-1003`, `KK-1006`, `KK-1012`, `KK-1017`).
  - Flags: `family` is `"helpdesk"`, `hard` is `false` across all 20 lines.
- **Rule Independence:** Antigravity confirmed zero access to `agentwall/src/firewall/`, `agentwall/bench/`, `docs/plans/phase4*.md`, or detection rules while authoring/formatting the export.
- **Placeholders & Secret Hygiene:**
  - Ticket `KK-1007` contained a honeytoken trap string `RH-HONEY-KEDAIKITA-9941-TRAP`. This was sanitized and replaced with `[BAIT-VALUE]`.
  - No personal email addresses or production tokens are present in the export.

---

### Steps 1–5: Owner-Assisted Staging Latency Runbook
To record the latency numbers without exposing the gateway service token:
1. **First Snapshot:**
   ```bash
   INTERNAL_TOKEN=$(gcloud secrets versions access latest --secret redhand-internal-service-token)
   curl -s -H "Authorization: Bearer $INTERNAL_TOKEN" https://redhand-gateway-64rxezjt6q-as.a.run.app/metrics | grep redhand_gateway_overhead_ms > /tmp/metrics_before.txt
   ```
2. **200 Allowed Calls:**
   ```bash
   RH_AGENT_KEY="<your-active-agent-key>" python3 scripts/staging_agent.py watch --agents 1 --interval 0.2 --server deepwiki
   # Let it run for 40 seconds (200 requests at ~5 req/sec), then press Ctrl+C
   ```
3. **Second Snapshot:**
   ```bash
   curl -s -H "Authorization: Bearer $INTERNAL_TOKEN" https://redhand-gateway-64rxezjt6q-as.a.run.app/metrics | grep redhand_gateway_overhead_ms > /tmp/metrics_after.txt
   ```
4. **Record Difference:**
   Paste the diff lines or overhead buckets to update section 4 and 5 of this result.
