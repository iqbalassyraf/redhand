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
| 1 | First metrics snapshot (`redhand_gateway_overhead_ms_*`) | PENDING OWNER ASSISTANCE | Requires owner to pull `redhand-internal-service-token` into shell without printing |
| 2 | Send 200 allowed `tools/call` requests via `scripts/staging_agent.py` | PENDING OWNER ASSISTANCE | Awaiting execution with active agent key |
| 3 | Second metrics snapshot after 200 calls | PENDING OWNER ASSISTANCE | Follows step 2 |
| 4 | Compute p50, p99, mean overhead from snapshot diff | PENDING OWNER ASSISTANCE | Calculated upon receiving snapshot metrics |
| 5 | Compare with latency budget (p50 <= 10ms, p99 <= 50ms) | PENDING OWNER ASSISTANCE | Verified upon calculation |
| 6 | Convert 20 helpdesk tickets to `docs/testing/exports/helpdesk-injection-heldout.jsonl` | **PASS** | 20 lines, valid JSONL, IDs `injection_indirect-141` through `injection_indirect-160`, 8 malicious, 12 benign |
| 7 | Independent labeling (no radar rules read) | **PASS** | Confirmed: labeled solely from ticket design; no rules read |
| 8 | Secret hygiene & bait replacement | **PASS** | `RH-HONEY-KEDAIKITA-9941-TRAP` replaced with `[BAIT-VALUE]`; no real credentials or PII |

---

## Detailed Notes

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
