# Model proxy prototype: measured overhead (local, fake provider)

- Run: 2026-11-17 05:47 UTC; commit `6228201`; `scripts/benchmark_model_proxy.py`; 300 paired requests per row.
- Machine: Linux-6.18.44-fc-v553-x86_64-with-glibc2.39, Python 3.13.18, 4 CPUs. **Loopback, fake provider, no real key.** The numbers are what the proxy ADDS; a real provider and network add their own time on top, and the proxy's share of the total would be small.
- Budget being tested (CLAUDE.md section 8, written for the tool route): gateway added latency p50 at most 10 ms, p99 at most 50 ms.

## Non-stream, provider answers after 0 ms

| | p50 / p95 / p99 (ms) |
|---|---|
| direct to the provider | 1.28 / 1.83 / 2.08 |
| through the gateway | 3.45 / 4.49 / 5.14 |
| **gateway overhead (paired, per request)** | **2.05 / 3.07 / 3.81** |

## Stream: 50 events, 20 ms apart

| | direct | through the gateway |
|---|---|---|
| time to first byte, p50 / p95 / p99 (ms) | 1.66 / 2.81 / 3.59 | 8.95 / 13.47 / 13.54 |
| gap between events, p50 / p95 / p99 (ms) | 20.25 / 20.50 / 20.78 | 20.25 / 20.58 / 21.79 |
| whole stream, p50 / p95 / p99 (ms) | 1014.80 / 1018.31 / 1024.92 | 1022.90 / 1031.45 / 1034.08 |
| bytes received (same?) | 6682 | 6682 (identical) |

## 100 streams at once

- Completed with 0 errors in 1.53 s (each stream alone takes about 1.1 s).
- Gateway memory (RSS): 97 MB before, 104 MB after.

## Non-stream, provider answers after 100 ms

| | p50 / p95 / p99 (ms) |
|---|---|
| direct to the provider | 102.53 / 103.15 / 104.69 |
| through the gateway | 105.67 / 107.06 / 108.75 |
| **gateway overhead (paired, per request)** | **3.14 / 4.89 / 6.72** |

## Not measured
- A real provider, TLS to the provider, network distance, several gateway instances, prompt and completion inspection (not built), the per-tenant key store (not built), reporting usage to core (not built).
