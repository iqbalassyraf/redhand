# Revocation and failure drill (local measurement)

- Run: 2026-11-17 04:18 UTC; commit `ac95cd8`; `scripts/revocation_drill.py`; 20 trials per action.
- Machine: Linux-6.18.44-fc-v553-x86_64-with-glibc2.39, Python 3.13.18, 4 CPUs. **Local loopback, in-memory store: not staging, not production.**
- Promise (CLAUDE.md 4.5): a freeze or revoke takes effect on the next gateway call, at most 5 s. The gateway reuses a passport lookup for at most its cache TTL (default 2 s, bounded to 4 s), plus one refresh.
- Polling: one call every ~50 ms per agent (every second for the "once a second" rows), so times are accurate to about 0.1 s (1 s for those rows).

## Time from the operator's 200 OK to the agent's first refused call (seconds)

| action | trials | p50 | p95 | max | never refused | allowed after first refusal |
|---|---|---|---|---|---|---|
| freeze | 20 | 0.41 | 0.42 | 0.43 | 0 | 0 |
| revoke | 20 | 0.40 | 0.41 | 0.46 | 0 | 0 |
| freeze-all | 20 | 0.35 | 0.40 | 0.40 | 0 | 0 |
| freeze, agent calls once a second | 10 | 0.98 | 0.98 | 0.98 | 0 | 0 |
| revoke, agent calls once a second | 10 | 0.98 | 0.99 | 0.99 | 0 | 0 |

## Failure modes

| scenario | result | detail |
|---|---|---|
| core paused | held | first refusal 4.32 s after core stopped; refusals seen: [503]; allowed after the first refusal: 0; back to allowing after resume |
| core killed | held | first refusal 1.81 s after core stopped; refusals seen: [503]; allowed after the first refusal: 0 |
| upstream killed | held | answers [502], slowest 0.01 s, gateway /health 200 |

## Not covered here
- Expired agent tokens (the shortest lifetime core allows is 60 s; covered by unit tests of the token verifier).
- Several gateway instances (each holds its own cache; the bound is per instance and the same).
- Real network latency, Cloud Run cold starts, Supabase.
