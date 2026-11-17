# Revocation and failure drill (local measurement)

- Run: 2026-11-17 07:50 UTC; commit `fe4a7f3`; `scripts/revocation_drill.py`; 20 trials per action.
- Machine: Linux-6.18.44-fc-v553-x86_64-with-glibc2.39, Python 3.13.18, 4 CPUs. **Local loopback, in-memory store: not staging, not production.**
- Promise (CLAUDE.md 4.5): a freeze or revoke takes effect on the next gateway call, at most 5 s. The gateway reuses a passport lookup for at most its cache TTL (default 2 s, capped at 2.5 s), plus one refresh.
- Polling: one call every ~50 ms per agent (every second for the "once a second" rows), so times are accurate to about 0.1 s (1 s for those rows).

## Time from the operator's 200 OK to the agent's first refused call (seconds)

| action | trials | p50 | p95 | max | never refused | allowed after first refusal |
|---|---|---|---|---|---|---|
| freeze | 20 | 0.38 | 0.43 | 0.43 | 0 | 0 |
| revoke | 20 | 0.36 | 0.41 | 0.42 | 0 | 0 |
| freeze-all | 20 | 0.29 | 0.35 | 0.36 | 0 | 0 |
| freeze, agent calls once a second | 10 | 0.98 | 0.98 | 0.98 | 0 | 0 |
| revoke, agent calls once a second | 10 | 0.98 | 0.98 | 0.98 | 0 | 0 |

## Failure modes

| scenario | result | detail |
|---|---|---|
| core paused | held | first refusal 3.33 s after core stopped; refusals seen: [503]; allowed after the first refusal: 0; back to allowing after resume |
| core killed | held | first refusal 1.77 s after core stopped; refusals seen: [503]; allowed after the first refusal: 0 |
| upstream killed | held | answers [502], slowest 0.01 s, gateway /health 200 |

## Not covered here
- Expired agent tokens (the shortest lifetime core allows is 60 s; covered by unit tests of the token verifier).
- Several gateway instances (each holds its own cache; the bound is per instance and the same).
- Real network latency, Cloud Run cold starts, Supabase.

## Compared with the first drill (`2026-11-17-revocation-drill.md`)
The only change between the two runs is the gateway's passport lookup timeout (2 s to 1 s) and the cap on the cache lifetime (4 s to 2.5 s; default stays 2 s).
Normal freeze, revoke and freeze-all are unchanged (about 0.4 s). **Core paused (hanging): first refusal at 3.33 s, was 4.32 s**, so the worst case with the default settings is now
2 s (cache) + 1 s (wait for a running refresh) + 1 s (lookup) = 4 s, and 4.5 s at the cap, both under the 5 s promise (a test keeps that sum at or under 4.5 s).
Cost: a core that answers slower than 1 s is now treated as unavailable and calls are refused (fail closed). Warm lookups are milliseconds; a cold core start can refuse the first calls.
