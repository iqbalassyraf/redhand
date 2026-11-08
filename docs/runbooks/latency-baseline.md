# Runbook: measure the gateway's added latency

Why: the budget is p50 at most 10 ms and p99 at most 50 ms added by the gateway (CLAUDE.md section 8), and M4 adds work to every call. We need a "before" number.
You need: Terminal, `gcloud` logged in, and an ACTIVE agent key (from the dashboard, **Passports**, the agent's **New key**; it is shown once: paste it into the terminal only, never into chat or a file).

1. Open Terminal and go to the project: `cd /Users/testing/Documents/project-redhand`
2. Read the gateway token into a variable (it prints nothing):
   `read -s RH_INTERNAL_TOKEN < <(gcloud secrets versions access latest --secret redhand-internal-service-token); export RH_INTERNAL_TOKEN`
   If that line errors on your shell, use: `export RH_INTERNAL_TOKEN="$(gcloud secrets versions access latest --secret redhand-internal-service-token)"` (it still prints nothing).
3. Make the agent key available without printing it: `read -s RH_AGENT_KEY; export RH_AGENT_KEY` then paste the key and press Return (nothing shows while you paste).
4. Run: `python3 scripts/latency_baseline.py --out /tmp/latency.json`
   It sends 200 gentle calls (about 40 seconds), reads the gateway's overhead numbers before and after, and prints the result.
5. Copy the printed numbers (they contain no secrets) into your message to Claude Code, or into `docs/testing/results/`.
6. Clean up: `unset RH_INTERNAL_TOKEN RH_AGENT_KEY`

Reading the result: **PASS** means the gateway adds at most 10 ms (typical) and 50 ms (worst 1 in 100). **OVER BUDGET** means we must fix the gateway before adding more work to it.
The percentiles are upper bounds from histogram buckets, and the number covers one gateway instance (see the caveat the script prints).

**What it does not measure:** the gateway takes this number before the call goes upstream. It covers sign-in checks, the passport lookup and the guardrails, but not the work done on the answer afterwards (secret redaction, honeytoken scan, the Radar hand-off). It is a "before" figure for the checking cost, not the whole added time.
