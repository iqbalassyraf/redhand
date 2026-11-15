# ADR 0021: Hardening round (H1 to H4)

**Status:** Proposed (2026-11-14), amended by each H PR. Owner approval 2026-11-14 for all four rounds, including the changes CLAUDE.md puts
behind explicit approval (token logic, enforcement behaviour, CI, deploy settings). Plan: `docs/plans/hardening-round.md`.

## Context
An audit of the code against CLAUDE.md sections 5 (security) and 9 (reliability) found concrete gaps. This ADR records what each round changes
and why, so a reviewer can follow the intent across the four PRs.

## H1: correctness and secrets (no behaviour change for agents)
- **Budget day.** The gateway-context query never selected `organizations.utc_offset_minutes`, so production always used the default UTC+8 day
  boundary. The in-memory twin returned every column regardless of the select list, which hid it; it now returns only the selected columns,
  like PostgREST. The test asserts the reset moment (05:00 UTC at UTC-5), which holds at any time of day.
- **No webhook URLs in logs.** A Slack webhook URL is the secret itself, a resume URL can carry a token, and httpx repeats the URL in its own
  error text. All five log sites now log the host, and the error's type and HTTP status only (`services/safe_log.py`); a static test fails if
  any log call in core mentions a `*webhook_url` unreduced.
- **Bounded gateway audit chain.** The in-memory chain grew without limit. It keeps the most recent 10,000 records; the hash of the record that
  falls out anchors the retained window, so tampering inside it is still detected. `/v1/audit/verify` states what it covers (records verified,
  dropped from memory, total) and that the complete record is the Black Box in redhand-core. The optional audit file is written by a writer
  thread, not on the request's thread, and a failing disk is counted, never raised.
- **Ingest replies before risk scoring.** Scoring ran inside the Black Box ingest request (up to 5 s) while the gateway's report timeout is
  5 s, so a slow database could make the gateway resend a stored batch. It now runs after the reply; at most 8 evaluations run at once (a
  skipped one is counted and picked up by the next report); a batch naming four or more agents reads signals in one query.
- **Context lookups run together.** After the first parallel batch, the destination list, the usage by other instances and the last-seen
  write are independent and run together; the agent query selects its nine columns instead of every column. The last-seen write is
  best-effort now (dashboard-only data must not deny an authorization lookup); the decisions still fail closed.
- **Folded into H2.2:** the gateway resolves an upstream's DNS twice per message (once to check it, once inside httpx). The only safe fix
  is to connect to the address that was checked (connection pinning), not to cache DNS, which would weaken the per-request check.

## Alternatives considered
- **Cache DNS answers at the gateway** to save a lookup: rejected, it would widen the DNS-rebinding window.
- **Drop the in-memory audit chain** entirely and rely on the Black Box: rejected, the gateway's chain is a second, independent record.
- **A message queue for scoring:** rejected for now; a bounded in-process cap and background task are enough, and nothing is lost (the signals
  are stored).

## Consequences
- `/v1/audit/verify` now proves the retained window, not "all records since start"; its answer says so.
- A failed last-seen write is logged and the lookup succeeds.
- Scoring after a Black Box batch can be skipped under load (counted); the next report catches up.
