# ADR 0022: Incident view, one timeline per agent (Phase 4.5 B3)

- **Status:** Accepted (owner chose B3 as the next update, 2026-11-16; B3 is approved in `docs/plans/phase4.5-build-plan.md`, Part 1).
- **Context:** To investigate one agent an owner had to visit the Black Box, the Radar, Honeytokens, the audit list and the Risk panel and
  line the records up by hand. B3 puts what RedHand already recorded about one agent into one ordered story, and stopping the agent is one
  click from there. No new data is collected.

## Decision
- **One read-only endpoint that merges, no new table.** `GET /v1/agents/{agent_id}/timeline` (security operator and above, like findings and
  risk scores) runs these reads together, each scoped by the caller's organization and, where the record names one, by the agent:
  refused and failed calls (Black Box), allowed activity per hour (the B2 roll-up `agent_tool_hourly`, so thousands of calls are a few rows),
  findings, honeytoken and decoy trips, control actions whose target is the agent, and the organization-wide actions that change what every
  agent may do (freeze all, Safe Mode for all). Audit rows that only repeat a trip (`honeytoken.tripped`, `honey_tool.tripped`) are not shown
  twice. Newest first; at most 200 items a page.
- **Cursor by time, ties kept together.** The next page is everything strictly older than the last item kept. Items that share the cut-off
  moment stay on one page; a source that filled its fetch reads that moment in full first (a test with ten events at one instant caught the
  first version skipping them). Beyond 1,000 rows of one source at one exact moment a page can still split them; this is logged.
- **Fail whole, not partial.** If any read fails the answer is 503. A timeline with a silent gap would read as "nothing happened".
- **Fields, not text.** Each item carries the fields its own screen already shows (tool, server, the gateway's fixed refusal wording, rule,
  confidence, review status, trip kind and place, action, reason, whether RedHand acted by itself). Never a payload, an argument value or key,
  a token id, a honeytoken value, or an audit row's details (a destination change stores the full host there). The dashboard words items in
  `apps/redhand-ui/src/lib/timeline.ts`, reusing the generated Radar rule sentences.
- **Freeze and review reuses the existing freeze.** The page calls the audited, idempotent freeze endpoint with a reason pre-filled
  ("Frozen from the incident view"). Unfreeze stays on Passports with its confirmation. The UI is not a new control path.
- **Incident summary export.** `GET /v1/agents/{agent_id}/timeline/export?format=json|csv`: the same fields, at most 5,000 items (it says when
  cut), 10 per hour per operator, audited as `passport.timeline_exported` before anything is read (if the audit cannot be written, nothing is
  exported). CSV cells a spreadsheet would run as a formula are defused (the Black Box export's `csv_cell`).
- **Links from alerts.** With `DASHBOARD_URL` set (plain https outside development; no credentials, query or fragment), every Telegram alert
  about one agent ends with `Timeline: <dashboard>/passports/<agent id>/timeline`, once per batched message and kept whole within the length
  limit. `deploy.sh` passes the first checked dashboard origin.
- **Migration `20261124000000_incident_view`:** an index `control_audit_log (organization_id, target_id, created_at desc)` (the audit read
  scanned the organization's rows; the other reads already had indexes, checked read-only on staging) and the new audit action. The rollback
  drops the index and restores the previous action list `NOT VALID`, so rows already written stay.

## Alternatives considered
- **A SQL view or function that unions the sources:** rejected for now. Parallel indexed reads are simpler to test in the in-memory twin and
  keep each source's own access rules; revisit if measured slow (locally: 10,000 events, first page 20 ms median).
- **A stored incident record (a case with an owner and a status):** rejected. That is new data and a workflow; the owner did not ask for it.
- **Showing ALLOW events one by one:** rejected; per-hour counts keep a busy agent's story readable.
- **A global or composite (time, kind, id) cursor:** a time cursor with ties kept together is simpler and correct below the tie limit.

## Consequences
- One more read surface across five data sets; every read is tenant-scoped in the service and tested (another organization's agent is 404, a
  row naming the agent under another organization never appears, viewers are refused).
- A new audit action and a new setting (`DASHBOARD_URL`). Telegram alert texts gain one line when it is set; existing sentences are unchanged.
- The dashboard's `tsconfig.json` allows `.ts` import extensions (with `noEmit`), so node tests and the build share one module.

## Amendment (2026-11-17): organization-wide items and the agent's lifetime (G4)
Antigravity's Part N run showed a new agent's timeline listing organization-wide Safe Mode actions from days before it was registered. Now freeze all
and Safe Mode for all appear only from the agent's registration (`agents.created_at`) onwards, plus at most one older item: the latest organization
Safe Mode "turned on" before registration, when it was still on then, because Safe Mode for all also restricts agents registered later. That item is
flagged `in_effect_at_registration` and the dashboard adds "Already in force when this agent was registered." An older freeze all is never carried
over (it froze only the agents that existed). An agent without a registration time keeps its full organization history; nothing is hidden on a guess.
