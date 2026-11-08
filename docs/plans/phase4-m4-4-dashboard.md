# Plan: Phase 4 M4.4, the Radar page in the dashboard

Status: PROPOSED (2026-11-08), waiting for the owner's approval. Part of `docs/plans/phase4-m4-plan.md` (section 5, milestone M4.4).

## 1. Goal
An owner can see what the Radar found, mark each finding as real or a false alarm, silence a noisy rule for one agent, and switch the
two checks on or off, all from the dashboard. Phase 4 "done" test served: the owner sees an injection or risky output the Radar
caught, without using the API directly.

## 2. Current state
- Everything this page needs already exists in core and is deployed to staging (M4.2/M4.3): `GET/PUT /v1/radar/settings`,
  `GET /v1/findings` (filters `review_status`, `kind`, `rule_id`, paging with `before`, `limit`), `POST /v1/findings/{id}/review`,
  `GET/POST /v1/radar/suppressions`, `DELETE /v1/radar/suppressions/{id}?reason=`. The settings response carries `capabilities`
  (`can_change_modes`, `can_review`, `can_suppress`) so the page can hide buttons the server would refuse.
- Dashboard pages follow one pattern: `apps/redhand-ui/src/app/<page>/page.tsx` ("use client", `useRequiredSession`, `apiFetch` wrappers in
  `src/lib/api.ts`, header with links to the other pages). Current pages: passports, blackbox, honeytokens, scanner.
- No Radar UI exists. Findings are visible today only through the API.

## 3. Approach
One new page `/radar` with three blocks, built like `/honeytokens`:
1. **Settings strip:** the two checks (injection, output) each `Off` / `Observe`, last 7 days summary (findings, open, would-have-blocked,
   confirmed, false alarms) from `last_7_days`. Turning a check off asks for confirmation (the API requires `confirm: true`). `Block`
   is shown as "not available yet" (the API refuses it); the text says why (not measured enough).
2. **Findings list:** newest first, filters (status, kind), "load older". Each row: time, agent name, tool and server, rule id with its
   plain-language reason (a fixed table in the UI of the 19 rules), severity/confidence, evasion tags, occurrences, status. Buttons:
   **Real** (confirm), **False alarm**, optional note (300 chars). **Silence this rule for this agent** opens a small form (reason
   3 to 300 chars, 1 to 90 days, default 30, explicit confirm tick).
3. **Active silences:** list with agent, rule, reason, expiry; **Remove** (admin).
The page shows plainly that the Radar only sees what passes through the gateway, that it is observe-only (nothing is blocked), and
the measured limits (link to the coverage matrix numbers in plain words: catches most script injection, about 4 in 10 injected
instructions, with false alarms on documentation-style text). A finding never contains the scanned text, and the page says so.

Alternative considered: put findings inside the existing Black Box page. Rejected: Black Box is the call timeline; findings have their
own review workflow and settings, and mixing them hides the observe-only controls. Alternative: show only a count on Passports.
Rejected: the owner cannot act on a count.

## 4. Changes
- `apps/redhand-ui/src/app/radar/page.tsx` (new), `apps/redhand-ui/src/lib/radarRules.ts` (new, the 19 rule ids with fixed plain
  descriptions, pure and unit-tested), `apps/redhand-ui/src/lib/api.ts` (types and `radarApi`), a "Radar" link in the header of the
  five pages (the header is duplicated per page today; I will not refactor it in this change).
- Docs: `docs/runbooks/radar.md` (dashboard section), changelog, handoff, a test brief for Antigravity.

## 5. Security impact
- No new trust boundary and no backend change: every action is authorized in core by role (viewer cannot read, security operator
  can read and review, admin can change modes and silence). The UI hides buttons from `capabilities` but is not the boundary.
- Untrusted data on the page: tool name, server slug, agent name, review notes and suppression reasons are operator-supplied or come
  from an MCP server. Rendered as plain React text only; no `dangerouslySetInnerHTML`; long values are truncated in display.
- No scanned text ever reaches the page (findings carry none), and the UI never asks for any.
- Confirmations: turning a check off and creating a silence require an explicit tick and send `confirm: true`; double-submit is
  prevented while a request runs. A 401 signs the operator out (same as other pages).
- Failure: if any call fails the page shows the error and changes nothing locally; it never assumes success.

## 6. Data / migrations
None.

## 7. Tests
- Unit (node --test, as for `passwordReset`): rule table is complete and matches the 19 ids in `radar.py` (a test reads the Python rule
  ids and compares), status/confidence labels, the confirm-needed logic, note and reason length validation, day clamp 1 to 90.
- `tsc --noEmit`, `next build`, lint clean (CI already runs them).
- Browser check on a local production build against the local-store core: empty state, a finding appears, review changes status,
  silence form validation (short reason refused), off needs the tick, viewer role sees the page without buttons or is refused,
  401 handling, narrow screen. Screenshots kept out of the repo.
- Staging check by Antigravity from a brief (with the three standing rules): real findings from the helpdesk attack tickets show
  with the right agent, review and silence work, silences list, viewer refused.

## 8. Cost and performance
No LLM, no new recurring cost. Two to three API reads per page load (settings, findings, silences), paged at 50.

## 9. Risks and open questions
- The header is copied into every page; adding a link touches five files. A shared header is a separate refactor (noted, not done).
- Plain-language rule descriptions are a claim about what each rule means; they reuse the fixed `reason` wording in `radar.py` so the
  two cannot drift (the unit test compares them).
- Decision for the owner: should viewers see the Radar page at all? The API says no (security operator or above). The plan follows the API.
