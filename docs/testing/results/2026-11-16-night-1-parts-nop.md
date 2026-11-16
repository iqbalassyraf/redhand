# Night 1 follow-up: staging deploy of B3/B4a/B4b and Parts N, O, P (Antigravity, 2026-11-16)

Brief: `docs/testing/briefs/2026-11-13-night-1.md` (Parts 0, N, O, P and Cleanup).
Previous result: `docs/testing/results/2026-11-14-night-1.md` (Parts 0 to M, PRs 57 to 72).
Run by: Antigravity with the owner at the keyboard (owner ran every command, deploy and click; Antigravity read the code, wrote the commands and read the screenshots).
Rule used: **NOT RUN is not PASS.** A step without evidence is marked NOT RUN or "owner-reported", never PASS by assumption.

> [!IMPORTANT]
> This report has **not** been checked against the staging database yet. Claude Code should run the read-only checks in section 7 before any verdict is final.

---

## 1. Summary

| Part | Feature | Result |
|---|---|---|
| 0 | Deploy migrations, core, dashboard; smoke | **PASS** |
| Staging clean-up before testing | Loop card, Risk ladder, pin mode, agents | **PASS** (owner screenshots) |
| N | Incident view (B3, #76) | **PASS on everything run**; N7, N9 NOT RUN; N10 for Claude |
| O | Model spend (B4a, #79) | **PASS on everything run**; O8 NOT RUN; O10 for Claude; one brief bug found |
| P | Approved models (B4b, #83) | **PASS on P1 to P4, P9, P11**; P5, P6, P7, P8 NOT RUN; P10 for Claude |

No product defect was found in anything that ran. One **brief defect** (Part O command rejected with HTTP 422) and one **product gap** (no way to issue an SDK key without raw SQL) were found. Two direct database writes were made during testing; they are listed in section 5 and must be reviewed.

---

## 2. Environment

| Item | Value |
|---|---|
| Git | `main` at `7340432` (merge of #83). `origin/main` has since moved to `26d92da` (#84, #85); those two were **not** deployed or tested here |
| Core | `https://redhand-core-825574069297.asia-southeast1.run.app`, revision `redhand-core-00033-xv2`, image `redhand-core:7340432` (Cloud Build `847bc230-...`, SUCCESS) |
| Gateway | `https://redhand-gateway-825574069297.asia-southeast1.run.app`, revision `redhand-gateway-00029-njd` (not redeployed; image unchanged) |
| Dashboard | `https://redhand.archtificial.com` (Vercel production, from `main`) |
| Database | Staging Supabase `qxxiksevqfmkqstrdkxi` |
| Core deploy command | `SUPABASE_URL=... DASHBOARD_ORIGIN="https://redhand.archtificial.com,https://redhand-dashboard.vercel.app" deploy/cloudrun/deploy.sh core` |

---

## 3. Part 0: deploy and smoke

| Step | Result | Evidence |
|---|---|---|
| Migration `20261124000000_incident_view.sql` | PASS | Applied in Supabase SQL editor by owner |
| Migration `20261125000000_model_spend.sql` | PASS | Applied by owner |
| Migration `20261126000000_approved_models.sql` | PASS | Applied by owner |
| Core deploy | PASS | Cloud Build SUCCESS (1m03s), revision `redhand-core-00033-xv2` serving |
| Gateway deploy | Skipped (image unchanged, as the brief allows) | |
| Dashboard | PASS | Vercel production from `main`; new Incident view, Model use column and Approved models card all render |
| `deploy/cloudrun/smoke.sh` | PASS | 13 of 13, "ALL CHECKS PASSED" |
| `scripts/staging_agent.py run` (with a fresh agent key) | PASS | 6 of 6: token exchange, initialize, tools/list shows only `read_wiki_structure`, in-scope call allowed, out-of-scope `ask_question` refused (`PolicyViolation: tool 'ask_question' is out of scope.`), unknown server refused (HTTP 404, -32004) |

### Staging clean-up before testing (owner screenshots)

| Item | State |
|---|---|
| Repeated calls card | "Watch (record repeats)", 20 calls within 60 seconds |
| MCP Scanner, deepwiki tool pinning | Mode `alert` ("Tool pinning is now alert.") |
| Risk response | Alert at 50, Safe Mode off, Freeze off ("Risk response saved. It applies from the next signal.") |
| Test agents | `night-incident`, `night-stale`, `night-risk`, `night-reg` shown revoked. **Note:** in the owner's screenshot `night-radar` and `night-dest` were still **active** at 21:14. They must be revoked (see section 8) |

---

## 4. Results per step

### Part N: incident view (B3)

| # | Result | Evidence / quote |
|---|---|---|
| N1 | PASS | Migration applied (index check reported by owner session) |
| N2 | PASS | Title "Timeline for night-incident"; items "Call refused: ask_question (deepwiki)" with reason "Tool 'ask_question' on server 'deepwiki' is not in this agent's passport scopes.", "2 tool calls in this hour, 1 refused", "Registered by a person", "Daily limit changed by a person"; newest first; sentence "This timeline shows only what RedHand recorded for this agent through the gateway..." shown |
| N3 | PASS | "Black Box event #5276" link present and opened; filters worked |
| N4 | PASS | Telegram: "RedHand: night-incident was frozen in the dashboard by [owner]. Reason: Frozen from the incident view" (20:09) |
| N5 | PASS | Calls refused while frozen |
| N6 | PASS | `redhand-timeline-a64d95a5.csv` downloaded; "Timeline exported by a person" listed |
| N7 | **NOT RUN** | Viewer sign-in was not done |
| N8 | PASS | `/passports/00000000-0000-0000-0000-00000000dead/timeline` shows "This agent was not found in your organization." |
| N9 | **NOT RUN** | Honeytoken trip with timeline link not done |
| N10 | For Claude Code | See section 7 |
| N11 | PASS | "night-incident revoked."; Telegram "night-incident was permanently revoked" (20:43). No honeytoken was created, so none to retire |

**Observation (not a defect, worth a look):** the `night-incident` timeline also shows organization-wide items from 04/11/2026 ("Safe Mode turned on for every agent by a person", reasons "testing", "via Telegram", "testing finish m2") that predate the agent's registration. That is probably by design (global Safe Mode affects every agent), but on a fresh agent it reads as history the agent did not have. Consider limiting org-wide items to the agent's lifetime.

### Part O: model spend (B4a)

| # | Result | Evidence / quote |
|---|---|---|
| O1 | PASS **after fixing the brief command** | Brief command returned **HTTP 422**. Cause: `TelemetryBatchIngestRequest` requires `sdk_version` (`extra="forbid"` model, field has no default). With `"sdk_version":"0.1.0"` added: HTTP 202. See section 6 |
| O2 | PASS | `night-spend` row: "Model use today" **$2.00**, "1,000,000 tokens" |
| O3 | PASS | Box "Model use for night-spend". Sentence: "Estimated from what the agent's SDK reported; prices as of 2026-11-16. Not an invoice." Row `anthropic/claude-sonnet-5-5`, 1 call, 1,000,000 / 0, $2.00. Days 2026-11-10 to 2026-11-15 "usage not reported", 2026-11-16 $2.00 |
| O4 | PASS | "$2.00 · 1,001,000 tokens · plus 1,000 tokens with no known price · 2 calls"; row `openai/gpt-mystery` "price unknown" (not $0); day row "$2.00 + 1,000 tokens, price unknown" |
| O5 | PASS | "Limit saved." and bar "66% of the $3.00 daily limit" |
| O6 | PASS | Telegram (21:29): "Spend alert: night-spend has an estimated $4.00 of model use today, at or over its $3.00 daily limit. Estimated from what its SDK reported, at provider prices as of 2026-11-16; it is not an invoice. Nothing was refused: RedHand does not stop model calls. Models with no known price (1000 tokens) are not included." Agent stayed active |
| O7 | PASS | Fourth span sent (HTTP 202); **no** second Telegram message. Box: "$6.00 · 3,001,000 tokens ... 4 calls", "200% of the $3.00 daily limit · alert sent, nothing was refused" |
| O8 | **NOT RUN** | Operator and viewer attempts not done |
| O9 | PASS (dialog text not captured) | Box cleared, "Limit saved.", field back to "blank = no limit". The confirm dialog wording was not quoted |
| O10 | For Claude Code | See section 7 |
| O11 | PASS | `night-spend` shown "revoked"; Telegram "night-spend was permanently revoked" (21:34) |

Note on wording: the O6 message ends with an extra sentence after "Nothing was refused: RedHand does not stop model calls." The brief says the message "ends with" that sentence. The extra sentence is accurate and useful; the brief, not the product, should be updated.

### Part P: approved models (B4b)

| # | Result | Evidence / quote |
|---|---|---|
| P1 | PASS | Card "Approved models": "Check is off: no list, nothing is flagged." |
| P2 | PASS | `night-model` with `openai/gpt-mystery`: HTTP 202, no "Model alert:" message |
| P3 | PASS | "Approved models saved." and "Check is on: 1 approved model." |
| P4 | PASS | Telegram (21:38): "Model alert: night-model used a model that is not on the approved list: openai/gpt-mystery. Recorded only: nothing was refused. Open the dashboard, Radar, Unapproved model." Agent stayed active |
| P5 | **NOT RUN** | Radar findings filter not checked; no screenshot |
| P6 | **NOT RUN** | Risk box not checked; no screenshot |
| P7 | **NOT RUN** | Extending the list and resending was skipped |
| P8 | **NOT RUN** | Operator attempt not done |
| P9 | Owner-reported, no screenshot | Owner cleared the list and saved. Dialog wording and "Check is off" not captured |
| P10 | For Claude Code | See section 7. Expect **two** rows (set, cleared), not three, because P7 did not run |
| P11 | Owner-reported, no screenshot | Owner revoked `night-model` and ran `unset RH_SDK_KEY RH_CORE` |

Note on wording: the P4 alert says "Open the dashboard, Radar, Unapproved model." while the brief calls the filter "Model not on the approved list". Check the two names match on the Radar page (it was not checked because P5 did not run).

---

## 5. Direct database writes made during testing (review these)

There is no dashboard or API path to create an organization SDK key, so the test key was made by hand in the Supabase SQL editor.

1. **Insert:** one row into `public.sdk_api_keys`, name `test-spend-key`, prefix `rh_test_spen`, `is_active = true`, using `SELECT id FROM public.organizations LIMIT 1`.
2. **Wrong organization:** `LIMIT 1` chose organization `29613512-8edc-4e63-a075-aae605654368`, which is **not** the owner's dashboard organization. The first successful ingest therefore created an agent row `night-spend` (id `b5132363-dc35-4436-b472-c7fb10a7c133`) and one trace span in that other organization.
3. **Update:** the key was moved with `UPDATE public.sdk_api_keys SET organization_id = (SELECT organization_id FROM public.agents WHERE name = 'night-incident' LIMIT 1) WHERE key_prefix = 'rh_test_spen';`
4. **Delete:** `DELETE FROM public.agents WHERE name = 'night-spend';` **This had no organization filter.** At that moment the only `night-spend` row should have been the one from step 2, but Claude Code should confirm nothing else was removed (and check what cascaded: `execution_traces` and any spend roll-up rows for agent `b5132363-...`).
5. **The test key's plaintext was typed into the chat session.** Treat it as exposed. It is still `is_active = true` until someone deactivates it (section 8).

Which script would undo these: none. No repo script manages `sdk_api_keys`.

---

## 6. Defects and gaps found

| # | Kind | Finding | Suggested fix |
|---|---|---|---|
| D1 | Brief defect | Part O/P curl commands omit the required `sdk_version` field, so they return HTTP 422 | Add `"sdk_version":"0.1.0"` to the O1 and P2 commands in `2026-11-13-night-1.md` (and any later brief that copies them) |
| G1 | Product gap | No way to issue, list, rotate or revoke an organization SDK key except raw SQL. A real customer cannot start sending model usage, so B4a and B4b cannot be used outside our own staging | Admin-only "SDK keys" API and dashboard card: create (show plaintext once), list by prefix, last used, revoke; audited like agent keys |
| G2 | Product observation | `/v1/telemetry/ingest` creates an `agents` row on first sight of a new `external_agent_id`. `night-spend` appeared as an **active** passport with no owner, no scopes and the default 90-day expiry. Any holder of an SDK key can therefore add active-looking agents to the Passports page | Decide on purpose: either create such agents in a distinct state ("reported only", no gateway access, clearly labelled) or require the agent to exist first. At minimum show "created by SDK telemetry" on the row and in the timeline |
| G3 | Brief wording | O6 "ends with" and P5 filter name differ from the product text (see notes above) | Update the brief |
| G4 | Small UX | Org-wide items older than the agent appear on a new agent's timeline (Part N note) | Optional: clip to the agent's `created_at` |

---

## 7. Read-only checks for Claude Code (Supabase SQL)

```sql
-- N10: one timeline export audit row for night-incident
select action, created_at from public.control_audit_log
where action = 'passport.timeline_exported'
  and target_id = (select id from public.agents where name = 'night-incident' order by created_at desc limit 1);

-- O10: spend limit set and removed for night-spend (expect 2, none from other roles because O8 did not run)
select action, actor_user_id, created_at from public.control_audit_log
where action = 'passport.spend_limit_changed'
  and target_id = (select id from public.agents where name = 'night-spend' order by created_at desc limit 1)
order by created_at;

-- P10: approved-models changes (expect 2: set, cleared)
select action, created_at from public.control_audit_log
where action = 'organization.approved_models_changed' order by created_at desc limit 5;

-- P5 back-fill: the RAD-MDL-001 finding exists for night-model and added 0 risk points
-- (adjust table/column names to the B4b migration)

-- Section 5: the test key, its organization, and leftovers in the other org
select id, organization_id, name, key_prefix, is_active, last_used_at from public.sdk_api_keys where key_prefix = 'rh_test_spen';
select id, organization_id, name, status from public.agents where name in ('night-spend','night-model','night-radar','night-dest');
select count(*) from public.execution_traces where agent_id = 'b5132363-dc35-4436-b472-c7fb10a7c133';

-- Cleanup state
select status, count(*) from public.agents where name like 'night-%' or name = 'pin-test' group by status;
```

Cloud Run (read-only): confirm no `AGENTWALL_*_ENABLED` variables on the gateway and minimum instances 0 on both services. **Not re-checked in this session.**

---

## 8. Cleanup state at end of session

| Item | State |
|---|---|
| Loop card Watch 20 / 60 | Done (screenshot) |
| Risk response Alert 50, Safe Mode off, Freeze off | Done (screenshot) |
| deepwiki pin mode `alert` | Done (screenshot). Note: `ask_wiki_question` is still **pending** in the pin list |
| Approved models list | Cleared (owner-reported) |
| `night-spend` limit | Cleared (screenshot) |
| `night-incident`, `night-stale`, `night-spend` | Revoked (screenshots) |
| `night-model` | Revoked (owner-reported) |
| `night-radar`, `night-dest` | **Still active in the 21:14 screenshot. Revoke them.** |
| `pin-test`, mistyped-name agent | Not checked this session |
| Test SDK key `rh_test_spen...` | **Still active. Deactivate:** `update public.sdk_api_keys set is_active = false where key_prefix = 'rh_test_spen';` |
| `AGENTWALL_*_ENABLED` unset, min instances 0 | Not re-checked |
| Shell variables | `RH_SDK_KEY`, `RH_CORE` unset (owner-reported). `RH_AGENT_KEY` from Part N: unset not confirmed |

---

## 9. Verdict (provisional, pending section 7)

- **B3 incident view (#76): GOOD on staging** for everything run. Gaps: viewer refusal (N7), honeytoken alert link (N9).
- **B4a model spend (#79): GOOD on staging** for everything run. Gap: role refusals (O8). Cannot be used by a customer until G1 is fixed.
- **B4b approved models (#83): PARTLY VERIFIED.** The alert path works (P2 to P4). The Radar finding, the zero-risk rule, list extension and role refusal (P5 to P8) are NOT RUN, so "adds 0 Risk points" is **not** verified on staging.

Remaining manual steps to close the gaps (about 15 minutes, owner plus an operator and a viewer account): N7, N9, O8, P5 to P8, then P10 again.

---

## 10. Recommendations for what comes next (Antigravity's view, for the owner and Claude Code to decide)

Ordered by what unblocks the most, safest first. Nothing below should start without the owner's go-ahead (CLAUDE.md).

### Now (today or tomorrow, small)
1. **Close the hygiene items from this session.** Deactivate the `rh_test_spen` key, revoke `night-radar` and `night-dest`, confirm no `AGENTWALL_*_ENABLED` and min instances 0. Claude Code runs section 7 and corrects this report.
2. **Revoke the old battleground keys** (`sk_live_...`, `sk-proj-...` in git history). This is the only item on the list with real-world exposure; the #84 secret-scan gate stops new leaks but does nothing for these.
3. **Fix the brief defect (D1)** so the next run of Part O/P works first time.
4. **Finish the 15 minutes of NOT RUN steps** (N7, N9, O8, P5 to P8). P5 and P6 matter most: "approved-model findings add 0 Risk points" is a stated design rule and is currently unverified on staging.

### Next (small decisions the owner owes)
5. **Approve the CLAUDE.md "Current phase" wording.** Suggested: "Phase 4.5 (decision layer). Phases 1 to 4 are built and on `main`; Phase 4's Radar stays Watch only until its false-alarm goal and blind round 4 pass. Phase 4.5 B1 to B4b are merged and staging-tested; B5 (model proxy) is gated on a measured prototype. Do not build Phase 5 features unless explicitly asked."
6. **Dependabot:** merge #73 with Actions pinned to commit SHAs; take the recreated #74 without the Tailwind major. Keep Tailwind v4 deferred.
7. **RAD-INJ-003:** open it on the staging Radar page and label it real or false alarm. It feeds the Phase 4 false-alarm goal.
8. **Blind round 4:** hand the brief to an outside writer (not Gemini or Grok, clean session). Phase 4 cannot leave Watch only without it.

### Then (development; Antigravity's recommended order)
9. **SDK key management (G1) before B5.** B4a and B4b are merged but no customer can use them without an SDK key, and today a key can only be made with raw SQL, which in this session went to the wrong organization. A small admin-only API plus a dashboard card (create and show once, list by prefix, last used, revoke, audited) makes two finished features usable and removes a risky manual step. Fold in a decision on **G2** (telemetry auto-creating active, owner-less agents) in the same change; it is a trust-boundary question for a security product.
10. **Production hosting decision** before any more features. Production already serves the new dashboard; the backend story (staging Cloud Run vs a separate production project, secrets, the HS256 vs JWKS question) should be settled and written down. The release-readiness scans in `docs/release-readiness.md` belong here too.
11. **B5 model-proxy prototype** after 9 and 10. It is the last Phase 4.5 feature and the biggest risk (it sits in the request path and could add latency or break calls). Keep it as a measured prototype first, as already planned: latency budget, failure mode (fail open vs closed), and a go/no-go on the numbers.
12. **Phase 5** only on the owner's explicit request, after the above.

### Process suggestions
- Keep the "check against staging before merge" rule, but run it per feature as merged (as done tonight) rather than one large night; it found the brief bug in minutes.
- Every future brief command that hits an API should be run once by Claude Code against the local store before the brief ships (this would have caught D1).
- Give each test run a dedicated SDK key and organization so test agents never mix with real ones.
