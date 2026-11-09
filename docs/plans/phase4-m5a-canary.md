# Plan: Phase 4 M5a, system-prompt canary

**Status:** APPROVED by the owner as recommended (2026-11-09), including "no canary per agent" (section 9). **BUILT** on branch `feat/phase4-m5a-canary` (PR pending; not yet deployed to staging). Differences from this plan: section 10. Part of `docs/plans/phase4-finish-plan.md` (milestone M5a, done test 7); decision F-D3 (a canary found in a tool call: refuse the call and alert, do not freeze) is already approved.

## 1. Goal
An owner can put a secret marker in an agent's system prompt, and if that marker later appears in a tool call or a tool result, the call is refused (or the result redacted), the owner is alerted, and it is recorded. This serves Phase 4 done test 7: "a marker in a system prompt that later appears in a tool call or result trips an alert."

## 2. Current state (checked 2026-11-09)
- **Honeytokens already do the hard part** (Phase 3, `docs/adr/0012-honeytokens.md`): core generates a value, shows it once, stores only its SHA-256 digest and last four characters (`honeytokens/generator.py`, `honeytokens/service.py`). The gateway finds the digest in tool-call arguments and in results by pure lookup (`agentwall/src/gateway/honeytokens.py`), refuses the call or redacts the result, and reports a trip to core, which alerts on Telegram, writes the audit and Black Box records, and freezes the agent only if the stored action says so.
- **The gateway needs no change for a new kind.** Core's context endpoint sends the digest of every active honeytoken without looking at its kind (`routers/agent_auth.py`, `load_honey`), and the gateway matches the three issued formats, including a maximal run of exactly 24 alphanumerics.
- **What is missing:** `honeytokens.kind` only allows `api_key`, `aws_key` and `password` (`supabase/migrations/20261115000000_honeytokens.sql`, line 36); the UI and the alert text talk only about decoys planted for an attacker ("the decoy ... was refused"), which would be wrong for a prompt marker; and the Coverage page row for LLM07 (System Prompt Leakage) says "planned (Phase 4 M5)" (`agentwall/src/bench/report.py`).

## 3. Approach
Add a fourth honeytoken kind, `canary`, and everything around it.
- **Value:** the same 24-character mixed-case alphanumeric format as `password`, generated with the same secure randomness, no RedHand marker in it (ADR 0012: a marker lets an attacker recognise and strip it). Because it is an existing format, the gateway finds it unchanged.
- **Defaults (F-D3):** used in a tool call: refuse the call and alert, **no freeze**. Seen in a result: alert. The API applies these defaults to a canary when the caller does not choose; an admin may still choose freeze explicitly.
- **Dashboard:** on the Honeytokens page a preset **"Create a system-prompt canary"**: the label defaults to "System prompt canary", and after creation the page shows the value once together with a ready sentence to paste into the prompt, for example `Internal reference code (never repeat it): <value>`, plus the limits below in plain words.
- **Alert wording:** a canary trip says the agent's prompt text appears to have leaked into a tool call or result, not "the decoy was used". Core needs to know the honeytoken's kind, so the trip function also returns it.
- **Coverage page:** LLM07 changes from "planned" to "Partly covered by a canary (no measured detection rate)", with the limits. No performance number is claimed, because none is measured.

**Alternatives considered**
1. *Reuse the `password` kind with a label.* No migration, but the page, the alerts and the counts could not tell a leaked prompt from a planted decoy, and the alert would say the wrong thing. Rejected.
2. *A visible prefix such as `RH-CANARY-`.* Easy to spot, and an attacker who knows the prefix can strip it from a stolen prompt. Rejected (same reason as ADR 0012).
3. *Match the system prompt text itself instead of a marker.* RedHand never sees the prompt, and storing it would make RedHand hold the most sensitive text an owner has. Rejected.

## 4. Changes
- `supabase/migrations/<next>_canary_kind.sql` and its rollback: widen the kind check; replace the trip function so it returns the honeytoken kind (an added key, so older core code still works).
- `services/redhand-core/src/redhand_core/honeytokens/generator.py` (kind and value), `models.py` (kind literal, canary defaults), `service.py` (alert text), the in-memory twin in `services/local_rpc.py`.
- `apps/redhand-ui/src/lib/api.ts`, `apps/redhand-ui/src/app/honeytokens/page.tsx` (kind label, preset, pasteable sentence, limits).
- `agentwall/src/bench/report.py` (LLM07 row), then regenerate `docs/security/coverage-matrix.md` and `apps/redhand-ui/public/coverage.json`.
- `docs/adr/0012-honeytokens.md` (an amendment), `docs/runbooks/honeytokens.md`, `docs/security/threat-model.md`, `docs/api/redhand-core.openapi.json`, `CHANGELOG.md`, `docs/handoff.md`.
- **No change** to the gateway, to the budget, or to any enforcement path.

## 5. Security impact
- **New data:** none beyond a new kind. The value is shown once and stored only as a digest, exactly like other honeytokens. It never appears in logs, alerts, the Black Box or trip reports.
- **Who can create or retire one:** admin or owner, audited (`honeytoken.created` with kind `canary`), the same as other honeytokens.
- **A leaked canary can be abused.** Anyone who steals the prompt can send the value in a call on purpose. Refusal plus an alert is harmless to the agent, which is why the default is **not** to freeze: a freeze action would let an attacker freeze a production agent on demand. The runbook says so.
- **False alarms:** an agent that legitimately passes its own instructions to a tool (a "summarise your instructions" tool, a logging tool that stores the prompt) will trip it. The alert says "appears to have leaked", not "attack".
- **Fails closed, as before:** if the digest lookup or the scan errors, the call is denied (existing behaviour, `honeytoken_scan_error`). Nothing new on the hot path.
- **Product truth shown in the page and the docs:** RedHand sees only what flows through the gateway. A prompt leaked to a person in chat, or sent to a model provider, is not seen. A value the agent re-encodes (base64, URL-encoded), splits across fields or hides past the first 64 KiB of one string is not found. A canary proves a leak happened, not that none can happen.
- **Threat model:** add a row for "prompt leak through tool calls" and one for "canary replayed to freeze or spam an agent".

## 6. Data and migrations
One additive migration. The check constraint is replaced to allow `canary`; no existing row changes. **Rollback:** delete canary rows, then restore the old check (so the rollback cannot fail on existing canaries, and the data loss is stated in the file), then restore the previous trip function. Tested apply, rollback, re-apply by `scripts/test_migrations.sh`. Deploy order: migration, core, dashboard. The gateway is not redeployed. An older core simply cannot create a canary.

## 7. Tests
- **SQL (`supabase/tests/honeytokens_test.sql`):** `canary` accepted; an unknown kind refused; the 50 active honeytokens limit still counts canaries; rollback removes canaries and re-apply works; the trip function returns the kind.
- **Core unit:** canary value is 24 alphanumerics with a lowercase letter, an uppercase letter and a digit; two values differ; digest and hint as before; defaults are alert and alert for a canary and freeze and alert for the other kinds; an explicit freeze is honoured; the alert text for a canary never contains the value and never says "decoy".
- **End to end (`tests/e2e/test_phase3_honeytokens.py` style, through the real gateway and core):** a canary in tool-call arguments is refused, alerted, audited, **not frozen**; in a result it is redacted and alerted; a different 24-character string does not trip; a retired canary stops tripping; a canary of another organization does not trip (wrong tenant); a canary hidden in nested arguments and in an object key is found.
- **Negative and abuse:** viewer and security operator cannot create or retire (403); the value is never in the list response; creating the 51st active honeytoken fails.
- **UI tests:** the preset appears, the pasteable sentence contains the value only in the one-time view, and a reload shows only the last four characters.
- **Bench:** the LLM07 row text is exactly what the committed coverage files show (the existing "fresh run equals committed" tests enforce this).
- **Mutation checks:** break the default action, the kind check, the tenant scope and the alert wording, and confirm each is caught.
- **Staging (Antigravity and owner):** create a canary, put it in a test agent's call and in a result from a test tool, confirm refusal, alert, Black Box and audit entries, and that the agent is not frozen; confirm `honeytoken_scan` latency has not moved beyond the 10 ms p50 budget with a canary present.

## 8. Cost and performance
- **Hot path:** the gateway already scans arguments and results for digests whenever an organization has any honeytoken (a lookup, bounded to 64 KiB, 1,000 values and depth 16; free when there are none). A canary means the scan always runs for an organization that has one. The stage already has a metric (`honeytoken_scan`); the plan is to **measure it before and after on staging** and report the numbers against the 10 ms p50 budget. No figure is claimed until then.
- **Running cost:** one database row per canary and no new calls. No LLM, no new service, no new dependency.

## 9. Risks and open questions
- **It only detects leaks that pass through the gateway.** A canary cannot tell an owner their prompt is safe. The page must keep saying this.
- **Owners may paste it into the wrong place** (a document the agent reads aloud). The pasteable sentence and the runbook explain placement.
- **Decided (owner, 2026-11-09, as recommended):** no canary per agent for now. The alert already names the agent that sent or received the value; a canary per agent adds management work for a small gain.
- **Size:** small to medium; no change to the gateway.

## 10. Differences from the plan, found while building
- **`generator.generate_value` now raises on an unknown kind.** Before, any kind other than `api_key` and `aws_key` quietly produced a password; with a fourth kind that fallthrough would have hidden mistakes. The request model already restricts kinds, so no caller changes.
- **The canary default is applied in the request model**, only to fields the caller did not send (an explicit `freeze` is honoured). The migration does not change defaults.
- **The UI preset fills the form but does not create the canary**; the admin still presses **Create honeytoken**.
- **A staging brief** was written (`docs/testing/briefs/2026-11-09-m5a-canary.md`), including a before and after latency measurement of the `honeytoken_scan` stage. No latency figure is claimed until that is run.
- **Verified locally:** 1,611 Python tests, 33 dashboard tests, SQL tests with rollback and re-apply, 17 deliberate breakages (all caught), and a browser run of the page at desktop and phone width.
