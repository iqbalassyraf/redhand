# Plan: Phase 4 M4.7b, quieter Radar rules and a fresh blind round

**Status:** DRAFT, awaiting the owner's approval (2026-11-12). Part of `docs/plans/phase4-finish-plan.md` (milestone M4.7b; done tests 5 and 6 as re-worded by F-D1). Decision F-D5 (under 5% strong findings on the frozen documents; the block gate stays at 3%) is already approved.

## 1. Goal
Cut false alarms from the Radar on ordinary real documentation without hiding attacks, and measure the result on text nobody tuned against. The result is reported whatever it is, including any loss in detection. This does not turn block mode on and cannot: block mode does not exist (ADR 0016).

## 2. Current state (checked 2026-11-12)
- **The three noisy rules** are in `agentwall/src/firewall/radar.py`:
  - `RAD-INJ-003` (fake system or role markers, around line 584): fires on a marker such as a `<system>` tag or a role line, medium when a directive is near.
  - `RAD-INJ-005` (tells the agent to run a command, around line 588): fires on a call cue plus almost any of destination, concealment, urgency, authority, agent address, override, risky or wrapper cues, or a "held" call cue.
  - `RAD-OUT-007` (sensitive file or path escape, `_paths`, around lines 838 to 872): already skips a path when a "documentation" window is near (`_PATH_DOC`), and downgrades in documents (`_DOC_DOWNGRADE`, line 148). It still fires on a path mention that is not in that window.
- **Evidence they are noisy:** `docs/security/real-document-replay.md` (2026-11-09): on 186 third-party READMEs, hidden instructions flagged 23 (12.4%, upper bound 17.9%) and risky output 11 (5.9%, 10.3%). 13 of the 23 hidden-instruction flags were `RAD-INJ-005` on an `npm install && npm test` style line written for a human developer; `RAD-OUT-007` was next. Staging DeepWiki proof (M4.6): 36 results with a strong finding out of 120 calls (the M4.7a figure).
- **Scan window:** `prepare()` keeps only the first 16 KiB of a result (`MAX_CHARS`, `radar.py:39` and `:194`), measured at about 0.8 ms per KiB so the worst case stays inside the 50 ms p99 budget. A long document is judged by its first 16 KiB only; the replay script already reads both ends, so the gateway and the measurement differ.
- **The gate** (`agentwall/src/bench/gate.py`, ADR 0016): independent evidence, scored on the rules that run now (fingerprint), false alarm upper bound at most 3%, detection lower bound at least 50%, at least 40 long (2 KiB) harmless samples; 125 harmless samples with no false alarm are needed for the 3% bound. **Nothing passes today.** Detection is about 4 in 10 on the independent round 3 (34 of 94, 36%; helper model off).
- **Test data:** harmless samples in the corpus are short (longest 824 characters). `scripts/radar_real_life_proof.py` has 137 repositories listed and runs the first 120 through the staging gateway (counts only). Blind rounds 1 to 3 are frozen records (`docs/security/blind-round-*.md`, `scripts/score_blind_round.py`). P4-D10: third-party text stays out of the repository.

## 3. Approach

### Step 1: decide the split before looking at anything (and commit it first)
- Take the 120 repositories the proof script runs. Sort them by `sha256(name)` and take the first 60 as the **tuning set** and the other 60 as the **frozen set**. The rule is deterministic, so nobody can choose favourable repositories after the fact.
- Commit the two lists (names only, no text) and the rule in its own commit **before any rule change**. The commit time is the proof that the split came first. The frozen list is a file nobody reads while tuning.
- The 17 repositories beyond the first 120 are not used.

### Step 2: get the text for the tuning set only
- A local script fetches the same documents the gateway sees, for the 60 tuning repositories only, into an untracked folder (outside the repository; its path is ignored by git). Open question 1 below says how.
- Only the tuning documents are ever opened. The frozen set is only measured by a **counts-only script** that scans and prints numbers: it never prints, stores or shows any text, and nobody opens the flagged documents.

### Step 3: tighten the three rules for documentation that only *shows* the pattern
Each change is the smallest one that fixes a class of flags seen in the tuning set, with the reason in a code comment:
- `RAD-INJ-005`: a shell or install command inside a code block, or after a prompt such as `$` or `>`, in a document that reads as documentation, no longer counts as "tells the agent to run a command" unless a real address-the-agent or conceal cue is also in the same window. A command sentence aimed at the agent keeps firing.
- `RAD-INJ-003`: a role or system marker inside a code fence or inline code, or described in a sentence about prompts ("the `system` role is..."), is weak evidence and drops to low. A marker with a directive next to it keeps its level.
- `RAD-OUT-007`: widen the documentation window to cover config examples, and require an access verb or a traversal to keep the finding for a bare mention of a well-known path in prose.
- No rule is silenced, and no new rule is added. If a class of tuning flags cannot be fixed without losing real attacks in the existing tests, it is left alone and listed.

### Step 4: scan window
Replace "the first 16 KiB" with **8 KiB from the start and 8 KiB from the end** of the result, joined at a marker, inside the **same total budget**, so worst-case CPU does not grow. An attack placed in the middle of a long document is still missed, and the Radar page and Coverage page keep saying so (a check that the sentence is still there goes into the tests). Documents of 16 KiB or less are unchanged.

### Step 5: measure, in this order, and report all of it
1. The existing tests and corpus (including held-out samples): detection must not fall on any frozen round (1 to 3 are re-scored for information only, as a loss check).
2. The tuning set: flags before and after, by rule.
3. The frozen set through the counts-only script (**once**, after the rule change is final): strong findings out of 60, with the 95% upper bound. Target under 5% (F-D5).
4. A fresh Antigravity blind round (Step 6).
5. The latency cost: the gateway Radar stage before and after on the same inputs (local benchmark, then the staging four-run method).

### Step 6: a new blind round (round 4)
- Written by an author who has seen none of the repository, none of the tuning documents and none of the rules (not Gemini, not Grok; the same constraint blind round 3 set).
- Size: at least **125 harmless** samples (the number needed for a 3% bound with no false alarm), of which at least **40 are hard** (look like attacks but are not) and at least **40 are 2 KiB or longer**; plus attacks for the detection side (at least 100, English and Malay), labelled by the author. Duplicates removed before scoring.
- Scored once with `scripts/score_blind_round.py` on the final rules (the fingerprint changes with any edit, so older rounds do not count for these rules), then frozen as `docs/security/blind-round-4.md`. A brief for the author is written first (`docs/testing/briefs/`), modelled on `2026-11-08-m4-1c-blind-round-3-injection.md`.

## 4. Changes
- `agentwall/src/firewall/radar.py`: rule edits and the window (the only runtime change); its docstring and the `MAX_CHARS` comment.
- New: `docs/security/m4-7b-split.md` (the 60 and 60 lists, rule, commit order), `scripts/radar_real_documents_fetch.py` (tuning set only, untracked output), a counts-only mode in `scripts/radar_real_documents.py` or a small new script for the frozen set (numbers only).
- Tests in `agentwall/tests/test_radar.py` (and the corpus): a pair for each tightened rule (documentation form no longer strong; the same words aimed at the agent still strong), the window (an attack in the first 8 KiB and in the last 8 KiB is found; one in the middle is not, and says so), and the budget (the amount of text scanned never exceeds 16 KiB).
- Docs: `docs/security/real-document-replay.md` (new numbers, old ones kept as history), `docs/security/coverage-matrix.md` and `apps/redhand-ui/public/coverage.json` (regenerated), `docs/runbooks/radar.md`, `CHANGELOG.md`, `docs/handoff.md`, `docs/security/threat-model.md` (the window sentence).
- **No change** to the gateway code, core, the database, the API, any dependency or block mode.

## 5. Security impact
- **Detection can fall.** Quieter rules may miss attacks that are written as documentation. This is the real trade-off, and the reason the blind round and the loss check exist. If detection falls on the rounds or on round 4 beyond what the owner accepts, the rule change is not shipped (decision for the owner, section 9).
- **Window:** an attacker who knows the window can place an attack in the middle of a long result. This was already true (anything after 16 KiB); the middle of a result under 16 KiB is still scanned, so only results over 16 KiB gain a blind spot between the two ends and lose nothing at the end. The page keeps saying it.
- **Data:** third-party text is kept only in an untracked local folder, never committed (P4-D10), never sent to a third service, and only for the tuning set. Counts and repository names only are committed. No customer data.
- **Fails closed:** unchanged. The Radar only observes (block mode does not exist). A scanner error still never changes or delays a call.
- **Claims:** no figure is claimed until measured. Compliance or "protects against" wording is not added anywhere.

## 6. Data and migrations
None. Rollback: revert the commit (the fingerprint returns to the old value).

## 7. Tests
- **Failing first:** documentation forms that currently raise strong flags (for each of the three rules) fail the new tests until the rules change.
- **Attack-side tests:** the existing corpus and held-out suites must pass unchanged; each existing attack sample that stops being found must be listed and justified (none removed silently; CLAUDE.md §7 says not to change an existing test to make a change pass).
- **Mutation checks:** loosen each tightened rule back, move the window to the old first 16 KiB, grow the total scan budget, drop the middle-gap marker. Each must be caught.
- **Window:** a result of 40 KiB with an attack in the first 8 KiB, the last 8 KiB, and the middle: found, found, not found.
- **Frozen set:** the counts-only script prints numbers only (a test checks that no document text reaches its output).
- **Full suite, ruff 0.17.3, mypy 2.4.1** as in CI.

## 8. Cost and performance
- **Hot path:** the Radar runs on a background queue after the result is returned (ADR 0015), so it adds no time to a call. The total text scanned stays at most 16 KiB, so the Radar's CPU per result is unchanged. Measured, not assumed: before and after on the same inputs.
- **Running cost:** none. No LLM call, no new service, no new dependency. Round 4 costs the author's time.

## 9. Risks and open questions
1. **Where the tuning text comes from (owner).** My recommendation: fetch the 60 tuning repositories' DeepWiki answers from the public DeepWiki server directly (the same text the gateway receives), into an untracked folder. Alternative: the installed-package READMEs the replay script already uses (no network, but a different kind of text from what the gateway sees). Which one?
2. **How much loss in detection is acceptable (owner).** My recommendation: none on the existing rules' attack tests, and a drop of at most 3 percentage points on blind rounds 1 to 3 re-scored for information; anything more is reported and the change is not shipped.
3. **Who writes round 4 (owner).** It must be someone other than Gemini and Grok who sees none of the repository. Antigravity is the usual route; if the same underlying model wrote a round before, that is stated in the record.
4. **The gate may still say "not yet".** Detection is about 36%, and the gate needs a lower bound of at least 50%. This plan targets false alarms only; closing the detection gap is a different piece of work (not in Phase 4's finish). Phase 4 closes as Watch only (F-D1).
5. **Hard-harmless text is assumed harmless** after a review of a sample, not all of it.
6. **Size:** large. Split into two PRs: (a) the split commit, the fetch and counts scripts and the baseline numbers; (b) the rule and window changes with tests and the round 4 results. Each is its own PR.
