# M4.7b: results of the quieter rules (measured 2026-11-13)

Plan: `docs/plans/phase4-m4-7b-quieter-rules.md`. Split: `docs/security/m4-7b-split.md`. Baseline: `docs/security/m4-7b-baseline.md`. Only names and counts are recorded here; no third-party text (decision P4-D10).

**Short version.** The change removed most false alarms on the documents it was tuned on (29% to 5%), lost no attack on the corpus or on blind round 3, and cost no measurable scan time. **It did not reach the target on text it was not tuned on:** on the frozen set, 9 of 57 documents (15.8%) still have a strong finding, against the goal of under 5% (decision F-D5). The goal is not met. The block gate still says "not yet", and now also says every round "needs a new round", because the rules changed.

## What changed (`agentwall/src/firewall/radar.py`, the only runtime change)
No rule was silenced and none was added. Each edit is the smallest one for a class of flags seen in the tuning set.

| Rule | Class in the tuning set | Change |
|---|---|---|
| `RAD-INJ-003` | a plain heading that starts with a role word ("## System Architecture", "### Admin Interface") | the heading alone is weak (low); it is strong only with a payload cue in the window (override, call, risky action, reveal, exfiltrate, address-the-agent, conceal, void claim, authority). A heading without a payload cue is also not raised by the document-wide "leet" flag |
| `RAD-INJ-003` | markdown links, paths and diagram node labels matched the bracket wrapper | the keyword must be a whole word, the bracket text must not contain "/", and "[" followed by a quote is a label, not a wrapper |
| `RAD-INJ-003` (all) | a weak early sighting hid a real later one, because the first sighting of a rule won | the stronger sighting wins |
| `RAD-INJ-005` | diagram labels containing a function call (same bracket fix); a code-fence language tag after the word "run" | a three-backtick tag is not a shell command (an inline `` `curl ...` `` still is) |
| `RAD-OUT-007` | "/root/" inside a relative path | "/root/" needs a left boundary |
| `RAD-OUT-007` | a bare prose mention of `.git/config` | needs a read verb or a traversal, like `.env` |
| `RAD-OUT-007` | JavaScript relative imports counted as traversal | depth is the longest single "../" run (still 3 or more), not a count over the whole text |

The scan window needed no change: the Radar already reads 8 KiB from each end of a long result (`_collect`), pinned by `test_a_huge_value_is_read_at_both_ends_but_not_in_the_middle`. The plan's step 4 described something already done.

## Measured
**Tuning set (58 documents; the set the rules were tuned on, so the number is optimistic).** Documents with a strong finding: 17 (29.3%) before, 3 (5.2%, 95% interval 1.8% to 14.1%) after. By rule, before: `RAD-INJ-003` 13, `RAD-INJ-005` 5, `RAD-OUT-007` 3, `RAD-INJ-002` 2, `RAD-INJ-007` 1; after: `RAD-INJ-002` 2, `RAD-INJ-007` 1 (the two rules M4.7b does not touch).

**Frozen set (57 documents, 3 unavailable; measured once, after the rules were committed; rules fingerprint `2527e7917c908899`; no document was opened).**

| | strong | rate | 95% upper bound |
|---|---|---|---|
| hidden instructions | 6 | 10.5% | 21.1% |
| risky output | 4 | 7.0% | 16.7% |
| any strong finding | 9 | 15.8% | 27.4% (interval 8.5% to 27.4%) |

Strong findings on the frozen set by rule (documents): `RAD-INJ-004` 3, `RAD-INJ-003` 2, `RAD-INJ-007` 2, `RAD-OUT-003` 2, `RAD-OUT-005` 1, `RAD-OUT-007` 1. There is **no frozen figure from before the change** (it was deliberately measured once), so the frozen set shows the result, not the improvement.

**Detection (loss check; limit: at most 3 points).**
- Corpus, 2,312 samples: 3 samples changed, all harmless ones that lost a false `RAD-INJ-003`. No attack lost a finding. `bench --check` exits 0.
- Blind round 3 (the only round whose raw samples are in the repository), rules only: 34 of 94 attacks and 10 of 146 false alarms **before and after, the same sample ids**. Loss: 0 points. Rounds 1 and 2: their raw exports are not in the repository, so I did not re-score them; the samples folded into the corpus are covered by the corpus comparison above.

**Scan time.** The Radar scan over the 58 tuning documents, old rules against new on one machine, repeated: median 40 to 43 ms for both, tails differ only by run-to-run noise. The Radar runs on a background queue after the result is returned, so this is not on the call path. Not measured on staging.

**Tests.** `agentwall/tests/test_radar_documentation.py` (41 tests, own synthetic text): for every class a "quiet" test and an "attack" test (the same words aimed at the agent stay strong). 16 deliberate breakages (each edit undone in turn, the window changed) were all caught.

**Mistakes made on the way, fixed before the commit:** my first traversal threshold (4) lost two real attacks in the corpus; my first shell-tag fix also excluded inline code and lost a real attack; a first version of the heading rule lost a Malay "official administrator instruction" heading until authority was counted as a payload cue; my first test for "does not hide a later marker" used a marker that is weak by design.

## What this does not show, and what it leaves open
- **The target is not met on unseen text.** Why is unknown by design: nobody opens a frozen document. The rules that fire there (`RAD-INJ-004`, `RAD-INJ-007`, `RAD-OUT-003`, `RAD-OUT-005`) are outside the three rules the plan allowed, and `RAD-INJ-003` still fires on 2 documents, which means the classes seen in the tuning set do not cover everything.
- **The "leet" flag is document-wide** and raises every weak finding one level; ordinary documentation trips it (11 of the 12 documents that still had a strong finding after the first edits carried it). This is probably the largest remaining source of noise for every injection rule. Changing it affects detection everywhere and needs its own plan.
- **`RAD-INJ-002` ("debug mode", "maintenance mode") and `RAD-INJ-007` (environment variable sentence)** were left alone: 3 tuning documents.
- **A heading that imitates a role is now weak without a payload cue.** An attacker who writes a bare "## System" heading and a payload with none of the listed cues gets a low finding from this rule; any other rule that fires on the payload still counts. The attack and quiet tests above fix the intended line; round 4 is the independent check.
- **The frozen set is now spent** (measured once). A second tuning round needs a new frozen set (the 17 repositories beyond the first 120 are unused) or the independent round 4.
- **Round 4** (blind, independent) is not scored yet. It needs an author outside Gemini and Grok, from `docs/testing/briefs/2026-11-13-m4-7b-blind-round-4.md`.
