# Blind round 3: indirect injection, scored once (frozen record)

Scored 2026-11-08 on `main` at commit b9e594c, **report only**: no rule, model or threshold was changed because of these numbers.
Samples: `docs/testing/exports/blind3-injection_indirect.jsonl` (250 texts) and `blind3-notes.md`. Scorer: `scripts/score_blind_round.py`
(a text counts as found when the detectors return at least one actionable, that is not low confidence, injection finding).

## Who wrote it
Grok 4 (xAI), through the owner. It states it saw only the brief and no repository material. That statement cannot be verified from here.
It is the first round not written by Gemini. One author, no independent review of the labels.

## Deviations from the brief (read these before trusting the numbers)
- 10 texts are exact duplicates of another text (6 attacks, 4 benign). All are kept in the file; scoring removes them: **94 attacks, 146 benign**.
- Only 11 of the 150 benign texts are long (500+ characters); the brief asked for about a third. Benign text is therefore shorter than real documents, which makes false alarms look lower than they would be on long documents.
- 25 of the 94 attacks are Malay or Indonesian (27%); the brief asked for about 45%. The Malay result rests on 25 attacks.
- 50 hard-benign were requested; 48 remain after removing duplicates.

## Results (shipped settings)
| Detectors | Attacks found | False alarms | Hard-benign false alarms |
|---|---|---|---|
| Rules only | 34 of 94 (36%) | 10 of 146 (7%) | 5 of 48 (10%) |
| Helper model only (actionable at 0.9 and above) | 9 of 94 (10%) | 0 of 146 | 0 of 48 |
| **Rules + model (what the gateway runs when the model is on)** | **36 of 94 (38%)** | **10 of 146 (7%)** | **5 of 48 (10%)** |

By language (rules + model): English 32 of 69 attacks (46%), 5 of 61 false alarms (8%); Malay and Indonesian 4 of 25 attacks (16%), 5 of 85 false alarms (6%).
By length (rules + model): under 300 characters 2 of 5; 300 to 499 21 of 61 (34%); 500 and over 13 of 28 (46%).

## What this means
- **The rules generalise about as before:** blind round 2 gave 41% with 8% false alarms, round 3 gives 36 to 38% with 7%. "About 4 in 10 hidden instructions" is the honest claim and it is what the dashboard says.
- **Malay and Indonesian injection detection is weak (16% on 25 attacks).** No claim of Malay coverage may be made for injection.
- **The helper model adds 2 attacks (36 to 38%) at the shipped thresholds.** It should stay off. The earlier estimate that it would find about half of attacks was wrong at these thresholds.
- **But it does carry signal:** its ranking quality on this unseen set is AUC 0.89 (English 0.90, Malay 0.84): attacks usually score higher than harmless text, they just score below the 0.9 line (median attack 0.63, median benign 0.22). A threshold that gives 5% false alarms on THIS set (about 0.62) would find 48 of 94 (51%), but that number was chosen on the same data it is measured on, so it is optimistic and **must not be quoted**.
- Block mode stays unavailable: nothing here comes near the evidence it needs.

## What would settle it
Lower the model's thresholds using rounds 1 to 3 only through cross-validation (never on a set it is then scored on), and confirm on a fresh round 4 written by another author (not Gemini, not Grok, ideally not me). Until then the model stays off and round 3 stays frozen: if its texts are used for training, round 3 is no longer a blind set.
