# Indirect-injection model (second stage), `injection_v1`

**Status:** built in Phase 4 M4.1c; not yet wired into the gateway (M4.3); not yet measured on a fresh blind round.

## What it is
A logistic regression over TF-IDF word (1 to 2) and character (3 to 5) n-grams of three-sentence windows. A document is scored by the mean of its two highest
window probabilities. It is stored as plain JSON (`agentwall/src/firewall/models/injection_v1.json`, about 2 MiB: vocabularies, idf weights, coefficients,
a manifest) and scored in pure Python (`agentwall/src/firewall/injection_model.py`): no pickle, no numpy, no runtime dependency, nothing to download.
The scorer reproduces scikit-learn exactly; a test checks it against probabilities scikit-learn produced at training time.

## Why it exists
After two independent blind rounds the rules find about 4 in 10 subtle indirect-injection attacks (`blind-round-2.md`) and flag some legitimate operational text.
A rules engine cannot rank; this model can. Cross-round validation (below) shows it separates attacks from benign text noticeably better (AUC about 0.93).

## What it is NOT
Not a promise. Its calibration shifts between authors, so only a score of 0.9 or more is actionable (medium or high confidence); 0.7 to 0.9 is recorded as
low confidence (visible, never alerts); below 0.7 nothing is recorded. It is not part of the default hot-path detector set. Block mode is not offered for it.

## Training data and provenance
Only the benchmark's development samples: 1392 samples (208 indirect-injection attacks, the rest benign text from all categories),
written by the RedHand team (with an AI assistant) and by Antigravity (Gemini) in two independent blind rounds that were then used as development data.
No customer data, no third-party datasets and no third-party model are used, so there are no external licences to clear. The held-out files are never training
data. Corpus digest at training time: `1eef50813cce3eaa`; sample id list digest: `069f2e11c025b751...`.
Retrain: `uv run --with scikit-learn --with numpy --with scipy python scripts/train_injection_model.py` (training-time only; scikit-learn is not a RedHand dependency);
`--check` fails when the committed model differs from a fresh run (the training is deterministic).

## Evidence (cross-round validation, injection samples only)
Train on the core samples plus one blind round, test on the other. These are the best available estimates and are **not** a measurement of the final model, which saw both rounds.

| Trained without | Test attacks / benign | AUC | Attacks found at 5% false alarms | at 10% false alarms |
|---|---|---|---|---|
| ids 601 to 800 (round 2) | 80 / 120 | 0.931 | 66% | 69% |
| ids 301 to 550 (round 1) | 100 / 150 | 0.93 | 55% | 78% |

For comparison the rules alone found 41% at 8% false alarms on round 2. Alternatives tried and rejected on the same folds: generic sentence embeddings (all-MiniLM-L6-v2,
Apache-2.0, AUC 0.76 to 0.88: worse than n-grams and heavy dependencies); n-grams over whole documents (AUC about 0.90, diluted on long documents).
Calibration varies between folds (a threshold that gave 59% at 4% false alarms on one gave 18% on the other), which is why the tiers are conservative and a fresh round is required.

## Cost
Load about 25 ms once. Scoring: about 2.4 ms for 1 KiB, 6 ms for 4 KiB, 8 ms for 16 KiB (at most 48 windows are scored). Measured locally in pure Python. It belongs on a background
path in the gateway (a bounded queue and a worker thread, results never block a call); it must not be added to the per-call hot path.

## Failure and abuse
- A missing, oversized or malformed model file means the second stage reports nothing; scanning and enforcement continue (tested).
- The file is data, not code: reviewed in a pull request like any other change, size-capped, with a parity test that a tampered file would fail. Training samples enter only through reviewed pull requests (poisoning).
- A model can be evaded by text it has not seen (adversarial rewording); the rules, scopes, honeytokens and budgets remain the other layers.
- A finding carries only a fixed rule id (`RAD-INJ-012`), family `model`, severity and confidence. No scanned text is stored or alerted.
