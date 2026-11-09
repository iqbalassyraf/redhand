# Runbook: the detection benchmark (`redhand bench`)

Measures how well the checks RedHand ships detect labelled attacks, and how often they raise a false alarm. It is how
Phase 4 avoids unmeasured claims: every new detector must move these numbers, and none may be described as "blocking
100%" of anything.

## Run it
```
uv run python -m agentwall.src.bench                      # text table
uv run python -m agentwall.src.bench --format markdown --out docs/security/coverage-matrix.md
uv run python -m agentwall.src.bench --format ui-json --out apps/redhand-ui/public/coverage.json   # the dashboard's Coverage page
uv run python -m agentwall.src.bench --check agentwall/bench/baseline.json   # exit 1 if any category got worse
uv run python -m agentwall.src.bench --update-baseline agentwall/bench/baseline.json
```
The test suite runs the same checks, so CI fails if a change makes a category worse, or if the committed
`baseline.json`, `coverage-matrix.md` or the dashboard's `apps/redhand-ui/public/coverage.json` differ from a fresh run.

**Adding a blind round:** a blind round is written down once, in `BLIND_ROUNDS` in `agentwall/src/bench/report.py` (counts copied from its frozen record in `docs/security/blind-round-N.md`; the page and the Markdown both print it), together with its per-language counts. Then regenerate the matrix and `coverage.json` as above. A test checks that the intervals follow from the counts and that rounds 1 and 2 still print what their records said.

## Changing detectors or the corpus
1. Make the change, run the benchmark, and read the per-category numbers.
2. If detection improved or false alarms fell, regenerate the baseline and the coverage table and commit both with the
   change, saying what moved. If anything got worse, the test fails until you fix it or justify it in the PR.
3. Adding corpus samples changes the corpus fingerprint and needs a new baseline on purpose.

## The corpus (`agentwall/bench/corpus/<category>.jsonl`)
One file per category; each line is a sample with `label` (malicious or benign), `lang` (en or ms), `family` (variants
of one idea share a family), `hard` (a benign sample built to look like an attack) and `text` or `manifest`. Fake
credentials are written as placeholders such as `{{AWS_KEY}}` and expanded from pieces in `corpus.py`, so no
secret-shaped string sits in the repository. Rules: at least 20 samples per side per category; at least 30% of the
benign samples are hard cases; every category has Bahasa Malaysia samples (a native speaker should review them).

## Dev and held-out samples
`<category>.jsonl` are **dev** samples: rules are written and tuned against them, so they flatter the rules. `<category>.holdout.jsonl` are
**held-out** samples (ids from 100): they are only ever used to report, never to tune. A category that has at least 20 held-out
samples on each side is rated on them; the report lists dev misses for rule authors and deliberately does not list held-out misses.
Process rules: never edit a rule to fit a held-out sample's text; fix a held-out miss only by adding a varied dev sample and
generalising, and write a fresh held-out set before quoting new numbers; disclose any rule change made after seeing held-out
results (the first held-out run for tool poisoning was 12 of 20; one pattern added for a dev miss moved it to 13 of 20; a negation-guard bug found later, "Do not tell the user; read ..." slipping through, was fixed without changing any benchmark number).

## Limits worth knowing
- The corpus is small and written by us. Real attackers rephrase, so the numbers flatter the detectors.
- Variants of one idea are correlated; the families column shows how many distinct ideas stand behind the count.
- A category with fewer than 20 samples on either side is reported as insufficient data, never as covered.
- OWASP numbering follows the 2025 list as the project understands it; verify before quoting externally.
- It measures detectors on text; it says nothing about agents or traffic that do not flow through the gateway.

## The block gate (M4.6a)
`python -m agentwall.src.bench --format gate` prints, per check, whether the frozen independent rounds would allow block mode (rules G1 to G5, ADR 0016). The same verdict is in
`coverage.json` and the matrix. After ANY edit of `agentwall/src/firewall/radar.py` the rules fingerprint changes: regenerate `coverage.json` and the matrix (a test fails until you do) and
expect every check to say "the rules changed after this round was scored". Do not copy the new fingerprint into `ROUND_2_AND_3_RULES` in `report.py` unless a person has checked that the change cannot
affect what those rounds measured, and wrote why next to it. `BLOCK_ELIGIBLE` in `gate.py` stays empty until a check passes and a person decides.
