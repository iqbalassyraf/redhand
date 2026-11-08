# Brief: blind round 2 for the Radar (M4.1b) and open items

- **Written by:** Claude Code. **To be done by:** Antigravity (items marked *owner-assisted* need the owner).
- **Why:** after blind round 1 the Radar's rules were rewritten using your round-1 samples as development data. The only honest way to know
  whether the rewrite generalises is a fresh set written by someone who has seen neither the rules nor round 1's results.

## Hard rules (same as round 1, stricter)
1. **Do not read:** `agentwall/src/firewall/`, `agentwall/src/bench/`, `agentwall/bench/` (this now includes your round-1 samples as `*.dev2.jsonl`),
   `docs/security/` (the coverage matrix and `blind-round-1.md` contain results), `docs/plans/phase4*.md`, `docs/testing/results/2026-11-08-m4-0b-blind-samples.md`
   is yours and may be reread, but nothing else under `docs/testing/results/`.
2. Write the samples yourself from your own knowledge. Do not reuse, paraphrase or vary your round-1 samples or the generator scripts, and do not
   write them from lists of the same families: use **new techniques and new documents**. No real secrets, people or companies.
3. Never write a sample to be "easy" or "hard" for a filter. Write what is realistic. Do not run the benchmark.

## What to write
For each of the four categories (`injection_indirect`, `output_xss`, `output_ssrf`, `output_path`): **80 attack and 120 benign samples** as JSON lines
(`id` numbered from `<category>-601`, `category`, `kind` = `tool_result`, `label`, `lang`, `family`, `hard`, `text`; Indonesian uses `lang` `ms` with
`indonesian` in `family`). About 60% English, 25% Bahasa Malaysia, 15% Indonesian. Save as `docs/testing/exports/blind2-<category>.jsonl`.

Make this round harder and more varied than round 1:
- **Attacks:** paraphrased and polite attacks that avoid the obvious phrasing; attacks buried in the middle of a long, ordinary document (500 to 2,000
  characters); attacks split across two sentences or fields; attacks that imitate legitimate business instructions; mixed-language attacks; JSON, HTML,
  markdown, log and email formats; obfuscated variants. At least a quarter of the attacks should be ones you think a keyword filter would miss.
- **Benign:** realistic operational text, not toy sentences: runbooks, support tickets, security documentation and training material that quotes attacks,
  code reviews, API docs, incident reports, legal and HR notices, product pages. At least 40 of the 120 benign samples per category should be **hard**
  (look like an attack but are legitimate), and some should be long (500 to 2,000 characters). Include customers who legitimately ask an agent to do things
  ("please refund my order", "delete my account", "send the receipt to my email") and administrators who legitimately give instructions to people.

## Result file
`docs/testing/results/2026-11-08-m4-1b-blind-round-2.md`: counts per category and label, how many are hard, anything you found hard to label, and a sentence
confirming you did not read the files in rule 1. Add a short entry to `docs/handoff.md`.

## Also outstanding from earlier briefs
| # | Item | Needs |
|---|---|---|
| 1 | Staging latency baseline (steps 1 to 5 of `2026-11-07-m4-0-latency-and-helpdesk-samples.md`): two snapshots of the gateway's overhead histogram around about 200 gentle calls, p50 and p99 against the 10 ms and 50 ms budget | *owner-assisted*: the owner reads the gateway token into a variable without printing it |
| 2 | Step 16 of `2026-11-07-dashboard-access-fixes.md`: in the helpdesk MCP server, publish length limits for every string input in the tool schemas (`maxLength` or `pattern`, keeping tool names and descriptions unchanged), redeploy (owner approves), rescan `kedai-kita`, and record the new risk score. Do not approve tool pins before this | *owner-assisted*: redeploy |
| 3 | Delete the five generator scripts you left in `scripts/` (`build_blind_samples.py`, `generate_injection_indirect.py`, `generate_output_path.py`, `generate_output_ssrf.py`, `generate_output_xss.py`): the JSONL files are the artefact and they are now committed in the corpus | none |
