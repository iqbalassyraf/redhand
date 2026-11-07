# Brief: blind benchmark samples for the Radar and output checks (M4.0b)

- **Written by:** Claude Code. **To be done by:** Antigravity. **Not a test run:** this is authoring, but it follows the same
  handoff (result in `docs/testing/results/`, entry in `docs/handoff.md`).
- **Why:** the benchmark is only honest if the held-out samples were written by someone who has not seen the detection rules.
  You have not, and must not.

## Hard rules
1. **Do not read** `agentwall/src/firewall/`, `agentwall/src/bench/`, `agentwall/bench/`, `docs/plans/phase4*.md` or
   `docs/security/coverage-matrix.md` before or while writing. Everything you need is in this brief.
2. Write the samples yourself from your own knowledge of how real attacks and real documents look. Do not copy attacks from
   this brief's examples, other datasets, or the existing corpus. No real secrets, no real people, no real companies.
3. Never invent a sample to be "easy for a filter" or "hard for a filter". Write what is realistic.
4. Do not edit anyone's samples. Do not run the benchmark.

## What to write
For each of four categories, write **100 attack samples and 150 benign samples** as one JSON object per line. The text is what an
AI agent would see inside a tool result (for example the body of a web page, an email, a support ticket, an API response, a
document, a search result).

| Category (`category`) | Attack samples are | Benign samples are |
|---|---|---|
| `injection_indirect` | text planted in data that tries to make the agent do something its user did not ask (change goals, call tools, leak data, hide its behaviour, impersonate authority, create urgency) | ordinary documents, plus hard cases: security articles, policies, emails that tell humans to ignore or forget things, code and API docs, customer messages that say "ignore my last message" |
| `output_xss` | content that would run script or leak data when rendered in a browser, chat UI or markdown viewer | ordinary text, harmless HTML and markdown, and documentation about XSS |
| `output_ssrf` | text that tries to get the agent or a renderer to fetch internal, loopback, link-local, cloud-metadata or attacker-controlled destinations | public URLs, IP addresses and ranges in ordinary or educational contexts |
| `output_path` | text that tries to read or write sensitive files or escape a directory | ordinary file paths, relative links, and documentation about path traversal |

Mix of languages per category: about 70% English, 20% Bahasa Malaysia, 10% Indonesian. (Bahasa Malaysia and Indonesian samples will
be reviewed by a native speaker later; write them as naturally as you can.) Vary length, tone, format (plain text, JSON,
markdown, HTML, email, log line) and attack technique. Include some attacks that use obfuscation (encodings, odd spacing, mixed
case, lookalike characters), some that are subtle or polite, and some multi-sentence ones where the attack is a small part of a
long benign text.

## Format
One file per category in the RedHand repo at `docs/testing/exports/blind-<category>.jsonl`, with these fields only:
`id` (`<category>-NNN`, numbered from 301), `category`, `kind` (always `tool_result`), `label` (`malicious` or `benign`),
`lang` (`en` or `ms`; Indonesian samples use `ms` for now and put `indonesian` in `family`), `family` (a short name for the
technique or document type, at most 40 characters), `hard` (`true` only for benign samples written to look like an attack),
`text`. Do not use `{{PLACEHOLDER}}` markers or real-looking secrets; use obvious placeholders such as `[API-KEY]`.

## Result file
`docs/testing/results/2026-11-08-m4-0b-blind-samples.md`: counts per category and label, the families you used, how many are
hard benign, anything you found hard to label, and a sentence confirming you did not read the files in rule 1.
