# Blind round 1: independent measurement of the Radar (frozen)

**This file records a single measurement and is never regenerated.** It is the honest baseline before the rules were improved.

- **When / what was measured:** 2026-11-08, the Radar rules module as merged in PR 38 (`338c148`, M4.1).
- **Samples:** 1,000 written by Antigravity (Gemini) from a brief that contained no rule text, who confirmed in writing that it did not read
  the rules or the benchmark (`docs/testing/results/2026-11-08-m4-0b-blind-samples.md`): per category 100 attack and 150 benign samples
  (35 hard benign), about 70% English and 30% Bahasa Malaysia or Indonesian. Plus 20 helpdesk tickets written by Antigravity for the demo.
- **Method:** a sample counts as detected (or as a false alarm) when the Radar raises a finding for that sample's own category. One run, no rule
  changed before or during it.
- **Afterwards:** these 1,000 samples were used to improve the rules, so they are now **development data** (`*.dev2.jsonl`). A new blind
  round (round 2) is the only way to measure the improvement. The 20 helpdesk tickets stay held out and were not looked at while improving the rules.

| Category | Detected (95% interval) | False alarms | False alarms on hard benign | English attacks detected | Malay or Indonesian attacks detected |
|---|---|---|---|---|---|
| `injection_indirect` | 24/100 = 24% (17% to 33%) | 5/150 = 3% (1% to 8%) | 5/35 | 21/70 = 30% (21% to 42%) | 3/30 = 10% (3% to 26%) |
| `output_xss` | 98/100 = 98% (93% to 99%) | 13/150 = 9% (5% to 14%) | 13/35 | 69/70 = 99% (92% to 100%) | 29/30 = 97% (83% to 99%) |
| `output_ssrf` | 76/100 = 76% (67% to 83%) | 4/150 = 3% (1% to 7%) | 4/35 | 60/70 = 86% (76% to 92%) | 16/30 = 53% (36% to 70%) |
| `output_path` | 66/100 = 66% (56% to 75%) | 7/150 = 5% (2% to 9%) | 7/35 | 43/70 = 61% (50% to 72%) | 23/30 = 77% (59% to 88%) |

Helpdesk tickets (injection): 5/8 = 62% (31% to 86%) attacks detected, 0/12 = 0% (0% to 24%) false alarms.

## What it showed
- Indirect injection: 24% detected. The rules matched the phrasing their author expected; Antigravity's attacks missed in nearly every family
  (tool calls, concealment, urgency, prompt disclosure, persona changes), and almost all Malay and Indonesian attacks.
- Output rules fire on documentation that quotes an attack (security articles, advisories, tutorials, runbooks): every false alarm in the four
  categories was such a document.
- SSRF and path misses were mostly bypass variants (decimal and dotless IPs, DNS rebinding, collector domains, `/proc` and Windows system files).
- The earlier held-out numbers written by the same author as the rules (85% injection) were contaminated and must not be quoted as coverage.
