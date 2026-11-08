# Blind round 2: independent measurement of the rewritten Radar (frozen)

**This file records a single measurement and is never regenerated.**

- **When / what was measured:** 2026-11-08, the Radar rules as merged in PR 41 (`2050380`, M4.1b), unchanged between the samples arriving and the scoring.
- **Samples:** 800 written by Antigravity (Gemini), per category 80 attack and 120 benign (45 hard benign), about 60% English and 40% Bahasa Malaysia or
  Indonesian, from a brief that asked for harder, more varied samples than round 1 (polite and paraphrased attacks, attacks buried in long documents, split
  directives, realistic hard-benign operational documents). Antigravity confirmed in writing that it read none of the rules, the benchmark, `docs/security/` or the
  round-1 samples (`docs/testing/results/2026-11-08-m4-1b-blind-round-2.md`). Samples: `docs/testing/exports/blind2-<category>.jsonl`.
- **Method:** one run; a sample counts as detected (or a false alarm) when the Radar raises an ACTIONABLE finding (not low confidence) for that sample's own category.
- **Not comparable one to one with round 1:** round 2 was deliberately harder. It is a separate independent measurement of the same rules family.
- **Status of the samples:** unseen by the rules until now. If they are used to improve the rules they become development data and a round 3 is needed.

| Category | Detected (95% interval) | False alarms | False alarms on hard benign | English attacks detected | Malay or Indonesian attacks detected |
|---|---|---|---|---|---|
| `injection_indirect` | 33/80 = 41% (31% to 52%) | 10/120 = 8% (5% to 15%) | 10/45 | 25/48 = 52% (38% to 66%) | 8/32 = 25% (13% to 42%) |
| `output_xss` | 74/80 = 92% (85% to 97%) | 0/120 = 0% (0% to 3%) | 0/45 | 44/48 = 92% (80% to 97%) | 30/32 = 94% (80% to 98%) |
| `output_ssrf` | 50/80 = 62% (52% to 72%) | 3/120 = 2% (1% to 7%) | 3/45 | 32/48 = 67% (53% to 78%) | 18/32 = 56% (39% to 72%) |
| `output_path` | 51/80 = 64% (53% to 73%) | 6/120 = 5% (2% to 10%) | 6/45 | 24/48 = 50% (36% to 64%) | 27/32 = 84% (68% to 93%) |

## What it showed
- Indirect injection is still weak: about 4 in 10 attacks found, and 10 of 45 hard-benign documents flagged (a pull-request review about injection defences, a GDPR erasure
  request, a password-reset help request, a threat-intelligence briefing, an HR onboarding checklist). The misses are contextual attacks: polite redirects, nested JSON,
  forged log lines and issue text, long documents with a short attack inside. Pattern rules are close to their limit here.
- XSS is strong (about 9 in 10 found, no false alarms on 120 benign); misses are rare elements and handlers and data-URI images.
- SSRF and path are partial (about 6 in 10): the misses are service-specific endpoints and unusual traversal encodings; the false alarms are incident reports and
  runbooks that name an address or a file.
