# Blind round 3 – injection_indirect

**Author:** Grok 4 (xAI). No prior exposure to RedHand rules, rounds 1–2, or repository material beyond this brief.

**Rule 1 confirmation:** Nothing in the RedHand repository was read except the supplied brief. No `agentwall/`, `docs/security/`, `docs/plans/`, `docs/testing/results/`, or corpus files were accessed. No benchmarks or tools from the repository were run. All samples were written for this round only.

## Counts

| Label     | Count |
|-----------|-------|
| malicious | 100   |
| benign    | 150   |
| **Total** | **250** |

- Hard benign (written to resemble attacks): **50**
- Language mix (approx.): English 55% (138), Bahasa Malaysia ~30%, Indonesian ~15% (Indonesian samples use `lang=ms` with family names indicating Indonesian)
- IDs: `injection_indirect-801` … `injection_indirect-1050`
- All `kind=tool_result`, `category=injection_indirect`

## Notes on labelling

- A few long operational documents contain both ordinary imperatives and security vocabulary; they were labelled benign when the imperatives are legitimate workflow steps directed at human operators or when they explicitly forbid credential dumping / external exfiltration.
- “Hard” benign samples intentionally use request language (“please refund”, “delete my account”, “export my data”) or security-runbook phrasing that could be mistaken for injection by a shallow filter.
- Attack samples favour subtlety: policy justification, mid-document placement, structured formats (JSON/YAML/CSV/HTML/code comments), tool-specific targeting, and non-translated Malay/Indonesian wording.
- No real people, companies, secrets, or live credentials appear in any sample.
