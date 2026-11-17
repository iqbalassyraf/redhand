# Launch kit

What stands between "it works on staging" and "a stranger can pay for it". Written 2026-11-17 for Phase 4.5 D1; nothing here has been run against production (there is none yet).

| Document | For | What it is |
|---|---|---|
| [`owner-checklist.md`](owner-checklist.md) | the owner | One page, in order: everything only the owner can do before announcing |
| [`first-customer-path.md`](first-customer-path.md) | the owner, support | The steps from "a stranger asks for access" to "their agent is protected", with what was tested and what was not |
| [`environment-variables.md`](environment-variables.md) | whoever deploys | Every setting, generated from the code, and the must-set list for production |
| [`../adr/0028-production-hosting.md`](../adr/0028-production-hosting.md) | the owner | The production hosting decision, ready to accept or change |
| [`what-redhand-controls.md`](what-redhand-controls.md) | customers (website or docs) | What RedHand does and does not protect, in plain words |
| [`terms-draft.md`](terms-draft.md), [`privacy-draft.md`](privacy-draft.md) | a lawyer | Drafts for legal review. Not legal advice and not ready to publish |
| [`support-and-status.md`](support-and-status.md) | the owner | Support contact, status page and incident text to fill in |
| `scripts/smoke_launch.py` | the owner | A black-box check of a deployed URL: refusals, headers, CORS, body limit, no development shortcuts |

Related: `docs/release-readiness.md` (the pre-release scans and tests), `docs/runbooks/` (operations), `docs/security/threat-model.md`.
