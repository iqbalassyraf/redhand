# DRAFT privacy notice: for legal review, not for publication

*An engineer's inventory of what the product handles, to give a lawyer a factual start. Not legal advice; not reviewed; do not publish. It makes no compliance claim.*

## What RedHand stores (from the code and the database schema)
| Data | Why | Where | Retention in the product |
|---|---|---|---|
| Account e-mail and password hash | sign-in | Supabase Auth | until the account is deleted (deleted separately from an organization: see the deletion runbook) |
| Organization name, address name, members and roles | running the service | Postgres | until the organization is purged |
| Agent passports (name, framework, owner, scopes) | the product | Postgres | until the organization is purged |
| Audit log of control actions (who froze what, when) | accountability | Postgres, append-only | until the organization is purged |
| Black Box events: tool, decision, timing, argument key names and a hash | incident review | Postgres | 30 days by default, configurable; payload text only if the customer turns capture on (7 days) |
| Telemetry traces from the SDK (may include agent reasoning and tool arguments the customer's SDK sends) | investigation | Postgres | per table purge jobs; shown to security operators and above, hidden from viewers |
| Radar findings, risk scores, spend roll-ups | detection | Postgres | findings 90 days; spend roll-ups 90 days |
| Telegram chat id of a linked operator | panic command | Postgres | until unlinked or purged |
| Request logs (addresses, paths, status; no bodies, no keys by design) | operations | Cloud Run / Vercel | the provider's retention |

## Open questions for counsel
- Roles: RedHand as processor for the customer's data about their agents' activity; as controller for account data. Data processing agreement needed?
- Cross-border transfer (region of the database and hosts: ADR 0028) and customer consent.
- Whether agent reasoning or tool arguments can contain personal data of the customer's own customers (they can: the SDK sends what the customer's code gives it). Minimisation advice.
- Breach notification duty and timeline.
- Sub-processors: Supabase, Google Cloud, Vercel, Telegram (if used), an e-mail provider (not chosen).
