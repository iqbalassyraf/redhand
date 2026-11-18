# ADR 0029: Model proxy provider-key custody (DRAFT, not a decision)

**Status:** Draft (2026-11-18). This is a design paper for the owner's go/no-go on the model proxy (ADR 0025). It is **not a decision**: nothing here is built, approved or scheduled, and accepting it would still need a plan for the code.

## Context
The proxy prototype holds ONE provider key for the whole deployment (`AGENTWALL_MODEL_PROXY_ANTHROPIC_KEY`, an environment variable). That is fine for one operator's own traffic and wrong for customers:
every tenant's calls would run on one account, one tenant's spend would be indistinguishable on the provider's side, and a leak of that process exposes every tenant at once. Because of this the proxy **refuses to start outside
development, dev, test, local and staging** (ADR 0025). This paper says what custody would have to look like before that refusal may be lifted. CLAUDE.md 5.2 and 5.5 apply: customer-provided credentials are encrypted at rest with envelope encryption and never returned.

## Options
| | Option | Verdict |
|---|---|---|
| A | Keep one deployment key | Rejected for customers: no tenant isolation of the credential, one leak exposes all, spend cannot be separated at the provider. Stays for the owner's own staging use. |
| B | **Per-tenant keys, envelope-encrypted with a cloud KMS key** | Recommended design (below). |
| C | Customer keeps the key; the in-VPC sidecar calls the provider | Strongest custody (RedHand never holds the key), but it is the higher-tier, self-hosted product, not the hosted Starter slice. Keep as the answer for customers who refuse B. |
| D | Customer sends their key on every request | Rejected: the key would transit RedHand on every call and sit in agent configuration, which is the leak path we want to remove. |

## Design sketch for B (not built)
- **Storage:** a tenant-scoped table (row-level security on, tenant manifest entry so export and deletion cover it) holding, per tenant and provider, the key **ciphertext**, a wrapped data key, the KMS key version, a key fingerprint (last four characters, never enough to use it), who added it and when. Plaintext is never stored.
- **Envelope encryption:** a fresh data key per secret, wrapped by a KMS key that RedHand cannot export. The gateway process decrypts only when it needs to forward a call and keeps the plaintext in memory for a short bounded time (a few minutes), never on disk, never in a log, an error message, a metric label, a trace or a core response.
- **Never returned:** no API, export or audit row returns the key. The export excludes the ciphertext columns, as it does for SDK key hashes (`tenant_data_manifest`).
- **Who can set it:** owner only, audited (`provider_key.set`, `provider_key.removed`: actor, tenant, provider, fingerprint, never the value), confirmation to replace or remove.
- **Rotation and revocation:** replacing a key takes effect on the next call after the gateway's cache lifetime; removing a key makes the proxy refuse every call for that tenant (fail closed). A KMS key version change re-wraps data keys without the customer's involvement. Deleting a tenant destroys its ciphertext rows with the rest of the purge.
- **Failure behaviour:** KMS unreachable, ciphertext unreadable, fingerprint mismatch or no key for the tenant: refuse the call. No fallback to the deployment key for a customer tenant.
- **Provider-side limits:** each tenant's own provider account carries its own rate limits and billing, so one tenant cannot exhaust another's.

## What must be true before the startup refusal may be lifted
1. Option B (or C for that tenant) is built, with tests for wrong tenant, removed key, rotated key, KMS down and a key that never appears in any response, log or export.
2. The threat-model rows below are reviewed by the owner.
3. The uptime and bypass paper (`docs/launch/model-proxy-uptime-and-bypass.md`) is accepted and its plan is in place.
4. The PDPA position (`docs/launch/model-proxy-pdpa-position.md`) has had legal review.
5. The cost model (`docs/launch/model-proxy-cost-model.md`) has real prices and the tier is priced from it.
6. A customer actually wants it (ADR 0025 go/no-go item 6, the owner's call).

## Threat-model rows (draft; copy into `docs/security/threat-model.md` when this is accepted)
| Threat | Defence in the design | Residual |
|---|---|---|
| Database read exposes provider keys | Only ciphertext stored; data key wrapped by a KMS key RedHand cannot export | A KMS or gateway-process compromise exposes keys in use |
| Gateway memory or log leaks a key | Plaintext held briefly in memory only; never logged or returned; scan gate and tests cover it | A memory dump of a running gateway |
| One tenant uses another's key | Key looked up by the tenant on the agent's passport, never by the request | A bug in that lookup, so the tenant isolation tests must include it |
| An insider or a stolen owner session replaces a key | Owner only, audited, confirmation, fingerprint in the audit row | The owner's own account security |
| An agent holding the customer's key bypasses the proxy | Not preventable: RedHand controls only what flows through it | Stated in customer copy |

## Consequences
Building B is a new secret store, a KMS dependency (a new dependency and an ongoing cost, both needing the owner's approval under CLAUDE.md 13) and a new failure mode. It is worth doing only if the owner decides the proxy is a product.
