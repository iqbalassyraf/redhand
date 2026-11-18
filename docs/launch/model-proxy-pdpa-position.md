# Model proxy: position on content in transit (DRAFT, for legal review; not a decision and not legal advice)

Written 2026-11-18 for ADR 0025 go/no-go item 5. **This paper makes no compliance claim.** Every statement about what the law requires is for a lawyer to confirm.

## What the proxy does with content
Prompts and completions pass through the gateway to the model provider and back. For counting only, the gateway reads event metadata (token counts, model name); it reads **no** prompt or completion text for any other purpose.

## What is stored and logged today (facts from the code, ADR 0025)
- **Stored:** per agent, per model, per day: call counts, input and output token counts, calls without usage. Model names. Nothing else about a call.
- **Not stored, not logged:** prompt text, completion text, tool arguments, the provider key, the agent's token. Metrics carry outcomes and sizes, never content.
- **Held briefly in memory:** the current partial event line of a stream (up to 64 KiB) and the request body being forwarded (up to 1 MiB).
- **Sent onward:** the request goes to the model provider (today api.anthropic.com), which has its own terms and retention. The customer's data therefore reaches a third party by design.

## Questions for legal review
1. Is carrying content in transit, without storing it, processing of personal data for the purposes of Malaysia's PDPA (as amended) and comparable ASEAN regimes? What follows for RedHand's role and the customer's?
2. Does sending prompts to a model provider outside Malaysia need a notice or consent, and from whom?
3. What must the terms and privacy drafts (`terms-draft.md`, `privacy-draft.md`) say about the proxy, and should they say it only for customers who switch it on?
4. Region: the provider's region is not controlled by RedHand. Is that acceptable, or does a customer need the option to use their own provider account in their region (see ADR 0029)?
5. If prompt inspection or redaction is ever added, what changes? (It is out of scope today.)

## What RedHand will not do without approval
Store content, send content to any third party other than the customer's chosen model provider, or add an LLM call of its own on this path.
