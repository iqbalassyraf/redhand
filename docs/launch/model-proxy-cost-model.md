# Model proxy: cost per agent (DRAFT model with blanks; not a price list)

Written 2026-11-18 for ADR 0025 go/no-go item 1. **Prices are blank on purpose:** they come from the Cloud Run price page for the chosen region on the day of the decision. Fill the blanks, do not guess them.
The proxy adds no model cost: the customer pays the provider. RedHand's cost is compute, connection time and bandwidth.

## What drives cost
| Driver | Why | Measured so far |
|---|---|---|
| CPU per call | About one gateway call of work | 2 to 3 ms overhead locally (ADR 0025); not measured on Cloud Run |
| Connection time | A stream holds a connection and its instance share open for the whole answer | Not measured; this is the main driver |
| Bandwidth | Prompts in, completions out, through RedHand | Pass-through; depends on the customer |
| Usage reports | One batched call to core per flush interval per instance | Fixed, small |
| Database | One row per agent, model and day (measured table) | Fixed, small |
| Minimum instances | Production needs at least one always on (ADR 0028) | Fixed monthly |

## Inputs to fill in
| Input | Value |
|---|---|
| Cloud Run vCPU-second price (region: ____) | |
| Cloud Run GiB-second price | |
| Egress price per GiB | |
| Instances kept warm | |
| Average calls per agent per day | |
| Average seconds a call holds a connection | |
| Average GiB through the proxy per agent per month | |

## Formula (fill in once the inputs are known)
monthly cost per agent = (calls per day x 30 x seconds per call x (vCPU price x vCPUs + GiB price x GiB)) + (GiB through x egress price) + (fixed monthly cost / number of agents)

Compare the result with the price per agent. CLAUDE.md requires cost-to-serve to stay a small fraction of the price; if it does not, the proxy belongs in a higher tier (ADR 0025).
