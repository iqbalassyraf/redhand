# What RedHand controls, and what it does not

*For customers. Plain words, no guarantees we cannot back with a test.*

**RedHand controls what flows through RedHand.** Your agents reach tools (MCP servers) through the RedHand gateway, and the gateway decides, on every call, whether that agent may do that thing. That is the whole claim.

## What it does
- **Knows each agent.** Every agent has a passport: who owns it, what it may touch, when it expires.
- **Checks every call at the gateway.** In scope: it goes through. Out of scope, frozen, revoked or expired: it is refused and recorded.
- **Stops an agent quickly.** Freezing or revoking an agent, or freezing all of them, takes effect on that agent's next call. In our local measurements that is under half a second; our promise is five seconds.
- **Gives agents short-lived, narrow credentials** instead of letting them hold your long-lived keys (for the connections RedHand brokers).
- **Watches for common trouble:** loops, calls to places you did not approve, models you did not approve, secrets leaving, text that looks like an attack on the agent. Some of these only alert (Watch mode); we say which.
- **Records what happened,** in a tamper-evident log, so you can look back at an incident.
- **Lets you take your data out and have it deleted.**

## What it does not do
- **It does not protect anything that does not go through RedHand.** An agent that talks to a tool directly, or uses a credential RedHand did not issue, is invisible to it.
- **It does not read or judge everything an agent says.** Its checks are rules and lookups, they can miss things, and they can raise false alarms. It is not a guarantee that no agent will ever do harm.
- **It does not replace your own security.** Keep your credentials safe, limit what each tool can do, and review what your agents are for.
- **Model spend figures are reported by your agent's software**, not measured by RedHand, unless the model calls go through RedHand (not offered yet). We call them estimates.
- **We make no compliance claims.** Records and reports can help your own compliance work; they do not make you compliant with any law or standard.

If any sentence here is more than your own reading of RedHand's behaviour can support, tell us and we will change the sentence.
