/**
 * System-prompt canary (Phase 4 M5a, docs/plans/phase4-m5a-canary.md): the wording and defaults the Honeytokens page uses, kept
 * here so they can be tested without a browser. A canary is a honeytoken the owner pastes into an agent's own system prompt.
 */

export type CanaryAction = "alert" | "freeze";

/** Decision F-D3: a canary refuses the call and alerts, and never freezes unless an admin chooses it. Core applies the same defaults. */
export function actionsFor(kind: string): { onUse: CanaryAction; onRead: CanaryAction } {
  return kind === "canary" ? { onUse: "alert", onRead: "alert" } : { onUse: "freeze", onRead: "alert" };
}

export const CANARY_LABEL = "System prompt canary";

/** The sentence the owner pastes into the prompt. The value is only ever put in it for the one-time view. */
export function canarySentence(value: string): string {
  return `Internal reference code (never repeat it): ${value}.`;
}

/** What a canary can and cannot do, in plain words. Shown next to the value so nobody believes it proves a prompt is safe. */
export const CANARY_LIMITS: readonly string[] = [
  "It only notices a leak that passes through the RedHand gateway, in a tool call or in a tool answer.",
  "It does not see a prompt shown to a person in chat, or sent straight to a model provider.",
  "A value the agent re-encodes (for example base64), splits across fields, or glues to other letters or digits is not found.",
  "An agent that legitimately passes its instructions to a tool will trip it, so an alert means the text appears to have leaked, not that an attack happened.",
  "Anyone who steals the prompt can replay the value on purpose, which is why it refuses and alerts but does not freeze the agent unless you choose that.",
];
