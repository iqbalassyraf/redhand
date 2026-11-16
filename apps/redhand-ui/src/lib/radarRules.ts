/**
 * The Radar rules as the dashboard describes them. GENERATED from agentwall/src/firewall/radar.py RULES (id, family, kind, default
 * severity and the fixed reason sentence); a unit test (tests/radarRules.test.mjs) fails if the two drift apart, so the page
 * never explains a rule differently from the code that raised it. Regenerate by copying RULES again when a rule changes.
 */

export type RuleKind = "injection" | "output";
export type Level = "low" | "medium" | "high";

export interface RadarRule {
  readonly family: string;
  readonly kind: RuleKind;
  readonly severity: Level;
  readonly reason: string;
}

export const RADAR_RULES: Readonly<Record<string, RadarRule>> = {
  "RAD-INJ-001": { family: "override", kind: "injection", severity: "high", reason: "The text tells the agent to ignore, drop or override its instructions." },
  "RAD-INJ-002": { family: "persona", kind: "injection", severity: "high", reason: "The text tries to give the agent a new role, mode or identity." },
  "RAD-INJ-003": { family: "marker", kind: "injection", severity: "high", reason: "The text contains fake system or role markers that imitate the conversation's own structure." },
  "RAD-INJ-004": { family: "exfiltration", kind: "injection", severity: "high", reason: "The text asks the agent to send sensitive or bulk data to a destination." },
  "RAD-INJ-005": { family: "tool-call", kind: "injection", severity: "high", reason: "The text tells the agent to call a tool or run a command, with signs it is not the user's request." },
  "RAD-INJ-006": { family: "concealment", kind: "injection", severity: "medium", reason: "The text asks the agent to hide what it is doing from the user." },
  "RAD-INJ-007": { family: "disclosure", kind: "injection", severity: "high", reason: "The text asks the agent to reveal its prompt, configuration or credentials." },
  "RAD-INJ-008": { family: "authority", kind: "injection", severity: "high", reason: "The text claims authority over the agent to get a sensitive action done." },
  "RAD-INJ-009": { family: "hidden", kind: "injection", severity: "high", reason: "The text hides instructions in characters a person cannot see." },
  "RAD-INJ-010": { family: "encoded", kind: "injection", severity: "high", reason: "An encoded block in the text decodes to instructions for the agent." },
  "RAD-INJ-011": { family: "direction", kind: "injection", severity: "medium", reason: "The text uses text-direction controls, which can make displayed text differ from what the agent reads." },
  "RAD-INJ-012": { family: "model", kind: "injection", severity: "medium", reason: "A statistical model rates this text as likely to contain an instruction aimed at the agent (second stage, no matched text)." },
  "RAD-OUT-001": { family: "xss", kind: "output", severity: "high", reason: "The content contains script or an event handler that runs when rendered." },
  "RAD-OUT-002": { family: "xss", kind: "output", severity: "high", reason: "The content contains a link or source with a script-running URL scheme." },
  "RAD-OUT-003": { family: "xss", kind: "output", severity: "medium", reason: "The content contains active markup (frame, object, redirect, external form or style import)." },
  "RAD-OUT-004": { family: "exfil-img", kind: "output", severity: "high", reason: "The content embeds an image whose address carries data to an outside server." },
  "RAD-OUT-005": { family: "ssrf", kind: "output", severity: "high", reason: "The content points at an internal, loopback, private or cloud-metadata address." },
  "RAD-OUT-006": { family: "ssrf", kind: "output", severity: "medium", reason: "The content points at a risky URL scheme or a known data-collection service." },
  "RAD-OUT-007": { family: "path", kind: "output", severity: "high", reason: "The content points at a sensitive file or escapes its directory." },
};

/** The loop rule is not one of the Radar's text rules (radar.py), so it is kept apart from RADAR_RULES, which a test compares with radar.py. */
export const LOOP_RULE_ID = "RAD-LOOP-001";
export const DESTINATION_RULE_ID = "RAD-DST-001";
export const MODEL_RULE_ID = "RAD-MDL-001";
export const MODEL_RULE_REASON =
  "An agent's SDK reported a model that is not on the approved list. Recorded only: nothing was refused, and it does not change the Risk score.";
export const DESTINATION_RULE_REASON =
  "The agent put a web or email address that is not on its allowed list into a call. Only the last two parts of the address are shown.";
export const LOOP_RULE_REASON = "The agent sent the same tool call, with the same arguments, more often than the limit in a short time: it may be stuck in a loop.";

/** Plain wording for a rule id; an id this version does not know is shown as itself, never hidden. */
export function describeRule(ruleId: string): string {
  if (ruleId === LOOP_RULE_ID) return LOOP_RULE_REASON;
  if (ruleId === DESTINATION_RULE_ID) return DESTINATION_RULE_REASON;
  if (ruleId === MODEL_RULE_ID) return MODEL_RULE_REASON;
  return RADAR_RULES[ruleId]?.reason ?? `Rule ${ruleId} (newer than this page).`;
}

export const EVASION_LABEL: Readonly<Record<string, string>> = {
  invisible: "invisible characters",
  lookalike: "look-alike letters",
  leet: "number-for-letter swaps",
  encoded: "encoded text",
  hidden: "hidden text",
};
