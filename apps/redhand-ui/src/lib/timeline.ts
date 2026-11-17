/**
 * The incident view's wording (Phase 4.5 B3). Pure functions: the page only renders what these return, and tests/timeline.test.mjs
 * checks every sentence. Nothing here adds information core did not send: no call contents, no argument values, no full addresses.
 */

import { describeRule } from "./radarRules.ts";
import { automaticActorLabel } from "./riskForm.ts";

export type TimelineKind = "refusal" | "error" | "activity" | "finding" | "trip" | "action";

export interface TimelineItem {
  at: string;
  kind: TimelineKind;
  seq: number | null;
  tool_name: string;
  server: string;
  reasons: string[];
  calls: number | null;
  refused: number | null;
  finding_id: string | null;
  rule_id: string;
  finding_kind: string;
  confidence: string;
  review_status: string;
  occurrences: number | null;
  trip_kind: string;
  seen_in: string;
  action: string;
  reason: string | null;
  automatic: boolean | null;
  /** An action on every agent of the organization (freeze all, Safe Mode for all). Absent on an older core. */
  organization_wide?: boolean;
  /** Safe Mode for every agent that was already on when this agent was registered (G4). Absent on an older core. */
  in_effect_at_registration?: boolean;
}

export interface TimelineResponse {
  agent: { id: string; name: string; status: string };
  items: TimelineItem[];
  next_before: string | null;
}

export type Tone = "bad" | "warn" | "info" | "quiet";

export interface ItemDescription {
  title: string;
  detail: string;
  tone: Tone;
  link: { href: string; label: string } | null;
}

export type FilterId = "all" | "refusals" | "findings" | "trips" | "actions";

export const FILTERS: ReadonlyArray<{ id: FilterId; label: string }> = [
  { id: "all", label: "Everything" },
  { id: "refusals", label: "Refused and failed calls" },
  { id: "findings", label: "Findings" },
  { id: "trips", label: "Trips" },
  { id: "actions", label: "Actions taken" },
];

export const TIMELINE_LIMITS_TEXT =
  "This timeline shows only what RedHand recorded for this agent through the gateway: refused and failed calls, activity per hour, " +
  "findings, honeytoken and decoy trips, and actions taken on its passport. No call contents are shown. An agent's activity outside " +
  "RedHand is not here.";

export const FREEZE_REASON = "Frozen from the incident view";

const FINDING_KIND: Readonly<Record<string, string>> = {
  injection: "instructions aimed at the agent",
  output: "risky content in a tool answer",
  loop: "repeated identical calls",
  destination: "an address outside the allowed list",
  model: "a model that is not on the approved list",
};

const REVIEW: Readonly<Record<string, string>> = {
  open: "Not reviewed yet.",
  confirmed: "Marked real.",
  false_alarm: "Marked a false alarm.",
};

const ACTIONS: Readonly<Record<string, string>> = {
  "passport.created": "Registered",
  "passport.frozen": "Frozen",
  "passport.unfrozen": "Unfrozen",
  "passport.revoked": "Revoked",
  "passport.scopes_changed": "Scopes changed",
  "passport.key_rotated": "Key rotated",
  "passport.renewed": "Renewed",
  "passport.safe_mode_enabled": "Safe Mode turned on",
  "passport.safe_mode_disabled": "Safe Mode turned off",
  "passport.budget_changed": "Daily limit changed",
  "passport.destination_added": "Allowed address added",
  "passport.destination_removed": "Allowed address removed",
  "passport.destination_mode_changed": "Destination check changed",
  "passport.timeline_exported": "Timeline exported",
  "radar_suppression.created": "A Radar rule silenced for this agent",
  "radar_suppression.revoked": "Radar silence removed",
  "organization.frozen_all": "Every agent frozen (freeze all)",
  "organization.safe_mode_enabled": "Safe Mode turned on for every agent",
  "organization.safe_mode_disabled": "Safe Mode turned off for every agent",
};

/** Shown on the one organization-wide item older than the agent: it restricted the agent from its start. */
export const IN_EFFECT_AT_REGISTRATION = "Already in force when this agent was registered.";

/** A plain name for an audit action; one this version does not know is shown as it is, never hidden. */
export function actionLabel(action: string): string {
  return ACTIONS[action] ?? action;
}

function where(tool: string, server: string): string {
  if (!tool) return server ? `(${server})` : "";
  return server ? `${tool} (${server})` : tool;
}

export function describeItem(item: TimelineItem): ItemDescription {
  switch (item.kind) {
    case "refusal":
    case "error":
      return {
        title: `${item.kind === "refusal" ? "Call refused" : "Call failed"}: ${where(item.tool_name, item.server)}`,
        detail: item.reasons[0] ?? "",
        tone: item.kind === "refusal" ? "bad" : "warn",
        link: item.seq !== null ? { href: "/blackbox", label: `Black Box event #${item.seq}` } : null,
      };
    case "activity": {
      const calls = item.calls ?? 0;
      const refused = item.refused ?? 0;
      return {
        title: `${calls} tool ${calls === 1 ? "call" : "calls"} in this hour${refused > 0 ? `, ${refused} refused` : ""}`,
        detail: "",
        tone: "quiet",
        link: null,
      };
    }
    case "finding": {
      const times = item.occurrences ?? 1;
      return {
        title: `Finding ${item.rule_id}: ${FINDING_KIND[item.finding_kind] ?? item.finding_kind} (${item.confidence} confidence)`,
        detail: `${describeRule(item.rule_id)} In ${where(item.tool_name, item.server)}, seen ${times} ${times === 1 ? "time" : "times"}. ` +
          `${REVIEW[item.review_status] ?? item.review_status}`,
        tone: "warn",
        link: { href: "/radar", label: "Open the Radar" },
      };
    }
    case "trip": {
      const place = where(item.tool_name, item.server);
      const title = item.trip_kind === "honey_tool"
        ? `Decoy tool called: ${place}`
        : item.seen_in === "result"
          ? `Honeytoken read in the answer of ${place}`
          : `Honeytoken used in a call to ${place}`;
      return { title, detail: "", tone: "bad", link: { href: "/honeytokens", label: "Open Honeytokens" } };
    }
    case "action": {
      const who = item.automatic ? automaticActorLabel(item.reason) : "a person";
      const detail = item.reason && !item.automatic ? `Reason: ${item.reason}` : (item.reason ?? "");
      return {
        title: `${actionLabel(item.action)} by ${who}`,
        detail: item.in_effect_at_registration ? `${IN_EFFECT_AT_REGISTRATION}${detail ? ` ${detail}` : ""}` : detail,
        tone: "info",
        link: null,
      };
    }
  }
}

export function matchesFilter(item: TimelineItem, filter: FilterId): boolean {
  switch (filter) {
    case "all":
      return true;
    case "refusals":
      return item.kind === "refusal" || item.kind === "error";
    case "findings":
      return item.kind === "finding";
    case "trips":
      return item.kind === "trip";
    case "actions":
      return item.kind === "action";
  }
}

/** Day separators use the viewer's own calendar day. */
export function dayKey(at: string): string {
  return new Date(at).toLocaleDateString();
}
