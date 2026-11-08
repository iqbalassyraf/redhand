/** Wording for the Radar self-test result. Pure, so it can be unit-tested. */

import type { SelfTestCategory } from "./api";

export const CHECK_LABEL: Readonly<Record<string, string>> = {
  injection_indirect: "Hidden instructions in tool answers",
  output_xss: "Script and active markup",
  output_ssrf: "Internal and cloud-metadata addresses",
  output_path: "Sensitive file paths",
};

export function pct(x: number): string {
  return `${Math.round(x * 100)}%`;
}

/** "19 of 20 (95%, range 76% to 99%)" for the attacks the check found. */
export function foundText(c: SelfTestCategory): string {
  const rate = c.malicious > 0 ? c.detected / c.malicious : 0;
  return `${c.detected} of ${c.malicious} (${pct(rate)}, range ${pct(c.detection_low)} to ${pct(c.detection_high)})`;
}

/** "0 of 20 (at most 16%)" — a zero or a full count is a bound with this few samples, not a measurement. */
export function falseAlarmText(c: SelfTestCategory): string {
  if (c.false_alarms === 0) return `0 of ${c.benign} (at most ${pct(c.false_alarm_high)} with 95% confidence)`;
  const rate = c.false_alarms / c.benign;
  return `${c.false_alarms} of ${c.benign} (${pct(rate)}, range ${pct(c.false_alarm_low)} to ${pct(c.false_alarm_high)})`;
}

/** Plain-language reason a run was refused or failed, from the HTTP status the page got. */
export function selfTestProblem(status: number | null): string {
  switch (status) {
    case 429:
      return "A self-test ran a moment ago. Wait about a minute and try again.";
    case 403:
      return "Your role cannot run the self-test.";
    case 502:
    case 503:
      return "The gateway could not run the self-test. Nothing was measured. Try again later; if it keeps failing, check the gateway.";
    default:
      return "The self-test could not be completed. Nothing was measured.";
  }
}
