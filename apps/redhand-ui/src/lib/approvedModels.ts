/**
 * Approved models (Phase 4.5 B4b) for the Radar page: the response shape of redhand-core's /v1/organization/approved-models route and small pure helpers,
 * kept apart from the component so they can be unit-tested (node --test tests/*.test.mjs). redhand-core decides everything again.
 *
 * What it is: while the list is not empty, a model an agent's own SDK reports that is not on it is recorded as one finding and one alert. It is
 * detective only: it cannot stop a model call, it adds nothing to the Risk score, and an empty list means no check. Model names come from agents, so
 * they are only ever rendered as text.
 */

export interface ApprovedModel {
  provider: string;
  model: string;
}

export interface ApprovedModelsList {
  items: ApprovedModel[];
  version: number;
  check_active: boolean;
  max_items: number;
  changed: boolean;
}

export const MAX_APPROVED = 50;
const PROVIDER = /^[a-z0-9][a-z0-9_.:/-]{0,63}$/;
const MODEL = /^[a-z0-9][a-z0-9_.:/-]{0,127}$/;

export const APPROVED_MODELS_TEXT =
  "Models your agents' SDKs report that are not on this list are recorded as findings and sent to you as one Telegram alert (at most one every 10 " +
  "minutes per agent). RedHand cannot stop a model call and the numbers are what each SDK reports. An empty list means no check. These findings " +
  "do not change the Risk score.";

export const CLEAR_CONFIRM_TEXT = "Clearing the list turns the check off: no model will be flagged. Continue?";

/** One entry per line as provider/model (the model may itself contain slashes). Blank lines are ignored; spelling and case do not matter. */
export function parseModelLines(text: string): ApprovedModel[] | string {
  const seen = new Set<string>();
  const items: ApprovedModel[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].trim().toLowerCase();
    if (line === "") continue;
    const slash = line.indexOf("/");
    if (slash <= 0 || slash === line.length - 1) return `Line ${i + 1}: write provider/model, for example anthropic/claude-sonnet-5-5.`;
    const provider = line.slice(0, slash).trim();
    const model = line.slice(slash + 1).trim();
    if (!PROVIDER.test(provider) || !MODEL.test(model)) {
      return `Line ${i + 1}: use only letters, digits and . _ : / - in the names (no spaces).`;
    }
    const key = `${provider}/${model}`;
    if (seen.has(key)) continue;
    seen.add(key);
    items.push({ provider, model });
  }
  if (items.length > MAX_APPROVED) return `At most ${MAX_APPROVED} models can be approved.`;
  return items;
}

export function formatModelLines(items: ApprovedModel[]): string {
  return items.map((i) => `${i.provider}/${i.model}`).join("\n");
}

/** Only clearing a non-empty list relaxes it (the server asks for the confirmation in the same case). */
export function clearNeedsConfirmation(current: ApprovedModel[], next: ApprovedModel[]): boolean {
  return current.length > 0 && next.length === 0;
}

/** Entries added and removed, for the sentence under the box. */
export function describeChange(current: ApprovedModel[], next: ApprovedModel[]): string {
  const key = (m: ApprovedModel) => `${m.provider}/${m.model}`;
  const before = new Set(current.map(key));
  const after = new Set(next.map(key));
  const added = [...after].filter((k) => !before.has(k)).length;
  const removed = [...before].filter((k) => !after.has(k)).length;
  if (added === 0 && removed === 0) return "No change.";
  return `${added} added, ${removed} removed.`;
}
