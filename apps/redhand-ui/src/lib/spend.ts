/**
 * Model spend (Phase 4.5 B4a) for the Passports page: the response shapes of redhand-core's /v1/spend routes and the small pure helpers that
 * word them, kept apart from the components so they can be unit-tested (node --test tests/*.test.mjs). redhand-core decides everything again.
 *
 * What every dollar figure is: an ESTIMATE from the token counts the agent's own SDK reported, at the provider's public prices on a stated
 * date. It is not measured by RedHand and not an invoice, and a model with no known price is "price unknown", never $0.
 * Text that came from an agent (model and provider names) is untrusted: it is only ever rendered as text, and shortened here.
 */

export interface ModelUse {
  provider: string;
  model: string;
  calls: number;
  prompt_tokens: number;
  completion_tokens: number;
  price_known: boolean;
  estimated_micro_usd: number | null;
  estimated_text: string | null;
  lower_bound: boolean;
}

/** What the model proxy measured (B5b): the provider's own token counts for calls that went through RedHand. Apart from the reported figures, never added to them. */
export interface MeasuredSpend {
  calls: number;
  calls_without_usage: number;
  prompt_tokens: number;
  completion_tokens: number;
  estimated_micro_usd: number;
  estimated_text: string;
  lower_bound: boolean;
  unpriced_tokens: number;
  unpriced_models: string[];
  models: ModelUse[];
}

export interface AgentSpend {
  agent_id: string;
  name: string;
  status: string;
  usage_reported: boolean;
  calls: number;
  prompt_tokens: number;
  completion_tokens: number;
  estimated_micro_usd: number;
  estimated_text: string;
  lower_bound: boolean;
  unpriced_tokens: number;
  unpriced_models: string[];
  spend_limit_micro_usd: number | null;
  spend_limit_text: string | null;
  percent_of_limit: number | null;
  models: ModelUse[];
  measured?: MeasuredSpend | null; // absent on an older core
  measured_unavailable?: boolean;
}

export interface SpendToday {
  day: string;
  resets_at: string;
  utc_offset_minutes: number;
  currency: "USD";
  prices_as_of: string;
  basis: string;
  agents: AgentSpend[];
}

export interface DaySpend {
  day: string;
  usage_reported: boolean;
  calls: number;
  estimated_micro_usd: number;
  estimated_text: string;
  lower_bound: boolean;
  unpriced_tokens: number;
  models: ModelUse[];
}

export interface AgentSpendDetail {
  currency: "USD";
  prices_as_of: string;
  basis: string;
  agent: AgentSpend;
  days: DaySpend[];
}

export interface SpendLimitResult {
  agent_id: string;
  spend_limit_micro_usd: number | null;
  changed: boolean;
}

export const MICRO = 1_000_000;
export const MAX_LIMIT_MICRO_USD = 10 ** 12; // $1,000,000 a day: the same bound the database enforces
const NAME_LIMIT = 60;

/** The one sentence that must sit next to every dollar figure. */
export function basisLine(pricesAsOf: string): string {
  return `Estimated from what the agent's SDK reported; prices as of ${pricesAsOf}. Not an invoice.`;
}

export const SPEND_LIMITS_TEXT =
  "These numbers come from the token counts each agent's own SDK reports, so an agent whose SDK does not report (or misreports) its model use " +
  "shows less than it really used. RedHand does not see the model call itself and cannot stop it: a limit here only sends an alert. Prices " +
  "are the provider's public standard rates and ignore discounts, caching and batch pricing. A model without a known price is shown as " +
  "\"price unknown\" and is left out of the dollar figure rather than counted as zero. The one exception to \"a limit only sends an alert\": an agent whose model calls go through " +
  "RedHand's model proxy (off by default) is also refused once what the proxy measured reaches the limit, a few seconds late, and a model with no known price is refused while a limit is set.";

export const LIMIT_CONFIRM_TEXT = "Raising or removing the limit means RedHand will alert later, or never. Continue?";

/** 1234567 -> "1,234,567". Plain digit grouping, so the page reads the same in every locale. */
export function formatTokens(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "0";
  return Math.floor(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/** Dollars typed in a box -> whole micro-dollars. Empty means "no limit" (null). No floating point: the digits are read as text. */
export function parseDollars(raw: string): number | null | "invalid" {
  const text = raw.trim().replace(/^\$/, "");
  if (text === "") return null;
  const match = /^(\d{1,7})(?:\.(\d{1,6}))?$/.exec(text);
  if (!match) return "invalid";
  const micro = Number(match[1]) * MICRO + Number((match[2] ?? "").padEnd(6, "0"));
  return micro >= 1 && micro <= MAX_LIMIT_MICRO_USD ? micro : "invalid";
}

/** The inverse, for filling the box: 2500000 -> "2.5", 2000000 -> "2". */
export function dollarsInput(micro: number | null): string {
  if (micro === null) return "";
  const whole = Math.floor(micro / MICRO);
  const frac = String(micro % MICRO).padStart(6, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : String(whole);
}

/** Only raising or removing an existing limit relaxes it (the server asks for the confirmation tick in the same cases). */
export function limitNeedsConfirmation(current: number | null, next: number | null): boolean {
  return current !== null && (next === null || next > current);
}

/** A provider/model pair for display: control characters replaced, shortened. It is agent-supplied text, so it is never trusted for layout. */
export function shownModel(provider: string, model: string): string {
  const clean = (text: string) => text.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202f\u2060-\u2064]/g, "?");
  const full = provider ? `${clean(provider)}/${clean(model)}` : clean(model);
  return full.length > NAME_LIMIT ? `${full.slice(0, NAME_LIMIT - 1)}…` : full;
}

/** What one model's cost cell says. A tiered model's figure is a floor, and an unknown price is never a dollar amount. */
export function modelCost(model: ModelUse): string {
  if (!model.price_known || model.estimated_text === null) return "price unknown";
  return model.lower_bound ? `at least ${model.estimated_text}` : model.estimated_text;
}

export interface SpendCell {
  headline: string;
  detail: string;
  tone: "none" | "ok" | "warn" | "alert";
}

/** The "Model use" cell of one agent: today's estimate, or the reason there is none. */
export function spendCell(view: AgentSpend | undefined): SpendCell {
  if (view === undefined) return { headline: "-", detail: "", tone: "none" };
  if (!view.usage_reported) return { headline: "usage not reported", detail: "its SDK sent no model use today", tone: "none" };
  const tokens = `${formatTokens(view.prompt_tokens + view.completion_tokens)} tokens`;
  const priced = view.estimated_micro_usd > 0 || view.unpriced_tokens === 0;
  const headline = priced ? (view.lower_bound ? `at least ${view.estimated_text}` : view.estimated_text) : "price unknown";
  const unknown = priced && view.unpriced_tokens > 0 ? ` · plus ${formatTokens(view.unpriced_tokens)} tokens with no known price` : "";
  const limit = view.percent_of_limit;
  const tone = limit === null ? "ok" : limit >= 100 ? "alert" : limit >= 80 ? "warn" : "ok";
  return { headline, detail: `${tokens}${unknown}`, tone };
}

export const MEASURED_BASIS =
  "Measured by RedHand's model proxy from the token counts the provider reported for calls that went through it. The proxy is off by default, and calls that do not go through it " +
  "appear only in the reported figure above. The two are never added together.";

export interface MeasuredLine {
  headline: string;
  detail: string;
}

/** The "measured by RedHand" line under an agent's reported figure, or null when the proxy measured nothing (never a zero). */
export function measuredLine(view: AgentSpend): MeasuredLine | null {
  if (view.measured_unavailable) return { headline: "measured usage could not be read", detail: "the reported figure is unaffected" };
  const m = view.measured;
  if (!m) return null;
  const priced = m.estimated_micro_usd > 0 || m.unpriced_tokens === 0;
  const amount = priced ? (m.lower_bound ? `at least ${m.estimated_text}` : m.estimated_text) : "price unknown";
  const headline = priced ? `${amount} measured by RedHand` : `${amount}, measured by RedHand`;
  const parts = [`${formatTokens(m.prompt_tokens + m.completion_tokens)} tokens`, `${m.calls} calls`];
  if (m.calls_without_usage > 0) parts.push(`${m.calls_without_usage} calls with no usage reported`);
  if (priced && m.unpriced_tokens > 0) parts.push(`plus ${formatTokens(m.unpriced_tokens)} tokens with no known price`);
  return { headline, detail: parts.join(" · ") };
}
