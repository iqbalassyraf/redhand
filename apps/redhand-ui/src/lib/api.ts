/**
 * Typed client for redhand-core. Every call carries the operator's access token; the
 * UI is never a security boundary (all authorization happens in redhand-core).
 */

import type { ApprovedModel, ApprovedModelsList } from "./approvedModels";
import type { AgentSpendDetail, SpendLimitResult, SpendToday } from "./spend";
import type { SdkKeyCreated, SdkKeyList } from "./sdkKeys";
import type { TimelineResponse } from "@/lib/timeline";

export const CORE_API_BASE =
  process.env.NEXT_PUBLIC_REDHAND_CORE_URL || "http://localhost:8000";

export const GATEWAY_BASE =
  process.env.NEXT_PUBLIC_REDHAND_GATEWAY_URL || "http://localhost:8080";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function describeError(body: unknown, status: number): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail
        .map((d) =>
          d && typeof d === "object" && "msg" in d ? String((d as { msg: unknown }).msg) : "Invalid input"
        )
        .join("; ");
    }
  }
  return `Request failed (HTTP ${status})`;
}

export async function apiFetch<T>(
  path: string,
  token: string | null,
  init: { method?: string; body?: unknown } = {}
): Promise<T> {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (init.body !== undefined) headers["Content-Type"] = "application/json";

  const resp = await fetch(`${CORE_API_BASE}${path}`, {
    method: init.method ?? "GET",
    headers,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
  const text = await resp.text();
  let parsed: unknown = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
  }
  if (!resp.ok) throw new ApiError(resp.status, describeError(parsed, resp.status));
  return parsed as T;
}

// ---------------------------------------------------------------------------
// Contracts (mirror redhand-core's Pydantic models)
// ---------------------------------------------------------------------------

export type PassportStatus = "active" | "frozen" | "revoked" | "expired";
export type ScopeAccess = "read" | "write";

export interface Scope {
  server: string;
  tool: string;
  access: ScopeAccess;
}

export interface Passport {
  id: string;
  organization_id: string;
  name: string;
  external_agent_id: string;
  framework: string;
  environment: string;
  owner_id: string | null;
  backup_owner_id: string | null;
  scopes: Scope[];
  status: PassportStatus;
  stored_status: string;
  status_reason: string | null;
  expires_at: string;
  version: number;
  created_at: string | null;
  last_seen_at: string | null;
  safe_mode: boolean;
  daily_call_limit: number | null;
  budget_action: "deny" | "freeze";
  /** Created by SDK telemetry (C1b); absent on an older core. */
  reported_only?: boolean;
}

export interface PassportCreateResponse {
  passport: Passport;
  agent_key: string;
}

export interface ControlActionResponse {
  passport: Passport;
  changed: boolean;
}

export interface FreezeAllResponse {
  organization_id: string;
  frozen_count: number;
  frozen_agent_ids: string[];
}

export interface ControlAuditEntry {
  id: string;
  actor_user_id: string;
  action: string;
  target_type: string;
  target_id: string;
  reason: string | null;
  details: Record<string, unknown>;
  created_at: string;
}

export interface McpServer {
  id: string;
  slug: string;
  name: string;
  url: string;
  is_active: boolean;
}

export interface AgentUsage {
  agent_id: string;
  name: string;
  calls: number;
  daily_call_limit: number | null;
  budget_action: string;
  percent: number | null;
}

export interface UsageSummary {
  day_key: string;
  resets_at: string;
  utc_offset_minutes: number;
  agents: AgentUsage[];
}

export const passportsApi = {
  list: (t: string) => apiFetch<Passport[]>("/v1/passports", t),
  create: (
    t: string,
    body: {
      name: string;
      framework: string;
      scopes: Scope[];
      expires_in_days: number;
      backup_owner_id?: string;
    }
  ) => apiFetch<PassportCreateResponse>("/v1/passports", t, { method: "POST", body }),
  freeze: (t: string, id: string, reason?: string) =>
    apiFetch<ControlActionResponse>(`/v1/passports/${id}/freeze`, t, {
      method: "POST",
      body: { reason: reason || null },
    }),
  unfreeze: (t: string, id: string, reason?: string) =>
    apiFetch<ControlActionResponse>(`/v1/passports/${id}/unfreeze`, t, {
      method: "POST",
      body: { reason: reason || null, confirm: true },
    }),
  promote: (t: string, id: string, reason?: string) =>
    apiFetch<ControlActionResponse>(`/v1/passports/${id}/promote`, t, {
      method: "POST",
      body: { reason: reason || null, confirm: true },
    }),
  revoke: (t: string, id: string, reason?: string) =>
    apiFetch<ControlActionResponse>(`/v1/passports/${id}/revoke`, t, {
      method: "POST",
      body: { reason: reason || null, confirm: true },
    }),
  usage: (t: string) => apiFetch<UsageSummary>("/v1/usage", t),
  budgetDefault: (t: string) =>
    apiFetch<{ default_daily_call_limit: number | null; changed: boolean }>("/v1/organization/budget-default", t),
  setBudgetDefault: (t: string, limit: number | null, reason: string, confirm: boolean) =>
    apiFetch<{ default_daily_call_limit: number | null; changed: boolean }>("/v1/organization/budget-default", t, {
      method: "PUT",
      body: { default_daily_call_limit: limit, reason: reason || null, confirm },
    }),
  setBudget: (
    t: string,
    id: string,
    dailyCallLimit: number | null,
    action: "deny" | "freeze",
    reason: string,
    confirm: boolean
  ) =>
    apiFetch<{ passport: Passport; changed: boolean }>(`/v1/passports/${id}/budget`, t, {
      method: "PUT",
      body: { daily_call_limit: dailyCallLimit, action, reason: reason || null, confirm },
    }),
  setSafeMode: (t: string, id: string, enabled: boolean, reason?: string) =>
    apiFetch<{ passport: Passport; changed: boolean }>(`/v1/passports/${id}/safe-mode`, t, {
      method: "POST",
      body: { enabled, reason: reason || null, confirm: !enabled },
    }),
  orgSafeMode: (t: string) => apiFetch<{ enabled: boolean; changed: boolean }>("/v1/organization/safe-mode", t),
  setOrgSafeMode: (t: string, enabled: boolean, reason?: string) =>
    apiFetch<{ enabled: boolean; changed: boolean }>("/v1/organization/safe-mode", t, {
      method: "POST",
      body: { enabled, reason: reason || null, confirm: !enabled },
    }),
  updateScopes: (t: string, id: string, scopes: Scope[], reason?: string) =>
    apiFetch<ControlActionResponse>(`/v1/passports/${id}/scopes`, t, {
      method: "PUT",
      body: { scopes, reason: reason || null, confirm: true },
    }),
  renew: (t: string, id: string, days: number) =>
    apiFetch<Passport>(`/v1/passports/${id}/renew`, t, {
      method: "POST",
      body: { expires_in_days: days },
    }),
  rotateKey: (t: string, id: string) =>
    apiFetch<{ passport: Passport; agent_key: string }>(`/v1/passports/${id}/rotate-key`, t, {
      method: "POST",
      body: {},
    }),
  freezeAll: (t: string, reason: string) =>
    apiFetch<FreezeAllResponse>("/v1/passports/freeze-all", t, {
      method: "POST",
      body: { reason: reason || null, confirm: true },
    }),
  audit: (t: string) => apiFetch<ControlAuditEntry[]>("/v1/audit/control?limit=50", t),
  servers: (t: string) => apiFetch<McpServer[]>("/v1/mcp-servers", t),
  createServer: (t: string, body: { slug: string; name: string; url: string }) =>
    apiFetch<McpServer>("/v1/mcp-servers", t, { method: "POST", body }),
};

export interface TelegramLinkCode {
  code: string;
  expires_at: string;
  bot_username: string | null;
  deep_link: string | null;
}

export interface TelegramLink {
  id: string;
  user_id: string;
  created_at: string;
}

export type BlackBoxDecision = "ALLOW" | "BLOCK" | "ERROR";

export interface BlackBoxEvent {
  seq: number;
  agent_id: string;
  agent_name: string | null;
  occurred_at: string;
  server: string;
  method: string;
  tool_name: string;
  decision: BlackBoxDecision;
  reasons: string[];
  upstream_status: number | null;
  latency_ms: number | null;
  argument_keys: string[];
}

export interface BlackBoxTimeline {
  events: BlackBoxEvent[];
  next_before_seq: number | null;
}

export interface VerifyResult {
  ok: boolean;
  checked: number;
  broken_seq: number | null;
  reason: string | null;
}

export interface BlackBoxCapabilities {
  can_manage: boolean;
  can_turn_capture_off: boolean;
  can_view_payloads: boolean;
  can_export: boolean;
  can_export_payloads: boolean;
}

export interface BlackBoxSettings {
  retention_days: number;
  payload_retention_days: number;
  payload_capture_enabled: boolean;
  changed: boolean;
  capabilities: BlackBoxCapabilities | null;
}

export interface PayloadExcerpt {
  text: string;
  truncated: boolean;
  original_bytes: number;
}

export interface EventPayload {
  seq: number;
  arguments_redacted: PayloadExcerpt | null;
  result_excerpt: PayloadExcerpt | null;
}

export interface BlackBoxExportOptions {
  format: "jsonl" | "csv";
  includePayloads: boolean;
  decision?: BlackBoxDecision;
}

export const blackboxApi = {
  events: (
    t: string,
    params: { agent_id?: string; decision?: BlackBoxDecision; before_seq?: number; limit?: number } = {}
  ) => {
    const query = new URLSearchParams();
    if (params.agent_id) query.set("agent_id", params.agent_id);
    if (params.decision) query.set("decision", params.decision);
    if (params.before_seq) query.set("before_seq", String(params.before_seq));
    if (params.limit) query.set("limit", String(params.limit));
    const qs = query.toString();
    return apiFetch<BlackBoxTimeline>(`/v1/blackbox/events${qs ? `?${qs}` : ""}`, t);
  },
  verify: (t: string, fromSeq: number, toSeq: number) =>
    apiFetch<VerifyResult>(`/v1/blackbox/verify?from_seq=${fromSeq}&to_seq=${toSeq}`, t),
  settings: (t: string) => apiFetch<BlackBoxSettings>("/v1/blackbox/settings", t),
  setRetention: (t: string, retentionDays: number, payloadRetentionDays: number, reason: string, confirm: boolean) =>
    apiFetch<BlackBoxSettings>("/v1/blackbox/retention", t, {
      method: "PUT",
      body: {
        retention_days: retentionDays,
        payload_retention_days: payloadRetentionDays,
        reason: reason || null,
        confirm,
      },
    }),
  setCapture: (t: string, enabled: boolean, reason: string, confirm: boolean) =>
    apiFetch<BlackBoxSettings>("/v1/blackbox/payload-capture", t, {
      method: "PUT",
      body: { enabled, reason: reason || null, confirm },
    }),
  payload: (t: string, seq: number) => apiFetch<EventPayload>(`/v1/blackbox/events/${seq}/payload`, t),
  clearPayloads: (t: string, reason: string) =>
    apiFetch<{ cleared: number }>("/v1/blackbox/payloads/clear", t, {
      method: "POST",
      body: { reason: reason || null, confirm: true },
    }),
};

/**
 * Downloads the export through fetch so the access token travels in a header, never in a URL. The file is
 * saved from memory; the server caps an export at 50,000 rows.
 */
export async function downloadBlackBoxExport(token: string, options: BlackBoxExportOptions): Promise<void> {
  const query = new URLSearchParams({ format: options.format });
  if (options.includePayloads) query.set("include_payloads", "true");
  if (options.decision) query.set("decision", options.decision);
  const resp = await fetch(`${CORE_API_BASE}/v1/blackbox/export?${query.toString()}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) {
    let parsed: unknown = null;
    try {
      parsed = await resp.json();
    } catch {
      parsed = null;
    }
    throw new ApiError(resp.status, describeError(parsed, resp.status));
  }
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `redhand-blackbox.${options.format}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export const telegramApi = {
  createCode: (t: string) => apiFetch<TelegramLinkCode>("/v1/telegram/link-code", t, { method: "POST" }),
  links: (t: string) => apiFetch<TelegramLink[]>("/v1/telegram/links", t),
  unlink: (t: string, id: string) =>
    apiFetch<{ link_id: string; changed: boolean }>(`/v1/telegram/links/${id}/unlink`, t, { method: "POST" }),
};

export type HoneytokenKind = "api_key" | "aws_key" | "password" | "canary";
export type HoneyAction = "alert" | "freeze";

export interface Honeytoken {
  id: string;
  label: string;
  kind: HoneytokenKind;
  hint: string;
  action_on_use: HoneyAction;
  action_on_read: HoneyAction;
  status: "active" | "retired";
  created_at: string;
  last_tripped_at: string | null;
  trip_count: number;
}

export interface HoneytokenCreated extends Honeytoken {
  /** Shown once: RedHand keeps only a digest. */
  value: string;
}

export interface HoneyTool {
  id: string;
  agent_id: string;
  server: string;
  name: string;
  description: string;
  action: HoneyAction;
  status: "active" | "retired";
  created_at: string;
  last_tripped_at: string | null;
  trip_count: number;
}

export const honeyApi = {
  tokens: (t: string) => apiFetch<Honeytoken[]>("/v1/honeytokens", t),
  createToken: (
    t: string,
    body: { label: string; kind: HoneytokenKind; action_on_use: HoneyAction; action_on_read: HoneyAction }
  ) => apiFetch<HoneytokenCreated>("/v1/honeytokens", t, { method: "POST", body }),
  retireToken: (t: string, id: string) =>
    apiFetch<{ changed: boolean }>(`/v1/honeytokens/${id}/retire`, t, { method: "POST" }),
  tools: (t: string) => apiFetch<HoneyTool[]>("/v1/honey-tools", t),
  createTool: (
    t: string,
    body: { agent_id: string; server: string; name: string; description: string; action: HoneyAction }
  ) => apiFetch<HoneyTool>("/v1/honey-tools", t, { method: "POST", body }),
  retireTool: (t: string, id: string) =>
    apiFetch<{ changed: boolean }>(`/v1/honey-tools/${id}/retire`, t, { method: "POST" }),
};

export type ScanSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface ScanFinding {
  id: string;
  severity: ScanSeverity;
  category: string;
  tool_name: string | null;
  title: string;
  description: string;
  remediation: string;
}

/** One result shape for both ways of scanning (a pasted manifest, or a live scan of a registered server). */
export interface ScanResult {
  verdict: "PASS" | "WARN" | "FAIL";
  risk_score: number;
  tool_count: number;
  truncated: boolean;
  findings: ScanFinding[];
  findings_omitted: number;
  source: string;
  limits: string;
}

interface LiveScanResponse {
  server_slug: string;
  verdict: "PASS" | "WARN" | "FAIL";
  risk_score: number;
  tool_count: number;
  truncated: boolean;
  findings: ScanFinding[];
  findings_omitted: number;
  limits: string;
}

export const scannerApi = {
  /** Live scan of a REGISTERED server, run by the gateway on core's behalf (admin only; the server decides). */
  scanServer: async (t: string, serverId: string): Promise<ScanResult> => {
    const r = await apiFetch<LiveScanResponse>(`/v1/mcp-servers/${serverId}/scan`, t, { method: "POST" });
    return {
      verdict: r.verdict, risk_score: r.risk_score, tool_count: r.tool_count, truncated: r.truncated,
      findings: r.findings, findings_omitted: r.findings_omitted, source: `registered server "${r.server_slug}"`, limits: r.limits,
    };
  },
  /** Static check of a pasted manifest, through the gateway's public, rate-limited vetting endpoint. Fetches nothing. */
  vetManifest: async (manifest: unknown): Promise<ScanResult> => {
    const resp = await fetch(`${GATEWAY_BASE}/v1/mcp/vet`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(manifest),
    });
    if (!resp.ok) {
      throw new ApiError(resp.status, resp.status === 429 ? "Too many checks; wait a minute." : `The check failed (HTTP ${resp.status}).`);
    }
    const r = (await resp.json()) as {
      verdict: "PASS" | "WARN" | "FAIL"; risk_score: number; total_tools_scanned: number; findings: ScanFinding[];
    };
    return {
      verdict: r.verdict, risk_score: r.risk_score, tool_count: r.total_tools_scanned, truncated: false,
      findings: r.findings, findings_omitted: 0, source: "pasted manifest",
      limits: "Static check of what you pasted: it cannot see what a tool does when called.",
    };
  },
};

export type PinMode = "off" | "alert" | "enforce";
export type PinStatus = "pending" | "approved" | "rejected" | "superseded";

export interface ToolPin {
  id: string;
  tool_name: string;
  status: PinStatus;
  change_kind: "new" | "changed";
  description: string;
  schema_text: string;
  rules: string[];
  first_seen_at: string;
  last_seen_at: string;
  approved_description: string | null;
  approved_schema_text: string | null;
}

export interface ToolPins {
  server_id: string;
  server_slug: string;
  pin_mode: PinMode;
  pending_count: number;
  pins: ToolPin[];
}

export const pinsApi = {
  list: (t: string, serverId: string) => apiFetch<ToolPins>(`/v1/mcp-servers/${serverId}/tool-pins`, t),
  decide: (t: string, pinId: string, decision: "approve" | "reject", reason: string) =>
    apiFetch<{ status: PinStatus }>(`/v1/tool-pins/${pinId}/decision`, t, { method: "POST", body: { decision, reason: reason || null } }),
  approveAll: (t: string, serverId: string, reason: string) =>
    apiFetch<{ approved: number }>(`/v1/mcp-servers/${serverId}/tool-pins/approve-all`, t, {
      method: "POST",
      body: { reason: reason || null, confirm: true },
    }),
  setMode: (t: string, serverId: string, mode: PinMode, reason: string) =>
    apiFetch<{ pin_mode: PinMode; changed: boolean }>(`/v1/mcp-servers/${serverId}/pin-mode`, t, {
      method: "PUT",
      body: { mode, reason: reason || null, confirm: true },
    }),
};

// --- Prompt Injection Radar and output checks (Phase 4 M4.2 API, M4.4 page) ------------------------------------------------

export type RadarLevel = "low" | "medium" | "high";
export type RadarMode = "off" | "observe" | "block";
export type FindingReviewStatus = "open" | "confirmed" | "false_alarm";

export interface RadarSummary {
  findings?: number;
  occurrences?: number;
  would_block?: number;
  open?: number;
  confirmed?: number;
  false_alarm?: number;
  would_block_open?: number;
}

export interface RadarSettings {
  radar_mode: RadarMode;
  output_check_mode: RadarMode;
  radar_mode_changed_at: string | null;
  output_check_mode_changed_at: string | null;
  block_available: boolean;
  last_7_days: RadarSummary;
  capabilities: { can_change_modes: boolean; can_review: boolean; can_suppress: boolean };
}

/** A finding never carries the scanned text: only a rule id, tags, counts and where it was seen. */
export interface RadarFinding {
  id: string;
  agent_id: string;
  agent_name: string | null;
  rule_id: string;
  family: string;
  kind: "injection" | "output" | "loop" | "destination" | "model";
  severity: RadarLevel;
  confidence: RadarLevel;
  place: "text" | "hidden" | "decoded" | "call";
  evasion: string[];
  tool_name: string;
  server_slug: string;
  would_block: boolean;
  occurrences: number;
  /** Destination findings only: the last two parts of the address (never a subdomain). */
  detail?: string | null;
  first_seen_at: string;
  last_seen_at: string;
  review_status: FindingReviewStatus;
  reviewed_at: string | null;
  review_note: string | null;
}

export interface RadarSuppression {
  id: string;
  agent_id: string;
  agent_name: string | null;
  rule_id: string;
  reason: string;
  created_at: string;
  expires_at: string;
}

export interface ReadinessCondition {
  id: string;
  name: string;
  passed: boolean;
  detail: string;
}

export interface ReadinessCheck {
  kind: "injection" | "output";
  label: string;
  ready: boolean;
  scanned: number;
  strong: number;
  strong_rate: number | null;
  false_alarms_worst_case: number;
  false_alarm_upper: number | null;
  conditions: ReadinessCondition[];
}

/** Whether this organization's own traffic is clean evidence for even CONSIDERING block mode. It grants nothing: block_available is always false. */
export interface ReadinessResult {
  block_available: false;
  window_start: string;
  window_days: number;
  checks: ReadinessCheck[];
  note: string;
}

export const radarApi = {
  settings: (t: string) => apiFetch<RadarSettings>("/v1/radar/settings", t),
  readiness: (t: string) => apiFetch<ReadinessResult>("/v1/radar/readiness", t),
  saveSettings: (
    t: string,
    body: { radar_mode: "off" | "observe"; output_check_mode: "off" | "observe"; confirm: boolean }
  ) => apiFetch<RadarSettings>("/v1/radar/settings", t, { method: "PUT", body }),
  findings: (t: string, params: { agent_id?: string; review_status?: string; kind?: string; before?: string; limit?: number }) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== "") query.set(key, String(value));
    const suffix = query.toString();
    return apiFetch<{ findings: RadarFinding[]; next_before: string | null }>(`/v1/findings${suffix ? `?${suffix}` : ""}`, t);
  },
  review: (t: string, id: string, body: { status: "confirmed" | "false_alarm"; note?: string }) =>
    apiFetch<{ review_status: FindingReviewStatus; changed: boolean }>(`/v1/findings/${id}/review`, t, { method: "POST", body }),
  suppressions: (t: string) => apiFetch<{ suppressions: RadarSuppression[] }>("/v1/radar/suppressions", t),
  suppress: (t: string, body: { agent_id: string; rule_id: string; days: number; reason: string; confirm: boolean }) =>
    apiFetch<{ id: string; created: boolean; expires_at: string }>("/v1/radar/suppressions", t, { method: "POST", body }),
  removeSuppression: (t: string, id: string) =>
    apiFetch<{ revoked: boolean }>(`/v1/radar/suppressions/${id}`, t, { method: "DELETE" }),
};

// --- Loop detection (Phase 4 M6) ---------------------------------------------------------------------------------------------

export type LoopMode = "off" | "observe" | "throttle";

export interface LoopSettings {
  loop_mode: LoopMode;
  loop_limit: number;
  loop_window_seconds: number;
  loop_mode_changed_at: string | null;
  last_7_days: { findings?: number; occurrences?: number; open?: number };
  capabilities: { can_change_modes: boolean; can_review: boolean; can_suppress: boolean };
}

export const loopApi = {
  settings: (t: string) => apiFetch<LoopSettings>("/v1/radar/loop-settings", t),
  save: (
    t: string,
    body: { loop_mode: LoopMode; loop_limit: number; loop_window_seconds: number; expected_mode: LoopMode; confirm: boolean }
  ) => apiFetch<LoopSettings>("/v1/radar/loop-settings", t, { method: "PUT", body }),
};

// --- Destination allowlist (Phase 4 M7) --------------------------------------------------------------------------------------

export type DestinationMode = "off" | "observe" | "enforce";

export interface DestinationEntry {
  id: string;
  host: string;
  created_at: string;
}

export interface DestinationSettings {
  destination_mode: DestinationMode;
  destination_mode_changed_at: string | null;
  entries: DestinationEntry[];
  max_entries: number;
  last_7_days: { findings?: number; occurrences?: number; open?: number };
  capabilities: { can_change: boolean };
}

export const destinationsApi = {
  settings: (t: string, agentId: string) => apiFetch<DestinationSettings>(`/v1/passports/${agentId}/destinations`, t),
  add: (t: string, agentId: string, body: { host: string; confirm: boolean }) =>
    apiFetch<{ id: string; host: string; added: boolean }>(`/v1/passports/${agentId}/destinations`, t, { method: "POST", body }),
  remove: (t: string, agentId: string, entryId: string) =>
    apiFetch<{ removed: boolean }>(`/v1/passports/${agentId}/destinations/${entryId}`, t, { method: "DELETE" }),
  setMode: (t: string, agentId: string, body: { destination_mode: DestinationMode; expected_mode: DestinationMode; confirm: boolean }) =>
    apiFetch<DestinationSettings>(`/v1/passports/${agentId}/destination-mode`, t, { method: "PUT", body }),
};

export interface SelfTestCategory {
  category: string;
  malicious: number;
  benign: number;
  detected: number;
  false_alarms: number;
  detection_low: number;
  detection_high: number;
  false_alarm_low: number;
  false_alarm_high: number;
  hard_benign: number;
  hard_false_alarms: number;
}

/** Counts only: no sample text and no sample ids come back. */
export interface SelfTestResult {
  corpus: string;
  model_enabled: boolean;
  samples: number;
  duration_ms: number;
  categories: SelfTestCategory[];
  limits: string;
  radar_mode: RadarMode;
  output_check_mode: RadarMode;
  ran_at: string;
}

export const selfTestApi = {
  run: (t: string) => apiFetch<SelfTestResult>("/v1/radar/self-test", t, { method: "POST" }),
};

// --- Risk Engine (Phase 4.5 B1) -------------------------------------------------------------------------------------------------

export type RiskLevel = "low" | "elevated" | "high" | "critical";

export interface RiskSignal {
  signal: string;
  label: string;
  recent: number;
  older: number;
  points: number;
  capped: boolean;
}

export interface AgentRiskSummary {
  agent_id: string;
  name: string;
  status: string;
  safe_mode: boolean;
  score: number;
  level: RiskLevel;
  /** Signals after the last human release only: what the ladder acts on. */
  action_score: number;
  reason: string;
  released_at: string | null;
}

export interface RiskLadder {
  alert_at: number | null;
  safe_mode_at: number | null;
  freeze_at: number | null;
  reaching: { alert: number; safe_mode: number; freeze: number };
  reaching_agents: { alert: string[]; safe_mode: string[]; freeze: string[] };
  capabilities: { can_change: boolean };
}

export interface RiskList {
  model: string;
  agents: AgentRiskSummary[];
  ladder: RiskLadder;
}

export interface BehaviourBacktest {
  hours: number;
  flagged_hours: number;
  spike_hours: number;
  new_tool_starts: number;
}

/** Phase 4.5 B2, watch only: shown next to the score, never part of it. */
export interface AgentBehaviour {
  status: "ok" | "unavailable";
  model: string;
  warm: boolean;
  history_days: number;
  warmup_days: number;
  hour_calls: number;
  usual_hourly: number;
  spike_threshold: number;
  spike: boolean;
  new_tools: string[];
  warning: boolean;
  backtest: BehaviourBacktest | null;
}

export interface RiskDetail {
  model: string;
  agent: AgentRiskSummary & { signals: RiskSignal[]; action_signals: RiskSignal[] };
  weights: { signal: string; label: string; points: number; cap: number }[];
  window_days: number;
  /** Absent on a core without the behaviour baseline. */
  behaviour?: AgentBehaviour | null;
}

export const insightsApi = {
  summary: (t: string, window: import("@/lib/insights").InsightsWindow) =>
    apiFetch<import("@/lib/insights").InsightsSummary>(`/v1/insights/summary?window=${window}`, t),
};

export const riskApi = {
  list: (t: string) => apiFetch<RiskList>("/v1/risk/agents", t),
  detail: (t: string, agentId: string) => apiFetch<RiskDetail>(`/v1/risk/agents/${agentId}`, t),
  ladder: (t: string) => apiFetch<RiskLadder>("/v1/risk/ladder", t),
  setLadder: (
    t: string,
    body: { alert_at: number | null; safe_mode_at: number | null; freeze_at: number | null; confirm: boolean; reason?: string }
  ) => apiFetch<RiskLadder>("/v1/risk/ladder", t, { method: "PUT", body }),
};

// Model spend (Phase 4.5 B4a): numbers are estimates from what each agent's SDK reported. See src/lib/spend.ts.
export const spendApi = {
  list: (t: string) => apiFetch<SpendToday>("/v1/spend/agents", t),
  detail: (t: string, agentId: string) => apiFetch<AgentSpendDetail>(`/v1/spend/agents/${agentId}`, t),
  setLimit: (t: string, agentId: string, body: { spend_limit_micro_usd: number | null; confirm: boolean; reason?: string }) =>
    apiFetch<SpendLimitResult>(`/v1/passports/${agentId}/spend-limit`, t, { method: "PUT", body }),
};
// ---------------------------------------------------------------------------
// Incident view (Phase 4.5 B3): one timeline per agent. Security operator and above.
// ---------------------------------------------------------------------------

export const timelineApi = {
  get: (t: string, agentId: string, before: string | null = null, limit = 50) => {
    const query = new URLSearchParams({ limit: String(limit) });
    if (before) query.set("before", before);
    return apiFetch<TimelineResponse>(`/v1/agents/${agentId}/timeline?${query.toString()}`, t);
  },
};

/** The incident summary download (JSON or CSV), through fetch so the token stays in a header. Audited and rate-limited by core. */
export async function downloadTimelineExport(token: string, agentId: string, format: "json" | "csv"): Promise<void> {
  const resp = await fetch(`${CORE_API_BASE}/v1/agents/${agentId}/timeline/export?format=${format}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) {
    let parsed: unknown = null;
    try {
      parsed = await resp.json();
    } catch {
      parsed = null;
    }
    throw new ApiError(resp.status, describeError(parsed, resp.status));
  }
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `redhand-timeline-${agentId.slice(0, 8)}.${format}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

// Approved models (Phase 4.5 B4b): detective only. See src/lib/approvedModels.ts.
export const approvedModelsApi = {
  get: (t: string) => apiFetch<ApprovedModelsList>("/v1/organization/approved-models", t),
  set: (t: string, body: { items: ApprovedModel[]; version: number; confirm: boolean; reason?: string }) =>
    apiFetch<ApprovedModelsList>("/v1/organization/approved-models", t, { method: "PUT", body }),
};

// Organization SDK keys (Phase 4.5 C1a). The plaintext key is only in the create response: never store it. See src/lib/sdkKeys.ts.
export const sdkKeysApi = {
  list: (t: string) => apiFetch<SdkKeyList>("/v1/organization/sdk-keys", t),
  create: (t: string, body: { name: string; expires_in_days: number }) => apiFetch<SdkKeyCreated>("/v1/organization/sdk-keys", t, { method: "POST", body }),
  revoke: (t: string, keyId: string) => apiFetch<{ id: string; changed: boolean }>(`/v1/organization/sdk-keys/${keyId}`, t, { method: "DELETE", body: {} }),
};


// Onboarding (Phase 4.5 D1). Codes and invite tokens are shown once by the server and never stored here. See src/lib/onboarding.ts.
export interface Me {
  user_id: string;
  email: string | null;
  organization_id: string;
  organization_name: string;
  role: "owner" | "admin" | "security_operator" | "viewer";
  organization_slug?: string;
  deletion_purge_after?: string | null;
}
export interface DeletionStatus { requested: boolean; requested_at: string | null; purge_after: string | null; already?: boolean }
export const lifecycleApi = {
  status: (t: string) => apiFetch<DeletionStatus>("/v1/organization/deletion", t),
  exportData: (t: string) => apiFetch<unknown>("/v1/organization/export", t),
  requestDeletion: (t: string, confirmSlug: string) =>
    apiFetch<DeletionStatus>("/v1/organization/delete-request", t, { method: "POST", body: { confirm_slug: confirmSlug } }),
  cancelDeletion: (t: string) => apiFetch<DeletionStatus>("/v1/organization/delete-request/cancel", t, { method: "POST" }),
};
export interface TeamMember { user_id: string; email: string | null; role: "owner" | "admin" | "security_operator" | "viewer"; joined_at: string | null }
export interface TeamInvite { id: string; role: "admin" | "security_operator" | "viewer"; state: "pending" | "used" | "revoked" | "expired"; created_at: string | null; expires_at: string | null }
export interface InviteCreated { token: string; join_path: string; invite: TeamInvite }

export const meApi = { get: (t: string) => apiFetch<Me>("/v1/me", t) };
export const onboardingApi = {
  createOrganization: (t: string, body: { name: string; code: string }) =>
    apiFetch<{ organization_id: string; slug: string; role: "owner" }>("/v1/organizations", t, { method: "POST", body }),
  acceptInvite: (t: string, token: string) =>
    apiFetch<{ organization_id: string; role: string }>("/v1/invites/accept", t, { method: "POST", body: { token } }),
  members: (t: string) => apiFetch<{ members: TeamMember[] }>("/v1/organization/members", t),
  setRole: (t: string, userId: string, role: string, confirm: boolean) =>
    apiFetch<{ user_id: string; changed: boolean; role: string }>(`/v1/organization/members/${userId}`, t, { method: "PUT", body: { role, confirm } }),
  removeMember: (t: string, userId: string) =>
    apiFetch<{ user_id: string; removed: boolean }>(`/v1/organization/members/${userId}`, t, { method: "DELETE", body: {} }),
  invites: (t: string) => apiFetch<{ invites: TeamInvite[]; max_pending: number }>("/v1/organization/invites", t),
  createInvite: (t: string, body: { role: string; expires_in_days: number }) =>
    apiFetch<InviteCreated>("/v1/organization/invites", t, { method: "POST", body }),
  revokeInvite: (t: string, id: string) =>
    apiFetch<{ id: string; changed: boolean }>(`/v1/organization/invites/${id}`, t, { method: "DELETE", body: {} }),
};
