/**
 * Typed client for redhand-core. Every call carries the operator's access token; the
 * UI is never a security boundary (all authorization happens in redhand-core).
 */

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
  revoke: (t: string, id: string, reason?: string) =>
    apiFetch<ControlActionResponse>(`/v1/passports/${id}/revoke`, t, {
      method: "POST",
      body: { reason: reason || null, confirm: true },
    }),
  usage: (t: string) => apiFetch<UsageSummary>("/v1/usage", t),
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

export const telegramApi = {
  createCode: (t: string) => apiFetch<TelegramLinkCode>("/v1/telegram/link-code", t, { method: "POST" }),
  links: (t: string) => apiFetch<TelegramLink[]>("/v1/telegram/links", t),
  unlink: (t: string, id: string) =>
    apiFetch<{ link_id: string; changed: boolean }>(`/v1/telegram/links/${id}/unlink`, t, { method: "POST" }),
};
