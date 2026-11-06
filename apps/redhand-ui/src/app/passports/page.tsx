"use client";

/**
 * Agent Passports: the Phase 1 control surface.
 * Register agents, see owner / scopes / expiry / status, and freeze, unfreeze, revoke or
 * freeze everything. Every action is authorized and audited by redhand-core.
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Hand, LogOut, OctagonX, Plus, RefreshCw, Trash2 } from "lucide-react";

import {
  ApiError,
  type ControlAuditEntry,
  type AgentUsage,
  type McpServer,
  type Passport,
  type PassportStatus,
  type Scope,
  passportsApi,
  type TelegramLink,
  type TelegramLinkCode,
  type UsageSummary,
  telegramApi,
} from "@/lib/api";
import { useAuth, useRequiredSession } from "@/lib/auth";

// Budget Guard's automatic freezes are recorded under this fixed actor (not a person).
const SYSTEM_ACTOR_ID = "00000000-0000-0000-0000-000000000000";

const FRAMEWORKS = ["n8n", "Claude", "LangGraph", "CrewAI", "custom"];

const STATUS_STYLE: Record<PassportStatus, string> = {
  active: "bg-[#E6F4EA] text-[#1E7B34]",
  frozen: "bg-[#E8F0FE] text-[#1A56DB]",
  revoked: "bg-[#FDECEC] text-[#B42318]",
  expired: "bg-[#F2F2F2] text-[#606060]",
};

function daysUntil(iso: string): number {
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86_400_000);
}

function shortId(id: string | null): string {
  return id ? `…${id.slice(-6)}` : "—";
}

function formatTime(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : "never";
}

export default function PassportsPage() {
  const session = useRequiredSession();
  const { signOut } = useAuth();
  const token = session?.token ?? null;

  const [passports, setPassports] = useState<Passport[]>([]);
  const [servers, setServers] = useState<McpServer[]>([]);
  const [audit, setAudit] = useState<ControlAuditEntry[]>([]);
  const [orgSafeMode, setOrgSafeMode] = useState(false);
  const [usage, setUsage] = useState<UsageSummary | null>(null);
  const [budgetDefault, setBudgetDefault] = useState<number | null>(null);
  const [budgetEditing, setBudgetEditing] = useState<Passport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [revealedKey, setRevealedKey] = useState<{ name: string; key: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<Passport | null>(null);

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        signOut();
        window.location.href = "/login";
        return;
      }
      setError(err instanceof Error ? err.message : "Something went wrong.");
    },
    [signOut]
  );

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      const [p, s, a, o, u, d] = await Promise.all([
        passportsApi.list(token),
        passportsApi.servers(token),
        passportsApi.audit(token),
        // An older core does not have this endpoint yet (404): show Safe Mode as off rather than failing.
        passportsApi.orgSafeMode(token).catch((err: unknown) => {
          if (err instanceof ApiError && err.status === 404) return { enabled: false, changed: false };
          throw err;
        }),
        // Same for the usage view on a core that predates Budget Guard.
        passportsApi.usage(token).catch((err: unknown) => {
          if (err instanceof ApiError && err.status === 404) return null;
          throw err;
        }),
        passportsApi.budgetDefault(token).catch((err: unknown) => {
          if (err instanceof ApiError && err.status === 404) return { default_daily_call_limit: null, changed: false };
          throw err;
        }),
      ]);
      setPassports(p);
      setServers(s);
      setAudit(a);
      setOrgSafeMode(o.enabled);
      setUsage(u);
      setBudgetDefault(d.default_daily_call_limit);
    } catch (err) {
      handleError(err);
    }
  }, [token, handleError]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const act = useCallback(
    async (label: string, action: () => Promise<unknown>) => {
      setBusy(true);
      setError(null);
      setNotice(null);
      try {
        await action();
        await refresh();
        setNotice(label);
      } catch (err) {
        handleError(err);
      } finally {
        setBusy(false);
      }
    },
    [refresh, handleError]
  );

  const counts = useMemo(() => {
    const c: Record<PassportStatus, number> = { active: 0, frozen: 0, revoked: 0, expired: 0 };
    for (const p of passports) c[p.status] += 1;
    return c;
  }, [passports]);

  if (!session || !token) return null;

  const onOrgSafeMode = () => {
    if (!orgSafeMode) {
      const reason = window.prompt("Turn Safe Mode on for ALL agents. Reason (recorded in the audit log):") ?? "";
      act("Safe Mode is on for all agents.", () => passportsApi.setOrgSafeMode(token, true, reason));
      return;
    }
    if (!window.confirm("Turn Safe Mode off for all agents? Write tools will work again (agents with their own Safe Mode stay restricted).")) return;
    const reason = window.prompt("Reason (recorded in the audit log):") ?? "";
    act("Safe Mode is off for all agents.", () => passportsApi.setOrgSafeMode(token, false, reason));
  };

  const onFreezeAll = () => {
    const typed = window.prompt(
      `This freezes all ${counts.active} active agents immediately. Type FREEZE to confirm.`
    );
    if (typed !== "FREEZE") return;
    const reason = window.prompt("Reason (recorded in the audit log):") ?? "";
    act("All active agents frozen.", () => passportsApi.freezeAll(token, reason));
  };

  return (
    <div className="min-h-screen bg-[#F8F8F8] text-[#0F0F0F]">
      <header className="flex h-[56px] items-center justify-between border-b border-[#E5E5E5] bg-[#FFFFFF] px-4">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-9 items-center justify-center rounded-[8px] bg-[#FF0000]">
              <Hand className="h-4 w-4 text-[#FFFFFF]" />
            </div>
            <span className="text-[20px] font-bold tracking-tight">RedHand</span>
          </div>
          <nav className="flex gap-1 text-[13px]">
            <Link href="/passports" className="rounded-full bg-[#0F0F0F] px-3 py-1.5 font-semibold text-[#FFFFFF]">
              Passports
            </Link>
            <Link href="/blackbox" className="rounded-full px-3 py-1.5 font-medium text-[#606060] hover:bg-[#F2F2F2]">
              Black Box
            </Link>
            <Link href="/honeytokens" className="rounded-full px-3 py-1.5 font-medium text-[#606060] hover:bg-[#F2F2F2]">
              Honeytokens
            </Link>
            <Link href="/" className="rounded-full px-3 py-1.5 font-medium text-[#606060] hover:bg-[#F2F2F2]">
              Command center (demo)
            </Link>
          </nav>
        </div>
        <div className="flex items-center gap-3 text-[12px]">
          <span className="text-[#606060]">
            {session.email}
            {session.role ? ` · ${session.role.replace("_", " ")}` : ""}
            {session.mode === "development" ? " · dev login" : ""}
          </span>
          <button
            onClick={() => {
              signOut();
              window.location.href = "/login";
            }}
            className="flex items-center gap-1 rounded-full px-3 py-1.5 hover:bg-[#F2F2F2]"
          >
            <LogOut className="h-3.5 w-3.5" /> Sign out
          </button>
        </div>
      </header>

      <main className="mx-auto flex max-w-[1200px] flex-col gap-6 px-4 py-6">
        <section className="flex flex-wrap items-center justify-between gap-4 rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-4">
          <div className="flex flex-wrap gap-4 text-[13px]">
            {(Object.keys(counts) as PassportStatus[]).map((s) => (
              <span key={s} className="flex items-center gap-1.5">
                <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${STATUS_STYLE[s]}`}>{s}</span>
                <span className="font-semibold">{counts[s]}</span>
              </span>
            ))}
          </div>
          <div className="flex items-center gap-2 text-[13px]">
            <span
              className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${
                orgSafeMode ? "bg-[#FFF4E5] text-[#8A4B00]" : "bg-[#F2F2F2] text-[#606060]"
              }`}
              title="While on, agents can use only tools their scopes declare as read. You declare read or write; RedHand cannot verify it."
            >
              Safe Mode (all agents): {orgSafeMode ? "on" : "off"}
            </span>
            <button
              onClick={onOrgSafeMode}
              disabled={busy}
              className="rounded-full border border-[#E5E5E5] px-3 py-1.5 text-[12px] font-medium hover:bg-[#F2F2F2] disabled:opacity-40"
            >
              {orgSafeMode ? "Turn off" : "Turn on"}
            </button>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={refresh}
              className="flex items-center gap-1 rounded-full border border-[#E5E5E5] px-3 py-2 text-[13px] hover:bg-[#F2F2F2]"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Refresh
            </button>
            <button
              onClick={onFreezeAll}
              disabled={busy || counts.active === 0}
              className="flex items-center gap-1.5 rounded-full bg-[#FF0000] px-4 py-2 text-[13px] font-bold text-[#FFFFFF] hover:bg-[#CC0000] disabled:opacity-40"
            >
              <OctagonX className="h-4 w-4" /> Freeze all agents
            </button>
          </div>
        </section>

        <p className="text-[12px] text-[#606060]">
          RedHand controls agents that connect through the RedHand gateway. Agents holding raw API keys
          or direct access outside the gateway are not covered.
        </p>

        {error && (
          <div role="alert" className="rounded-[8px] bg-[#FDECEC] p-3 text-[13px] text-[#B42318]">
            {error}
          </div>
        )}
        {notice && <div className="rounded-[8px] bg-[#E6F4EA] p-3 text-[13px] text-[#1E7B34]">{notice}</div>}

        {revealedKey && (
          <div className="rounded-[12px] border-2 border-[#0F0F0F] bg-[#FFFFFF] p-4">
            <p className="text-[13px] font-semibold">Agent key for {revealedKey.name}</p>
            <p className="mt-1 text-[12px] text-[#606060]">
              Shown once. Store it in the agent&apos;s secret store; RedHand keeps only a hash. The agent
              exchanges it at <code>/v1/agent-auth/token</code> for a 10-minute access token.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <code className="flex-1 break-all rounded-[8px] bg-[#F2F2F2] p-2 text-[12px]">{revealedKey.key}</code>
              <button
                onClick={() => navigator.clipboard.writeText(revealedKey.key)}
                className="rounded-full border border-[#E5E5E5] px-3 py-1.5 text-[12px] hover:bg-[#F2F2F2]"
              >
                Copy
              </button>
              <button
                onClick={() => setRevealedKey(null)}
                className="rounded-full bg-[#0F0F0F] px-3 py-1.5 text-[12px] font-semibold text-[#FFFFFF]"
              >
                I&apos;ve stored it
              </button>
            </div>
          </div>
        )}

        <PassportTable
          passports={passports}
          busy={busy}
          onFreeze={(p) => act(`${p.name} frozen.`, () => passportsApi.freeze(token, p.id))}
          onUnfreeze={(p) => {
            if (!window.confirm(`Unfreeze ${p.name}? It will be able to call its tools again.`)) return;
            act(`${p.name} unfrozen.`, () => passportsApi.unfreeze(token, p.id));
          }}
          onRevoke={(p) => {
            if (!window.confirm(`Permanently revoke ${p.name}? This cannot be undone.`)) return;
            const reason = window.prompt("Reason (recorded in the audit log):") ?? "";
            act(`${p.name} revoked.`, () => passportsApi.revoke(token, p.id, reason));
          }}
          onRotate={(p) => {
            if (!window.confirm(`Issue a new key for ${p.name}? The current key stops working now.`)) return;
            act(`New key issued for ${p.name}.`, async () => {
              const res = await passportsApi.rotateKey(token, p.id);
              setRevealedKey({ name: p.name, key: res.agent_key });
            });
          }}
          onRenew={(p) => {
            const days = Number(window.prompt("Renew for how many days? (1-365)", "90"));
            if (!Number.isInteger(days) || days < 1 || days > 365) return;
            act(`${p.name} renewed for ${days} days.`, () => passportsApi.renew(token, p.id, days));
          }}
          onEditScopes={(p) => setEditing(p)}
          usage={usage}
          onEditBudget={(p) => setBudgetEditing(p)}
          orgSafeMode={orgSafeMode}
          onSafeMode={(p) => {
            if (!p.safe_mode) {
              act(`Safe Mode is on for ${p.name}.`, () => passportsApi.setSafeMode(token, p.id, true));
              return;
            }
            if (!window.confirm(`Turn Safe Mode off for ${p.name}? Its write tools will work again.`)) return;
            const reason = window.prompt("Reason (recorded in the audit log):") ?? "";
            act(`Safe Mode is off for ${p.name}.`, () => passportsApi.setSafeMode(token, p.id, false, reason));
          }}
        />

        {budgetEditing && (
          <BudgetEditor
            key={budgetEditing.id}
            passport={budgetEditing}
            busy={busy}
            onCancel={() => setBudgetEditing(null)}
            onSave={(limit, action, reason, confirm) => {
              const target = budgetEditing;
              setBudgetEditing(null);
              act(`Daily limit updated for ${target.name}.`, () =>
                passportsApi.setBudget(token, target.id, limit, action, reason, confirm)
              );
            }}
          />
        )}

        {editing && (
          <ScopeEditor
            key={editing.id}
            passport={editing}
            servers={servers}
            busy={busy}
            onCancel={() => setEditing(null)}
            onSave={(scopes, reason) => {
              const target = editing;
              setEditing(null);
              act(`Scopes updated for ${target.name}.`, () =>
                passportsApi.updateScopes(token, target.id, scopes, reason)
              );
            }}
          />
        )}

        <div className="grid gap-6 lg:grid-cols-2">
          <RegisterAgentForm
            servers={servers}
            busy={busy}
            onSubmit={(body) =>
              act(`${body.name} registered.`, async () => {
                const res = await passportsApi.create(token, body);
                setRevealedKey({ name: res.passport.name, key: res.agent_key });
              })
            }
          />
          <McpServersPanel
            servers={servers}
            busy={busy}
            onCreate={(body) => act(`MCP server ${body.slug} registered.`, () => passportsApi.createServer(token, body))}
          />
        </div>

        <BudgetDefaultPanel
          current={budgetDefault}
          busy={busy}
          onChange={(limit, reason, confirm) =>
            act(
              limit === null ? "New agents will start with no limit." : `New agents will start with ${limit} calls per day.`,
              () => passportsApi.setBudgetDefault(token, limit, reason, confirm)
            )
          }
        />

        <TelegramPanel token={token} onChanged={refresh} onError={handleError} />

        <AuditPanel entries={audit} passports={passports} servers={servers} />
      </main>
    </div>
  );
}

function PassportTable(props: {
  passports: Passport[];
  busy: boolean;
  onFreeze: (p: Passport) => void;
  onUnfreeze: (p: Passport) => void;
  onRevoke: (p: Passport) => void;
  onRotate: (p: Passport) => void;
  onRenew: (p: Passport) => void;
  onEditScopes: (p: Passport) => void;
  orgSafeMode: boolean;
  onSafeMode: (p: Passport) => void;
  usage: UsageSummary | null;
  onEditBudget: (p: Passport) => void;
}) {
  const { passports, busy } = props;
  const usageByAgent = new Map<string, AgentUsage>((props.usage?.agents ?? []).map((u) => [u.agent_id, u]));
  return (
    <section className="overflow-x-auto rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF]">
      <table className="w-full min-w-[900px] text-left text-[13px]">
        <thead className="border-b border-[#E5E5E5] text-[11px] uppercase tracking-wider text-[#606060]">
          <tr>
            <th className="p-3">Agent</th>
            <th className="p-3">Status</th>
            <th className="p-3">Owner</th>
            <th className="p-3">Scopes</th>
            <th className="p-3">Calls today</th>
            <th className="p-3">Expires</th>
            <th className="p-3">Last seen</th>
            <th className="p-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {passports.length === 0 && (
            <tr>
              <td colSpan={8} className="p-6 text-center text-[#606060]">
                No agents yet. Register one below.
              </td>
            </tr>
          )}
          {passports.map((p) => {
            const days = daysUntil(p.expires_at);
            return (
              <tr key={p.id} className="border-b border-[#F2F2F2] align-top">
                <td className="p-3">
                  <div className="font-semibold">{p.name}</div>
                  <div className="text-[11px] text-[#606060]">
                    {p.external_agent_id} · {p.framework} · v{p.version}
                  </div>
                </td>
                <td className="p-3">
                  <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${STATUS_STYLE[p.status]}`}>
                    {p.status}
                  </span>
                  {p.status_reason && <div className="mt-1 text-[11px] text-[#606060]">{p.status_reason}</div>}
                  {p.status !== "revoked" && (p.safe_mode || props.orgSafeMode) && (
                    <div className="mt-1">
                      <span className="rounded-full bg-[#FFF4E5] px-2 py-0.5 text-[11px] font-semibold text-[#8A4B00]">
                        safe mode{props.orgSafeMode && !p.safe_mode ? " (all)" : ""}
                      </span>
                    </div>
                  )}
                </td>
                <td className="p-3 text-[12px]">
                  <div title={p.owner_id ?? ""}>{shortId(p.owner_id)}</div>
                  <div className="text-[11px] text-[#606060]" title={p.backup_owner_id ?? ""}>
                    backup {shortId(p.backup_owner_id)}
                  </div>
                </td>
                <td className="p-3">
                  <div className="flex max-w-[260px] flex-wrap gap-1">
                    {p.scopes.length === 0 && <span className="text-[12px] text-[#606060]">none</span>}
                    {p.scopes.map((s) => (
                      <span
                        key={`${s.server}/${s.tool}/${s.access}`}
                        className={`rounded-[6px] bg-[#F2F2F2] px-1.5 py-0.5 font-mono text-[11px] ${
                          p.status !== "revoked" && (p.safe_mode || props.orgSafeMode) && s.access === "write" ? "line-through opacity-60" : ""
                        }`}
                        title={
                          p.status !== "revoked" && (p.safe_mode || props.orgSafeMode) && s.access === "write"
                            ? "Suspended: Safe Mode is on and this scope is declared write"
                            : undefined
                        }
                      >
                        {s.server}/{s.tool} <span className="text-[#606060]">{s.access}</span>
                      </span>
                    ))}
                  </div>
                </td>
                <td className="p-3 text-[12px]">
                  <CallsCell passport={p} usage={usageByAgent.get(p.id)} />
                </td>
                <td className="p-3 text-[12px]">
                  <div>{new Date(p.expires_at).toLocaleDateString()}</div>
                  <div className={`text-[11px] ${days <= 7 ? "text-[#B42318]" : "text-[#606060]"}`}>
                    {days > 0 ? `${days} days left` : "expired"}
                  </div>
                </td>
                <td className="p-3 text-[12px] text-[#606060]">{formatTime(p.last_seen_at)}</td>
                <td className="p-3">
                  <div className="flex flex-wrap justify-end gap-1">
                    {p.status === "active" && (
                      <ActionButton disabled={busy} onClick={() => props.onFreeze(p)} label="Freeze" />
                    )}
                    {p.status === "frozen" && (
                      <ActionButton disabled={busy} onClick={() => props.onUnfreeze(p)} label="Unfreeze" />
                    )}
                    {p.status !== "revoked" && (
                      <>
                        <ActionButton disabled={busy} onClick={() => props.onEditScopes(p)} label="Scopes" />
                        <ActionButton disabled={busy} onClick={() => props.onEditBudget(p)} label="Limit" />
                        <ActionButton
                          disabled={busy}
                          onClick={() => props.onSafeMode(p)}
                          label={p.safe_mode ? "End Safe Mode" : "Safe Mode"}
                        />
                        <ActionButton disabled={busy} onClick={() => props.onRenew(p)} label="Renew" />
                        <ActionButton disabled={busy} onClick={() => props.onRotate(p)} label="New key" />
                        <ActionButton disabled={busy} onClick={() => props.onRevoke(p)} label="Revoke" danger />
                      </>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}

function ActionButton(props: { label: string; onClick: () => void; disabled?: boolean; danger?: boolean }) {
  return (
    <button
      onClick={props.onClick}
      disabled={props.disabled}
      className={`rounded-full border px-2.5 py-1 text-[12px] font-medium disabled:opacity-40 ${
        props.danger
          ? "border-[#F5C2C0] text-[#B42318] hover:bg-[#FDECEC]"
          : "border-[#E5E5E5] hover:bg-[#F2F2F2]"
      }`}
    >
      {props.label}
    </button>
  );
}

function RegisterAgentForm(props: {
  servers: McpServer[];
  busy: boolean;
  onSubmit: (body: { name: string; framework: string; scopes: Scope[]; expires_in_days: number }) => void;
}) {
  const [name, setName] = useState("");
  const [framework, setFramework] = useState("n8n");
  const [days, setDays] = useState(90);
  const [scopes, setScopes] = useState<Scope[]>([]);

  return (
    <section className="rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-4">
      <h2 className="text-[15px] font-semibold">Register an agent</h2>
      <form
        className="mt-3 flex flex-col gap-3 text-[13px]"
        onSubmit={(e) => {
          e.preventDefault();
          if (
            scopes.length === 0 &&
            !window.confirm("This agent has no scopes and will be refused on every tool. Register it anyway?")
          ) {
            return;
          }
          props.onSubmit({ name, framework, scopes, expires_in_days: days });
          setName("");
          setScopes([]);
        }}
      >
        <input
          required
          maxLength={120}
          placeholder="Agent name, e.g. Invoice follow-up bot"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="h-[36px] rounded-[8px] border border-[#E5E5E5] px-3 focus:border-[#0F0F0F] focus:outline-none"
        />
        <div className="flex gap-2">
          <select
            value={framework}
            onChange={(e) => setFramework(e.target.value)}
            className="h-[36px] flex-1 rounded-[8px] border border-[#E5E5E5] px-2"
          >
            {FRAMEWORKS.map((f) => (
              <option key={f}>{f}</option>
            ))}
          </select>
          <label className="flex items-center gap-2 text-[12px] text-[#606060]">
            Expires in
            <input
              type="number"
              min={1}
              max={365}
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              className="h-[36px] w-[70px] rounded-[8px] border border-[#E5E5E5] px-2"
            />
            days
          </label>
        </div>

        <ScopeFields servers={props.servers} scopes={scopes} onChange={setScopes} />
        {scopes.length === 0 && (
          <p role="note" className="rounded-[8px] bg-[#FFF4E5] p-2 text-[12px] text-[#8A4B00]">
            No scopes: this agent will be refused on every tool until you add some.
          </p>
        )}

        <button
          type="submit"
          disabled={props.busy}
          className="h-[36px] rounded-full bg-[#0F0F0F] font-semibold text-[#FFFFFF] disabled:opacity-40"
        >
          Register and issue key
        </button>
      </form>
    </section>
  );
}

/** Editable list of scopes; shared by the register form and the scope editor. */
function ScopeFields(props: { servers: McpServer[]; scopes: Scope[]; onChange: (next: Scope[]) => void }) {
  const { scopes, onChange } = props;
  const activeServers = props.servers.filter((srv) => srv.is_active);
  const update = (i: number, patch: Partial<Scope>) =>
    onChange(scopes.map((s, idx) => (idx === i ? { ...s, ...patch } : s)));

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-[12px] font-semibold text-[#606060]">Scopes (what it may use)</span>
        <button
          type="button"
          // New scopes default to "write": an undeclared tool counts as write, so Safe Mode suspends it.
          onClick={() => onChange([...scopes, { server: activeServers[0]?.slug ?? "", tool: "", access: "write" }])}
          className="flex items-center gap-1 text-[12px] font-medium hover:underline"
        >
          <Plus className="h-3.5 w-3.5" /> Add scope
        </button>
      </div>
      {scopes.map((s, i) => (
        <div key={i} className="flex gap-2">
          <select
            value={s.server}
            onChange={(e) => update(i, { server: e.target.value })}
            className="h-[34px] w-[130px] rounded-[8px] border border-[#E5E5E5] px-2"
            required
          >
            <option value="" disabled>
              server
            </option>
            {activeServers.map((srv) => (
              <option key={srv.id} value={srv.slug}>
                {srv.slug}
              </option>
            ))}
          </select>
          <input
            required
            placeholder="tool name or *"
            value={s.tool}
            onChange={(e) => update(i, { tool: e.target.value })}
            className="h-[34px] flex-1 rounded-[8px] border border-[#E5E5E5] px-2 font-mono text-[12px]"
          />
          <select
            value={s.access}
            onChange={(e) => update(i, { access: e.target.value as Scope["access"] })}
            className="h-[34px] rounded-[8px] border border-[#E5E5E5] px-2"
            title="In Safe Mode only read tools work. You declare read or write; RedHand cannot verify it."
          >
            <option value="read">read</option>
            <option value="write">write</option>
          </select>
          <button
            type="button"
            aria-label="Remove scope"
            onClick={() => onChange(scopes.filter((_, idx) => idx !== i))}
            className="px-1 text-[#606060] hover:text-[#B42318]"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      ))}
      {props.servers.length === 0 && (
        <p className="text-[12px] text-[#606060]">Register an MCP server first to grant tool scopes.</p>
      )}
      {scopes.some((s) => s.tool === "*" && s.access === "read") && (
        <p role="note" className="rounded-[8px] bg-[#FFF4E5] p-2 text-[12px] text-[#8A4B00]">
          A <code>*</code> scope declared read means every tool on that server counts as read-only in Safe Mode.
          Only do this if the server really has no write tools.
        </p>
      )}
      <p className="text-[11px] text-[#606060]">
        The gateway enforces server and tool. In Safe Mode only scopes declared <strong>read</strong> work.
        You declare read or write: RedHand cannot verify that a tool really is read-only.
      </p>
    </div>
  );
}

function ScopeEditor(props: {
  passport: Passport;
  servers: McpServer[];
  busy: boolean;
  onSave: (scopes: Scope[], reason: string) => void;
  onCancel: () => void;
}) {
  const [scopes, setScopes] = useState<Scope[]>(props.passport.scopes);
  const [reason, setReason] = useState("");
  return (
    <section className="rounded-[12px] border-2 border-[#0F0F0F] bg-[#FFFFFF] p-4">
      <h2 className="text-[15px] font-semibold">Edit scopes for {props.passport.name}</h2>
      <form
        className="mt-3 flex flex-col gap-3 text-[13px]"
        onSubmit={(e) => {
          e.preventDefault();
          props.onSave(scopes, reason);
        }}
      >
        <ScopeFields servers={props.servers} scopes={scopes} onChange={setScopes} />
        {scopes.length === 0 && (
          <p role="note" className="rounded-[8px] bg-[#FFF4E5] p-2 text-[12px] text-[#8A4B00]">
            Saving with no scopes makes this agent refuse every tool.
          </p>
        )}
        <input
          maxLength={500}
          placeholder="Reason (recorded in the audit log)"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          className="h-[34px] rounded-[8px] border border-[#E5E5E5] px-3"
        />
        <div className="flex gap-2">
          <button
            type="submit"
            disabled={props.busy}
            className="h-[34px] flex-1 rounded-full bg-[#0F0F0F] font-semibold text-[#FFFFFF] disabled:opacity-40"
          >
            Save scopes (admin)
          </button>
          <button
            type="button"
            onClick={props.onCancel}
            className="h-[34px] rounded-full border border-[#E5E5E5] px-4 hover:bg-[#F2F2F2]"
          >
            Cancel
          </button>
        </div>
      </form>
    </section>
  );
}

function McpServersPanel(props: {
  servers: McpServer[];
  busy: boolean;
  onCreate: (body: { slug: string; name: string; url: string }) => void;
}) {
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  return (
    <section className="rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-4">
      <h2 className="text-[15px] font-semibold">MCP servers</h2>
      <p className="mt-1 text-[12px] text-[#606060]">
        Agents reach a server at <code>/mcp/&lt;slug&gt;</code> on the RedHand gateway.
      </p>
      <ul className="mt-3 flex flex-col gap-1 text-[13px]">
        {props.servers.length === 0 && <li className="text-[#606060]">None registered.</li>}
        {props.servers.map((s) => (
          <li key={s.id} className="flex items-center justify-between gap-2">
            <span>
              <span className="font-mono font-semibold">{s.slug}</span> · {s.name}
              {!s.is_active && <span className="ml-1 text-[11px] text-[#606060]">(inactive)</span>}
            </span>
            <span className="truncate text-[11px] text-[#606060]" title={s.url}>
              {s.url}
            </span>
          </li>
        ))}
      </ul>
      <form
        className="mt-3 flex flex-col gap-2 text-[13px]"
        onSubmit={(e) => {
          e.preventDefault();
          props.onCreate({ slug, name, url });
          setSlug("");
          setName("");
          setUrl("");
        }}
      >
        <div className="flex gap-2">
          <input
            required
            pattern="[a-z0-9][a-z0-9\-]{0,62}"
            placeholder="slug (e.g. xero)"
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
            className="h-[34px] w-[140px] rounded-[8px] border border-[#E5E5E5] px-2 font-mono text-[12px]"
          />
          <input
            required
            placeholder="Display name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="h-[34px] flex-1 rounded-[8px] border border-[#E5E5E5] px-2"
          />
        </div>
        <input
          required
          type="url"
          placeholder="https://mcp.example.com/..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="h-[34px] rounded-[8px] border border-[#E5E5E5] px-2"
        />
        <button
          type="submit"
          disabled={props.busy}
          className="h-[34px] rounded-full border border-[#0F0F0F] font-semibold hover:bg-[#F2F2F2] disabled:opacity-40"
        >
          Register server (admin)
        </button>
      </form>
    </section>
  );
}

function AuditPanel(props: { entries: ControlAuditEntry[]; passports: Passport[]; servers: McpServer[] }) {
  const names = new Map(props.passports.map((p) => [p.id, p.name]));
  const serverSlugs = new Map(props.servers.map((s) => [s.id, s.slug]));
  const targetLabel = (e: ControlAuditEntry): string => {
    if (e.target_type === "agent") return names.get(e.target_id) ?? shortId(e.target_id);
    if (e.target_type === "mcp_server") return `MCP server ${serverSlugs.get(e.target_id) ?? shortId(e.target_id)}`;
    if (e.target_type === "organization") return "all agents";
    return e.target_type;
  };
  return (
    <section className="rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-4">
      <h2 className="text-[15px] font-semibold">Control audit log</h2>
      <p className="mt-1 text-[12px] text-[#606060]">Append-only record of who changed what, and when.</p>
      <ul className="mt-3 flex flex-col divide-y divide-[#F2F2F2] text-[13px]">
        {props.entries.length === 0 && <li className="py-2 text-[#606060]">No control actions yet.</li>}
        {props.entries.map((e) => (
          <li key={e.id} className="flex flex-wrap items-baseline justify-between gap-2 py-2">
            <span>
              <span className="font-mono font-semibold">{e.action}</span>{" "}
              {targetLabel(e)}
              {e.reason && <span className="text-[#606060]"> · {e.reason}</span>}
              {(e.action === "passport.budget_changed" || e.action === "organization.budget_default_changed") && (
                <span className="text-[#606060]">
                  {" "}
                  · {e.action === "organization.budget_default_changed" ? "default limit" : "limit"}{" "}
                  {String(e.details?.old_limit ?? "none")} → {String(e.details?.new_limit ?? "none")}
                  {e.details?.old_action !== undefined && e.details.old_action !== e.details.new_action
                    ? ` · at limit: ${String(e.details.old_action)} → ${String(e.details.new_action)}`
                    : ""}
                </span>
              )}
              {typeof e.details?.frozen_count === "number" && (
                <span className="text-[#606060]"> · {String(e.details.frozen_count)} agents</span>
              )}
            </span>
            <span className="text-[11px] text-[#606060]">
              by {e.actor_user_id === SYSTEM_ACTOR_ID ? "RedHand Budget Guard" : shortId(e.actor_user_id)} ·{" "}
              {new Date(e.created_at).toLocaleString()}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Link a phone to the panic command and manage linked chats (admin / owner). */
function TelegramPanel(props: {
  token: string;
  onChanged: () => void;
  onError: (err: unknown) => void;
}) {
  const { token, onChanged, onError } = props;
  const [links, setLinks] = useState<TelegramLink[]>([]);
  const [code, setCode] = useState<TelegramLinkCode | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  // The dashboard does not know the operator's role in production; the server decides.
  const [forbidden, setForbidden] = useState(false);

  const load = useCallback(async () => {
    try {
      setLinks(await telegramApi.links(token));
      setUnavailable(false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setForbidden(true);
        return;
      }
      onError(err);
    }
  }, [token, onError]);

  useEffect(() => {
    load();
  }, [load]);

  const createCode = async () => {
    try {
      setCode(await telegramApi.createCode(token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 503) {
        setUnavailable(true);
        return;
      }
      if (err instanceof ApiError && err.status === 403) {
        setForbidden(true);
        return;
      }
      onError(err);
    }
  };

  const unlink = async (link: TelegramLink) => {
    if (!window.confirm("Remove this phone? It will no longer be able to freeze agents.")) return;
    try {
      await telegramApi.unlink(token, link.id);
      await load();
      onChanged();
    } catch (err) {
      onError(err);
    }
  };

  return (
    <section className="rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-4">
      <h2 className="text-[15px] font-semibold">Telegram panic command</h2>
      <p className="mt-1 text-[12px] text-[#606060]">
        Freeze agents from your phone with <code>/freeze_all</code> or <code>/freeze &lt;name&gt;</code>. Unfreezing
        and revoking stay in this dashboard, so a lost phone can stop agents but never start them.
      </p>
      {forbidden && (
        <p role="note" className="mt-3 rounded-[8px] bg-[#FFF4E5] p-2 text-[12px] text-[#8A4B00]">
          Only an owner or admin can link or manage phones.
        </p>
      )}
      {unavailable && (
        <p role="note" className="mt-3 rounded-[8px] bg-[#FFF4E5] p-2 text-[12px] text-[#8A4B00]">
          Telegram is not set up on this RedHand server yet.
        </p>
      )}
      <ul className="mt-3 flex flex-col gap-1 text-[13px]">
        {links.length === 0 && <li className="text-[#606060]">No phone linked.</li>}
        {links.map((l) => (
          <li key={l.id} className="flex items-center justify-between gap-2">
            <span>
              Linked by {shortId(l.user_id)} · {new Date(l.created_at).toLocaleString()}
            </span>
            <ActionButton label="Unlink" danger onClick={() => unlink(l)} />
          </li>
        ))}
      </ul>
      <button
        onClick={createCode}
        disabled={forbidden}
        className="mt-3 disabled:opacity-40 h-[34px] rounded-full border border-[#0F0F0F] px-4 text-[13px] font-semibold hover:bg-[#F2F2F2]"
      >
        Link Telegram
      </button>
      {code && (
        <div className="mt-3 rounded-[8px] bg-[#F2F2F2] p-3 text-[13px]">
          <p>
            Send this to the bot within 10 minutes: <code className="font-semibold">/link {code.code}</code>
          </p>
          {code.deep_link && (
            <p className="mt-1">
              Or open{" "}
              <a href={code.deep_link} target="_blank" rel="noreferrer" className="underline">
                {code.deep_link}
              </a>{" "}
              on your phone and tap Start.
            </p>
          )}
          <p className="mt-1 text-[11px] text-[#606060]">The code works once. Anyone who has it can link their phone.</p>
        </div>
      )}
    </section>
  );
}

/** Calls today against the limit. Counts tool calls through the gateway; never money. */
function CallsCell(props: { passport: Passport; usage: AgentUsage | undefined }) {
  const { passport, usage } = props;
  if (passport.status === "revoked") return <span className="text-[#606060]">-</span>;
  const calls = usage?.calls ?? 0;
  const limit = passport.daily_call_limit;
  if (limit === null) {
    return (
      <div>
        <div>{calls} calls</div>
        <div className="text-[11px] text-[#8A4B00]">no limit set</div>
      </div>
    );
  }
  const percent = Math.min(100, Math.floor((calls * 100) / limit));
  const color = percent >= 100 ? "bg-[#B42318]" : percent >= 80 ? "bg-[#E8A33D]" : "bg-[#1E7B34]";
  return (
    <div className="min-w-[110px]">
      <div className="font-semibold">
        {calls} / {limit}
      </div>
      <div className="mt-1 h-[6px] w-full rounded-full bg-[#F2F2F2]" role="progressbar" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}>
        <div className={`h-[6px] rounded-full ${color}`} style={{ width: `${percent}%` }} />
      </div>
      <div className="mt-1 text-[11px] text-[#606060]">
        {percent >= 100 ? "refused until tomorrow" : `${percent}%`}
        {passport.budget_action === "freeze" ? " · freezes at limit" : ""}
      </div>
    </div>
  );
}

/** Set an agent's daily limit on tool calls (calls through the gateway, not money). */
function BudgetEditor(props: {
  passport: Passport;
  busy: boolean;
  onSave: (limit: number | null, action: "deny" | "freeze", reason: string, confirm: boolean) => void;
  onCancel: () => void;
}) {
  const { passport } = props;
  const [limit, setLimit] = useState(passport.daily_call_limit === null ? "" : String(passport.daily_call_limit));
  const [action, setAction] = useState<"deny" | "freeze">(passport.budget_action);
  const [reason, setReason] = useState("");
  const parsed = limit.trim() === "" ? null : Number(limit);
  const valid = parsed === null || (Number.isInteger(parsed) && parsed >= 1 && parsed <= 10_000_000);
  const old = passport.daily_call_limit;
  // Raising or removing a limit, or turning auto-freeze off, relaxes the restriction: the server wants an admin and confirmation.
  const relaxes = (old !== null && (parsed === null || parsed > old)) || (passport.budget_action === "freeze" && action !== "freeze");
  return (
    <section className="rounded-[12px] border-2 border-[#0F0F0F] bg-[#FFFFFF] p-4">
      <h2 className="text-[15px] font-semibold">Daily limit for {passport.name}</h2>
      <p className="mt-1 text-[12px] text-[#606060]">
        A cap on tool calls this agent makes through the RedHand gateway per day (the day starts at midnight in your
        organization&apos;s time zone). It does not see LLM tokens or money.
      </p>
      <form
        className="mt-3 flex flex-col gap-3 text-[13px]"
        onSubmit={(e) => {
          e.preventDefault();
          if (!valid) return;
          if (relaxes && !window.confirm("This relaxes the restriction (raises or removes the limit, or turns auto-freeze off). Continue?")) return;
          props.onSave(parsed, action, reason, relaxes);
        }}
      >
        <label className="flex items-center gap-2">
          Calls per day
          <input
            inputMode="numeric"
            placeholder="blank = no limit"
            value={limit}
            onChange={(e) => setLimit(e.target.value)}
            className="h-[34px] w-[160px] rounded-[8px] border border-[#E5E5E5] px-2"
          />
        </label>
        {!valid && <p role="alert" className="text-[12px] text-[#B42318]">Enter a whole number from 1 to 10,000,000, or leave it blank.</p>}
        <label className="flex items-center gap-2">
          At the limit
          <select
            value={action}
            onChange={(e) => setAction(e.target.value as "deny" | "freeze")}
            className="h-[34px] rounded-[8px] border border-[#E5E5E5] px-2"
          >
            <option value="deny">refuse further calls and alert me</option>
            <option value="freeze">refuse, alert me, and freeze the agent</option>
          </select>
        </label>
        <input
          maxLength={500}
          placeholder="Reason (recorded in the audit log)"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          className="h-[34px] rounded-[8px] border border-[#E5E5E5] px-3"
        />
        {relaxes && (
          <p role="note" className="rounded-[8px] bg-[#FFF4E5] p-2 text-[12px] text-[#8A4B00]">
            Raising or removing a limit needs an admin. You will be asked to confirm.
          </p>
        )}
        <div className="flex gap-2">
          <button
            type="submit"
            disabled={props.busy || !valid}
            className="h-[34px] flex-1 rounded-full bg-[#0F0F0F] font-semibold text-[#FFFFFF] disabled:opacity-40"
          >
            Save limit
          </button>
          <button
            type="button"
            onClick={props.onCancel}
            className="h-[34px] rounded-full border border-[#E5E5E5] px-4 hover:bg-[#F2F2F2]"
          >
            Cancel
          </button>
        </div>
      </form>
    </section>
  );
}

/** The daily call limit every NEW agent starts with (existing agents are not changed). */
function BudgetDefaultPanel(props: {
  current: number | null;
  busy: boolean;
  onChange: (limit: number | null, reason: string, confirm: boolean) => void;
}) {
  const { current } = props;
  const change = () => {
    const answer = window.prompt(
      "Daily tool calls that NEW agents start with (blank = no default). Existing agents are not changed.",
      current === null ? "" : String(current)
    );
    if (answer === null) return;
    const limit = answer.trim() === "" ? null : Number(answer);
    if (limit !== null && (!Number.isInteger(limit) || limit < 1 || limit > 10_000_000)) {
      window.alert("Enter a whole number from 1 to 10,000,000, or leave it blank.");
      return;
    }
    const relaxes = current !== null && (limit === null || limit > current);
    if (relaxes && !window.confirm("This raises or removes the default, so agents registered later start with a weaker limit. Continue?")) return;
    const reason = window.prompt("Reason (recorded in the audit log):") ?? "";
    props.onChange(limit, reason, relaxes);
  };
  return (
    <section className="flex flex-wrap items-center justify-between gap-3 rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-4">
      <div>
        <h2 className="text-[15px] font-semibold">Default daily limit for new agents</h2>
        <p className="mt-1 text-[12px] text-[#606060]">
          {current === null
            ? "No default: a new agent starts with no limit and is never stopped until you set one."
            : `New agents start with a limit of ${current} tool calls per day. You can change it per agent.`}{" "}
          Counts tool calls through the gateway, not money.
        </p>
      </div>
      <button
        onClick={change}
        disabled={props.busy}
        className="h-[34px] rounded-full border border-[#0F0F0F] px-4 text-[13px] font-semibold hover:bg-[#F2F2F2] disabled:opacity-40"
      >
        Change (admin)
      </button>
    </section>
  );
}
