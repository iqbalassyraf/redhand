"use client";

/**
 * Agent Passports: the Phase 1 control surface.
 * Register agents, see owner / scopes / expiry / status, and freeze, unfreeze, revoke or
 * freeze everything. Every action is authorized and audited by redhand-core.
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { OctagonX, Plus, RefreshCw, Trash2 } from "lucide-react";

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
  type AgentRiskSummary,
  type RiskList,
  type Me,
  meApi,
  riskApi,
  spendApi,
  telegramApi,
} from "@/lib/api";
import { useAuth, useRequiredSession } from "@/lib/auth";
import { AppShell } from "@/components/shell/AppShell";
import { LEVEL_LABEL, LEVEL_STYLE, automaticActorLabel } from "@/lib/riskForm";
import { type AgentSpend, type SpendToday, spendCell } from "@/lib/spend";
import { DestinationsPanel } from "./DestinationsPanel";
import { RiskLadderCard } from "./RiskLadderCard";
import { RiskPanel } from "./RiskPanel";
import { SdkKeysCard } from "./SdkKeysCard";
import { TeamCard } from "./TeamCard";
import { SpendPanel } from "./SpendPanel";
import { isDeletionPendingMessage } from "@/lib/lifecycle";
import { isAdmin, isNoOrganizationMessage } from "@/lib/onboarding";
import { REPORTED_ONLY_HELP, REPORTED_ONLY_LABEL, canPromote, promoteConfirmText } from "@/lib/reportedOnly";

// RedHand's own automatic actions (Budget Guard, honeytokens, the Risk Engine) are recorded under this fixed actor (not a person).
const SYSTEM_ACTOR_ID = "00000000-0000-0000-0000-000000000000";

const FRAMEWORKS = ["n8n", "Claude", "LangGraph", "CrewAI", "custom"];

const STATUS_STYLE: Record<PassportStatus, string> = {
  active: "bg-rh-teal-wash text-rh-teal-text",
  frozen: "bg-rh-steel-wash text-rh-steel-text",
  revoked: "bg-rh-crimson-wash text-rh-crimson-text",
  expired: "bg-rh-elevated text-rh-text-2",
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
  const [destinationsFor, setDestinationsFor] = useState<Passport | null>(null);
  const [risk, setRisk] = useState<RiskList | null>(null);
  const [riskFor, setRiskFor] = useState<Passport | null>(null);
  const [spend, setSpend] = useState<SpendToday | null>(null);
  const [spendFor, setSpendFor] = useState<Passport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [revealedKey, setRevealedKey] = useState<{ name: string; key: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<Passport | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const admin = isAdmin(me?.role);

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        signOut("/login");
        return;
      }
      if (err instanceof ApiError && err.status === 403 && isNoOrganizationMessage(err.message)) {
        window.location.href = "/welcome"; // signed in, but not in an organization yet: create or join one
        return;
      }
      if (err instanceof ApiError && err.status === 403 && isDeletionPendingMessage(err.message)) {
        window.location.href = "/organization"; // deletion is pending: only the organization data page (status, export, cancel) still works
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
      setMe(await meApi.get(token).catch(() => null)); // an older core has no /v1/me: the page then shows every action and the server decides
      setPassports(p);
      setServers(s);
      setAudit(a);
      setOrgSafeMode(o.enabled);
      setUsage(u);
      setBudgetDefault(d.default_daily_call_limit);
      // Risk scores need the security operator role, and an older core has no Risk Engine: either way the rest of the page works.
      setRisk(await riskApi.list(token).catch((err: unknown) => {
        if (err instanceof ApiError && (err.status === 403 || err.status === 404)) return null;
        throw err;
      }));
      // Model use: an older core has no such route (404). A read that fails shows no figure (never a zero) and must not break the page.
      setSpend(await spendApi.list(token).catch(() => null));
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
    <AppShell title="Passports" organization={me?.organization_name} role={me?.role}>

      <div className="mx-auto flex max-w-[1200px] min-w-0 flex-col gap-6">
        <section className="rh-glass flex flex-wrap items-center justify-between gap-4 rounded-rh-md p-4">
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
                orgSafeMode ? "bg-rh-ochre-wash text-rh-ochre" : "bg-rh-elevated text-rh-text-2"
              }`}
              title="While on, agents can use only tools their scopes declare as read. You declare read or write; RedHand cannot verify it."
            >
              Safe Mode (all agents): {orgSafeMode ? "on" : "off"}
            </span>
            <button
              onClick={onOrgSafeMode}
              disabled={busy}
              className="rounded-full border border-rh-hairline px-3 py-1.5 text-[12px] font-medium hover:bg-rh-elevated disabled:opacity-40"
            >
              {orgSafeMode ? "Turn off" : "Turn on"}
            </button>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={refresh}
              className="flex items-center gap-1 rounded-full border border-rh-hairline px-3 py-2 text-[13px] hover:bg-rh-elevated"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Refresh
            </button>
            <button
              onClick={onFreezeAll}
              disabled={busy || counts.active === 0}
              className="flex items-center gap-1.5 rounded-full bg-control-crimson px-4 py-2 text-[13px] font-bold text-white shadow-rh-crimson transition hover:bg-control-crimsonDeep disabled:opacity-40"
            >
              <OctagonX className="h-4 w-4" /> Freeze all agents
            </button>
          </div>
        </section>

        <p className="text-[12px] text-rh-text-2">
          RedHand controls agents that connect through the RedHand gateway. Agents holding raw API keys
          or direct access outside the gateway are not covered.
        </p>

        {error && (
          <div role="alert" className="rounded-[8px] bg-rh-crimson-wash p-3 text-[13px] text-rh-crimson-text">
            {error}
          </div>
        )}
        {notice && <div className="rounded-[8px] bg-rh-teal-wash p-3 text-[13px] text-rh-teal-text">{notice}</div>}

        {risk && token && (
          <RiskLadderCard
            key={`${risk.ladder.alert_at}-${risk.ladder.safe_mode_at}-${risk.ladder.freeze_at}`}
            token={token}
            ladder={risk.ladder}
            onSaved={(message) => { setNotice(message); refresh(); }}
            onError={handleError}
          />
        )}

        {revealedKey && (
          <div className="rh-glass rounded-rh-md border-2 border-control-borderStrong p-4">
            <p className="text-[13px] font-semibold">Agent key for {revealedKey.name}</p>
            <p className="mt-1 text-[12px] text-rh-text-2">
              Shown once. Store it in the agent&apos;s secret store; RedHand keeps only a hash. The agent
              exchanges it at <code>/v1/agent-auth/token</code> for a 10-minute access token.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <code className="flex-1 break-all rounded-[8px] bg-rh-elevated p-2 text-[12px]">{revealedKey.key}</code>
              <button
                onClick={() => navigator.clipboard.writeText(revealedKey.key)}
                className="rounded-full border border-rh-hairline px-3 py-1.5 text-[12px] hover:bg-rh-elevated"
              >
                Copy
              </button>
              <button
                onClick={() => setRevealedKey(null)}
                className="rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-3 py-1.5 text-[12px] font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep"
              >
                I&apos;ve stored it
              </button>
            </div>
          </div>
        )}

        <PassportTable
          canIssueKeys={!me || admin}
          passports={passports}
          busy={busy}
          onFreeze={(p) => act(`${p.name} frozen.`, () => passportsApi.freeze(token, p.id))}
          onUnfreeze={(p) => {
            if (!window.confirm(`Unfreeze ${p.name}? It will be able to call its tools again.`)) return;
            act(`${p.name} unfrozen.`, () => passportsApi.unfreeze(token, p.id));
          }}
          onPromote={(p) => {
            if (!window.confirm(promoteConfirmText(p.name))) return;
            const reason = window.prompt("Reason (recorded in the audit log):") ?? "";
            act(`${p.name} promoted.`, () => passportsApi.promote(token, p.id, reason));
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
          onDestinations={(p) => setDestinationsFor(destinationsFor?.id === p.id ? null : p)}
          risk={risk}
          onRisk={(p) => setRiskFor(riskFor?.id === p.id ? null : p)}
          spend={spend}
          onSpend={(p) => setSpendFor(spendFor?.id === p.id ? null : p)}
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

        {destinationsFor && token && (
          <DestinationsPanel
            key={destinationsFor.id}
            token={token}
            agentId={destinationsFor.id}
            agentName={destinationsFor.name}
            onClose={() => setDestinationsFor(null)}
            onUnauthorized={() => {
              signOut("/login");
            }}
          />
        )}

        {spendFor && token && (
          <SpendPanel
            key={spendFor.id}
            token={token}
            agentId={spendFor.id}
            agentName={spendFor.name}
            onClose={() => setSpendFor(null)}
            onChanged={refresh}
            onUnauthorized={() => {
              signOut("/login");
            }}
          />
        )}

        {riskFor && token && (
          <RiskPanel
            key={riskFor.id}
            token={token}
            agentId={riskFor.id}
            agentName={riskFor.name}
            onClose={() => setRiskFor(null)}
            onUnauthorized={() => {
              signOut("/login");
            }}
          />
        )}

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

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {me && !admin ? (
            <section className="rh-glass rounded-rh-md p-4 text-[13px] text-rh-text-2">
              <h2 className="text-[15px] font-semibold text-rh-text">Register an agent</h2>
              <p className="mt-1">Registering an agent issues its key, so it needs an admin. Ask one of your admins to register it.</p>
            </section>
          ) : <RegisterAgentForm
            servers={servers}
            busy={busy}
            onSubmit={(body) =>
              act(`${body.name} registered.`, async () => {
                const res = await passportsApi.create(token, body);
                setRevealedKey({ name: res.passport.name, key: res.agent_key });
              })
            }
          />}
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

        <SdkKeysCard
          token={token}
          onUnauthorized={() => {
            signOut("/login");
          }}
        />

        {me && admin && (
          <TeamCard
            token={token}
            ownRole={me.role}
            ownUserId={me.user_id}
            onUnauthorized={() => {
              signOut("/login");
            }}
          />
        )}

        <AuditPanel entries={audit} passports={passports} servers={servers} />
      </div>
    </AppShell>
  );
}

function PassportTable(props: {
  passports: Passport[];
  busy: boolean;
  onFreeze: (p: Passport) => void;
  onUnfreeze: (p: Passport) => void;
  onPromote: (p: Passport) => void;
  onRevoke: (p: Passport) => void;
  onRotate: (p: Passport) => void;
  canIssueKeys: boolean;
  onRenew: (p: Passport) => void;
  onEditScopes: (p: Passport) => void;
  orgSafeMode: boolean;
  onSafeMode: (p: Passport) => void;
  usage: UsageSummary | null;
  onEditBudget: (p: Passport) => void;
  onDestinations: (p: Passport) => void;
  risk: RiskList | null;
  onRisk: (p: Passport) => void;
  spend: SpendToday | null;
  onSpend: (p: Passport) => void;
}) {
  const { passports, busy } = props;
  const riskByAgent = new Map<string, AgentRiskSummary>((props.risk?.agents ?? []).map((r) => [r.agent_id, r]));
  const usageByAgent = new Map<string, AgentUsage>((props.usage?.agents ?? []).map((u) => [u.agent_id, u]));
  const spendByAgent = new Map<string, AgentSpend>((props.spend?.agents ?? []).map((s) => [s.agent_id, s]));
  return (
    <section className="rh-glass overflow-x-auto rounded-rh-md">
      <table className="w-full min-w-[900px] text-left text-[13px]">
        <thead className="border-b border-rh-hairline text-[11px] uppercase tracking-wider text-rh-text-2">
          <tr>
            <th className="p-3">Agent</th>
            <th className="p-3">Status</th>
            <th className="p-3">Owner</th>
            <th className="p-3">Scopes</th>
            <th className="p-3">Calls today</th>
            <th className="p-3">Model use today</th>
            <th className="p-3">Expires</th>
            <th className="p-3">Last seen</th>
            <th className="p-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {passports.length === 0 && (
            <tr>
              <td colSpan={9} className="p-6 text-center text-rh-text-2">
                No agents yet. Register one below.
              </td>
            </tr>
          )}
          {passports.map((p) => {
            const days = daysUntil(p.expires_at);
            return (
              <tr key={p.id} className="border-b border-rh-hairline align-top">
                <td className="p-3">
                  <div className="font-semibold">{p.name}</div>
                  <div className="text-[11px] text-rh-text-2">
                    {p.external_agent_id} · {p.framework} · v{p.version}
                  </div>
                </td>
                <td className="p-3">
                  <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${STATUS_STYLE[p.status]}`}>
                    {p.status}
                  </span>
                  {p.status_reason && <div className="mt-1 text-[11px] text-rh-text-2">{p.status_reason}</div>}
                  {(() => {
                    const r = riskByAgent.get(p.id);
                    if (!r) return null;  // no score: a role that cannot read risk, or an older core
                    return (
                      <div className="mt-1">
                        <button
                          onClick={() => props.onRisk(p)}
                          title={r.reason}
                          className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${LEVEL_STYLE[r.level]} hover:underline`}
                        >
                          risk {r.score} · {LEVEL_LABEL[r.level]}
                        </button>
                      </div>
                    );
                  })()}
                  {p.reported_only === true && (
                    <div className="mt-1">
                      <span title={REPORTED_ONLY_HELP} className="rounded-full bg-rh-purple-wash px-2 py-0.5 text-[11px] font-semibold text-rh-purple-text">
                        {REPORTED_ONLY_LABEL}
                      </span>
                    </div>
                  )}
                  {p.status !== "revoked" && (p.safe_mode || props.orgSafeMode) && (
                    <div className="mt-1">
                      <span className="rounded-full bg-rh-ochre-wash px-2 py-0.5 text-[11px] font-semibold text-rh-ochre">
                        safe mode{props.orgSafeMode && !p.safe_mode ? " (all)" : ""}
                      </span>
                    </div>
                  )}
                </td>
                <td className="p-3 text-[12px]">
                  <div title={p.owner_id ?? ""}>{shortId(p.owner_id)}</div>
                  <div className="text-[11px] text-rh-text-2" title={p.backup_owner_id ?? ""}>
                    backup {shortId(p.backup_owner_id)}
                  </div>
                </td>
                <td className="p-3">
                  <div className="flex max-w-[260px] flex-wrap gap-1">
                    {p.scopes.length === 0 && <span className="text-[12px] text-rh-text-2">none</span>}
                    {p.scopes.map((s) => (
                      <span
                        key={`${s.server}/${s.tool}/${s.access}`}
                        className={`rounded-[6px] bg-rh-elevated px-1.5 py-0.5 font-mono text-[11px] ${
                          p.status !== "revoked" && (p.safe_mode || props.orgSafeMode) && s.access === "write" ? "line-through opacity-60" : ""
                        }`}
                        title={
                          p.status !== "revoked" && (p.safe_mode || props.orgSafeMode) && s.access === "write"
                            ? "Suspended: Safe Mode is on and this scope is declared write"
                            : undefined
                        }
                      >
                        {s.server}/{s.tool} <span className="text-rh-text-2">{s.access}</span>
                      </span>
                    ))}
                  </div>
                </td>
                <td className="p-3 text-[12px]">
                  <CallsCell passport={p} usage={usageByAgent.get(p.id)} />
                </td>
                <td className="p-3 text-[12px]">
                  {p.status === "revoked" || props.spend === null ? (
                    <span className="text-rh-text-2">-</span>
                  ) : (
                    (() => {
                      const cell = spendCell(spendByAgent.get(p.id));
                      const color = cell.tone === "alert" ? "text-rh-crimson-text" : cell.tone === "warn" ? "text-rh-ochre" : "";
                      return (
                        <button onClick={() => props.onSpend(p)} className="text-left hover:underline" title="Estimated from what the agent's SDK reported. Click for detail.">
                          <div className={`font-semibold ${color}`}>{cell.headline}</div>
                          {cell.detail && <div className="max-w-[180px] text-[11px] text-rh-text-2">{cell.detail}</div>}
                        </button>
                      );
                    })()
                  )}
                </td>
                <td className="p-3 text-[12px]">
                  <div>{new Date(p.expires_at).toLocaleDateString()}</div>
                  <div className={`text-[11px] ${days <= 7 ? "text-rh-crimson-text" : "text-rh-text-2"}`}>
                    {days > 0 ? `${days} days left` : "expired"}
                  </div>
                </td>
                <td className="p-3 text-[12px] text-rh-text-2">{formatTime(p.last_seen_at)}</td>
                <td className="p-3">
                  <div className="flex flex-wrap justify-end gap-1">
                    <Link
                      href={`/passports/${p.id}/timeline`}
                      className="rounded-full border border-rh-hairline px-2.5 py-1 text-[12px] font-medium hover:bg-rh-elevated"
                    >
                      Timeline
                    </Link>
                    {p.status === "active" && (
                      <ActionButton disabled={busy} onClick={() => props.onFreeze(p)} label="Freeze" />
                    )}
                    {p.status === "frozen" && (
                      <ActionButton disabled={busy} onClick={() => props.onUnfreeze(p)} label="Unfreeze" />
                    )}
                    {canPromote(p) && <ActionButton disabled={busy} onClick={() => props.onPromote(p)} label="Promote" />}
                    {p.status !== "revoked" && (
                      <>
                        <ActionButton disabled={busy} onClick={() => props.onEditScopes(p)} label="Scopes" />
                        <ActionButton disabled={busy} onClick={() => props.onEditBudget(p)} label="Limit" />
                        <ActionButton disabled={busy} onClick={() => props.onDestinations(p)} label="Destinations" />
                        <ActionButton
                          disabled={busy}
                          onClick={() => props.onSafeMode(p)}
                          label={p.safe_mode ? "End Safe Mode" : "Safe Mode"}
                        />
                        <ActionButton disabled={busy} onClick={() => props.onRenew(p)} label="Renew" />
                        {props.canIssueKeys && <ActionButton disabled={busy} onClick={() => props.onRotate(p)} label="New key" />}
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
          ? "border-rh-crimson text-rh-crimson-text hover:bg-rh-crimson-wash"
          : "border-rh-hairline hover:bg-rh-elevated"
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
    <section className="rh-glass rounded-rh-md p-4">
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
          className="h-[36px] rounded-[8px] border border-rh-hairline px-3 focus:border-rh-strong focus:outline-none"
        />
        <div className="flex flex-wrap gap-2">
          <select
            value={framework}
            onChange={(e) => setFramework(e.target.value)}
            className="h-[36px] flex-1 rounded-[8px] border border-rh-hairline px-2"
          >
            {FRAMEWORKS.map((f) => (
              <option key={f}>{f}</option>
            ))}
          </select>
          <label className="flex items-center gap-2 text-[12px] text-rh-text-2">
            Expires in
            <input
              type="number"
              min={1}
              max={365}
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              className="h-[36px] w-[70px] rounded-[8px] border border-rh-hairline px-2"
            />
            days
          </label>
        </div>

        <ScopeFields servers={props.servers} scopes={scopes} onChange={setScopes} />
        {scopes.length === 0 && (
          <p role="note" className="rounded-[8px] bg-rh-ochre-wash p-2 text-[12px] text-rh-ochre">
            No scopes: this agent will be refused on every tool until you add some.
          </p>
        )}

        <button
          type="submit"
          disabled={props.busy}
          className="h-[36px] rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-40"
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
        <span className="text-[12px] font-semibold text-rh-text-2">Scopes (what it may use)</span>
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
        <div key={i} className="flex flex-wrap gap-2">
          <select
            value={s.server}
            onChange={(e) => update(i, { server: e.target.value })}
            className="h-[34px] w-[130px] rounded-[8px] border border-rh-hairline px-2"
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
            className="h-[34px] min-w-0 flex-1 rounded-[8px] border border-rh-hairline px-2 font-mono text-[12px]"
          />
          <select
            value={s.access}
            onChange={(e) => update(i, { access: e.target.value as Scope["access"] })}
            className="h-[34px] rounded-[8px] border border-rh-hairline px-2"
            title="In Safe Mode only read tools work. You declare read or write; RedHand cannot verify it."
          >
            <option value="read">read</option>
            <option value="write">write</option>
          </select>
          <button
            type="button"
            aria-label="Remove scope"
            onClick={() => onChange(scopes.filter((_, idx) => idx !== i))}
            className="px-1 text-rh-text-2 hover:text-rh-crimson-text"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      ))}
      {props.servers.length === 0 && (
        <p className="text-[12px] text-rh-text-2">Register an MCP server first to grant tool scopes.</p>
      )}
      {scopes.some((s) => s.tool === "*" && s.access === "read") && (
        <p role="note" className="rounded-[8px] bg-rh-ochre-wash p-2 text-[12px] text-rh-ochre">
          A <code>*</code> scope declared read means every tool on that server counts as read-only in Safe Mode.
          Only do this if the server really has no write tools.
        </p>
      )}
      <p className="text-[11px] text-rh-text-2">
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
    <section className="rh-glass rounded-rh-md border-2 border-control-borderStrong p-4">
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
          <p role="note" className="rounded-[8px] bg-rh-ochre-wash p-2 text-[12px] text-rh-ochre">
            Saving with no scopes makes this agent refuse every tool.
          </p>
        )}
        <input
          maxLength={500}
          placeholder="Reason (recorded in the audit log)"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          className="h-[34px] rounded-[8px] border border-rh-hairline px-3"
        />
        <div className="flex gap-2">
          <button
            type="submit"
            disabled={props.busy}
            className="h-[34px] flex-1 rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-40"
          >
            Save scopes (admin)
          </button>
          <button
            type="button"
            onClick={props.onCancel}
            className="h-[34px] rounded-full border border-rh-hairline px-4 hover:bg-rh-elevated"
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
    <section className="rh-glass rounded-rh-md p-4">
      <h2 className="text-[15px] font-semibold">MCP servers</h2>
      <p className="mt-1 text-[12px] text-rh-text-2">
        Agents reach a server at <code>/mcp/&lt;slug&gt;</code> on the RedHand gateway.
      </p>
      <ul className="mt-3 flex flex-col gap-1 text-[13px]">
        {props.servers.length === 0 && <li className="text-rh-text-2">None registered.</li>}
        {props.servers.map((s) => (
          <li key={s.id} className="flex items-center justify-between gap-2">
            <span>
              <span className="font-mono font-semibold">{s.slug}</span> · {s.name}
              {!s.is_active && <span className="ml-1 text-[11px] text-rh-text-2">(inactive)</span>}
            </span>
            <span className="truncate text-[11px] text-rh-text-2" title={s.url}>
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
        <div className="flex flex-wrap gap-2">
          <input
            required
            pattern="[a-z0-9][a-z0-9\-]{0,62}"
            placeholder="slug (e.g. xero)"
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
            className="h-[34px] w-[140px] rounded-[8px] border border-rh-hairline px-2 font-mono text-[12px]"
          />
          <input
            required
            placeholder="Display name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="h-[34px] min-w-0 flex-1 rounded-[8px] border border-rh-hairline px-2"
          />
        </div>
        <input
          required
          type="url"
          placeholder="https://mcp.example.com/..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="h-[34px] rounded-[8px] border border-rh-hairline px-2"
        />
        <button
          type="submit"
          disabled={props.busy}
          className="h-[34px] rounded-full border border-rh-strong font-semibold hover:bg-rh-elevated disabled:opacity-40"
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
    <section className="rh-glass rounded-rh-md p-4">
      <h2 className="text-[15px] font-semibold">Control audit log</h2>
      <p className="mt-1 text-[12px] text-rh-text-2">Append-only record of who changed what, and when.</p>
      <ul className="mt-3 flex flex-col divide-y divide-rh-hairline text-[13px]">
        {props.entries.length === 0 && <li className="py-2 text-rh-text-2">No control actions yet.</li>}
        {props.entries.map((e) => (
          <li key={e.id} className="flex flex-wrap items-baseline justify-between gap-2 py-2">
            <span>
              <span className="font-mono font-semibold">{e.action}</span>{" "}
              {targetLabel(e)}
              {e.reason && <span className="text-rh-text-2"> · {e.reason}</span>}
              {(e.action === "passport.budget_changed" || e.action === "organization.budget_default_changed") && (
                <span className="text-rh-text-2">
                  {" "}
                  · {e.action === "organization.budget_default_changed" ? "default limit" : "limit"}{" "}
                  {String(e.details?.old_limit ?? "none")} → {String(e.details?.new_limit ?? "none")}
                  {e.details?.old_action !== undefined && e.details.old_action !== e.details.new_action
                    ? ` · at limit: ${String(e.details.old_action)} → ${String(e.details.new_action)}`
                    : ""}
                </span>
              )}
              {typeof e.details?.frozen_count === "number" && (
                <span className="text-rh-text-2"> · {String(e.details.frozen_count)} agents</span>
              )}
            </span>
            <span className="text-[11px] text-rh-text-2">
              by {e.actor_user_id === SYSTEM_ACTOR_ID ? automaticActorLabel(e.reason) : shortId(e.actor_user_id)} ·{" "}
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
    <section className="rh-glass rounded-rh-md p-4">
      <h2 className="text-[15px] font-semibold">Telegram panic command</h2>
      <p className="mt-1 text-[12px] text-rh-text-2">
        Freeze agents from your phone with <code>/freeze_all</code> or <code>/freeze &lt;name&gt;</code>. Unfreezing
        and revoking stay in this dashboard, so a lost phone can stop agents but never start them.
      </p>
      {forbidden && (
        <p role="note" className="mt-3 rounded-[8px] bg-rh-ochre-wash p-2 text-[12px] text-rh-ochre">
          Only an owner or admin can link or manage phones.
        </p>
      )}
      {unavailable && (
        <p role="note" className="mt-3 rounded-[8px] bg-rh-ochre-wash p-2 text-[12px] text-rh-ochre">
          Telegram is not set up on this RedHand server yet.
        </p>
      )}
      <ul className="mt-3 flex flex-col gap-1 text-[13px]">
        {links.length === 0 && <li className="text-rh-text-2">No phone linked.</li>}
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
        className="mt-3 disabled:opacity-40 h-[34px] rounded-full border border-rh-strong px-4 text-[13px] font-semibold hover:bg-rh-elevated"
      >
        Link Telegram
      </button>
      {code && (
        <div className="mt-3 rounded-[8px] bg-rh-elevated p-3 text-[13px]">
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
          <p className="mt-1 text-[11px] text-rh-text-2">The code works once. Anyone who has it can link their phone.</p>
        </div>
      )}
    </section>
  );
}

/** Calls today against the limit. Counts tool calls through the gateway; never money. */
function CallsCell(props: { passport: Passport; usage: AgentUsage | undefined }) {
  const { passport, usage } = props;
  if (passport.status === "revoked") return <span className="text-rh-text-2">-</span>;
  const calls = usage?.calls ?? 0;
  const limit = passport.daily_call_limit;
  if (limit === null) {
    return (
      <div>
        <div>{calls} calls</div>
        <div className="text-[11px] text-rh-ochre">no limit set</div>
      </div>
    );
  }
  const percent = Math.min(100, Math.floor((calls * 100) / limit));
  const color = percent >= 100 ? "bg-rh-crimson" : percent >= 80 ? "bg-rh-ochre" : "bg-rh-teal";
  return (
    <div className="min-w-[110px]">
      <div className="font-semibold">
        {calls} / {limit}
      </div>
      <div className="mt-1 h-[6px] w-full rounded-full bg-rh-elevated" role="progressbar" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}>
        <div className={`h-[6px] rounded-full ${color}`} style={{ width: `${percent}%` }} />
      </div>
      <div className="mt-1 text-[11px] text-rh-text-2">
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
    <section className="rh-glass rounded-rh-md border-2 border-control-borderStrong p-4">
      <h2 className="text-[15px] font-semibold">Daily limit for {passport.name}</h2>
      <p className="mt-1 text-[12px] text-rh-text-2">
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
            className="h-[34px] w-[160px] rounded-[8px] border border-rh-hairline px-2"
          />
        </label>
        {!valid && <p role="alert" className="text-[12px] text-rh-crimson-text">Enter a whole number from 1 to 10,000,000, or leave it blank.</p>}
        <label className="flex items-center gap-2">
          At the limit
          <select
            value={action}
            onChange={(e) => setAction(e.target.value as "deny" | "freeze")}
            className="h-[34px] rounded-[8px] border border-rh-hairline px-2"
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
          className="h-[34px] rounded-[8px] border border-rh-hairline px-3"
        />
        {relaxes && (
          <p role="note" className="rounded-[8px] bg-rh-ochre-wash p-2 text-[12px] text-rh-ochre">
            Raising or removing a limit needs an admin. You will be asked to confirm.
          </p>
        )}
        <div className="flex gap-2">
          <button
            type="submit"
            disabled={props.busy || !valid}
            className="h-[34px] flex-1 rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-40"
          >
            Save limit
          </button>
          <button
            type="button"
            onClick={props.onCancel}
            className="h-[34px] rounded-full border border-rh-hairline px-4 hover:bg-rh-elevated"
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
    <section className="rh-glass flex flex-wrap items-center justify-between gap-3 rounded-rh-md p-4">
      <div>
        <h2 className="text-[15px] font-semibold">Default daily limit for new agents</h2>
        <p className="mt-1 text-[12px] text-rh-text-2">
          {current === null
            ? "No default: a new agent starts with no limit and is never stopped until you set one."
            : `New agents start with a limit of ${current} tool calls per day. You can change it per agent.`}{" "}
          Counts tool calls through the gateway, not money.
        </p>
      </div>
      <button
        onClick={change}
        disabled={props.busy}
        className="h-[34px] rounded-full border border-rh-strong px-4 text-[13px] font-semibold hover:bg-rh-elevated disabled:opacity-40"
      >
        Change (admin)
      </button>
    </section>
  );
}
