"use client";

/**
 * Honeytokens and decoy tools (Phase 3 M3/M4): fake credentials and fake tools that only a misbehaving agent
 * would touch. A honeytoken's value is shown once, when it is created. The UI is never a security boundary:
 * redhand-core decides who may create or retire anything.
 */

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Copy, Hand, LogOut, RefreshCw } from "lucide-react";

import {
  ApiError,
  type HoneyAction,
  type HoneyTool,
  type Honeytoken,
  type HoneytokenCreated,
  type HoneytokenKind,
  type Passport,
  honeyApi,
  passportsApi,
} from "@/lib/api";
import { useAuth, useRequiredSession } from "@/lib/auth";

const KIND_LABEL: Record<HoneytokenKind, string> = {
  api_key: "API key (sk_live_…)",
  aws_key: "AWS-style key (AKIA…)",
  password: "Password (24 characters)",
};

function when(iso: string | null): string {
  if (!iso) return "never";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export default function HoneytokensPage() {
  const session = useRequiredSession();
  const { signOut } = useAuth();
  const token = session?.token ?? null;

  const [tokens, setTokens] = useState<Honeytoken[]>([]);
  const [tools, setTools] = useState<HoneyTool[]>([]);
  const [agents, setAgents] = useState<Passport[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revealed, setRevealed] = useState<HoneytokenCreated | null>(null);

  const [label, setLabel] = useState("");
  const [kind, setKind] = useState<HoneytokenKind>("api_key");
  const [onUse, setOnUse] = useState<HoneyAction>("freeze");
  const [onRead, setOnRead] = useState<HoneyAction>("alert");

  const [toolAgent, setToolAgent] = useState("");
  const [toolServer, setToolServer] = useState("");
  const [toolName, setToolName] = useState("");
  const [toolDescription, setToolDescription] = useState("");
  const [toolAction, setToolAction] = useState<HoneyAction>("alert");

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

  const load = useCallback(async () => {
    if (!token) return;
    setError(null);
    try {
      const [t, h, a] = await Promise.all([honeyApi.tokens(token), honeyApi.tools(token), passportsApi.list(token)]);
      setTokens(t);
      setTools(h);
      setAgents(a.filter((p) => p.status !== "revoked"));
    } catch (err) {
      handleError(err);
    }
  }, [token, handleError]);

  useEffect(() => {
    load();
  }, [load]);

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      await load();
    } catch (err) {
      handleError(err);
    } finally {
      setBusy(false);
    }
  };

  if (!session || !token) return null;

  const createToken = () =>
    run(async () => {
      const created = await honeyApi.createToken(token, { label: label.trim(), kind, action_on_use: onUse, action_on_read: onRead });
      setRevealed(created);
      setLabel("");
    });

  const createTool = () =>
    run(async () => {
      await honeyApi.createTool(token, {
        agent_id: toolAgent,
        server: toolServer.trim(),
        name: toolName.trim(),
        description: toolDescription.trim(),
        action: toolAction,
      });
      setNotice("Decoy tool added. It appears in that agent's tool list within a few seconds.");
      setToolName("");
      setToolDescription("");
    });

  // Mirrors redhand-core's rule: starts with a letter, then letters, digits or underscores, 3 to 64 characters.
  const toolNameValid = /^[A-Za-z][A-Za-z0-9_]{2,63}$/.test(toolName.trim());
  const field = "rounded-[8px] border border-[#E5E5E5] px-2 py-1 text-[12px]";
  const agentName = (id: string) => agents.find((a) => a.id === id)?.name ?? id.slice(0, 8);

  return (
    <div className="min-h-screen bg-[#F8F8F8] text-[#0F0F0F]">
      <header className="flex h-[56px] items-center justify-between border-b border-[#E5E5E5] bg-[#FFFFFF] px-4">
        <div className="flex min-w-0 items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-9 items-center justify-center rounded-[8px] bg-[#FF0000]">
              <Hand className="h-4 w-4 text-[#FFFFFF]" />
            </div>
            <span className="text-[20px] font-bold tracking-tight">RedHand</span>
          </div>
          <nav className="flex gap-1 overflow-x-auto whitespace-nowrap text-[13px]">
            <Link href="/passports" className="rounded-full px-3 py-1.5 font-medium text-[#606060] hover:bg-[#F2F2F2]">
              Passports
            </Link>
            <Link href="/blackbox" className="rounded-full px-3 py-1.5 font-medium text-[#606060] hover:bg-[#F2F2F2]">
              Black Box
            </Link>
            <Link href="/honeytokens" className="rounded-full bg-[#0F0F0F] px-3 py-1.5 font-semibold text-[#FFFFFF]">
              Honeytokens
            </Link>
            <Link href="/scanner" className="rounded-full px-3 py-1.5 font-medium text-[#606060] hover:bg-[#F2F2F2]">
              MCP Scanner
            </Link>
            <Link href="/radar" className="rounded-full px-3 py-1.5 font-medium text-[#606060] hover:bg-[#F2F2F2]">
              Radar
            </Link>
            <Link href="/coverage" className="rounded-full px-3 py-1.5 font-medium text-[#606060] hover:bg-[#F2F2F2]">
              Coverage
            </Link>
          </nav>
        </div>
        <div className="flex items-center gap-3 text-[12px]">
          <span className="hidden text-[#606060] sm:inline">
            {session.email}
            {session.role ? ` · ${session.role.replace("_", " ")}` : ""}
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

      <main className="mx-auto max-w-5xl px-4 py-6">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h1 className="text-[18px] font-bold">Honeytokens and decoy tools</h1>
            <p className="text-[12px] text-[#606060]">
              Bait that only a misbehaving agent would touch. RedHand sees it only when it flows through the
              RedHand gateway: it says nothing about agents, keys or tools used outside it.
            </p>
          </div>
          <button
            onClick={() => load()}
            className="flex items-center gap-1.5 rounded-full border border-[#E5E5E5] bg-[#FFFFFF] px-3 py-1.5 text-[12px] font-semibold hover:bg-[#F2F2F2]"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>

        {error ? <div className="mb-3 rounded-[8px] border border-[#FDECEC] bg-[#FFF5F5] px-3 py-2 text-[12px] text-[#B42318]">{error}</div> : null}
        {notice ? <div className="mb-3 rounded-[8px] border border-[#E6F4EA] bg-[#F3FBF5] px-3 py-2 text-[12px] text-[#1E7B34]">{notice}</div> : null}

        {revealed ? (
          <div className="mb-4 rounded-[10px] border border-[#FFE0B2] bg-[#FFF8EC] p-4 text-[12px]">
            <div className="mb-1 font-semibold">Copy it now: this value is shown only once.</div>
            <p className="mb-2 text-[#8A5A00]">
              Plant it where only a misbehaving agent would find it (a decoy file, a decoy database row). RedHand keeps
              only a fingerprint, so it cannot show it to you again.
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded-[8px] bg-[#FFFFFF] px-2 py-1.5 font-mono">{revealed.value}</code>
              <button
                onClick={() => navigator.clipboard?.writeText(revealed.value)}
                className="flex items-center gap-1 rounded-full border border-[#E5E5E5] bg-[#FFFFFF] px-3 py-1.5 font-semibold hover:bg-[#F2F2F2]"
              >
                <Copy className="h-3.5 w-3.5" /> Copy
              </button>
              <button
                onClick={() => setRevealed(null)}
                className="rounded-full bg-[#0F0F0F] px-3 py-1.5 font-semibold text-[#FFFFFF]"
              >
                I have saved it
              </button>
            </div>
          </div>
        ) : null}

        <section className="mb-6 rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4 text-[12px]">
          <h2 className="mb-3 text-[14px] font-semibold">Honeytokens (fake credentials)</h2>
          <div className="mb-4 flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1">
              <span className="text-[#606060]">Label</span>
              <input value={label} maxLength={64} onChange={(e) => setLabel(e.target.value)} placeholder="Decoy key in .env" className={`${field} w-52`} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[#606060]">Looks like</span>
              <select value={kind} onChange={(e) => setKind(e.target.value as HoneytokenKind)} className={field}>
                {(Object.keys(KIND_LABEL) as HoneytokenKind[]).map((k) => (
                  <option key={k} value={k}>{KIND_LABEL[k]}</option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[#606060]">If an agent USES it</span>
              <select value={onUse} onChange={(e) => setOnUse(e.target.value as HoneyAction)} className={field}>
                <option value="freeze">Refuse the call, alert, freeze the agent</option>
                <option value="alert">Refuse the call and alert</option>
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[#606060]">If it shows up in a RESULT</span>
              <select value={onRead} onChange={(e) => setOnRead(e.target.value as HoneyAction)} className={field}>
                <option value="alert">Alert</option>
                <option value="freeze">Alert and freeze the agent</option>
              </select>
            </label>
            <button
              onClick={createToken} disabled={busy || label.trim().length === 0}
              className="rounded-full bg-[#0F0F0F] px-3 py-1.5 font-semibold text-[#FFFFFF] disabled:opacity-40"
            >
              Create honeytoken
            </button>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#E5E5E5] text-left text-[#606060]">
                <th className="py-2">Label</th><th>Kind</th><th>Ends in</th><th>On use / on read</th><th>Last tripped</th><th>Trips</th><th />
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => (
                <tr key={t.id} className={`border-b border-[#F2F2F2] last:border-0 ${t.status === "retired" ? "opacity-50" : ""}`}>
                  <td className="py-2">{t.label}</td>
                  <td>{KIND_LABEL[t.kind]}</td>
                  <td className="font-mono">…{t.hint}</td>
                  <td>{t.action_on_use} / {t.action_on_read}</td>
                  <td>{when(t.last_tripped_at)}</td>
                  <td>{t.trip_count}</td>
                  <td className="text-right">
                    {t.status === "active" ? (
                      <button
                        disabled={busy}
                        onClick={() => {
                          if (!window.confirm(`Retire "${t.label}"? It will stop tripping.`)) return;
                          run(async () => {
                            await honeyApi.retireToken(token, t.id);
                          });
                        }}
                        className="rounded-full border border-[#E5E5E5] px-3 py-1 font-semibold hover:bg-[#F2F2F2] disabled:opacity-50"
                      >
                        Retire
                      </button>
                    ) : (
                      "retired"
                    )}
                  </td>
                </tr>
              ))}
              {tokens.length === 0 ? (
                <tr><td colSpan={7} className="py-4 text-center text-[#606060]">No honeytokens yet.</td></tr>
              ) : null}
            </tbody>
          </table>
        </section>

        <section className="rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4 text-[12px]">
          <h2 className="mb-1 text-[14px] font-semibold">Decoy tools</h2>
          <p className="mb-3 text-[#606060]">
            A tempting tool added to one agent&apos;s tool list on one MCP server (for example
            &quot;export_all_customer_records&quot;). A call to it is never forwarded. An honest agent can call a
            tempting tool when a user asks for exactly that, so expect some false alarms: the default is to alert, not freeze.
          </p>
          <div className="mb-4 flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1">
              <span className="text-[#606060]">Agent</span>
              <select value={toolAgent} onChange={(e) => setToolAgent(e.target.value)} className={field}>
                <option value="">Choose…</option>
                {agents.map((a) => (
                  <option key={a.id} value={a.id}>{a.name}</option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[#606060]">MCP server slug</span>
              <input value={toolServer} onChange={(e) => setToolServer(e.target.value)} placeholder="xero" className={`${field} w-28`} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[#606060]">Tool name</span>
              <input value={toolName} maxLength={64} onChange={(e) => setToolName(e.target.value)} placeholder="export_all_customer_records" className={`${field} w-56`} />
              {toolName.trim() && !toolNameValid ? (
                <span className="text-[#B42318]">Letters, digits and underscores only (no spaces), starting with a letter, 3 to 64 characters.</span>
              ) : null}
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[#606060]">Description the agent sees</span>
              <input value={toolDescription} maxLength={300} onChange={(e) => setToolDescription(e.target.value)} className={`${field} w-64`} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[#606060]">When called</span>
              <select value={toolAction} onChange={(e) => setToolAction(e.target.value as HoneyAction)} className={field}>
                <option value="alert">Alert</option>
                <option value="freeze">Alert and freeze the agent</option>
              </select>
            </label>
            <button
              onClick={createTool}
              disabled={busy || !toolAgent || !toolServer.trim() || !toolNameValid || !toolDescription.trim()}
              className="rounded-full bg-[#0F0F0F] px-3 py-1.5 font-semibold text-[#FFFFFF] disabled:opacity-40"
            >
              Add decoy tool
            </button>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#E5E5E5] text-left text-[#606060]">
                <th className="py-2">Tool</th><th>Agent</th><th>Server</th><th>When called</th><th>Last tripped</th><th>Trips</th><th />
              </tr>
            </thead>
            <tbody>
              {tools.map((t) => (
                <tr key={t.id} className={`border-b border-[#F2F2F2] last:border-0 ${t.status === "retired" ? "opacity-50" : ""}`}>
                  <td className="py-2 font-mono">{t.name}</td>
                  <td>{agentName(t.agent_id)}</td>
                  <td>{t.server}</td>
                  <td>{t.action}</td>
                  <td>{when(t.last_tripped_at)}</td>
                  <td>{t.trip_count}</td>
                  <td className="text-right">
                    {t.status === "active" ? (
                      <button
                        disabled={busy}
                        onClick={() => {
                          if (!window.confirm(`Remove the decoy tool "${t.name}"?`)) return;
                          run(async () => {
                            await honeyApi.retireTool(token, t.id);
                          });
                        }}
                        className="rounded-full border border-[#E5E5E5] px-3 py-1 font-semibold hover:bg-[#F2F2F2] disabled:opacity-50"
                      >
                        Remove
                      </button>
                    ) : (
                      "removed"
                    )}
                  </td>
                </tr>
              ))}
              {tools.length === 0 ? (
                <tr><td colSpan={7} className="py-4 text-center text-[#606060]">No decoy tools yet.</td></tr>
              ) : null}
            </tbody>
          </table>
        </section>
      </main>
    </div>
  );
}
