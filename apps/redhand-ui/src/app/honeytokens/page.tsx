"use client";

/**
 * Honeytokens and decoy tools (Phase 3 M3/M4): fake credentials and fake tools that only a misbehaving agent
 * would touch. A honeytoken's value is shown once, when it is created. The UI is never a security boundary:
 * redhand-core decides who may create or retire anything.
 */

import React, { useCallback, useEffect, useState } from "react";
import { Copy, RefreshCw } from "lucide-react";

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
import { AppShell } from "@/components/shell/AppShell";
import { CANARY_LABEL, CANARY_LIMITS, actionsFor, canarySentence } from "@/lib/canary";

const KIND_LABEL: Record<HoneytokenKind, string> = {
  api_key: "API key (sk_live_…)",
  aws_key: "AWS-style key (AKIA…)",
  password: "Password (24 characters)",
  canary: "System-prompt canary",
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

  // Choosing the canary kind sets its safer defaults (refuse and alert, never freeze); the admin may still change them.
  const changeKind = (next: HoneytokenKind) => {
    setKind(next);
    const defaults = actionsFor(next);
    setOnUse(defaults.onUse);
    setOnRead(defaults.onRead);
  };
  const fillCanaryPreset = () => {
    setLabel(CANARY_LABEL);
    changeKind("canary");
  };

  const [toolAgent, setToolAgent] = useState("");
  const [toolServer, setToolServer] = useState("");
  const [toolName, setToolName] = useState("");
  const [toolDescription, setToolDescription] = useState("");
  const [toolAction, setToolAction] = useState<HoneyAction>("alert");

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        signOut("/login");
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
  const field = "rounded-[8px] border border-rh-hairline px-2 py-1 text-[12px]";
  const agentName = (id: string) => agents.find((a) => a.id === id)?.name ?? id.slice(0, 8);

  return (
    <AppShell title="Honeytokens" role={session.role}>

      <div className="mx-auto max-w-5xl px-4 py-6">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h1 className="text-[18px] font-bold">Honeytokens and decoy tools</h1>
            <p className="text-[12px] text-rh-text-2">
              Bait that only a misbehaving agent would touch. RedHand sees it only when it flows through the
              RedHand gateway: it says nothing about agents, keys or tools used outside it.
            </p>
          </div>
          <button
            onClick={() => load()}
            className="flex items-center gap-1.5 rounded-full border border-rh-hairline bg-rh-card px-3 py-1.5 text-[12px] font-semibold hover:bg-rh-elevated"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>

        {error ? <div className="mb-3 rounded-[8px] border border-rh-crimson bg-rh-crimson-wash px-3 py-2 text-[12px] text-rh-crimson-text">{error}</div> : null}
        {notice ? <div className="mb-3 rounded-[8px] border border-rh-teal bg-rh-teal-wash px-3 py-2 text-[12px] text-rh-teal-text">{notice}</div> : null}

        {revealed ? (
          <div className="mb-4 rounded-[10px] border border-rh-ochre bg-rh-ochre-wash p-4 text-[12px]">
            <div className="mb-1 font-semibold">
              {revealed.kind === "canary" ? "Copy this sentence now: the value in it is shown only once." : "Copy it now: this value is shown only once."}
            </div>
            <p className="mb-2 text-rh-ochre">
              {revealed.kind === "canary"
                ? "Paste it into the agent's system prompt. If that text later appears in a tool call or a tool answer that passes through RedHand, you are alerted. RedHand keeps only a fingerprint, so it cannot show it to you again."
                : "Plant it where only a misbehaving agent would find it (a decoy file, a decoy database row). RedHand keeps only a fingerprint, so it cannot show it to you again."}
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 break-all rounded-[8px] bg-rh-card px-2 py-1.5 font-mono">
                {revealed.kind === "canary" ? canarySentence(revealed.value) : revealed.value}
              </code>
              <button
                onClick={() => navigator.clipboard?.writeText(revealed.kind === "canary" ? canarySentence(revealed.value) : revealed.value)}
                className="flex items-center gap-1 rounded-full border border-rh-hairline bg-rh-card px-3 py-1.5 font-semibold hover:bg-rh-elevated"
              >
                <Copy className="h-3.5 w-3.5" /> Copy
              </button>
              <button
                onClick={() => setRevealed(null)}
                className="rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-3 py-1.5 font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep"
              >
                I have saved it
              </button>
            </div>
            {revealed.kind === "canary" ? (
              <ul className="mt-3 list-disc space-y-1 pl-5 text-rh-ochre">
                {CANARY_LIMITS.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            ) : null}
          </div>
        ) : null}

        <section className="rh-glass mb-6 rounded-rh-md p-4 text-[12px]">
          <h2 className="mb-1 text-[14px] font-semibold">Honeytokens (fake credentials) and system-prompt canaries</h2>
          <p className="mb-3 text-rh-text-2">
            A canary is a honeytoken you paste into an agent&apos;s own system prompt: if it later appears in a tool call or a tool answer,
            that prompt text appears to have leaked.
            <button
              onClick={fillCanaryPreset}
              className="ml-2 rounded-full border border-rh-hairline px-3 py-1 font-semibold hover:bg-rh-elevated"
            >
              Create a system-prompt canary
            </button>
          </p>
          <div className="mb-4 flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1">
              <span className="text-rh-text-2">Label</span>
              <input value={label} maxLength={64} onChange={(e) => setLabel(e.target.value)} placeholder="Decoy key in .env" className={`${field} w-52`} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-rh-text-2">Looks like</span>
              <select value={kind} onChange={(e) => changeKind(e.target.value as HoneytokenKind)} className={field}>
                {(Object.keys(KIND_LABEL) as HoneytokenKind[]).map((k) => (
                  <option key={k} value={k}>{KIND_LABEL[k]}</option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-rh-text-2">If an agent USES it</span>
              <select value={onUse} onChange={(e) => setOnUse(e.target.value as HoneyAction)} className={field}>
                <option value="freeze">Refuse the call, alert, freeze the agent</option>
                <option value="alert">Refuse the call and alert</option>
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-rh-text-2">If it shows up in a RESULT</span>
              <select value={onRead} onChange={(e) => setOnRead(e.target.value as HoneyAction)} className={field}>
                <option value="alert">Alert</option>
                <option value="freeze">Alert and freeze the agent</option>
              </select>
            </label>
            <button
              onClick={createToken} disabled={busy || label.trim().length === 0}
              className="rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-3 py-1.5 font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-40"
            >
              Create honeytoken
            </button>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-rh-hairline text-left text-rh-text-2">
                <th className="py-2">Label</th><th>Kind</th><th>Ends in</th><th>On use / on read</th><th>Last tripped</th><th>Trips</th><th />
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => (
                <tr key={t.id} className={`border-b border-rh-hairline last:border-0 ${t.status === "retired" ? "opacity-50" : ""}`}>
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
                        className="rounded-full border border-rh-hairline px-3 py-1 font-semibold hover:bg-rh-elevated disabled:opacity-50"
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
                <tr><td colSpan={7} className="py-4 text-center text-rh-text-2">No honeytokens yet.</td></tr>
              ) : null}
            </tbody>
          </table>
        </section>

        <section className="rh-glass rounded-rh-md p-4 text-[12px]">
          <h2 className="mb-1 text-[14px] font-semibold">Decoy tools</h2>
          <p className="mb-3 text-rh-text-2">
            A tempting tool added to one agent&apos;s tool list on one MCP server (for example
            &quot;export_all_customer_records&quot;). A call to it is never forwarded. An honest agent can call a
            tempting tool when a user asks for exactly that, so expect some false alarms: the default is to alert, not freeze.
          </p>
          <div className="mb-4 flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1">
              <span className="text-rh-text-2">Agent</span>
              <select value={toolAgent} onChange={(e) => setToolAgent(e.target.value)} className={field}>
                <option value="">Choose…</option>
                {agents.map((a) => (
                  <option key={a.id} value={a.id}>{a.name}</option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-rh-text-2">MCP server slug</span>
              <input value={toolServer} onChange={(e) => setToolServer(e.target.value)} placeholder="xero" className={`${field} w-28`} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-rh-text-2">Tool name</span>
              <input value={toolName} maxLength={64} onChange={(e) => setToolName(e.target.value)} placeholder="export_all_customer_records" className={`${field} w-56`} />
              {toolName.trim() && !toolNameValid ? (
                <span className="text-rh-crimson-text">Letters, digits and underscores only (no spaces), starting with a letter, 3 to 64 characters.</span>
              ) : null}
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-rh-text-2">Description the agent sees</span>
              <input value={toolDescription} maxLength={300} onChange={(e) => setToolDescription(e.target.value)} className={`${field} w-64`} />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-rh-text-2">When called</span>
              <select value={toolAction} onChange={(e) => setToolAction(e.target.value as HoneyAction)} className={field}>
                <option value="alert">Alert</option>
                <option value="freeze">Alert and freeze the agent</option>
              </select>
            </label>
            <button
              onClick={createTool}
              disabled={busy || !toolAgent || !toolServer.trim() || !toolNameValid || !toolDescription.trim()}
              className="rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-3 py-1.5 font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-40"
            >
              Add decoy tool
            </button>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-rh-hairline text-left text-rh-text-2">
                <th className="py-2">Tool</th><th>Agent</th><th>Server</th><th>When called</th><th>Last tripped</th><th>Trips</th><th />
              </tr>
            </thead>
            <tbody>
              {tools.map((t) => (
                <tr key={t.id} className={`border-b border-rh-hairline last:border-0 ${t.status === "retired" ? "opacity-50" : ""}`}>
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
                        className="rounded-full border border-rh-hairline px-3 py-1 font-semibold hover:bg-rh-elevated disabled:opacity-50"
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
                <tr><td colSpan={7} className="py-4 text-center text-rh-text-2">No decoy tools yet.</td></tr>
              ) : null}
            </tbody>
          </table>
        </section>
      </div>
    </AppShell>
  );
}
