"use client";

/**
 * Tool pinning for one registered server (Phase 4 M3): approve or reject the tool versions the gateway has seen, and choose
 * what the gateway does about changes. Everything a server says about a tool is untrusted and is shown as plain text only.
 * The UI is never a security boundary: redhand-core decides who may approve or change the mode.
 */

import React, { useCallback, useEffect, useState } from "react";

import { ApiError, type PinMode, type ToolPin, type ToolPins, pinsApi } from "@/lib/api";

const MODE_HELP: Record<PinMode, string> = {
  off: "No checks. Changes to this server's tools are not noticed.",
  alert: "Changes are reported to you. Agents still see and can call every tool. (Default.)",
  enforce:
    "Agents see and can call only tools whose CURRENT version you approved. A changed or new tool is hidden and refused until you approve it. Approve the current tools first, or agents lose access to them.",
};

const STATUS_STYLE: Record<string, string> = {
  pending: "bg-rh-ochre-wash text-rh-ochre",
  approved: "bg-rh-teal-wash text-rh-teal-text",
  rejected: "bg-rh-crimson-wash text-rh-crimson-text",
  superseded: "bg-rh-elevated text-rh-text-2",
};

function Text({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 flex-1">
      <div className="mb-0.5 text-[11px] font-semibold text-rh-text-2">{label}</div>
      <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-[8px] bg-rh-subtle p-2 font-mono text-[11px]">
        {value || "(empty)"}
      </pre>
    </div>
  );
}

export function ToolPinsPanel({ token, serverId, onUnauthorized }: { token: string; serverId: string; onUnauthorized: () => void }) {
  const [data, setData] = useState<ToolPins | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const fail = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized();
        return;
      }
      setError(err instanceof Error ? err.message : "Something went wrong.");
    },
    [onUnauthorized]
  );

  const load = useCallback(async () => {
    try {
      setData(await pinsApi.list(token, serverId));
    } catch (err) {
      fail(err);
    }
  }, [token, serverId, fail]);

  useEffect(() => {
    load();
  }, [load]);

  const act = async (action: () => Promise<string>) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(await action());
      await load();
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  if (!data) return <div className="p-3 text-rh-text-2">{error ?? "Loading…"}</div>;

  const changeMode = (mode: PinMode) => {
    if (mode === data.pin_mode) return;
    const extra = mode === "enforce" ? `\n\n${data.pending_count} tool version(s) are still pending and would be hidden from agents.` : "";
    if (!window.confirm(`Set tool pinning to "${mode}"?\n\n${MODE_HELP[mode]}${extra}`)) return;
    act(async () => {
      await pinsApi.setMode(token, serverId, mode, "");
      return `Tool pinning is now ${mode}.`;
    });
  };

  return (
    <div className="border-t border-rh-hairline bg-rh-subtle p-3">
      {error ? <div className="mb-2 rounded-[8px] border border-rh-crimson bg-rh-crimson-wash px-3 py-2 text-rh-crimson-text">{error}</div> : null}
      {notice ? <div className="mb-2 rounded-[8px] border border-rh-teal bg-rh-teal-wash px-3 py-2 text-rh-teal-text">{notice}</div> : null}

      <div className="mb-3 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2">
          <span className="font-semibold">Mode</span>
          <select
            value={data.pin_mode} disabled={busy} onChange={(e) => changeMode(e.target.value as PinMode)}
            className="rounded-[8px] border border-rh-hairline bg-rh-card px-2 py-1"
          >
            <option value="off">off</option>
            <option value="alert">alert</option>
            <option value="enforce">enforce</option>
          </select>
        </label>
        <span className="text-rh-text-2">{MODE_HELP[data.pin_mode]}</span>
        {data.pending_count > 0 ? (
          <button
            disabled={busy}
            onClick={() => {
              if (!window.confirm(`Approve the newest pending version of every tool on this server (${data.pending_count} pending)? Only do this if you have reviewed them.`)) return;
              act(async () => `Approved ${(await pinsApi.approveAll(token, serverId, "")).approved} tool(s).`);
            }}
            className="ml-auto rounded-full border border-rh-hairline bg-rh-card px-3 py-1.5 font-semibold hover:bg-rh-elevated disabled:opacity-50"
          >
            Approve all pending
          </button>
        ) : null}
      </div>

      {data.pins.length === 0 ? (
        <p className="text-rh-text-2">
          No tool versions yet. They appear when an agent lists this server&apos;s tools through the gateway.
        </p>
      ) : (
        <ul className="space-y-3">
          {data.pins.map((p: ToolPin) => (
            <li key={p.id} className="rh-glass rounded-rh-sm p-3">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <span className="font-mono font-semibold">{p.tool_name}</span>
                <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${STATUS_STYLE[p.status] ?? ""}`}>{p.status}</span>
                <span className="text-rh-text-2">{p.change_kind === "changed" ? "changed since you approved it" : "new tool"}</span>
                {p.rules.length > 0 ? <span className="text-[11px] text-rh-crimson-text">rules: {p.rules.join(", ")}</span> : null}
                {p.status === "pending" ? (
                  <span className="ml-auto flex gap-2">
                    <button
                      disabled={busy}
                      onClick={() => act(async () => { await pinsApi.decide(token, p.id, "reject", ""); return `Rejected ${p.tool_name}.`; })}
                      className="rounded-full border border-rh-hairline px-3 py-1 font-semibold hover:bg-rh-elevated disabled:opacity-50"
                    >
                      Reject
                    </button>
                    <button
                      disabled={busy}
                      onClick={() => act(async () => { await pinsApi.decide(token, p.id, "approve", ""); return `Approved ${p.tool_name}.`; })}
                      className="rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-3 py-1 font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-50"
                    >
                      Approve
                    </button>
                  </span>
                ) : null}
              </div>
              <div className="flex flex-wrap gap-3">
                {p.approved_description !== null ? <Text label="Approved description" value={p.approved_description} /> : null}
                <Text label={p.approved_description !== null ? "New description" : "Description"} value={p.description} />
              </div>
              {p.approved_schema_text !== null && p.approved_schema_text !== p.schema_text ? (
                <div className="mt-2 flex flex-wrap gap-3">
                  <Text label="Approved input schema" value={p.approved_schema_text} />
                  <Text label="New input schema" value={p.schema_text} />
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
