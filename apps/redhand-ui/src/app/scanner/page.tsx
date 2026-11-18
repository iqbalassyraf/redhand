"use client";

/**
 * MCP Scanner (Phase 4 M2): check a tool server before agents use it. Paste a manifest, or scan a server registered in
 * RedHand. Everything in a result that came from the server is untrusted and is shown as plain text only. The UI is never
 * a security boundary: redhand-core decides who may scan what.
 */

import React, { useCallback, useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";

import { ToolPinsPanel } from "@/components/scanner/ToolPinsPanel";
import {
  ApiError,
  type McpServer,
  type ScanResult,
  type ScanSeverity,
  passportsApi,
  scannerApi,
} from "@/lib/api";
import { useAuth, useRequiredSession } from "@/lib/auth";
import { AppShell } from "@/components/shell/AppShell";

const SEVERITY_STYLE: Record<ScanSeverity, string> = {
  CRITICAL: "bg-rh-crimson-wash text-rh-crimson-text",
  HIGH: "bg-rh-crimson-wash text-rh-crimson-text",
  MEDIUM: "bg-rh-ochre-wash text-rh-ochre",
  LOW: "bg-rh-elevated text-rh-text-2",
  INFO: "bg-rh-elevated text-rh-text-2",
};
const VERDICT_STYLE = {
  PASS: "bg-rh-teal-wash text-rh-teal-text",
  WARN: "bg-rh-ochre-wash text-rh-ochre",
  FAIL: "bg-rh-crimson-wash text-rh-crimson-text",
} as const;
const MAX_MANIFEST_CHARS = 250_000;


export default function ScannerPage() {
  const session = useRequiredSession();
  const { signOut } = useAuth();
  const token = session?.token ?? null;

  const [servers, setServers] = useState<McpServer[]>([]);
  const [manifestText, setManifestText] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [openPins, setOpenPins] = useState<string | null>(null);

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
    try {
      setServers((await passportsApi.servers(token)).filter((s) => s.is_active));
    } catch (err) {
      handleError(err);
    }
  }, [token, handleError]);

  useEffect(() => {
    load();
  }, [load]);

  if (!session || !token) return null;

  const run = async (label: string, action: () => Promise<ScanResult>) => {
    setBusy(label);
    setError(null);
    setResult(null);
    try {
      setResult(await action());
    } catch (err) {
      handleError(err);
    } finally {
      setBusy(null);
    }
  };

  const checkManifest = () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(manifestText);
    } catch {
      setError("That is not valid JSON.");
      return;
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      setError("A manifest is a JSON object.");
      return;
    }
    run("manifest", () => scannerApi.vetManifest(parsed));
  };

  return (
    <AppShell title="MCP Scanner" role={session.role}>

      <div className="mx-auto max-w-5xl px-4 py-6 text-[12px]">
        <div className="mb-4">
          <h1 className="text-[18px] font-bold">MCP Scanner</h1>
          <p className="text-rh-text-2">
            Check a tool server before agents use it: hidden instructions in tool descriptions, risky tools and weak schemas. Tool pins
            notice when a server changes a tool after you approved it.
            Rules catch known patterns and miss rephrased attacks, so a pass is not a guarantee. RedHand only covers agents
            that connect through the RedHand gateway.
          </p>
        </div>

        {error ? <div className="mb-3 rounded-[8px] border border-rh-crimson bg-rh-crimson-wash px-3 py-2 text-rh-crimson-text">{error}</div> : null}

        <section className="rh-glass mb-4 rounded-rh-md p-4">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-[14px] font-semibold">Scan a registered server</h2>
            <button onClick={() => load()} className="flex items-center gap-1 rounded-full border border-rh-hairline px-3 py-1 font-semibold hover:bg-rh-elevated">
              <RefreshCw className="h-3.5 w-3.5" /> Refresh
            </button>
          </div>
          <p className="mb-3 text-rh-text-2">
            RedHand asks the server for its tool list the way an agent would, through the gateway&apos;s safety checks (public
            addresses only). Admins only. A server that needs credentials to list its tools cannot be scanned.
          </p>
          {servers.length === 0 ? (
            <p className="text-rh-text-2">No registered servers. Register one on the Passports page first.</p>
          ) : (
            <ul className="divide-y divide-rh-hairline">
              {servers.map((s) => (
                <li key={s.id} className="py-2">
                  <div className="flex items-center justify-between">
                    <span>
                      <span className="font-semibold">{s.name}</span> <span className="text-rh-text-2">({s.slug})</span>
                    </span>
                    <span className="flex gap-2">
                      <button
                        onClick={() => setOpenPins(openPins === s.id ? null : s.id)}
                        className="rounded-full border border-rh-hairline px-3 py-1.5 font-semibold hover:bg-rh-elevated"
                      >
                        {openPins === s.id ? "Hide tool pins" : "Tool pins"}
                      </button>
                      <button
                        disabled={busy !== null}
                        onClick={() => run(s.id, () => scannerApi.scanServer(token, s.id))}
                        className="rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-3 py-1.5 font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-50"
                      >
                        {busy === s.id ? "Scanning…" : "Scan"}
                      </button>
                    </span>
                  </div>
                  {openPins === s.id ? (
                    <div className="mt-2 overflow-hidden rounded-[8px] border border-rh-hairline">
                      <ToolPinsPanel
                        token={token}
                        serverId={s.id}
                        onUnauthorized={() => {
                          signOut("/login");
                        }}
                      />
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="rh-glass mb-4 rounded-rh-md p-4">
          <h2 className="mb-2 text-[14px] font-semibold">Check a pasted manifest</h2>
          <p className="mb-2 text-rh-text-2">
            Paste an MCP server manifest as JSON (name, command, args, env, tools). Nothing is fetched or stored. Do not paste real
            credentials.
          </p>
          <textarea
            value={manifestText}
            maxLength={MAX_MANIFEST_CHARS}
            onChange={(e) => setManifestText(e.target.value)}
            rows={8}
            spellCheck={false}
            placeholder='{"name": "my-server", "command": "node", "args": ["server.js"], "tools": [{"name": "lookup", "description": "…", "inputSchema": {}}]}'
            className="mb-2 w-full rounded-[8px] border border-rh-hairline p-2 font-mono text-[11px]"
          />
          <button
            disabled={busy !== null || manifestText.trim().length === 0}
            onClick={checkManifest}
            className="rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-3 py-1.5 font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-40"
          >
            {busy === "manifest" ? "Checking…" : "Check manifest"}
          </button>
        </section>

        {result ? <ResultView result={result} /> : null}
      </div>
    </AppShell>
  );
}

function ResultView({ result }: { result: ScanResult }) {
  const high = result.findings.filter((f) => f.severity === "HIGH" || f.severity === "CRITICAL").length;
  return (
    <section className="rh-glass rounded-rh-md p-4" aria-label="Scan result">
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <span className={`rounded-full px-3 py-1 text-[13px] font-bold ${VERDICT_STYLE[result.verdict]}`}>{result.verdict}</span>
        <span>
          Risk score <strong>{result.risk_score}</strong> of 100
        </span>
        <span className="text-rh-text-2">
          {result.tool_count} tool(s) scanned · {result.findings.length + result.findings_omitted} finding(s) ({high} high) · {result.source}
        </span>
      </div>
      {result.truncated ? (
        <div className="mb-3 rounded-[8px] border border-rh-ochre bg-rh-ochre-wash px-3 py-2 text-rh-ochre">
          The server has more tools than the scanner reads. The rest were not scanned.
        </div>
      ) : null}
      {result.findings.length === 0 ? (
        <p className="text-rh-text-2">No findings. This is not a guarantee: rules catch known patterns only.</p>
      ) : (
        <table className="w-full">
          <thead>
            <tr className="border-b border-rh-hairline text-left text-rh-text-2">
              <th className="py-2">Severity</th>
              <th>Tool</th>
              <th>Finding</th>
              <th>What to do</th>
            </tr>
          </thead>
          <tbody>
            {result.findings.map((f, i) => (
              <tr key={`${f.id}-${i}`} className="border-b border-rh-hairline align-top last:border-0">
                <td className="py-2">
                  <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${SEVERITY_STYLE[f.severity]}`}>{f.severity}</span>
                </td>
                <td className="font-mono">{f.tool_name ?? "(server)"}</td>
                <td>
                  <div className="font-semibold">{f.title}</div>
                  <div className="text-rh-text-2">{f.description}</div>
                  <div className="text-[11px] text-rh-text-2">{f.id}</div>
                </td>
                <td className="text-rh-text-2">{f.remediation}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {result.findings_omitted > 0 ? <p className="mt-2 text-rh-text-2">{result.findings_omitted} more finding(s) not shown.</p> : null}
      <p className="mt-3 text-rh-text-2">{result.limits}</p>
    </section>
  );
}
