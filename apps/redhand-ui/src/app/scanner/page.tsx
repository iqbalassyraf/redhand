"use client";

/**
 * MCP Scanner (Phase 4 M2): check a tool server before agents use it. Paste a manifest, or scan a server registered in
 * RedHand. Everything in a result that came from the server is untrusted and is shown as plain text only. The UI is never
 * a security boundary: redhand-core decides who may scan what.
 */

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Hand, LogOut, RefreshCw } from "lucide-react";

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

const SEVERITY_STYLE: Record<ScanSeverity, string> = {
  CRITICAL: "bg-[#FDECEC] text-[#B42318]",
  HIGH: "bg-[#FDECEC] text-[#B42318]",
  MEDIUM: "bg-[#FFF4E5] text-[#8A5A00]",
  LOW: "bg-[#F2F2F2] text-[#606060]",
  INFO: "bg-[#F2F2F2] text-[#606060]",
};
const VERDICT_STYLE = {
  PASS: "bg-[#E6F4EA] text-[#1E7B34]",
  WARN: "bg-[#FFF4E5] text-[#8A5A00]",
  FAIL: "bg-[#FDECEC] text-[#B42318]",
} as const;
const MAX_MANIFEST_CHARS = 250_000;

function NavLink({ href, label, active }: { href: string; label: string; active?: boolean }) {
  return (
    <Link
      href={href}
      className={`rounded-full px-3 py-1.5 ${active ? "bg-[#0F0F0F] font-semibold text-[#FFFFFF]" : "font-medium text-[#606060] hover:bg-[#F2F2F2]"}`}
    >
      {label}
    </Link>
  );
}

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
            <NavLink href="/passports" label="Passports" />
            <NavLink href="/blackbox" label="Black Box" />
            <NavLink href="/honeytokens" label="Honeytokens" />
            <NavLink href="/scanner" label="MCP Scanner" active />
          </nav>
        </div>
        <div className="flex items-center gap-3 text-[12px]">
          <span className="text-[#606060]">
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

      <main className="mx-auto max-w-5xl px-4 py-6 text-[12px]">
        <div className="mb-4">
          <h1 className="text-[18px] font-bold">MCP Scanner</h1>
          <p className="text-[#606060]">
            Check a tool server before agents use it: hidden instructions in tool descriptions, risky tools and weak schemas. Tool pins
            notice when a server changes a tool after you approved it.
            Rules catch known patterns and miss rephrased attacks, so a pass is not a guarantee. RedHand only covers agents
            that connect through the RedHand gateway.
          </p>
        </div>

        {error ? <div className="mb-3 rounded-[8px] border border-[#FDECEC] bg-[#FFF5F5] px-3 py-2 text-[#B42318]">{error}</div> : null}

        <section className="mb-4 rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-[14px] font-semibold">Scan a registered server</h2>
            <button onClick={() => load()} className="flex items-center gap-1 rounded-full border border-[#E5E5E5] px-3 py-1 font-semibold hover:bg-[#F2F2F2]">
              <RefreshCw className="h-3.5 w-3.5" /> Refresh
            </button>
          </div>
          <p className="mb-3 text-[#606060]">
            RedHand asks the server for its tool list the way an agent would, through the gateway&apos;s safety checks (public
            addresses only). Admins only. A server that needs credentials to list its tools cannot be scanned.
          </p>
          {servers.length === 0 ? (
            <p className="text-[#606060]">No registered servers. Register one on the Passports page first.</p>
          ) : (
            <ul className="divide-y divide-[#F2F2F2]">
              {servers.map((s) => (
                <li key={s.id} className="py-2">
                  <div className="flex items-center justify-between">
                    <span>
                      <span className="font-semibold">{s.name}</span> <span className="text-[#606060]">({s.slug})</span>
                    </span>
                    <span className="flex gap-2">
                      <button
                        onClick={() => setOpenPins(openPins === s.id ? null : s.id)}
                        className="rounded-full border border-[#E5E5E5] px-3 py-1.5 font-semibold hover:bg-[#F2F2F2]"
                      >
                        {openPins === s.id ? "Hide tool pins" : "Tool pins"}
                      </button>
                      <button
                        disabled={busy !== null}
                        onClick={() => run(s.id, () => scannerApi.scanServer(token, s.id))}
                        className="rounded-full bg-[#0F0F0F] px-3 py-1.5 font-semibold text-[#FFFFFF] disabled:opacity-50"
                      >
                        {busy === s.id ? "Scanning…" : "Scan"}
                      </button>
                    </span>
                  </div>
                  {openPins === s.id ? (
                    <div className="mt-2 overflow-hidden rounded-[8px] border border-[#E5E5E5]">
                      <ToolPinsPanel
                        token={token}
                        serverId={s.id}
                        onUnauthorized={() => {
                          signOut();
                          window.location.href = "/login";
                        }}
                      />
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="mb-4 rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4">
          <h2 className="mb-2 text-[14px] font-semibold">Check a pasted manifest</h2>
          <p className="mb-2 text-[#606060]">
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
            className="mb-2 w-full rounded-[8px] border border-[#E5E5E5] p-2 font-mono text-[11px]"
          />
          <button
            disabled={busy !== null || manifestText.trim().length === 0}
            onClick={checkManifest}
            className="rounded-full bg-[#0F0F0F] px-3 py-1.5 font-semibold text-[#FFFFFF] disabled:opacity-40"
          >
            {busy === "manifest" ? "Checking…" : "Check manifest"}
          </button>
        </section>

        {result ? <ResultView result={result} /> : null}
      </main>
    </div>
  );
}

function ResultView({ result }: { result: ScanResult }) {
  const high = result.findings.filter((f) => f.severity === "HIGH" || f.severity === "CRITICAL").length;
  return (
    <section className="rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4" aria-label="Scan result">
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <span className={`rounded-full px-3 py-1 text-[13px] font-bold ${VERDICT_STYLE[result.verdict]}`}>{result.verdict}</span>
        <span>
          Risk score <strong>{result.risk_score}</strong> of 100
        </span>
        <span className="text-[#606060]">
          {result.tool_count} tool(s) scanned · {result.findings.length + result.findings_omitted} finding(s) ({high} high) · {result.source}
        </span>
      </div>
      {result.truncated ? (
        <div className="mb-3 rounded-[8px] border border-[#FFE0B2] bg-[#FFF8EC] px-3 py-2 text-[#8A5A00]">
          The server has more tools than the scanner reads. The rest were not scanned.
        </div>
      ) : null}
      {result.findings.length === 0 ? (
        <p className="text-[#606060]">No findings. This is not a guarantee: rules catch known patterns only.</p>
      ) : (
        <table className="w-full">
          <thead>
            <tr className="border-b border-[#E5E5E5] text-left text-[#606060]">
              <th className="py-2">Severity</th>
              <th>Tool</th>
              <th>Finding</th>
              <th>What to do</th>
            </tr>
          </thead>
          <tbody>
            {result.findings.map((f, i) => (
              <tr key={`${f.id}-${i}`} className="border-b border-[#F2F2F2] align-top last:border-0">
                <td className="py-2">
                  <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${SEVERITY_STYLE[f.severity]}`}>{f.severity}</span>
                </td>
                <td className="font-mono">{f.tool_name ?? "(server)"}</td>
                <td>
                  <div className="font-semibold">{f.title}</div>
                  <div className="text-[#606060]">{f.description}</div>
                  <div className="text-[11px] text-[#909090]">{f.id}</div>
                </td>
                <td className="text-[#606060]">{f.remediation}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {result.findings_omitted > 0 ? <p className="mt-2 text-[#606060]">{result.findings_omitted} more finding(s) not shown.</p> : null}
      <p className="mt-3 text-[#606060]">{result.limits}</p>
    </section>
  );
}
