"use client";

/**
 * Black Box Recorder: the organization's timeline of what the gateway allowed, refused or failed
 * to forward, plus a Verify button that proves the record was not altered (Phase 3 M1).
 */

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Download, Hand, LogOut, RefreshCw, ShieldCheck } from "lucide-react";

import { EventDrawer } from "@/components/blackbox/EventDrawer";
import { SettingsPanel } from "@/components/blackbox/SettingsPanel";
import {
  ApiError,
  type BlackBoxDecision,
  type BlackBoxEvent,
  type BlackBoxSettings,
  blackboxApi,
  downloadBlackBoxExport,
} from "@/lib/api";
import { useAuth, useRequiredSession } from "@/lib/auth";

const DECISION_STYLE: Record<BlackBoxDecision, string> = {
  ALLOW: "bg-[#E6F4EA] text-[#1E7B34]",
  BLOCK: "bg-[#FDECEC] text-[#B42318]",
  ERROR: "bg-[#FFF4E5] text-[#8A5A00]",
};

function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export default function BlackBoxPage() {
  const session = useRequiredSession();
  const { signOut } = useAuth();
  const token = session?.token ?? null;

  const [events, setEvents] = useState<BlackBoxEvent[]>([]);
  const [nextBeforeSeq, setNextBeforeSeq] = useState<number | null>(null);
  const [decisionFilter, setDecisionFilter] = useState<BlackBoxDecision | "">("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [settings, setSettings] = useState<BlackBoxSettings | null>(null);
  const [settingsBusy, setSettingsBusy] = useState(false);
  const [selected, setSelected] = useState<BlackBoxEvent | null>(null);
  const [exportFormat, setExportFormat] = useState<"jsonl" | "csv">("jsonl");
  const [exportPayloads, setExportPayloads] = useState(false);
  const [exporting, setExporting] = useState(false);

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

  const load = useCallback(
    async (opts: { reset?: boolean; beforeSeq?: number } = {}) => {
      if (!token) return;
      setLoading(true);
      setError(null);
      try {
        const page = await blackboxApi.events(token, {
          decision: decisionFilter || undefined,
          before_seq: opts.beforeSeq,
          limit: 50,
        });
        setEvents((prev) => (opts.reset ? page.events : [...prev, ...page.events]));
        setNextBeforeSeq(page.next_before_seq);
      } catch (err) {
        handleError(err);
      } finally {
        setLoading(false);
      }
    },
    [token, decisionFilter, handleError]
  );

  const loadSettings = useCallback(async () => {
    if (!token) return;
    try {
      setSettings(await blackboxApi.settings(token));
    } catch (err) {
      handleError(err);
    }
  }, [token, handleError]);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  // Runs a settings change and shows what the server answered; the server decides, the UI only reports.
  const changeSettings = async (action: () => Promise<BlackBoxSettings | { cleared: number }>, done: string) => {
    setSettingsBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await action();
      setNotice("cleared" in result ? `Deleted payloads from ${result.cleared} event(s).` : done);
      await loadSettings();
    } catch (err) {
      handleError(err);
    } finally {
      setSettingsBusy(false);
    }
  };

  const onExport = async () => {
    if (!token) return;
    setExporting(true);
    setError(null);
    setNotice(null);
    try {
      await downloadBlackBoxExport(token, {
        format: exportFormat,
        includePayloads: exportPayloads && !!settings?.capabilities?.can_export_payloads,
        decision: decisionFilter || undefined,
      });
      setNotice("Export downloaded. It was recorded in the audit log. Handle it as customer data.");
    } catch (err) {
      handleError(err);
    } finally {
      setExporting(false);
    }
  };

  useEffect(() => {
    load({ reset: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, decisionFilter]);

  const onVerify = async () => {
    if (!token || events.length === 0) return;
    setVerifying(true);
    setError(null);
    setNotice(null);
    try {
      const newestSeq = events[0].seq;
      const result = await blackboxApi.verify(token, 1, newestSeq);
      if (result.ok) {
        setNotice(`Verified: ${result.checked} event(s) from seq 1 to ${newestSeq}, chain intact.`);
      } else {
        setError(`Verification FAILED at seq ${result.broken_seq} (${result.reason}). The record was altered.`);
      }
    } catch (err) {
      handleError(err);
    } finally {
      setVerifying(false);
    }
  };

  if (!session || !token) return null;

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
            <Link href="/blackbox" className="rounded-full bg-[#0F0F0F] px-3 py-1.5 font-semibold text-[#FFFFFF]">
              Black Box
            </Link>
            <Link href="/honeytokens" className="rounded-full px-3 py-1.5 font-medium text-[#606060] hover:bg-[#F2F2F2]">
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
            <h1 className="text-[18px] font-bold">Black Box Recorder</h1>
            <p className="text-[12px] text-[#606060]">
              Every tool call the gateway allowed, refused or failed to forward, through RedHand only.{" "}
              {settings?.payload_capture_enabled
                ? "Payload capture is ON: redacted excerpts of arguments and results are stored."
                : "Metadata only: no raw arguments or results are stored."}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={onVerify}
              disabled={verifying || events.length === 0}
              className="flex items-center gap-1.5 rounded-full border border-[#E5E5E5] bg-[#FFFFFF] px-3 py-1.5 text-[12px] font-semibold hover:bg-[#F2F2F2] disabled:opacity-50"
            >
              <ShieldCheck className="h-3.5 w-3.5" /> {verifying ? "Verifying…" : "Verify chain"}
            </button>
            <button
              onClick={() => load({ reset: true })}
              className="flex items-center gap-1.5 rounded-full border border-[#E5E5E5] bg-[#FFFFFF] px-3 py-1.5 text-[12px] font-semibold hover:bg-[#F2F2F2]"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Refresh
            </button>
          </div>
        </div>

        {settings?.payload_capture_enabled ? (
          <div className="mb-3 rounded-[8px] border border-[#FFE0B2] bg-[#FFF8EC] px-3 py-2 text-[12px] text-[#8A5A00]">
            Payload capture is on. Redacted excerpts may still contain names or free text. Only admins can read them, and every read is audited.
          </div>
        ) : null}

        {settings ? (
          <SettingsPanel
            settings={settings}
            busy={settingsBusy}
            onSaveRetention={(r, p, reason) =>
              changeSettings(() => blackboxApi.setRetention(token, r, p, reason, true), "Retention updated.")
            }
            onSetCapture={(enabled, reason) =>
              changeSettings(
                () => blackboxApi.setCapture(token, enabled, reason, enabled),
                enabled ? "Payload capture is on." : "Payload capture is off."
              )
            }
            onClearPayloads={(reason) => changeSettings(() => blackboxApi.clearPayloads(token, reason), "")}
          />
        ) : null}

        {error ? (
          <div className="mb-3 rounded-[8px] border border-[#FDECEC] bg-[#FFF5F5] px-3 py-2 text-[12px] text-[#B42318]">{error}</div>
        ) : null}
        {notice ? (
          <div className="mb-3 rounded-[8px] border border-[#E6F4EA] bg-[#F3FBF5] px-3 py-2 text-[12px] text-[#1E7B34]">{notice}</div>
        ) : null}

        <div className="mb-3 flex flex-wrap items-center gap-1 text-[12px]">
          {(["", "ALLOW", "BLOCK", "ERROR"] as const).map((d) => (
            <button
              key={d || "all"}
              onClick={() => setDecisionFilter(d)}
              className={`rounded-full px-3 py-1 font-medium ${
                decisionFilter === d ? "bg-[#0F0F0F] text-[#FFFFFF]" : "bg-[#FFFFFF] text-[#606060] hover:bg-[#F2F2F2]"
              } border border-[#E5E5E5]`}
            >
              {d || "All"}
            </button>
          ))}
          {settings?.capabilities?.can_export ? (
            <div className="ml-auto flex items-center gap-2">
              <select
                value={exportFormat} onChange={(e) => setExportFormat(e.target.value as "jsonl" | "csv")}
                className="rounded-[8px] border border-[#E5E5E5] bg-[#FFFFFF] px-2 py-1" aria-label="Export format"
              >
                <option value="jsonl">JSON Lines</option>
                <option value="csv">CSV</option>
              </select>
              {settings.capabilities.can_export_payloads ? (
                <label className="flex items-center gap-1 text-[#606060]">
                  <input type="checkbox" checked={exportPayloads} onChange={(e) => setExportPayloads(e.target.checked)} />
                  with payloads
                </label>
              ) : null}
              <button
                onClick={onExport} disabled={exporting}
                className="flex items-center gap-1.5 rounded-full border border-[#E5E5E5] bg-[#FFFFFF] px-3 py-1.5 font-semibold hover:bg-[#F2F2F2] disabled:opacity-50"
              >
                <Download className="h-3.5 w-3.5" /> {exporting ? "Exporting…" : "Export"}
              </button>
            </div>
          ) : null}
        </div>

        <div className="overflow-hidden rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF]">
          <table className="w-full text-[12px]">
            <thead>
              <tr className="border-b border-[#E5E5E5] text-left text-[#606060]">
                <th className="px-3 py-2">Time</th>
                <th className="px-3 py-2">Decision</th>
                <th className="px-3 py-2">Server</th>
                <th className="px-3 py-2">Tool</th>
                <th className="px-3 py-2">Reasons</th>
                <th className="px-3 py-2">Latency</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr
                  key={e.seq}
                  onClick={() => setSelected(e)}
                  className="cursor-pointer border-b border-[#F2F2F2] last:border-0 hover:bg-[#FAFAFA]"
                >
                  <td className="px-3 py-2 text-[#606060]">{formatTime(e.occurred_at)}</td>
                  <td className="px-3 py-2">
                    <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${DECISION_STYLE[e.decision]}`}>
                      {e.decision}
                    </span>
                  </td>
                  <td className="px-3 py-2">{e.server || "—"}</td>
                  <td className="px-3 py-2 font-mono">{e.tool_name || e.method}</td>
                  <td className="px-3 py-2 text-[#606060]">{e.reasons.join("; ") || "—"}</td>
                  <td className="px-3 py-2 text-[#606060]">{e.latency_ms != null ? `${e.latency_ms.toFixed(1)} ms` : "—"}</td>
                </tr>
              ))}
              {events.length === 0 && !loading ? (
                <tr>
                  <td colSpan={6} className="px-3 py-6 text-center text-[#606060]">
                    No events recorded yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>

        {nextBeforeSeq != null ? (
          <div className="mt-3 flex justify-center">
            <button
              onClick={() => load({ beforeSeq: nextBeforeSeq })}
              disabled={loading}
              className="rounded-full border border-[#E5E5E5] bg-[#FFFFFF] px-4 py-1.5 text-[12px] font-semibold hover:bg-[#F2F2F2] disabled:opacity-50"
            >
              {loading ? "Loading…" : "Load older events"}
            </button>
          </div>
        ) : null}
      </main>
      {selected ? (
        <EventDrawer
          event={selected}
          token={token}
          canViewPayload={!!settings?.capabilities?.can_view_payloads}
          onClose={() => setSelected(null)}
          onUnauthorized={() => {
            signOut();
            window.location.href = "/login";
          }}
        />
      ) : null}
    </div>
  );
}
