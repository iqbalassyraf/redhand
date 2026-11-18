"use client";

/**
 * Black Box Recorder: the organization's timeline of what the gateway allowed, refused or failed
 * to forward, plus a Verify button that proves the record was not altered (Phase 3 M1).
 */

import React, { useCallback, useEffect, useState } from "react";
import { Download, RefreshCw, ShieldCheck } from "lucide-react";

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
import { AppShell } from "@/components/shell/AppShell";

const DECISION_STYLE: Record<BlackBoxDecision, string> = {
  ALLOW: "bg-rh-teal-wash text-rh-teal-text",
  BLOCK: "bg-rh-crimson-wash text-rh-crimson-text",
  ERROR: "bg-rh-ochre-wash text-rh-ochre",
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
        signOut("/login");
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
    <AppShell title="Black Box" role={session.role}>

      <div className="mx-auto max-w-5xl px-4 py-6">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h1 className="text-[18px] font-bold">Black Box Recorder</h1>
            <p className="text-[12px] text-rh-text-2">
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
              className="flex items-center gap-1.5 rounded-full border border-rh-hairline bg-rh-card px-3 py-1.5 text-[12px] font-semibold hover:bg-rh-elevated disabled:opacity-50"
            >
              <ShieldCheck className="h-3.5 w-3.5" /> {verifying ? "Verifying…" : "Verify chain"}
            </button>
            <button
              onClick={() => load({ reset: true })}
              className="flex items-center gap-1.5 rounded-full border border-rh-hairline bg-rh-card px-3 py-1.5 text-[12px] font-semibold hover:bg-rh-elevated"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Refresh
            </button>
          </div>
        </div>

        {settings?.payload_capture_enabled ? (
          <div className="mb-3 rounded-[8px] border border-rh-ochre bg-rh-ochre-wash px-3 py-2 text-[12px] text-rh-ochre">
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
          <div className="mb-3 rounded-[8px] border border-rh-crimson bg-rh-crimson-wash px-3 py-2 text-[12px] text-rh-crimson-text">{error}</div>
        ) : null}
        {notice ? (
          <div className="mb-3 rounded-[8px] border border-rh-teal bg-rh-teal-wash px-3 py-2 text-[12px] text-rh-teal-text">{notice}</div>
        ) : null}

        <div className="mb-3 flex flex-wrap items-center gap-1 text-[12px]">
          {(["", "ALLOW", "BLOCK", "ERROR"] as const).map((d) => (
            <button
              key={d || "all"}
              onClick={() => setDecisionFilter(d)}
              className={`rounded-full border px-3 py-1 font-medium transition-colors ${
                decisionFilter === d
                  ? "border-control-crimsonBorder bg-control-crimson text-white shadow-rh-crimson"
                  : "border-rh-hairline bg-rh-card text-rh-text-2 hover:bg-rh-elevated"
              }`}
            >
              {d || "All"}
            </button>
          ))}
          {settings?.capabilities?.can_export ? (
            <div className="ml-auto flex items-center gap-2">
              <select
                value={exportFormat} onChange={(e) => setExportFormat(e.target.value as "jsonl" | "csv")}
                className="rounded-[8px] border border-rh-hairline bg-rh-card px-2 py-1" aria-label="Export format"
              >
                <option value="jsonl">JSON Lines</option>
                <option value="csv">CSV</option>
              </select>
              {settings.capabilities.can_export_payloads ? (
                <label className="flex items-center gap-1 text-rh-text-2">
                  <input type="checkbox" checked={exportPayloads} onChange={(e) => setExportPayloads(e.target.checked)} />
                  with payloads
                </label>
              ) : null}
              <button
                onClick={onExport} disabled={exporting}
                className="flex items-center gap-1.5 rounded-full border border-rh-hairline bg-rh-card px-3 py-1.5 font-semibold hover:bg-rh-elevated disabled:opacity-50"
              >
                <Download className="h-3.5 w-3.5" /> {exporting ? "Exporting…" : "Export"}
              </button>
            </div>
          ) : null}
        </div>

        <div className="rh-glass overflow-hidden rounded-rh-md">
          <table className="w-full text-[12px]">
            <thead>
              <tr className="border-b border-rh-hairline text-left text-rh-text-2">
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
                  className="cursor-pointer border-b border-rh-hairline last:border-0 hover:bg-rh-subtle"
                >
                  <td className="px-3 py-2 text-rh-text-2">{formatTime(e.occurred_at)}</td>
                  <td className="px-3 py-2">
                    <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${DECISION_STYLE[e.decision]}`}>
                      {e.decision}
                    </span>
                  </td>
                  <td className="px-3 py-2">{e.server || "—"}</td>
                  <td className="px-3 py-2 font-mono">{e.tool_name || e.method}</td>
                  <td className="px-3 py-2 text-rh-text-2">{e.reasons.join("; ") || "—"}</td>
                  <td className="px-3 py-2 text-rh-text-2">{e.latency_ms != null ? `${e.latency_ms.toFixed(1)} ms` : "—"}</td>
                </tr>
              ))}
              {events.length === 0 && !loading ? (
                <tr>
                  <td colSpan={6} className="px-3 py-6 text-center text-rh-text-2">
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
              className="rounded-full border border-rh-hairline bg-rh-card px-4 py-1.5 text-[12px] font-semibold hover:bg-rh-elevated disabled:opacity-50"
            >
              {loading ? "Loading…" : "Load older events"}
            </button>
          </div>
        ) : null}
      </div>
      {selected ? (
        <EventDrawer
          event={selected}
          token={token}
          canViewPayload={!!settings?.capabilities?.can_view_payloads}
          onClose={() => setSelected(null)}
          onUnauthorized={() => {
            signOut("/login");
          }}
        />
      ) : null}
    </AppShell>
  );
}
