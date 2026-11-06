"use client";

/**
 * Black Box settings: retention periods and payload capture. What is shown depends on the capabilities the
 * server reports for the caller's role; that only hides buttons. Every action is authorized by redhand-core.
 */

import React, { useEffect, useState } from "react";

import type { BlackBoxSettings } from "@/lib/api";

interface Props {
  settings: BlackBoxSettings;
  busy: boolean;
  onSaveRetention: (retentionDays: number, payloadRetentionDays: number, reason: string) => void;
  onSetCapture: (enabled: boolean, reason: string) => void;
  onClearPayloads: (reason: string) => void;
}

// Draft wording, to be reviewed by the owner or their lawyer before launch. It states the limits plainly and
// makes no compliance claim.
export const CAPTURE_WARNING = [
  "From now on, a redacted excerpt (up to 2 KB) of each tool call's arguments and results is stored.",
  "Redaction is pattern based and best effort. It removes API keys and tokens, email addresses, Malaysian NRIC numbers, card and phone numbers, and fields named like passwords. It does NOT detect names, addresses or free text, so customer data can still be stored.",
  "You need your own lawful basis to store this data. This is not legal advice and RedHand makes no compliance claim.",
  "Only admins can read payloads, and every read and export is recorded in the audit log.",
];

export function SettingsPanel({ settings, busy, onSaveRetention, onSetCapture, onClearPayloads }: Props) {
  const caps = settings.capabilities;
  const [retention, setRetention] = useState(settings.retention_days);
  const [payloadRetention, setPayloadRetention] = useState(settings.payload_retention_days);
  const [reason, setReason] = useState("");
  const [captureDialog, setCaptureDialog] = useState(false);
  const [understood, setUnderstood] = useState(false);

  useEffect(() => {
    setRetention(settings.retention_days);
    setPayloadRetention(settings.payload_retention_days);
  }, [settings.retention_days, settings.payload_retention_days]);

  const retentionChanged = retention !== settings.retention_days || payloadRetention !== settings.payload_retention_days;
  const retentionValid =
    Number.isInteger(retention) && retention >= 7 && retention <= 90 &&
    Number.isInteger(payloadRetention) && payloadRetention >= 1 && payloadRetention <= 30;

  const saveRetention = () => {
    const shorter = retention < settings.retention_days || payloadRetention < settings.payload_retention_days;
    const message = shorter
      ? "Shortening retention deletes older events (or payloads) at the next daily purge. This cannot be undone. Continue?"
      : "Change the retention periods?";
    if (!window.confirm(message)) return;
    onSaveRetention(retention, payloadRetention, reason);
  };

  const clearPayloads = () => {
    if (!window.confirm("Delete every captured payload now? Events and the tamper-evident chain stay. This cannot be undone.")) return;
    onClearPayloads(reason);
  };

  const inputClass = "w-20 rounded-[8px] border border-[#E5E5E5] px-2 py-1 text-[12px] disabled:bg-[#F8F8F8]";

  return (
    <section className="mb-4 rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4 text-[12px]">
      <h2 className="mb-3 text-[14px] font-semibold">Recording settings</h2>

      <div className="mb-4 flex flex-wrap items-end gap-4">
        <label className="flex flex-col gap-1">
          <span className="text-[#606060]">Keep events for (7 to 90 days)</span>
          <input
            type="number" min={7} max={90} value={retention} disabled={!caps?.can_manage || busy}
            onChange={(e) => setRetention(Number(e.target.value))} className={inputClass}
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[#606060]">Keep payloads for (1 to 30 days)</span>
          <input
            type="number" min={1} max={30} value={payloadRetention} disabled={!caps?.can_manage || busy}
            onChange={(e) => setPayloadRetention(Number(e.target.value))} className={inputClass}
          />
        </label>
        {caps?.can_manage ? (
          <>
            <label className="flex flex-col gap-1">
              <span className="text-[#606060]">Reason (optional)</span>
              <input
                type="text" maxLength={200} value={reason} onChange={(e) => setReason(e.target.value)}
                className="w-56 rounded-[8px] border border-[#E5E5E5] px-2 py-1 text-[12px]"
              />
            </label>
            <button
              onClick={saveRetention} disabled={busy || !retentionChanged || !retentionValid}
              className="rounded-full bg-[#0F0F0F] px-3 py-1.5 font-semibold text-[#FFFFFF] disabled:opacity-40"
            >
              Save retention
            </button>
          </>
        ) : (
          <span className="text-[#606060]">Only admins can change retention.</span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-3 border-t border-[#F2F2F2] pt-3">
        <div className="min-w-[220px] flex-1">
          <div className="font-semibold">
            Payload capture is {settings.payload_capture_enabled ? "ON" : "off"}
          </div>
          <div className="text-[#606060]">
            {settings.payload_capture_enabled
              ? "Redacted excerpts of tool call arguments and results are stored for the payload retention."
              : "Off by default. When on, redacted excerpts of tool call arguments and results are stored."}
          </div>
        </div>
        {settings.payload_capture_enabled ? (
          caps?.can_turn_capture_off ? (
            <button
              onClick={() => onSetCapture(false, reason)} disabled={busy}
              className="rounded-full border border-[#E5E5E5] px-3 py-1.5 font-semibold hover:bg-[#F2F2F2] disabled:opacity-50"
            >
              Turn capture off
            </button>
          ) : null
        ) : caps?.can_manage ? (
          <button
            onClick={() => { setUnderstood(false); setCaptureDialog(true); }} disabled={busy}
            className="rounded-full border border-[#E5E5E5] px-3 py-1.5 font-semibold hover:bg-[#F2F2F2] disabled:opacity-50"
          >
            Turn capture on…
          </button>
        ) : (
          <span className="text-[#606060]">Only admins can turn capture on.</span>
        )}
        {caps?.can_manage ? (
          <button
            onClick={clearPayloads} disabled={busy}
            className="rounded-full border border-[#FDECEC] px-3 py-1.5 font-semibold text-[#B42318] hover:bg-[#FFF5F5] disabled:opacity-50"
          >
            Delete captured payloads now
          </button>
        ) : null}
      </div>

      {captureDialog ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#0F0F0F]/40 p-4" role="dialog" aria-modal="true">
          <div className="max-w-lg rounded-[12px] bg-[#FFFFFF] p-5 text-[13px] shadow-lg">
            <h3 className="mb-2 text-[16px] font-bold">Turn on payload capture?</h3>
            <ul className="mb-3 list-disc space-y-2 pl-5 text-[#303030]">
              {CAPTURE_WARNING.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
            <label className="mb-4 flex items-start gap-2">
              <input type="checkbox" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} className="mt-0.5" />
              <span>I understand, and I have a lawful basis to store this data.</span>
            </label>
            <div className="flex justify-end gap-2">
              <button onClick={() => setCaptureDialog(false)} className="rounded-full border border-[#E5E5E5] px-3 py-1.5 font-semibold hover:bg-[#F2F2F2]">
                Cancel
              </button>
              <button
                disabled={!understood || busy}
                onClick={() => { setCaptureDialog(false); onSetCapture(true, reason); }}
                className="rounded-full bg-[#FF0000] px-3 py-1.5 font-semibold text-[#FFFFFF] disabled:opacity-40"
              >
                Turn capture on
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
