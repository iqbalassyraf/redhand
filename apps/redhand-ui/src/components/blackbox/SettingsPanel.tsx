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

// Wording for the capture-on dialog. Every sentence here is checked against what the code does (docs/runbooks/
// black-box-recorder.md). It states the limits plainly and makes no compliance claim: whether the owner has a lawful
// basis to store this data is for the owner (and their lawyer) to decide.
export function captureWarning(payloadRetentionDays: number): string[] {
  return [
    "From now on, a redacted excerpt (up to 2 KB) of each tool call's arguments and results is stored. A single value over 16 KB is skipped, not stored.",
    "Redaction is pattern based and best effort. It removes API keys and tokens, email addresses, Malaysian NRIC numbers, card and phone numbers, and fields named like passwords. It does NOT detect names, addresses or free text, so customer data can still be stored.",
    `Excerpts are kept for ${payloadRetentionDays} days (you can change this in these settings), then removed. Turning capture off does not delete what is already stored: use "Delete captured payloads now" for that.`,
    "Only admins can read excerpts, and every read and every export is recorded in the audit log.",
    "You need your own lawful basis to store this data. This is not legal advice and RedHand makes no compliance claim.",
  ];
}

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

  const inputClass = "w-20 rounded-[8px] border border-rh-hairline px-2 py-1 text-[12px] disabled:bg-rh-subtle";

  return (
    <section className="rh-glass mb-4 rounded-rh-md p-4 text-[12px]">
      <h2 className="mb-3 text-[14px] font-semibold">Recording settings</h2>

      <div className="mb-4 flex flex-wrap items-end gap-4">
        <label className="flex flex-col gap-1">
          <span className="text-rh-text-2">Keep events for (7 to 90 days)</span>
          <input
            type="number" min={7} max={90} value={retention} disabled={!caps?.can_manage || busy}
            onChange={(e) => setRetention(Number(e.target.value))} className={inputClass}
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-rh-text-2">Keep payloads for (1 to 30 days)</span>
          <input
            type="number" min={1} max={30} value={payloadRetention} disabled={!caps?.can_manage || busy}
            onChange={(e) => setPayloadRetention(Number(e.target.value))} className={inputClass}
          />
        </label>
        {caps?.can_manage ? (
          <>
            <label className="flex flex-col gap-1">
              <span className="text-rh-text-2">Reason (optional)</span>
              <input
                type="text" maxLength={200} value={reason} onChange={(e) => setReason(e.target.value)}
                className="w-56 rounded-[8px] border border-rh-hairline px-2 py-1 text-[12px]"
              />
            </label>
            <button
              onClick={saveRetention} disabled={busy || !retentionChanged || !retentionValid}
              className="rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-3 py-1.5 font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-40"
            >
              Save retention
            </button>
          </>
        ) : (
          <span className="text-rh-text-2">Only admins can change retention.</span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-3 border-t border-rh-hairline pt-3">
        <div className="min-w-[220px] flex-1">
          <div className="font-semibold">
            Payload capture is {settings.payload_capture_enabled ? "ON" : "off"}
          </div>
          <div className="text-rh-text-2">
            {settings.payload_capture_enabled
              ? "Redacted excerpts of tool call arguments and results are stored for the payload retention."
              : "Off by default. When on, redacted excerpts of tool call arguments and results are stored."}
          </div>
        </div>
        {settings.payload_capture_enabled ? (
          caps?.can_turn_capture_off ? (
            <button
              onClick={() => onSetCapture(false, reason)} disabled={busy}
              className="rounded-full border border-rh-hairline px-3 py-1.5 font-semibold hover:bg-rh-elevated disabled:opacity-50"
            >
              Turn capture off
            </button>
          ) : null
        ) : caps?.can_manage ? (
          <button
            onClick={() => { setUnderstood(false); setCaptureDialog(true); }} disabled={busy}
            className="rounded-full border border-rh-hairline px-3 py-1.5 font-semibold hover:bg-rh-elevated disabled:opacity-50"
          >
            Turn capture on…
          </button>
        ) : (
          <span className="text-rh-text-2">Only admins can turn capture on.</span>
        )}
        {caps?.can_manage ? (
          <button
            onClick={clearPayloads} disabled={busy}
            className="rounded-full border border-rh-crimson px-3 py-1.5 font-semibold text-rh-crimson-text hover:bg-rh-crimson-wash disabled:opacity-50"
          >
            Delete captured payloads now
          </button>
        ) : null}
      </div>

      {captureDialog ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-control-scrim p-4 backdrop-blur-sm" role="dialog" aria-modal="true">
          <div className="rh-glass max-w-lg rounded-rh-lg p-5 text-[13px]">
            <h3 className="mb-2 text-[16px] font-bold">Turn on payload capture?</h3>
            <ul className="mb-3 list-disc space-y-2 pl-5 text-rh-text">
              {captureWarning(settings.payload_retention_days).map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
            <label className="mb-4 flex items-start gap-2">
              <input type="checkbox" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} className="mt-0.5" />
              <span>I understand, and I have a lawful basis to store this data.</span>
            </label>
            <div className="flex justify-end gap-2">
              <button onClick={() => setCaptureDialog(false)} className="rounded-full border border-rh-hairline px-3 py-1.5 font-semibold hover:bg-rh-elevated">
                Cancel
              </button>
              <button
                disabled={!understood || busy}
                onClick={() => { setCaptureDialog(false); onSetCapture(true, reason); }}
                className="rounded-full bg-control-crimson px-3 py-1.5 font-semibold text-white shadow-rh-crimson transition hover:bg-control-crimsonDeep disabled:opacity-40"
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
