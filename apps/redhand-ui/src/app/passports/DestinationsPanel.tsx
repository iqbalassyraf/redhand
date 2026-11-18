"use client";

/**
 * Allowed destinations for one agent (Phase 4 M7): the hosts it may send data to, and whether the gateway only watches (records
 * addresses outside the list) or enforces (also refuses the call). The gateway reads the web and email addresses an agent writes into a call;
 * it does not see what a tool does with the data, and an address written a way it cannot read is not found (the limits are stated here).
 * The UI is never a security boundary: redhand-core decides who may change anything and normalizes every host; `capabilities.can_change`
 * only hides buttons the server would refuse. Everything from the server is rendered as text.
 */

import React, { useCallback, useEffect, useState } from "react";

import { ApiError, type DestinationMode, type DestinationSettings, destinationsApi } from "@/lib/api";
import {
  DESTINATION_LIMITS_TEXT,
  DESTINATION_MODE_LABEL,
  MAX_ALLOWED_DESTINATIONS,
  destinationConfirmText,
  destinationNeedsConfirmation,
  enforceBlockedReason,
  removeBlockedReason,
  validateHostInput,
} from "@/lib/destinationForm";

const field = "rounded-[8px] border border-rh-hairline px-2 py-1 text-[12px]";
const button = "rounded-full border border-rh-hairline bg-rh-card px-3 py-1 text-[12px] font-semibold hover:bg-rh-elevated disabled:opacity-50";

export function DestinationsPanel(props: { token: string; agentId: string; agentName: string; onClose: () => void; onUnauthorized: () => void }) {
  const { token, agentId } = props;
  const [data, setData] = useState<DestinationSettings | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [draftMode, setDraftMode] = useState<DestinationMode>("off");
  const [confirmMode, setConfirmMode] = useState(false);
  const [host, setHost] = useState("");
  const [confirmAdd, setConfirmAdd] = useState(false);

  const fail = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        props.onUnauthorized();
        return;
      }
      setError(err instanceof Error ? err.message : "Something went wrong.");
    },
    [props]
  );

  const load = useCallback(async () => {
    try {
      const d = await destinationsApi.settings(token, agentId);
      setData(d);
      setUnavailable(false);
      setDraftMode(d.destination_mode);
      setConfirmMode(false);
    } catch (err) {
      if (err instanceof ApiError && (err.status === 404 || err.status === 405)) {
        setData(null);
        setUnavailable(true); // an older core has no allowlist: say so and leave the rest of the page working
        return;
      }
      fail(err);
    }
  }, [token, agentId, fail]);

  useEffect(() => {
    load();
  }, [load]);

  const run = async (action: () => Promise<unknown>, done: string) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      setNotice(done);
      await load();
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  const can = data?.capabilities.can_change === true;
  const needsConfirm = data ? destinationNeedsConfirmation(data.destination_mode, draftMode) : false;
  const blocked = data ? enforceBlockedReason(draftMode, data.entries.length) : null;
  const hostProblem = host.trim() === "" ? null : validateHostInput(host);

  return (
    <section className="rh-glass rounded-rh-md border-2 border-control-borderStrong p-4 text-[12px]" aria-label="Allowed destinations">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[15px] font-semibold">Allowed destinations for {props.agentName}</h2>
        <button onClick={props.onClose} className={button}>Close</button>
      </div>
      {error && <p role="alert" className="mt-2 rounded-[8px] bg-rh-crimson-wash p-2 text-rh-crimson-text">{error}</p>}
      {notice && <p role="status" className="mt-2 rounded-[8px] bg-rh-teal-wash p-2 text-rh-teal-text">{notice}</p>}
      {unavailable || !data ? (
        <p className="mt-2 text-rh-text-2">{unavailable ? "Destination checks are not available from this server yet." : "Loading…"}</p>
      ) : (
        <>
          <p className="mt-2 text-rh-text-2">{DESTINATION_LIMITS_TEXT}</p>
          <div className="mt-3 flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1">
              <span className="text-rh-text-2">Check</span>
              <select
                value={draftMode}
                disabled={!can}
                onChange={(e) => { setNotice(null); setError(null); setDraftMode(e.target.value as DestinationMode); }}
                className={field}
              >
                {(["observe", "enforce", "off"] as const).map((m) => <option key={m} value={m}>{DESTINATION_MODE_LABEL[m]}</option>)}
              </select>
            </label>
            {can ? (
              <>
                <button
                  className={button}
                  disabled={busy || draftMode === data.destination_mode || blocked !== null || (needsConfirm && !confirmMode)}
                  onClick={() => run(() => destinationsApi.setMode(token, agentId, { destination_mode: draftMode, expected_mode: data.destination_mode, confirm: needsConfirm && confirmMode }), "Saved. It reaches the gateway within a few seconds.")}
                >
                  Save
                </button>
                {draftMode !== data.destination_mode && <span className="font-semibold text-rh-ochre">Not saved yet: press Save to apply this change.</span>}
              </>
            ) : (
              <span className="text-rh-text-2">Only an admin can change these.</span>
            )}
          </div>
          {blocked && can && <p className="mt-2 text-rh-crimson-text">{blocked}</p>}
          {needsConfirm && can && (
            <label className="mt-2 flex items-center gap-2">
              <input type="checkbox" checked={confirmMode} onChange={(e) => setConfirmMode(e.target.checked)} />
              <span>{destinationConfirmText(draftMode)}</span>
            </label>
          )}

          <h3 className="mt-4 text-[13px] font-semibold">Allowed hosts ({data.entries.length} of {MAX_ALLOWED_DESTINATIONS})</h3>
          {data.entries.length === 0 ? (
            <p className="mt-1 text-rh-text-2">None. With the check on, every address in a call is outside the list.</p>
          ) : (
            <ul className="mt-1 divide-y divide-rh-hairline">
              {data.entries.map((e) => {
                const why = removeBlockedReason(data.destination_mode, data.entries.length);
                return (
                  <li key={e.id} className="flex flex-wrap items-center gap-2 py-1.5">
                    <code className="rounded bg-rh-elevated px-1.5 py-0.5">{e.host}</code>
                    {can && (
                      <button className={button} disabled={busy || why !== null} title={why ?? undefined}
                        onClick={() => run(() => destinationsApi.remove(token, agentId, e.id), `${e.host} removed.`)}>
                        Remove
                      </button>
                    )}
                  </li>
                );
              })}
            </ul>
          )}

          {can && (
            <div className="mt-3 rounded-[8px] bg-rh-subtle p-3">
              <div className="flex flex-wrap items-end gap-2">
                <label className="flex flex-col gap-1">
                  <span className="text-rh-text-2">Allow a host (a name or an address only)</span>
                  <input value={host} maxLength={300} placeholder="files.example.com" onChange={(e) => { setHost(e.target.value); setError(null); }} className={`${field} w-72`} />
                </label>
                <button className={button} disabled={busy || host.trim() === "" || hostProblem !== null || !confirmAdd}
                  onClick={() => run(async () => { await destinationsApi.add(token, agentId, { host: host.trim(), confirm: true }); setHost(""); setConfirmAdd(false); }, "Host allowed.")}>
                  Allow
                </button>
              </div>
              {hostProblem && <p role="alert" className="mt-1 text-rh-crimson-text">{hostProblem}</p>}
              <label className="mt-2 flex items-center gap-2">
                <input type="checkbox" checked={confirmAdd} onChange={(e) => setConfirmAdd(e.target.checked)} />
                <span>I understand: this lets the agent send data to this address.</span>
              </label>
            </div>
          )}

          <p className="mt-3 text-rh-text-2">
            Last 7 days: <b className="text-rh-text">{data.last_7_days.findings ?? 0}</b> {data.last_7_days.findings === 1 ? "finding" : "findings"} for this agent (see Radar, kind &quot;Address outside the list&quot;).
          </p>
        </>
      )}
    </section>
  );
}
