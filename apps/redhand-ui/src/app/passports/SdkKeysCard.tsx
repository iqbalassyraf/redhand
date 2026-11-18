"use client";

/**
 * Organization SDK keys (Phase 4.5 C1a): create, list and revoke the keys an agent's SDK uses to send traces and model use. redhand-core authorizes every
 * change (admins only) and audits it. A new key is shown exactly once, from the create response held in this component's state only; it is never written
 * to storage or logs, and leaving or refreshing the page forgets it.
 */

import React, { useCallback, useEffect, useState } from "react";

import { ApiError, sdkKeysApi } from "@/lib/api";
import {
  REVOKE_CONFIRM_TEXT,
  SDK_KEYS_TEXT,
  SHOW_ONCE_TEXT,
  type SdkKeyList,
  lastUsedText,
  parseDays,
  parseName,
  stateLabel,
  usableCount,
} from "@/lib/sdkKeys";

const button = "rounded-full border border-rh-hairline bg-rh-card px-3 py-1 text-[12px] font-semibold hover:bg-rh-elevated disabled:opacity-50";
const STATE_STYLE = { active: "bg-rh-teal-wash text-rh-teal-text", expired: "bg-rh-elevated text-rh-text-2", revoked: "bg-rh-crimson-wash text-rh-crimson-text" } as const;

export function SdkKeysCard(props: { token: string; onUnauthorized: () => void }) {
  const { token } = props;
  const [list, setList] = useState<SdkKeyList | null>(null);
  const [name, setName] = useState("");
  const [days, setDays] = useState("90");
  const [shown, setShown] = useState<{ name: string; secret: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const fail = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        props.onUnauthorized();
        return;
      }
      setError(err instanceof ApiError && err.status === 404 ? "SDK keys are not available from this server yet." : err instanceof Error ? err.message : "Something went wrong.");
    },
    [props]
  );

  const load = useCallback(async () => {
    try {
      setList(await sdkKeysApi.list(token));
    } catch (err) {
      fail(err);
    }
  }, [token, fail]);

  useEffect(() => {
    load();
  }, [load]);

  const parsedName = parseName(name);
  const parsedDays = parseDays(days);
  const invalid = parsedName === "invalid" || parsedDays === "invalid";

  const create = async () => {
    if (parsedName === "invalid" || parsedDays === "invalid") return;
    setBusy(true);
    setError(null);
    setNotice(null);
    setCopied(false);
    try {
      const res = await sdkKeysApi.create(token, { name: parsedName, expires_in_days: parsedDays });
      setShown({ name: res.key.name, secret: res.secret });
      setName("");
      await load();
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (keyId: string, keyName: string) => {
    if (!window.confirm(REVOKE_CONFIRM_TEXT)) return;
    setBusy(true);
    setError(null);
    try {
      const res = await sdkKeysApi.revoke(token, keyId);
      setNotice(res.changed ? `${keyName} revoked.` : `${keyName} was already revoked.`);
      await load();
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="rh-glass rounded-rh-md p-4 text-[12px]" aria-label="SDK keys">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[15px] font-semibold">SDK keys</h2>
        <button onClick={load} className={button}>Refresh</button>
      </div>
      <p className="mt-1 text-rh-text-2">{SDK_KEYS_TEXT}</p>

      {shown && (
        <div role="status" className="mt-3 rounded-[8px] border-2 border-rh-strong bg-rh-ochre-wash p-3">
          <p className="font-semibold">New key for {shown.name}</p>
          <p className="mt-1">{SHOW_ONCE_TEXT}</p>
          <code className="mt-2 block break-all rounded-[6px] bg-rh-card p-2 font-mono text-[12px]">{shown.secret}</code>
          <div className="mt-2 flex gap-2">
            <button
              className={button}
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(shown.secret);
                  setCopied(true);
                } catch {
                  setCopied(false);
                }
              }}
            >
              {copied ? "Copied" : "Copy key"}
            </button>
            <button className={button} onClick={() => setShown(null)}>I have stored it</button>
          </div>
        </div>
      )}

      {error && <p role="alert" className="mt-2 rounded-[8px] bg-rh-crimson-wash p-2 text-rh-crimson-text">{error}</p>}
      {notice && <p role="status" className="mt-2 rounded-[8px] bg-rh-teal-wash p-2 text-rh-teal-text">{notice}</p>}

      {!list ? (
        !error && <p className="mt-2 text-rh-text-2">Loading…</p>
      ) : (
        <>
          <p className="mt-3 font-semibold">{usableCount(list.keys)} of {list.max_active} active keys.</p>
          {list.keys.length === 0 ? (
            <p className="mt-1 text-rh-text-2">No SDK keys yet.</p>
          ) : (
            <div className="mt-1 overflow-x-auto">
              <table className="w-full min-w-[560px] text-left">
                <thead className="text-[11px] uppercase tracking-wider text-rh-text-2">
                  <tr>
                    <th className="py-1 pr-3">Name</th>
                    <th className="py-1 pr-3">Key</th>
                    <th className="py-1 pr-3">State</th>
                    <th className="py-1 pr-3">Expires</th>
                    <th className="py-1 pr-3">Last used</th>
                    <th className="py-1"></th>
                  </tr>
                </thead>
                <tbody>
                  {list.keys.map((k) => (
                    <tr key={k.id} className="border-t border-rh-hairline">
                      <td className="py-1 pr-3">{k.name}</td>
                      <td className="py-1 pr-3 font-mono text-[11px]">{k.key_prefix}…</td>
                      <td className="py-1 pr-3">
                        <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${STATE_STYLE[k.state]}`}>{stateLabel(k.state)}</span>
                      </td>
                      <td className="py-1 pr-3">{k.expires_at ? new Date(k.expires_at).toLocaleDateString() : "never"}</td>
                      <td className="py-1 pr-3">{lastUsedText(k)}</td>
                      <td className="py-1 text-right">
                        {k.state === "active" && (
                          <button className={button} disabled={busy} onClick={() => revoke(k.id, k.name)}>Revoke</button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <form
            className="mt-3 flex flex-wrap items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              create();
            }}
          >
            <label className="flex flex-col gap-1">
              Name
              <input value={name} onChange={(e) => setName(e.target.value)} maxLength={100} placeholder="for example ci pipeline" className="h-[34px] w-[200px] rounded-[8px] border border-rh-hairline px-2" />
            </label>
            <label className="flex flex-col gap-1">
              Expires after (days)
              <input value={days} onChange={(e) => setDays(e.target.value)} inputMode="numeric" className="h-[34px] w-[90px] rounded-[8px] border border-rh-hairline px-2" />
            </label>
            <button type="submit" disabled={busy || invalid} className="h-[34px] rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-4 font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-40">
              Create SDK key
            </button>
          </form>
          {parsedDays === "invalid" && <p role="alert" className="mt-1 text-rh-crimson-text">Enter a whole number of days from 1 to 365.</p>}
          <p className="mt-1 text-rh-text-2">Creating and revoking keys needs an admin. Every change is recorded in the audit log.</p>
        </>
      )}
    </section>
  );
}
