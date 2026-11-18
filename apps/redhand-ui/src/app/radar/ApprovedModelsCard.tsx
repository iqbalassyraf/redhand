"use client";

/**
 * Approved models (Phase 4.5 B4b): the list of models the organization's agents may use. While it is not empty, a model an agent's own SDK reports that
 * is not on it becomes a finding ("Model not on the approved list") and one Telegram alert. Detective only: it cannot stop a model call, adds nothing to
 * the Risk score, and an empty list means no check. redhand-core decides and audits every change (admin; clearing needs confirmation); this card only
 * shows it. Model names come from agents and are rendered as plain text only.
 */

import React, { useCallback, useEffect, useState } from "react";

import { ApiError, approvedModelsApi } from "@/lib/api";
import {
  APPROVED_MODELS_TEXT,
  type ApprovedModelsList,
  CLEAR_CONFIRM_TEXT,
  clearNeedsConfirmation,
  describeChange,
  formatModelLines,
  parseModelLines,
} from "@/lib/approvedModels";

const button = "rounded-full border border-rh-hairline bg-rh-card px-3 py-1 text-[12px] font-semibold hover:bg-rh-elevated disabled:opacity-50";

export function ApprovedModelsCard(props: { token: string; onUnauthorized: () => void; onSaved?: () => void }) {
  const { token } = props;
  const [list, setList] = useState<ApprovedModelsList | null>(null);
  const [text, setText] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [typed, setTyped] = useState(false); // a reload must not overwrite what the person is typing

  const load = useCallback(async () => {
    try {
      const next = await approvedModelsApi.get(token);
      setList(next);
      setUnavailable(false);
      setTyped((wasTyped) => {
        if (!wasTyped) setText(formatModelLines(next.items));
        return wasTyped;
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        props.onUnauthorized();
        return;
      }
      if (err instanceof ApiError && err.status === 404) setUnavailable(true);
      else setError(err instanceof Error ? err.message : "Something went wrong.");
    }
  }, [token, props]);

  useEffect(() => {
    load();
  }, [load]);

  const parsed = parseModelLines(text);
  const invalid = typeof parsed === "string";

  const save = async () => {
    if (typeof parsed === "string" || !list) return;
    const needsConfirm = clearNeedsConfirmation(list.items, parsed);
    if (needsConfirm && !window.confirm(CLEAR_CONFIRM_TEXT)) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await approvedModelsApi.set(token, { items: parsed, version: list.version, confirm: needsConfirm, reason: reason.trim() || undefined });
      setTyped(false);
      setList(res);
      setText(formatModelLines(res.items));
      setReason("");
      setNotice(res.changed ? "Approved models saved." : "That is already the list.");
      props.onSaved?.();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        props.onUnauthorized();
        return;
      }
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="rh-glass mb-6 rounded-rh-md p-4 text-[12px]" aria-label="Approved models">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[14px] font-semibold">Approved models</h2>
        <button onClick={load} className={button}>Refresh</button>
      </div>
      {unavailable ? (
        <p className="text-rh-text-2">Approved models are not available from this server yet.</p>
      ) : !list ? (
        !error && <p className="text-rh-text-2">Loading…</p>
      ) : (
        <>
          <p className="text-rh-text-2">{APPROVED_MODELS_TEXT}</p>
          <p className="mt-2 font-semibold">
            {list.check_active ? `Check is on: ${list.items.length} approved model${list.items.length === 1 ? "" : "s"}.` : "Check is off: no list, nothing is flagged."}
          </p>
          <form
            className="mt-2 flex flex-col gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              save();
            }}
          >
            <label className="flex flex-col gap-1">
              One model per line, as provider/model
              <textarea
                rows={5}
                value={text}
                onChange={(e) => {
                  setTyped(true);
                  setText(e.target.value);
                }}
                placeholder="anthropic/claude-sonnet-5-5"
                className="rounded-[8px] border border-rh-hairline p-2 font-mono text-[12px]"
                spellCheck={false}
              />
            </label>
            {invalid ? (
              <p role="alert" className="text-rh-crimson-text">{parsed}</p>
            ) : (
              <p className="text-rh-text-2">{describeChange(list.items, parsed)}</p>
            )}
            <input
              maxLength={500}
              placeholder="Reason (recorded in the audit log)"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="h-[34px] rounded-[8px] border border-rh-hairline px-3"
            />
            <p className="text-rh-text-2">Changing the list needs an admin. A model name can be a dated version (…-20260301) of an approved one.</p>
            <div>
              <button type="submit" disabled={busy || invalid} className="h-[34px] rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-4 font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-40">
                Save approved models
              </button>
            </div>
          </form>
        </>
      )}
      {error && <p role="alert" className="mt-2 rounded-[8px] bg-rh-crimson-wash p-2 text-rh-crimson-text">{error}</p>}
      {notice && <p role="status" className="mt-2 rounded-[8px] bg-rh-teal-wash p-2 text-rh-teal-text">{notice}</p>}
    </section>
  );
}
