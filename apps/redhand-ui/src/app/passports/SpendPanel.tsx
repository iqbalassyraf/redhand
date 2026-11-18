"use client";

/**
 * One agent's model use (Phase 4.5 B4a): today's estimate per model, the last 7 days, and the daily dollar limit that only sends an alert.
 * Every figure is an ESTIMATE from the token counts the agent's own SDK reported, at published prices on a stated date; a model with no
 * known price is "price unknown", never $0. redhand-core computes everything and authorizes the limit change (admin, audited); this panel
 * only shows it. Model names come from the agent and are rendered as plain text only.
 */

import React, { useCallback, useEffect, useRef, useState } from "react";

import { ApiError, spendApi } from "@/lib/api";
import {
  type AgentSpendDetail,
  LIMIT_CONFIRM_TEXT,
  SPEND_LIMITS_TEXT,
  basisLine,
  dollarsInput,
  formatTokens,
  limitNeedsConfirmation,
  modelCost,
  parseDollars,
  shownModel,
  spendCell,
  measuredLine,
  MEASURED_BASIS,
} from "@/lib/spend";

const button = "rounded-full border border-rh-hairline bg-rh-card px-3 py-1 text-[12px] font-semibold hover:bg-rh-elevated disabled:opacity-50";
const TONE_BAR = { none: "bg-rh-teal", ok: "bg-rh-teal", warn: "bg-rh-ochre", alert: "bg-rh-crimson" } as const;

export function SpendPanel(props: {
  token: string;
  agentId: string;
  agentName: string;
  onClose: () => void;
  onChanged: () => void;
  onUnauthorized: () => void;
}) {
  const { token, agentId } = props;
  const [detail, setDetail] = useState<AgentSpendDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [limitText, setLimitText] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const typed = useRef(false); // true while the box holds something the person typed: a reload must not overwrite it

  const load = useCallback(async () => {
    setError(null);
    try {
      const next = await spendApi.detail(token, agentId);
      setDetail(next);
      if (!typed.current) setLimitText(dollarsInput(next.agent.spend_limit_micro_usd));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        props.onUnauthorized();
        return;
      }
      setError(err instanceof ApiError && err.status === 404 ? "Model use is not available from this server yet." : err instanceof Error ? err.message : "Something went wrong.");
    }
  }, [token, agentId, props]);

  useEffect(() => {
    load();
  }, [load]);

  const parsed = parseDollars(limitText);
  const invalid = parsed === "invalid";
  const current = detail?.agent.spend_limit_micro_usd ?? null;

  const save = async () => {
    if (parsed === "invalid" || !detail) return;
    const needsConfirm = limitNeedsConfirmation(current, parsed);
    if (needsConfirm && !window.confirm(LIMIT_CONFIRM_TEXT)) return;
    setBusy(true);
    setNotice(null);
    try {
      const res = await spendApi.setLimit(token, agentId, { spend_limit_micro_usd: parsed, confirm: needsConfirm, reason: reason.trim() || undefined });
      setNotice(res.changed ? "Limit saved." : "That is already the limit.");
      setReason("");
      typed.current = false;
      await load();
      props.onChanged();
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

  const agent = detail?.agent;
  const cell = spendCell(agent);
  const measured = agent ? measuredLine(agent) : null;
  const maxDay = Math.max(1, ...(detail?.days ?? []).map((d) => d.estimated_micro_usd));
  return (
    <section className="rh-glass rounded-rh-md border-2 border-control-borderStrong p-4 text-[12px]" aria-label="Model use">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[15px] font-semibold">Model use for {props.agentName}</h2>
        <div className="flex gap-2">
          <button onClick={load} className={button}>Refresh</button>
          <button onClick={props.onClose} className={button}>Close</button>
        </div>
      </div>
      {error && <p role="alert" className="mt-2 rounded-[8px] bg-rh-crimson-wash p-2 text-rh-crimson-text">{error}</p>}
      {notice && <p role="status" className="mt-2 rounded-[8px] bg-rh-teal-wash p-2 text-rh-teal-text">{notice}</p>}
      {!detail || !agent ? (
        !error && <p className="mt-2 text-rh-text-2">Loading…</p>
      ) : (
        <>
          <p className="mt-2 text-rh-text-2">{basisLine(detail.prices_as_of)}</p>
          <details className="mt-1 text-rh-text-2">
            <summary className="cursor-pointer font-semibold">What these numbers are not</summary>
            <p className="mt-1">{SPEND_LIMITS_TEXT}</p>
          </details>

          <h3 className="mt-4 text-[13px] font-semibold">Today</h3>
          <div className="mt-1 flex flex-wrap items-baseline gap-3">
            <span className="text-[22px] font-bold leading-none">{cell.headline}</span>
            <span className="text-rh-text-2">{cell.detail}{agent.usage_reported ? ` · ${agent.calls} calls` : ""}</span>
          </div>
          {measured && (
            <div className="mt-3" aria-label="Measured by RedHand">
              <div className="flex flex-wrap items-baseline gap-3">
                <span className="text-[16px] font-bold leading-none">{measured.headline}</span>
                <span className="text-rh-text-2">{measured.detail}</span>
              </div>
              <p className="mt-1 text-rh-text-2">{MEASURED_BASIS}</p>
            </div>
          )}
          {agent.spend_limit_micro_usd !== null && agent.percent_of_limit !== null && (
            <div className="mt-2 max-w-[360px]">
              <div className="h-[6px] w-full rounded-full bg-rh-elevated" role="progressbar" aria-valuenow={Math.min(100, agent.percent_of_limit)} aria-valuemin={0} aria-valuemax={100}>
                <div className={`h-[6px] rounded-full ${TONE_BAR[cell.tone]}`} style={{ width: `${Math.min(100, agent.percent_of_limit)}%` }} />
              </div>
              <div className="mt-1 text-rh-text-2">
                {agent.percent_of_limit}% of the {agent.spend_limit_text} daily limit{agent.percent_of_limit >= 100 ? " · alert sent (from the reported figure)" : ""}
              </div>
            </div>
          )}
          {agent.models.length > 0 && (
            <div className="mt-2 overflow-x-auto">
              <table className="w-full min-w-[420px] text-left">
                <thead className="text-[11px] uppercase tracking-wider text-rh-text-2">
                  <tr>
                    <th className="py-1 pr-3">Model (as reported)</th>
                    <th className="py-1 pr-3">Calls</th>
                    <th className="py-1 pr-3">Tokens in / out</th>
                    <th className="py-1">Estimated cost</th>
                  </tr>
                </thead>
                <tbody>
                  {agent.models.map((m) => (
                    <tr key={`${m.provider}/${m.model}`} className="border-t border-rh-hairline">
                      <td className="py-1 pr-3 font-mono text-[11px]" title={`${m.provider}/${m.model}`}>{shownModel(m.provider, m.model)}</td>
                      <td className="py-1 pr-3">{m.calls}</td>
                      <td className="py-1 pr-3">{formatTokens(m.prompt_tokens)} / {formatTokens(m.completion_tokens)}</td>
                      <td className={`py-1 ${m.price_known ? "" : "text-rh-ochre"}`}>{modelCost(m)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <h3 className="mt-4 text-[13px] font-semibold">Last 7 days</h3>
          <ul className="mt-1">
            {detail.days.map((d) => (
              <li key={d.day} className="flex items-center gap-3 py-0.5">
                <span className="w-[84px] shrink-0 text-rh-text-2">{d.day}</span>
                {d.usage_reported ? (
                  <>
                    <span className="h-[8px] rounded-full bg-rh-teal" style={{ width: `${Math.max(2, Math.round((d.estimated_micro_usd * 160) / maxDay))}px` }} aria-hidden="true" />
                    <span>{d.lower_bound ? "at least " : ""}{d.estimated_text}{d.unpriced_tokens > 0 ? ` + ${formatTokens(d.unpriced_tokens)} tokens, price unknown` : ""}</span>
                  </>
                ) : (
                  <span className="text-rh-text-2">usage not reported</span>
                )}
              </li>
            ))}
          </ul>

          <h3 className="mt-4 text-[13px] font-semibold">Daily limit (alert only)</h3>
          <form
            className="mt-1 flex flex-col gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              save();
            }}
          >
            <label className="flex flex-wrap items-center gap-2">
              US dollars per day
              <input
                inputMode="decimal"
                placeholder="blank = no limit"
                value={limitText}
                onChange={(e) => {
                  typed.current = true;
                  setLimitText(e.target.value);
                }}
                className="h-[34px] w-[160px] rounded-[8px] border border-rh-hairline px-2"
              />
            </label>
            {invalid && <p role="alert" className="text-rh-crimson-text">Enter an amount from $0.000001 to $1,000,000, with up to six decimals, or leave it blank.</p>}
            <input
              maxLength={500}
              placeholder="Reason (recorded in the audit log)"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="h-[34px] rounded-[8px] border border-rh-hairline px-3"
            />
            <p className="text-rh-text-2">
              When the estimate for the day reaches this amount, RedHand sends one Telegram alert for the day. It never refuses a call. Changing it needs an
              admin; raising or removing it asks you to confirm.
            </p>
            <div>
              <button type="submit" disabled={busy || invalid} className="h-[34px] rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-4 font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-40">
                Save limit
              </button>
            </div>
          </form>
        </>
      )}
    </section>
  );
}
