"use client";

/**
 * The organization's response ladder (Phase 4.5 B1): at which risk score RedHand alerts, turns Safe Mode on, or freezes an agent by itself.
 * Alert is on by default; Safe Mode and freeze are off until an admin turns them on with a confirmation. Before saving, the card names the
 * agents the ladder would act on right now. redhand-core authorizes and audits every change; `capabilities.can_change` only hides controls
 * the server would refuse.
 */

import React, { useState } from "react";

import { type RiskLadder, riskApi } from "@/lib/api";
import { LADDER_CONFIRM_TEXT, RUNG_LABEL, type Rung, ladderNeedsConfirmation, parseThreshold, validateLadder } from "@/lib/riskForm";

const field = "w-20 rounded-[8px] border border-rh-hairline px-2 py-1 text-[12px]";
const button = "rounded-full border border-rh-hairline bg-rh-card px-3 py-1 text-[12px] font-semibold hover:bg-rh-elevated disabled:opacity-50";
const RUNGS: { key: Rung; field: "alert_at" | "safe_mode_at" | "freeze_at" }[] = [
  { key: "alert", field: "alert_at" },
  { key: "safe_mode", field: "safe_mode_at" },
  { key: "freeze", field: "freeze_at" },
];

const asText = (value: number | null) => (value === null ? "" : String(value));

export function RiskLadderCard(props: { token: string; ladder: RiskLadder; onSaved: (message: string) => void; onError: (err: unknown) => void }) {
  const { ladder } = props;
  const [draft, setDraft] = useState({ alert_at: asText(ladder.alert_at), safe_mode_at: asText(ladder.safe_mode_at), freeze_at: asText(ladder.freeze_at) });
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);

  const parsed = { alert_at: parseThreshold(draft.alert_at), safe_mode_at: parseThreshold(draft.safe_mode_at), freeze_at: parseThreshold(draft.freeze_at) };
  const invalid = Object.values(parsed).some((v) => v === "invalid");
  const next = invalid ? null : (parsed as { alert_at: number | null; safe_mode_at: number | null; freeze_at: number | null });
  const problem = invalid ? "Each threshold is a whole number from 1 to 100, or empty for off." : next ? validateLadder(next) : null;
  const changed = next !== null && (next.alert_at !== ladder.alert_at || next.safe_mode_at !== ladder.safe_mode_at || next.freeze_at !== ladder.freeze_at);
  const needsConfirm = next !== null && ladderNeedsConfirmation(ladder, next);
  const can = ladder.capabilities.can_change;

  const save = async () => {
    if (!next || busy) return;
    setBusy(true);
    try {
      await riskApi.setLadder(props.token, { ...next, confirm: needsConfirm && confirm });
      setConfirm(false);
      props.onSaved("Risk response saved. It applies from the next signal.");
    } catch (err) {
      props.onError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="rh-glass rounded-rh-md p-4 text-[12px]" aria-label="Risk response">
      <h2 className="text-[14px] font-semibold">Risk response</h2>
      <p className="mt-1 text-rh-text-2">
        What RedHand does by itself when an agent&apos;s risk score reaches a number. Leave a box empty to turn that step off. Safe Mode and freeze
        are off unless you turn them on; a person can always undo them.
      </p>
      <div className="mt-3 grid gap-2 sm:grid-cols-3">
        {RUNGS.map(({ key, field: name }) => (
          <label key={key} className="flex flex-col gap-1 rounded-[8px] bg-rh-subtle p-2">
            <span className="font-semibold">{RUNG_LABEL[key]}</span>
            <span className="flex items-center gap-2">
              <span className="text-rh-text-2">at score</span>
              <input
                inputMode="numeric"
                value={draft[name]}
                disabled={!can}
                placeholder="off"
                onChange={(e) => setDraft({ ...draft, [name]: e.target.value })}
                className={field}
                aria-label={`${RUNG_LABEL[key]} threshold`}
              />
            </span>
            <span className="text-rh-text-2">
              {ladder.reaching[key] === 0 ? "No agent reaches it now." : `${ladder.reaching[key]} now: ${ladder.reaching_agents[key].join(", ")}${ladder.reaching[key] > ladder.reaching_agents[key].length ? ", …" : ""}`}
            </span>
          </label>
        ))}
      </div>
      {problem && can && <p role="alert" className="mt-2 text-rh-crimson-text">{problem}</p>}
      {needsConfirm && can && !problem && (
        <label className="mt-2 flex items-center gap-2">
          <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />
          <span>{LADDER_CONFIRM_TEXT}</span>
        </label>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        {can ? (
          <>
            <button className={button} disabled={busy || !changed || problem !== null || (needsConfirm && !confirm)} onClick={save}>Save</button>
            {changed && <span className="font-semibold text-rh-ochre">Not saved yet: press Save to apply this change.</span>}
          </>
        ) : (
          <span className="text-rh-text-2">Only an admin can change these.</span>
        )}
      </div>
    </section>
  );
}
