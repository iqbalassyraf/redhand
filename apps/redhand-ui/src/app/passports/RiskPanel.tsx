"use client";

/**
 * One agent's risk score (Phase 4.5 B1): the score and level, every signal with the points it added, what the ladder acts on after a
 * person's release, the published weights, and the evidence itself (the agent's latest findings and refused calls), so the number is never
 * taken on trust. The UI is never a security boundary: redhand-core computes the score and decides every action. Everything from the
 * server is rendered as text.
 */

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";

import { ApiError, type BlackBoxEvent, type RadarFinding, type RiskDetail, blackboxApi, radarApi, riskApi } from "@/lib/api";
import { BEHAVIOUR_LIMITS_TEXT, backtestText, behaviourHeadline, hourText, shownToolName } from "@/lib/behaviour";
import { LEVEL_LABEL, LEVEL_STYLE, RISK_LIMITS_TEXT, signalDetail } from "@/lib/riskForm";

const button = "rounded-full border border-rh-hairline bg-rh-card px-3 py-1 text-[12px] font-semibold hover:bg-rh-elevated disabled:opacity-50";
const EVIDENCE_ROWS = 5;

export function RiskPanel(props: { token: string; agentId: string; agentName: string; onClose: () => void; onUnauthorized: () => void }) {
  const { token, agentId } = props;
  const [detail, setDetail] = useState<RiskDetail | null>(null);
  const [findings, setFindings] = useState<RadarFinding[] | null>(null);
  const [refusals, setRefusals] = useState<BlackBoxEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setDetail(await riskApi.detail(token, agentId));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        props.onUnauthorized();
        return;
      }
      setError(err instanceof ApiError && err.status === 404 ? "Risk scores are not available from this server yet." : err instanceof Error ? err.message : "Something went wrong.");
      return;
    }
    // The evidence is best effort: a role that cannot read the Black Box still sees the score and its reasons.
    radarApi.findings(token, { agent_id: agentId, limit: EVIDENCE_ROWS }).then((r) => setFindings(r.findings)).catch(() => setFindings(null));
    blackboxApi.events(token, { agent_id: agentId, decision: "BLOCK", limit: EVIDENCE_ROWS }).then((r) => setRefusals(r.events)).catch(() => setRefusals(null));
  }, [token, agentId, props]);

  useEffect(() => {
    load();
  }, [load]);

  const agent = detail?.agent;
  return (
    <section className="rh-glass rounded-rh-md border-2 border-control-borderStrong p-4 text-[12px]" aria-label="Risk">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[15px] font-semibold">Risk for {props.agentName}</h2>
        <div className="flex gap-2">
          <button onClick={load} className={button}>Refresh</button>
          <button onClick={props.onClose} className={button}>Close</button>
        </div>
      </div>
      {error && <p role="alert" className="mt-2 rounded-[8px] bg-rh-crimson-wash p-2 text-rh-crimson-text">{error}</p>}
      {!agent || !detail ? (
        !error && <p className="mt-2 text-rh-text-2">Loading…</p>
      ) : (
        <>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <span className="text-[28px] font-bold leading-none">{agent.score}</span>
            <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${LEVEL_STYLE[agent.level]}`}>{LEVEL_LABEL[agent.level]}</span>
            <span className="text-rh-text-2">out of 100, last {detail.window_days} days</span>
          </div>
          {agent.released_at && (
            <p className="mt-2 rounded-[8px] bg-rh-subtle p-2">
              A person released this agent on {new Date(agent.released_at).toLocaleString()}. RedHand acts only on what came after:
              score <b>{agent.action_score}</b> for actions.
            </p>
          )}
          <h3 className="mt-4 text-[13px] font-semibold">Why</h3>
          {agent.signals.length === 0 ? (
            <p className="mt-1 text-rh-text-2">No signals in the last {detail.window_days} days.</p>
          ) : (
            <ul className="mt-1 divide-y divide-rh-hairline">
              {agent.signals.map((s) => (
                <li key={s.signal} className="flex flex-wrap justify-between gap-2 py-1.5">
                  <span className="font-semibold">{s.label}</span>
                  <span className="text-rh-text-2">{signalDetail(s)}</span>
                </li>
              ))}
            </ul>
          )}

          {detail.behaviour && (
            <div className={`mt-4 rounded-[8px] p-3 ${detail.behaviour.warning ? "bg-rh-ochre-wash" : "bg-rh-subtle"}`} aria-label="Behaviour">
              <h3 className="text-[13px] font-semibold">Behaviour (watch only, not part of the score)</h3>
              <p className="mt-1 font-semibold">{behaviourHeadline(detail.behaviour)}</p>
              {detail.behaviour.status === "ok" && detail.behaviour.warm && <p className="mt-1">{hourText(detail.behaviour)}</p>}
              {detail.behaviour.new_tools.length > 0 && (
                <p className="mt-1">
                  New tools in the last 24 hours:{" "}
                  {detail.behaviour.new_tools.map((t, i) => (
                    <React.Fragment key={t}>{i > 0 && ", "}<code className="rounded bg-rh-card px-1">{shownToolName(t)}</code></React.Fragment>
                  ))}
                </p>
              )}
              {backtestText(detail.behaviour) && <p className="mt-1 text-rh-text-2">{backtestText(detail.behaviour)}</p>}
              <p className="mt-1 text-rh-text-2">{BEHAVIOUR_LIMITS_TEXT}</p>
            </div>
          )}

          <h3 className="mt-4 text-[13px] font-semibold">Evidence</h3>
          <p className="mt-1 text-rh-text-2">The latest records behind the score. Trips are listed on the <Link href="/honeytokens" className="font-semibold underline">Honeytokens</Link> page.</p>
          <div className="mt-2 grid gap-3 md:grid-cols-2">
            <div>
              <p className="font-semibold">Findings</p>
              {findings === null ? <p className="text-rh-text-2">Not available for your role.</p> : findings.length === 0 ? <p className="text-rh-text-2">None.</p> : (
                <ul className="mt-1 space-y-1">
                  {findings.map((f) => (
                    <li key={f.id}><code className="rounded bg-rh-elevated px-1">{f.rule_id}</code> {f.tool_name || "a tool"} · {f.review_status.replace("_", " ")} · {new Date(f.last_seen_at).toLocaleString()}</li>
                  ))}
                </ul>
              )}
              <Link href="/radar" className="mt-1 inline-block font-semibold underline">All findings on the Radar page</Link>
            </div>
            <div>
              <p className="font-semibold">Refused calls</p>
              {refusals === null ? <p className="text-rh-text-2">Not available for your role.</p> : refusals.length === 0 ? <p className="text-rh-text-2">None.</p> : (
                <ul className="mt-1 space-y-1">
                  {refusals.map((e) => (
                    <li key={e.seq}>{e.tool_name || e.method} · {e.reasons[0] ?? "refused"} · {new Date(e.occurred_at).toLocaleString()}</li>
                  ))}
                </ul>
              )}
              <Link href="/blackbox" className="mt-1 inline-block font-semibold underline">All events in the Black Box</Link>
            </div>
          </div>

          <h3 className="mt-4 text-[13px] font-semibold">How the score is counted (version {detail.model})</h3>
          <p className="mt-1 text-rh-text-2">{RISK_LIMITS_TEXT}</p>
          <div className="mt-2 overflow-x-auto">
            <table className="w-full min-w-[360px] text-left">
              <thead className="text-rh-text-2"><tr><th className="py-1 pr-3 font-medium">Signal</th><th className="py-1 pr-3 font-medium">Points each</th><th className="py-1 font-medium">At most</th></tr></thead>
              <tbody>
                {detail.weights.map((w) => (
                  <tr key={w.signal} className="border-t border-rh-hairline"><td className="py-1 pr-3">{w.label}</td><td className="py-1 pr-3">{w.points}</td><td className="py-1">{w.cap}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}
