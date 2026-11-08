"use client";

/**
 * Prompt Injection Radar and output checks (Phase 4 M4.4): what the Radar found in tool answers, with review, per-agent silences
 * and the two switches. OBSERVE ONLY: nothing is blocked. The Radar sees only what passes through the RedHand gateway, and a
 * finding never contains the scanned text. The UI is never a security boundary: redhand-core decides who may read, review,
 * silence or change a mode; buttons are hidden from the server's `capabilities` only so people are not offered what would be refused.
 */

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Hand, LogOut, RefreshCw } from "lucide-react";

import {
  ApiError,
  type FindingReviewStatus,
  type RadarFinding,
  type RadarSettings,
  type RadarSuppression,
  radarApi,
} from "@/lib/api";
import { useAuth, useRequiredSession } from "@/lib/auth";
import { EVASION_LABEL, describeRule } from "@/lib/radarRules";
import {
  NOTE_MAX,
  SUPPRESSION_DAYS_MAX,
  SUPPRESSION_DAYS_MIN,
  clampDays,
  settingsNeedConfirmation,
  shorten,
  validateNote,
  validateSuppression,
} from "@/lib/radarForm";

const STATUS_LABEL: Record<FindingReviewStatus, string> = {
  open: "Not reviewed",
  confirmed: "Real",
  false_alarm: "False alarm",
};

const PLACE_LABEL = { text: "in the text", hidden: "in hidden text", decoded: "in decoded text" } as const;

function when(iso: string | null): string {
  if (!iso) return "never";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function NavLink({ href, label, active }: { href: string; label: string; active?: boolean }) {
  return (
    <Link
      href={href}
      className={`rounded-full px-3 py-1.5 ${active ? "bg-[#0F0F0F] font-semibold text-[#FFFFFF]" : "font-medium text-[#606060] hover:bg-[#F2F2F2]"}`}
    >
      {label}
    </Link>
  );
}

export default function RadarPage() {
  const session = useRequiredSession();
  const { signOut } = useAuth();
  const token = session?.token ?? null;

  const [settings, setSettings] = useState<RadarSettings | null>(null);
  const [findings, setFindings] = useState<RadarFinding[]>([]);
  const [nextBefore, setNextBefore] = useState<string | null>(null);
  const [silences, setSilences] = useState<RadarSuppression[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [busy, setBusy] = useState(false);

  const [statusFilter, setStatusFilter] = useState("");
  const [kindFilter, setKindFilter] = useState("");

  const [draftRadar, setDraftRadar] = useState<"off" | "observe">("observe");
  const [draftOutput, setDraftOutput] = useState<"off" | "observe">("observe");
  const [confirmOff, setConfirmOff] = useState(false);

  const [noteFor, setNoteFor] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [silenceFor, setSilenceFor] = useState<RadarFinding | null>(null);
  const [silenceReason, setSilenceReason] = useState("");
  const [silenceDays, setSilenceDays] = useState(30);
  const [silenceConfirm, setSilenceConfirm] = useState(false);

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        signOut();
        window.location.href = "/login";
        return;
      }
      if (err instanceof ApiError && err.status === 403) {
        setForbidden(true);
        return;
      }
      setError(err instanceof Error ? err.message : "Something went wrong.");
    },
    [signOut]
  );

  const loadFindings = useCallback(
    async (append: boolean, before?: string) => {
      if (!token) return;
      const page = await radarApi.findings(token, { review_status: statusFilter, kind: kindFilter, before, limit: 50 });
      setFindings((prev) => (append ? [...prev, ...page.findings] : page.findings));
      setNextBefore(page.next_before);
    },
    [token, statusFilter, kindFilter]
  );

  const load = useCallback(async () => {
    if (!token) return;
    setError(null);
    try {
      const [s, sil] = await Promise.all([radarApi.settings(token), radarApi.suppressions(token)]);
      setSettings(s);
      setSilences(sil.suppressions);
      setDraftRadar(s.radar_mode === "off" ? "off" : "observe");
      setDraftOutput(s.output_check_mode === "off" ? "off" : "observe");
      setConfirmOff(false);
      await loadFindings(false);
    } catch (err) {
      handleError(err);
    }
  }, [token, loadFindings, handleError]);

  useEffect(() => {
    load();
  }, [load]);

  const run = async (action: () => Promise<void>) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      await load();
    } catch (err) {
      handleError(err);
    } finally {
      setBusy(false);
    }
  };

  if (!session || !token) return null;

  const caps = settings?.capabilities;
  const needsConfirm = settings
    ? settingsNeedConfirmation(
        { radar: settings.radar_mode, output: settings.output_check_mode },
        { radar: draftRadar, output: draftOutput }
      )
    : false;
  const unchanged = settings ? draftRadar === settings.radar_mode && draftOutput === settings.output_check_mode : true;

  const saveSettings = () => {
    if (needsConfirm && !confirmOff) {
      setNotice(null);
      setError("Tick the box to confirm turning a check off.");
      return;
    }
    run(async () => {
      await radarApi.saveSettings(token, { radar_mode: draftRadar, output_check_mode: draftOutput, confirm: needsConfirm && confirmOff });
      setNotice("Settings saved. They reach the gateway within a few seconds.");
    });
  };

  const review = (finding: RadarFinding, status: "confirmed" | "false_alarm") => {
    const problem = validateNote(noteFor === finding.id ? note : "");
    if (problem) {
      setNotice(null);
      setError(problem);
      return;
    }
    run(async () => {
      const text = noteFor === finding.id ? note.trim() : "";
      await radarApi.review(token, finding.id, { status, ...(text ? { note: text } : {}) });
      setNoteFor(null);
      setNote("");
    });
  };

  const silence = () => {
    if (!silenceFor) return;
    const problem = validateSuppression(silenceReason, silenceDays, silenceConfirm);
    if (problem) {
      setNotice(null);
      setError(problem);
      return;
    }
    run(async () => {
      await radarApi.suppress(token, {
        agent_id: silenceFor.agent_id,
        rule_id: silenceFor.rule_id,
        days: silenceDays,
        reason: silenceReason.trim(),
        confirm: true,
      });
      setNotice(`Silenced ${silenceFor.rule_id} for ${silenceFor.agent_name ?? "this agent"} for ${silenceDays} day(s).`);
      setSilenceFor(null);
      setSilenceReason("");
      setSilenceConfirm(false);
      setSilenceDays(30);
    });
  };

  const field = "rounded-[8px] border border-[#E5E5E5] px-2 py-1 text-[12px]";
  const button = "rounded-full border border-[#E5E5E5] bg-[#FFFFFF] px-3 py-1 text-[12px] font-semibold hover:bg-[#F2F2F2] disabled:opacity-50";
  const week = settings?.last_7_days ?? {};

  return (
    <div className="min-h-screen bg-[#F8F8F8] text-[#0F0F0F]">
      <header className="flex h-[56px] items-center justify-between border-b border-[#E5E5E5] bg-[#FFFFFF] px-4">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-9 items-center justify-center rounded-[8px] bg-[#FF0000]">
              <Hand className="h-4 w-4 text-[#FFFFFF]" />
            </div>
            <span className="text-[20px] font-bold tracking-tight">RedHand</span>
          </div>
          <nav className="flex gap-1 text-[13px]">
            <NavLink href="/passports" label="Passports" />
            <NavLink href="/blackbox" label="Black Box" />
            <NavLink href="/honeytokens" label="Honeytokens" />
            <NavLink href="/scanner" label="MCP Scanner" />
            <NavLink href="/radar" label="Radar" active />
          </nav>
        </div>
        <div className="flex items-center gap-3 text-[12px]">
          <span className="text-[#606060]">
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
            <h1 className="text-[18px] font-bold">Radar: injection and risky output</h1>
            <p className="text-[12px] text-[#606060]">
              Looks at what tools answer, before the agent reads it. It only watches: nothing is blocked or changed. It sees only
              what passes through the RedHand gateway, and it does not store the text it scanned. It is a smoke detector, not a
              wall: on our unseen tests it finds most script-style output attacks, but only about 4 in 10 hidden instructions, and
              it can raise false alarms on documentation-style text.
            </p>
          </div>
          <button onClick={() => load()} className={`flex items-center gap-1.5 ${button}`}>
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>

        {error ? <div className="mb-3 rounded-[8px] border border-[#FDECEC] bg-[#FFF5F5] px-3 py-2 text-[12px] text-[#B42318]">{error}</div> : null}
        {notice ? <div className="mb-3 rounded-[8px] border border-[#E6F4EA] bg-[#F3FBF5] px-3 py-2 text-[12px] text-[#1E7B34]">{notice}</div> : null}

        {forbidden ? (
          <div className="rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4 text-[12px]">
            Your role cannot see the Radar. Ask an owner or admin to give you the security operator role.
          </div>
        ) : (
          <>
            <section className="mb-6 rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4 text-[12px]">
              <h2 className="mb-3 text-[14px] font-semibold">Checks</h2>
              <div className="mb-3 flex flex-wrap items-end gap-4">
                <label className="flex flex-col gap-1">
                  <span className="text-[#606060]">Hidden instructions in tool answers</span>
                  <select
                    value={draftRadar}
                    disabled={!caps?.can_change_modes}
                    onChange={(e) => setDraftRadar(e.target.value as "off" | "observe")}
                    className={field}
                  >
                    <option value="observe">Watch (record findings)</option>
                    <option value="off">Off</option>
                  </select>
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-[#606060]">Risky output (script, odd links, internal addresses)</span>
                  <select
                    value={draftOutput}
                    disabled={!caps?.can_change_modes}
                    onChange={(e) => setDraftOutput(e.target.value as "off" | "observe")}
                    className={field}
                  >
                    <option value="observe">Watch (record findings)</option>
                    <option value="off">Off</option>
                  </select>
                </label>
                {caps?.can_change_modes ? (
                  <button onClick={saveSettings} disabled={busy || unchanged} className={button}>
                    Save
                  </button>
                ) : (
                  <span className="text-[#606060]">Only an admin can change these.</span>
                )}
              </div>
              {needsConfirm && caps?.can_change_modes ? (
                <label className="mb-2 flex items-center gap-2">
                  <input type="checkbox" checked={confirmOff} onChange={(e) => setConfirmOff(e.target.checked)} />
                  <span>I understand: while a check is off, RedHand stops recording what it would have found.</span>
                </label>
              ) : null}
              <p className="text-[#606060]">
                Blocking is not available. It stays off until we have enough measured evidence that it would not stop real work.
                {settings ? ` Injection check changed ${when(settings.radar_mode_changed_at)}; output check changed ${when(settings.output_check_mode_changed_at)}.` : ""}
              </p>
              <div className="mt-3 flex flex-wrap gap-4 text-[#606060]">
                <span>Last 7 days:</span>
                <span><b className="text-[#0F0F0F]">{week.findings ?? 0}</b> findings</span>
                <span><b className="text-[#0F0F0F]">{week.open ?? 0}</b> not reviewed</span>
                <span><b className="text-[#0F0F0F]">{week.confirmed ?? 0}</b> real</span>
                <span><b className="text-[#0F0F0F]">{week.false_alarm ?? 0}</b> false alarms</span>
                <span title="Findings a future blocking mode would have stopped">
                  <b className="text-[#0F0F0F]">{week.would_block ?? 0}</b> would have been blocked
                </span>
              </div>
            </section>

            <section className="mb-6 rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4 text-[12px]">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-[14px] font-semibold">Findings</h2>
                <div className="flex gap-2">
                  <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className={field} aria-label="Filter by review">
                    <option value="">Any review</option>
                    <option value="open">Not reviewed</option>
                    <option value="confirmed">Real</option>
                    <option value="false_alarm">False alarm</option>
                  </select>
                  <select value={kindFilter} onChange={(e) => setKindFilter(e.target.value)} className={field} aria-label="Filter by kind">
                    <option value="">Any kind</option>
                    <option value="injection">Hidden instructions</option>
                    <option value="output">Risky output</option>
                  </select>
                </div>
              </div>
              {findings.length === 0 ? (
                <p className="text-[#606060]">
                  No findings. That means the Radar saw nothing it recognises in what passed through the gateway, not that
                  nothing is wrong.
                </p>
              ) : (
                <ul className="divide-y divide-[#F2F2F2]">
                  {findings.map((f) => (
                    <li key={f.id} className="py-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded-full bg-[#0F0F0F] px-2 py-0.5 font-mono text-[11px] text-[#FFFFFF]">{f.rule_id}</span>
                        <span className="font-semibold">{f.agent_name ?? f.agent_id.slice(0, 8)}</span>
                        <span className="text-[#606060]">
                          via {shorten(f.tool_name || "(unknown tool)")} on {shorten(f.server_slug || "(unknown server)")}
                        </span>
                        <span className="ml-auto text-[#606060]">{when(f.last_seen_at)}</span>
                      </div>
                      <p className="mt-1">{describeRule(f.rule_id)}</p>
                      <p className="mt-1 text-[#606060]">
                        {f.severity} severity, {f.confidence} confidence, {PLACE_LABEL[f.place]}
                        {f.evasion.length ? `, tricks: ${f.evasion.map((e) => EVASION_LABEL[e] ?? e).join(", ")}` : ""}
                        {` · seen ${f.occurrences} time${f.occurrences === 1 ? "" : "s"}`}
                        {f.would_block ? " · would be blocked" : ""} · <b className="text-[#0F0F0F]">{STATUS_LABEL[f.review_status]}</b>
                        {f.review_note ? ` · note: ${shorten(f.review_note, 120)}` : ""}
                      </p>
                      {caps?.can_review || caps?.can_suppress ? (
                        <div className="mt-2 flex flex-wrap items-center gap-2">
                          {caps?.can_review ? (
                            <>
                              <button disabled={busy || f.review_status === "confirmed"} onClick={() => review(f, "confirmed")} className={button}>
                                Real
                              </button>
                              <button disabled={busy || f.review_status === "false_alarm"} onClick={() => review(f, "false_alarm")} className={button}>
                                False alarm
                              </button>
                              <button
                                onClick={() => {
                                  setNoteFor(noteFor === f.id ? null : f.id);
                                  setNote("");
                                }}
                                className={button}
                              >
                                {noteFor === f.id ? "No note" : "Add a note"}
                              </button>
                            </>
                          ) : null}
                          {caps?.can_suppress ? (
                            <button onClick={() => { setSilenceFor(silenceFor?.id === f.id ? null : f); setError(null); }} className={button}>
                              Silence this rule for this agent
                            </button>
                          ) : null}
                        </div>
                      ) : null}
                      {noteFor === f.id ? (
                        <div className="mt-2 flex items-center gap-2">
                          <input
                            value={note}
                            maxLength={NOTE_MAX}
                            onChange={(e) => setNote(e.target.value)}
                            placeholder="Optional note, then press Real or False alarm"
                            className={`${field} w-96`}
                          />
                          <span className="text-[#606060]">{note.length}/{NOTE_MAX}</span>
                        </div>
                      ) : null}
                      {silenceFor?.id === f.id ? (
                        <div className="mt-2 rounded-[8px] border border-[#FFE0B2] bg-[#FFF8EC] p-3">
                          <p className="mb-2">
                            Stops the Radar recording <b>{f.rule_id}</b> for <b>{f.agent_name ?? "this agent"}</b>. Other rules and other
                            agents are not affected. It ends by itself.
                          </p>
                          <div className="mb-2 flex flex-wrap items-end gap-3">
                            <label className="flex flex-col gap-1">
                              <span className="text-[#606060]">Reason (required)</span>
                              <input value={silenceReason} maxLength={NOTE_MAX} onChange={(e) => setSilenceReason(e.target.value)} className={`${field} w-80`} />
                            </label>
                            <label className="flex flex-col gap-1">
                              <span className="text-[#606060]">Days ({SUPPRESSION_DAYS_MIN} to {SUPPRESSION_DAYS_MAX})</span>
                              <input
                                type="number"
                                min={SUPPRESSION_DAYS_MIN}
                                max={SUPPRESSION_DAYS_MAX}
                                value={silenceDays}
                                onChange={(e) => setSilenceDays(clampDays(e.target.valueAsNumber))}
                                className={`${field} w-20`}
                              />
                            </label>
                          </div>
                          <label className="mb-2 flex items-center gap-2">
                            <input type="checkbox" checked={silenceConfirm} onChange={(e) => setSilenceConfirm(e.target.checked)} />
                            <span>I understand this rule will not record findings for this agent until it ends or I remove it.</span>
                          </label>
                          <button disabled={busy} onClick={silence} className={button}>Silence it</button>
                        </div>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
              {nextBefore ? (
                <button
                  disabled={busy}
                  onClick={() => run(async () => { await loadFindings(true, nextBefore); })}
                  className={`mt-3 ${button}`}
                >
                  Load older
                </button>
              ) : null}
            </section>

            <section className="rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4 text-[12px]">
              <h2 className="mb-3 text-[14px] font-semibold">Active silences</h2>
              {silences.length === 0 ? (
                <p className="text-[#606060]">None. Every rule is recording for every agent.</p>
              ) : (
                <ul className="divide-y divide-[#F2F2F2]">
                  {silences.map((s) => (
                    <li key={s.id} className="flex flex-wrap items-center gap-2 py-2">
                      <span className="rounded-full bg-[#0F0F0F] px-2 py-0.5 font-mono text-[11px] text-[#FFFFFF]">{s.rule_id}</span>
                      <span className="font-semibold">{s.agent_name ?? s.agent_id.slice(0, 8)}</span>
                      <span className="text-[#606060]">{shorten(s.reason, 100)}</span>
                      <span className="ml-auto text-[#606060]">ends {when(s.expires_at)}</span>
                      {caps?.can_suppress ? (
                        <button disabled={busy} onClick={() => run(async () => { await radarApi.removeSuppression(token, s.id); })} className={button}>
                          Remove
                        </button>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </>
        )}
      </main>
    </div>
  );
}
