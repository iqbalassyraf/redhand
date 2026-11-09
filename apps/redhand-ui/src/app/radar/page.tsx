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
  type ReadinessResult,
  type SelfTestResult,
  radarApi,
  selfTestApi,
} from "@/lib/api";
import { useAuth, useRequiredSession } from "@/lib/auth";
import { type BlockGate, isCoverageData } from "@/lib/coverage";
import { EVASION_LABEL, describeRule } from "@/lib/radarRules";
import { evidenceFor, falseAlarmText as readinessFalseAlarmText, headline, isReadinessResult, trafficText } from "@/lib/readiness";
import { CHECK_LABEL, falseAlarmText, foundText, selfTestProblem } from "@/lib/selfTest";
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

  const [readiness, setReadiness] = useState<ReadinessResult | null>(null);
  const [readinessFailed, setReadinessFailed] = useState(false);
  const [gate, setGate] = useState<BlockGate | null>(null);

  const [selfTest, setSelfTest] = useState<SelfTestResult | null>(null);
  const [selfTestRunning, setSelfTestRunning] = useState(false);
  const [selfTestError, setSelfTestError] = useState<string | null>(null);

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
      try {
        const r: unknown = await radarApi.readiness(token);
        if (isReadinessResult(r)) {
          setReadiness(r);
          setReadinessFailed(false);
        } else {
          setReadiness(null);
          setReadinessFailed(true);
        }
      } catch {
        setReadiness(null);
        setReadinessFailed(true); // the panel says "not available"; it never blocks the rest of the page
      }
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

  useEffect(() => {
    let cancelled = false;
    fetch("/coverage.json")
      .then((resp) => (resp.ok ? resp.json() : Promise.reject(new Error("not found"))))
      .then((body: unknown) => {
        if (!cancelled && isCoverageData(body)) setGate(body.block_gate);
      })
      .catch(() => {
        /* the panel then shows our tests as unavailable and links to the Coverage page */
      });
    return () => {
      cancelled = true;
    };
  }, []);

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

  const runSelfTest = async () => {
    if (selfTestRunning) return;
    setSelfTestRunning(true);
    setSelfTestError(null);
    try {
      setSelfTest(await selfTestApi.run(token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        signOut();
        window.location.href = "/login";
        return;
      }
      setSelfTest(null); // never leave an older result next to a failure
      setSelfTestError(selfTestProblem(err instanceof ApiError ? err.status : null));
    } finally {
      setSelfTestRunning(false);
    }
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
        <div className="flex min-w-0 items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-9 items-center justify-center rounded-[8px] bg-[#FF0000]">
              <Hand className="h-4 w-4 text-[#FFFFFF]" />
            </div>
            <span className="text-[20px] font-bold tracking-tight">RedHand</span>
          </div>
          <nav className="flex gap-1 overflow-x-auto whitespace-nowrap text-[13px]">
            <NavLink href="/passports" label="Passports" />
            <NavLink href="/blackbox" label="Black Box" />
            <NavLink href="/honeytokens" label="Honeytokens" />
            <NavLink href="/scanner" label="MCP Scanner" />
            <NavLink href="/radar" label="Radar" active />
            <NavLink href="/coverage" label="Coverage" />
          </nav>
        </div>
        <div className="flex items-center gap-3 text-[12px]">
          <span className="hidden text-[#606060] sm:inline">
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
                    onChange={(e) => { setNotice(null); setError(null); setDraftRadar(e.target.value as "off" | "observe"); }}
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
                    onChange={(e) => { setNotice(null); setError(null); setDraftOutput(e.target.value as "off" | "observe"); }}
                    className={field}
                  >
                    <option value="observe">Watch (record findings)</option>
                    <option value="off">Off</option>
                  </select>
                </label>
                {caps?.can_change_modes ? (
                  <>
                    <button onClick={saveSettings} disabled={busy || unchanged} className={button}>
                      Save
                    </button>
                    {unchanged ? null : <span className="font-semibold text-[#8A5A00]">Not saved yet: press Save to apply this change.</span>}
                  </>
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
                Blocking is not available. It stays off until measured evidence shows it would not stop real work; the{" "}
                <Link href="/coverage" className="font-semibold underline">Coverage page</Link> lists what is still missing, check by check.
                {settings ? ` Injection check changed ${when(settings.radar_mode_changed_at)}; output check changed ${when(settings.output_check_mode_changed_at)}.` : ""}
              </p>
              <div className="mt-3 flex flex-wrap gap-4 text-[#606060]">
                <span>Last 7 days:</span>
                <span><b className="text-[#0F0F0F]">{week.findings ?? 0}</b> findings</span>
                <span><b className="text-[#0F0F0F]">{week.open ?? 0}</b> not reviewed</span>
                <span><b className="text-[#0F0F0F]">{week.confirmed ?? 0}</b> real</span>
                <span><b className="text-[#0F0F0F]">{week.false_alarm ?? 0}</b> false alarms</span>
                <span title="Findings that were not low confidence. Nothing was blocked: the Radar only watches.">
                  <b className="text-[#0F0F0F]">{week.would_block ?? 0}</b> strong findings
                </span>
              </div>
            </section>

            <section className="mb-6 rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4 text-[12px]">
              <h2 className="mb-1 text-[14px] font-semibold">Could blocking ever be switched on?</h2>
              <p className="mb-3 text-[#606060]">
                Not today: blocking is not available. Two separate things must both look good before anyone could even consider it: our tests on
                independent samples, and your own traffic. This panel shows both. It only reads numbers and changes nothing.
              </p>
              {readinessFailed ? (
                <p className="rounded-[8px] border border-[#E5E5E5] bg-[#F8F8F8] px-3 py-2 text-[#606060]">
                  The figures from your traffic are not available right now. Nothing is wrong with your checks; try Refresh in a moment.
                </p>
              ) : null}
              {readiness ? (
                <div className="grid gap-3 sm:grid-cols-2">
                  {readiness.checks.map((check) => (
                    <div key={check.kind} className="rounded-[8px] border border-[#E5E5E5] p-3">
                      <div className="mb-1 flex items-center justify-between gap-2">
                        <span className="text-[13px] font-semibold">{check.label}</span>
                        <span className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-semibold ${check.ready ? "bg-[#FFF8EC] text-[#8A5A00]" : "bg-[#F2F2F2] text-[#606060]"}`}>
                          {check.ready ? "candidate" : "not yet"}
                        </span>
                      </div>
                      <p className="mb-2 text-[#606060]">{headline(check)}</p>
                      <p className="mb-1 font-semibold">Your traffic, last {readiness.window_days} days</p>
                      <p className="text-[#606060]">{trafficText(check)}</p>
                      <p className="mb-2 text-[#606060]">{readinessFalseAlarmText(check)}</p>
                      <ul className="mb-2 space-y-1">
                        {check.conditions.map((c) => (
                          <li key={c.id} className="flex gap-2">
                            <span className={`mt-0.5 h-fit shrink-0 rounded-full px-2 py-0.5 text-[11px] font-semibold ${c.passed ? "bg-[#E6F4EA] text-[#1E7B34]" : "bg-[#FDECEC] text-[#B42318]"}`}>
                              {c.passed ? "pass" : "not yet"}
                            </span>
                            <span className="text-[#606060]"><b className="text-[#0F0F0F]">{c.name}:</b> {c.detail}</span>
                          </li>
                        ))}
                      </ul>
                      <p className="mb-1 font-semibold">Our independent tests</p>
                      {evidenceFor(gate, check.kind).length > 0 ? (
                        <ul className="text-[#606060]">
                          {evidenceFor(gate, check.kind).map((line) => (
                            <li key={line.label}>{line.label}: {line.passed} of {line.total} rules pass{line.eligible ? "" : " (not ready)"}</li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-[#606060]">Not loaded.</p>
                      )}
                    </div>
                  ))}
                </div>
              ) : null}
              <p className="mt-3 text-[#606060]">
                {readiness?.note ?? "Blocking is not available and cannot be switched on."} Details of our tests are on the{" "}
                <Link href="/coverage" className="font-semibold underline">Coverage page</Link>.
              </p>
            </section>

            <section className="mb-6 rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4 text-[12px]">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-[14px] font-semibold">Self-test</h2>
                <button onClick={runSelfTest} disabled={selfTestRunning} className={button}>
                  {selfTestRunning ? "Running…" : "Run self-test"}
                </button>
              </div>
              <p className="text-[#606060]">
                Asks the gateway to run the Radar over {selfTest?.samples ?? "about 180"} of our own held-out test texts and shows how many it
                catches. It proves the Radar code running in the gateway behaves as measured. It does not prove that your agents&apos; traffic
                goes through the gateway, and it cannot show what these samples do not contain. You can run it once a minute.
              </p>
              <p className="mt-2 rounded-[8px] border border-[#FFE0B2] bg-[#FFF8EC] px-3 py-2">
                <b>Do not read these numbers as how well the Radar works in real life.</b> These texts were written by the same team that
                wrote the rules, so they flatter it. On text written by someone else, the Radar found about 4 in 10 hidden instructions.
                See the <Link href="/coverage" className="font-semibold underline">Coverage page</Link> for the independent results.
              </p>
              {selfTestError ? <div className="mt-3 rounded-[8px] border border-[#FDECEC] bg-[#FFF5F5] px-3 py-2 text-[#B42318]">{selfTestError}</div> : null}
              {selfTest ? (
                <div className="mt-3">
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[560px] text-left">
                      <thead className="text-[#606060]">
                        <tr>
                          <th className="py-1 pr-3 font-medium">Check</th>
                          <th className="py-1 pr-3 font-medium">Attacks found</th>
                          <th className="py-1 font-medium">False alarms on harmless text</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selfTest.categories.map((c) => (
                          <tr key={c.category} className="border-t border-[#F2F2F2]">
                            <td className="py-2 pr-3">{CHECK_LABEL[c.category] ?? c.category}</td>
                            <td className="py-2 pr-3">{foundText(c)}</td>
                            <td className="py-2">{falseAlarmText(c)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <p className="mt-2 text-[#606060]">
                    Ran {when(selfTest.ran_at)} on {selfTest.samples} texts in {Math.round(selfTest.duration_ms)} ms, sample set {selfTest.corpus}.
                    Helper model: {selfTest.model_enabled ? "on" : "off"}. Your switches right now: hidden instructions{" "}
                    <b className="text-[#0F0F0F]">{selfTest.radar_mode === "observe" ? "watching" : selfTest.radar_mode}</b>, risky output{" "}
                    <b className="text-[#0F0F0F]">{selfTest.output_check_mode === "observe" ? "watching" : selfTest.output_check_mode}</b>.
                    {selfTest.radar_mode === "off" || selfTest.output_check_mode === "off"
                      ? " A switch that is off means the gateway is not scanning for you, even though the code works."
                      : ""}
                  </p>
                  <p className="mt-1 text-[#606060]">{selfTest.limits}</p>
                </div>
              ) : null}
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
                        {f.would_block ? " · strong finding" : ""} · <b className="text-[#0F0F0F]">{STATUS_LABEL[f.review_status]}</b>
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
