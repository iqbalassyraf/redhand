"use client";

/**
 * Detection coverage (Phase 4 M4.5a): how well each RedHand detector works on samples it has seen and on samples it has not, per language,
 * and where it does not work. The data is /coverage.json, generated from the same benchmark as docs/security/coverage-matrix.md (a test
 * fails if they differ). It holds counts and names only, and everything is shown as plain text. Nothing here means RedHand blocks anything:
 * the Radar only watches, and RedHand only sees what flows through its gateway.
 */

import React, { useEffect, useState } from "react";


import { useAuth, useRequiredSession } from "@/lib/auth";
import { AppShell } from "@/components/shell/AppShell";
import { type BlockGate, type CoverageData, type CoverageResult, isCoverageData, measured, statusStyle } from "@/lib/coverage";


function Status({ value }: { value: string }) {
  const style = statusStyle(value);
  return <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${style.classes}`}>{style.label}</span>;
}

function ResultsTable({ rows }: { rows: CoverageResult[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-[12px]">
        <thead className="text-rh-text-2">
          <tr>
            <th className="py-1 pr-3 font-medium">Check</th>
            <th className="py-1 pr-3 font-medium">Attacks / harmless</th>
            <th className="py-1 pr-3 font-medium">Attacks found (95% range)</th>
            <th className="py-1 pr-3 font-medium">False alarms (95% range)</th>
            <th className="py-1 font-medium">Rating</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.category} className="border-t border-rh-hairline align-top">
              <td className="py-2 pr-3 font-mono">{r.category}</td>
              <td className="py-2 pr-3">{r.malicious} / {r.benign}</td>
              <td className="py-2 pr-3">{r.detection}</td>
              <td className="py-2 pr-3">{r.false_alarm_rate}</td>
              <td className="py-2"><Status value={r.status} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function GatePill({ passed }: { passed: boolean }) {
  return (
    <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${passed ? "bg-rh-teal-wash text-rh-teal-text" : "bg-rh-crimson-wash text-rh-crimson-text"}`}>
      {passed ? "pass" : "not yet"}
    </span>
  );
}

/** Whether the measured evidence would ever allow blocking. Blocking does not exist; this explains, check by check, why it stays off. */
function BlockGateSection({ gate, className }: { gate: BlockGate; className: string }) {
  return (
    <section className={className}>
      <h2 className="mb-1 text-[14px] font-semibold">{gate.eligible.length === 0 ? "Ready to block? Not yet." : "Ready to block? Some checks pass this test."}</h2>
      <p className="mb-2 text-rh-text-2">
        Blocking is not available and cannot be switched on. This is the test a check must pass first, using only the independent test
        rounds below (never samples we wrote ourselves). A check is ready only when every one of these holds:
      </p>
      <ul className="mb-3 list-disc space-y-0.5 pl-5 text-rh-text-2">
        {gate.rules.map((rule) => (
          <li key={rule.id}><b className="text-rh-text">{rule.name}.</b> {rule.description}</li>
        ))}
      </ul>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {gate.checks.map((check) => (
          <div key={check.category} className="rounded-[8px] border border-rh-hairline p-3">
            <div className="mb-2 flex items-center justify-between gap-2">
              <span className="text-[13px] font-semibold">{check.label}</span>
              <GatePill passed={check.eligible} />
            </div>
            <ul className="space-y-1.5">
              {check.results.map((r) => (
                <li key={r.id} className="flex gap-2">
                  <span className="mt-0.5 shrink-0"><GatePill passed={r.passed} /></span>
                  <span className="text-rh-text-2">{r.detail}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <p className="mt-3 text-rh-text-2">
        Even a check that passes all of this would still be only a candidate: blocking would also need a speed test, a person reviewing the
        labels, and a separate decision. Rules version <code>{gate.rules_fingerprint}</code>: if the rules change, earlier rounds stop
        counting until they are measured again.
      </p>
    </section>
  );
}

export default function CoveragePage() {
  const session = useRequiredSession();
  const { signOut } = useAuth();
  const [data, setData] = useState<CoverageData | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch("/coverage.json")
      .then((resp) => (resp.ok ? resp.json() : Promise.reject(new Error("not found"))))
      .then((body: unknown) => {
        if (cancelled) return;
        if (isCoverageData(body)) setData(body);
        else setFailed(true);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!session) return null;

  const card = "rh-glass mb-6 rounded-rh-md p-4 text-[12px]";

  return (
    <AppShell title="Coverage" role={session.role}>

      <div className="mx-auto max-w-5xl px-4 py-6">
        <h1 className="text-[18px] font-bold">Detection coverage</h1>
        <p className="mb-4 text-[12px] text-rh-text-2">
          How well each check works, measured, including where it does not. Nothing here means RedHand blocks everything or
          protects anything outside its gateway. The Radar only watches: it never blocks.
        </p>

        {failed ? (
          <div className="rounded-[8px] border border-rh-crimson bg-rh-crimson-wash px-3 py-2 text-[12px] text-rh-crimson-text">
            The coverage data could not be loaded. Reload the page; if it keeps failing, the dashboard needs to be redeployed.
          </div>
        ) : null}

        {data ? (
          <>
            <section className="mb-6 rounded-[10px] border border-rh-ochre bg-rh-ochre-wash p-4 text-[12px]">
              <h2 className="mb-2 text-[14px] font-semibold">Known gaps (read these first)</h2>
              <ul className="list-disc space-y-1 pl-5">
                {data.known_gaps.map((gap) => (
                  <li key={gap}>{gap}</li>
                ))}
              </ul>
            </section>

            <BlockGateSection gate={data.block_gate} className={card} />

            <section className={card}>
              <h2 className="mb-1 text-[14px] font-semibold">How to read this</h2>
              <p className="text-rh-text-2">
                {data.total_samples} labelled samples, written by the RedHand team (and, for the blind rounds, by an outside author).
                The 95% range shows how uncertain a rate is at this size: a small set can only prove so much. Variants of one idea are
                correlated, so real attackers will do worse than the tables suggest. Ratings use fixed rules:
              </p>
              <ul className="mt-2 list-disc space-y-0.5 pl-5 text-rh-text-2">
                {Object.entries(data.status_rules).map(([name, rule]) => (
                  <li key={name}><b className="text-rh-text">{name}</b>: {rule}</li>
                ))}
              </ul>
            </section>

            <section className={card}>
              <h2 className="mb-1 text-[14px] font-semibold">Languages</h2>
              <p className="mb-3 text-rh-text-2">
                &ldquo;Reviewed by a native speaker&rdquo; means someone fluent checked the rules and samples. For every language below the answer is no.
              </p>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {data.languages.map((lang) => (
                  <div key={lang.code} className="rounded-[8px] border border-rh-hairline p-3">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="text-[13px] font-semibold">{lang.name}</span>
                      <span className="rounded-full bg-rh-elevated px-2 py-0.5 text-[11px] font-semibold text-rh-text-2">
                        {lang.native_reviewed ? "native-reviewed" : "not native-reviewed"}
                      </span>
                    </div>
                    <p className="mb-2 text-rh-text-2">{lang.note}</p>
                    <p>
                      Hidden-instruction attacks found in the independent round:{" "}
                      <b>{lang.blind3 ? measured(lang.blind3.attacks_found, lang.blind3.attacks) : "not measured"}</b>
                      {lang.blind3 && lang.blind3.harmless > 0 ? (
                        <span className="text-rh-text-2"> · harmless texts flagged: {lang.blind3.harmless_flagged} of {lang.blind3.harmless}</span>
                      ) : null}
                    </p>
                  </div>
                ))}
              </div>
            </section>

            <section className={card}>
              <h2 className="mb-1 text-[14px] font-semibold">Held-out samples (never tuned on)</h2>
              <p className="mb-3 text-rh-text-2">
                Written before the rules and not used to tune them. Small sets: with 20 harmless samples the false alarm rate is only
                known to be below about 16%, so read &ldquo;covered&rdquo; here as &ldquo;no misses found yet&rdquo;.
              </p>
              <ResultsTable rows={data.holdout} />
            </section>

            {data.blind_rounds.map((round) => (
              <section key={round.key} className={card}>
                <h2 className="mb-1 text-[14px] font-semibold">{round.title}</h2>
                <p className="mb-1 text-rh-text-2">Written by {round.author}. {round.note}</p>
                <p className="mb-3 text-rh-text-2">Full record: <code>{round.record}</code></p>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[560px] text-left text-[12px]">
                    <thead className="text-rh-text-2">
                      <tr>
                        <th className="py-1 pr-3 font-medium">Check</th>
                        <th className="py-1 pr-3 font-medium">Attacks found (95% range)</th>
                        <th className="py-1 pr-3 font-medium">False alarms (95% range)</th>
                        <th className="py-1 font-medium">False alarms on tricky harmless text</th>
                      </tr>
                    </thead>
                    <tbody>
                      {round.rows.map((row) => (
                        <tr key={row.category} className="border-t border-rh-hairline">
                          <td className="py-2 pr-3 font-mono">{row.category}</td>
                          <td className="py-2 pr-3">{row.detection}</td>
                          <td className="py-2 pr-3">{row.false_alarms}</td>
                          <td className="py-2">{row.hard_false_alarms}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            ))}

            <details className={card}>
              <summary className="cursor-pointer text-[14px] font-semibold">Development samples (the rules were written against these, so they flatter the rules)</summary>
              <div className="mt-3">
                <ResultsTable rows={data.dev} />
              </div>
            </details>

            <section className={card}>
              <h2 className="mb-2 text-[14px] font-semibold">OWASP LLM Top 10 (as understood by the project)</h2>
              <ul className="space-y-1">
                {data.owasp.map((item) => (
                  <li key={item.item}>
                    <b>{item.item}</b> {item.name}:{" "}
                    <span className="text-rh-text-2">{item.status.length ? item.status.join("; ") : "not measured"}{item.note ? ` · ${item.note}` : ""}</span>
                  </li>
                ))}
              </ul>
            </section>
          </>
        ) : failed ? null : (
          <p className="text-[12px] text-rh-text-2">Loading…</p>
        )}
      </div>
    </AppShell>
  );
}
