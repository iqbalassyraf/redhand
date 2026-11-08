"use client";

/**
 * Detection coverage (Phase 4 M4.5a): how well each RedHand detector works on samples it has seen and on samples it has not, per language,
 * and where it does not work. The data is /coverage.json, generated from the same benchmark as docs/security/coverage-matrix.md (a test
 * fails if they differ). It holds counts and names only, and everything is shown as plain text. Nothing here means RedHand blocks anything:
 * the Radar only watches, and RedHand only sees what flows through its gateway.
 */

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Hand, LogOut } from "lucide-react";

import { useAuth, useRequiredSession } from "@/lib/auth";
import { type CoverageData, type CoverageResult, isCoverageData, measured, statusStyle } from "@/lib/coverage";

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

function Status({ value }: { value: string }) {
  const style = statusStyle(value);
  return <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${style.classes}`}>{style.label}</span>;
}

function ResultsTable({ rows }: { rows: CoverageResult[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-[12px]">
        <thead className="text-[#606060]">
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
            <tr key={r.category} className="border-t border-[#F2F2F2] align-top">
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

  const card = "mb-6 rounded-[10px] border border-[#E5E5E5] bg-[#FFFFFF] p-4 text-[12px]";

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
            <NavLink href="/radar" label="Radar" />
            <NavLink href="/coverage" label="Coverage" active />
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
        <h1 className="text-[18px] font-bold">Detection coverage</h1>
        <p className="mb-4 text-[12px] text-[#606060]">
          How well each check works, measured, including where it does not. Nothing here means RedHand blocks everything or
          protects anything outside its gateway. The Radar only watches: it never blocks.
        </p>

        {failed ? (
          <div className="rounded-[8px] border border-[#FDECEC] bg-[#FFF5F5] px-3 py-2 text-[12px] text-[#B42318]">
            The coverage data could not be loaded. Reload the page; if it keeps failing, the dashboard needs to be redeployed.
          </div>
        ) : null}

        {data ? (
          <>
            <section className="mb-6 rounded-[10px] border border-[#FFE0B2] bg-[#FFF8EC] p-4 text-[12px]">
              <h2 className="mb-2 text-[14px] font-semibold">Known gaps (read these first)</h2>
              <ul className="list-disc space-y-1 pl-5">
                {data.known_gaps.map((gap) => (
                  <li key={gap}>{gap}</li>
                ))}
              </ul>
            </section>

            <section className={card}>
              <h2 className="mb-1 text-[14px] font-semibold">How to read this</h2>
              <p className="text-[#606060]">
                {data.total_samples} labelled samples, written by the RedHand team (and, for the blind rounds, by an outside author).
                The 95% range shows how uncertain a rate is at this size: a small set can only prove so much. Variants of one idea are
                correlated, so real attackers will do worse than the tables suggest. Ratings use fixed rules:
              </p>
              <ul className="mt-2 list-disc space-y-0.5 pl-5 text-[#606060]">
                {Object.entries(data.status_rules).map(([name, rule]) => (
                  <li key={name}><b className="text-[#0F0F0F]">{name}</b>: {rule}</li>
                ))}
              </ul>
            </section>

            <section className={card}>
              <h2 className="mb-1 text-[14px] font-semibold">Languages</h2>
              <p className="mb-3 text-[#606060]">
                &ldquo;Reviewed by a native speaker&rdquo; means someone fluent checked the rules and samples. For every language below the answer is no.
              </p>
              <div className="grid gap-3 sm:grid-cols-2">
                {data.languages.map((lang) => (
                  <div key={lang.code} className="rounded-[8px] border border-[#E5E5E5] p-3">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="text-[13px] font-semibold">{lang.name}</span>
                      <span className="rounded-full bg-[#F2F2F2] px-2 py-0.5 text-[11px] font-semibold text-[#606060]">
                        {lang.native_reviewed ? "native-reviewed" : "not native-reviewed"}
                      </span>
                    </div>
                    <p className="mb-2 text-[#606060]">{lang.note}</p>
                    <p>
                      Hidden-instruction attacks found in the independent round:{" "}
                      <b>{lang.blind3 ? measured(lang.blind3.attacks_found, lang.blind3.attacks) : "not measured"}</b>
                      {lang.blind3 && lang.blind3.harmless > 0 ? (
                        <span className="text-[#606060]"> · harmless texts flagged: {lang.blind3.harmless_flagged} of {lang.blind3.harmless}</span>
                      ) : null}
                    </p>
                  </div>
                ))}
              </div>
            </section>

            <section className={card}>
              <h2 className="mb-1 text-[14px] font-semibold">Held-out samples (never tuned on)</h2>
              <p className="mb-3 text-[#606060]">
                Written before the rules and not used to tune them. Small sets: with 20 harmless samples the false alarm rate is only
                known to be below about 16%, so read &ldquo;covered&rdquo; here as &ldquo;no misses found yet&rdquo;.
              </p>
              <ResultsTable rows={data.holdout} />
            </section>

            {data.blind_rounds.map((round) => (
              <section key={round.key} className={card}>
                <h2 className="mb-1 text-[14px] font-semibold">{round.title}</h2>
                <p className="mb-1 text-[#606060]">Written by {round.author}. {round.note}</p>
                <p className="mb-3 text-[#606060]">Full record: <code>{round.record}</code></p>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[560px] text-left text-[12px]">
                    <thead className="text-[#606060]">
                      <tr>
                        <th className="py-1 pr-3 font-medium">Check</th>
                        <th className="py-1 pr-3 font-medium">Attacks found (95% range)</th>
                        <th className="py-1 pr-3 font-medium">False alarms (95% range)</th>
                        <th className="py-1 font-medium">False alarms on tricky harmless text</th>
                      </tr>
                    </thead>
                    <tbody>
                      {round.rows.map((row) => (
                        <tr key={row.category} className="border-t border-[#F2F2F2]">
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
                    <span className="text-[#606060]">{item.status.length ? item.status.join("; ") : "not measured"}{item.note ? ` · ${item.note}` : ""}</span>
                  </li>
                ))}
              </ul>
            </section>
          </>
        ) : failed ? null : (
          <p className="text-[12px] text-[#606060]">Loading…</p>
        )}
      </main>
    </div>
  );
}
