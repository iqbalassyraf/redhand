"use client";

/**
 * Hand-drawn SVG charts for the Insights page (no chart library, so no new dependency). Geometry lives in `src/lib/chartGeometry.ts` and is
 * tested there. Colours are the design tokens through CSS variables; marks keep 3:1 contrast against the card. Every chart sits in a
 * `ChartCard`, which carries a text summary for screen readers and a "View as table" toggle: the picture is never the only way to read it.
 */

import React, { useState } from "react";

import { areaPath, bandPath, donutArcs, flowLayout, linePath, niceMax, scaleLinear, stack, type FlowInput } from "@/lib/chartGeometry";
import { formatCount, type Tone } from "@/lib/insights";

const TONE_VAR: Record<Tone, string> = {
  teal: "var(--rh-teal)",
  steel: "var(--rh-steel)",
  ochre: "var(--rh-ochre)",
  crimson: "var(--rh-crimson)",
  purple: "var(--rh-slate-purple)",
  neutral: "var(--rh-text-secondary)",
};

export interface ChartTable { headers: string[]; rows: string[][] }

export function ChartCard({ title, subtitle, summary, table, empty, children }: {
  title: string;
  subtitle?: string;
  /** Read by screen readers instead of the drawing. */
  summary: string;
  table: ChartTable;
  /** When set the chart is replaced by this message (nothing to draw is not the same as zero). */
  empty?: string;
  children: React.ReactNode;
}) {
  const [asTable, setAsTable] = useState(false);
  return (
    <section className="rh-glass rounded-rh-md p-4">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-[13px] font-semibold text-rh-text">{title}</h2>
          {subtitle && <p className="mt-0.5 text-[12px] text-rh-text-2">{subtitle}</p>}
        </div>
        {!empty && (
          <button
            onClick={() => setAsTable((v) => !v)}
            aria-pressed={asTable}
            className="shrink-0 rounded-[6px] border border-rh-hairline px-2 py-1 text-[11px] text-rh-text-2 hover:bg-rh-elevated"
          >
            {asTable ? "View as chart" : "View as table"}
          </button>
        )}
      </div>
      {empty ? (
        <div className="flex h-[160px] items-center justify-center rounded-[8px] border border-dashed border-rh-hairline px-4 text-center text-[12px] text-rh-text-2">{empty}</div>
      ) : asTable ? (
        <div className="max-h-[220px] overflow-auto">
          <table className="w-full text-left text-[12px]">
            <thead><tr>{table.headers.map((h) => <th key={h} className="border-b border-rh-hairline px-2 py-1 font-medium text-rh-text-2">{h}</th>)}</tr></thead>
            <tbody>
              {table.rows.map((r, i) => (
                <tr key={i}>{r.map((c, j) => <td key={j} className={`border-b border-rh-hairline px-2 py-1 text-rh-text ${j > 0 ? "rh-tabular" : ""}`}>{c}</td>)}</tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div role="img" aria-label={summary}>{children}</div>
      )}
    </section>
  );
}

const W = 360;
const H = 160;
const PAD = { left: 52, right: 8, top: 8, bottom: 22 };

function axisLabels(labels: string[], maxLabels: number): { i: number; text: string }[] {
  if (labels.length === 0) return [];
  const step = Math.max(1, Math.ceil(labels.length / maxLabels));
  return labels.map((text, i) => ({ i, text })).filter(({ i }) => i % step === 0);
}

/** Stacked areas over time. `layers` are drawn bottom to top; `format` renders the y axis ticks. */
export function StackedArea({ labels, layers, format = formatCount }: {
  labels: string[];
  layers: { name: string; tone: Tone; values: number[] }[];
  format?: (n: number) => string;
}) {
  const stacked = stack(layers.map((l) => l.values));
  const top = stacked.length ? stacked[stacked.length - 1].upper : [];
  const max = niceMax(Math.max(0, ...top));
  const x = scaleLinear([0, Math.max(1, labels.length - 1)], [PAD.left, W - PAD.right]);
  const y = scaleLinear([0, max], [H - PAD.bottom, PAD.top]);
  const xs = labels.map((_, i) => x(i));
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" aria-hidden>
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line x1={PAD.left} x2={W - PAD.right} y1={y(max * f)} y2={y(max * f)} style={{ stroke: "var(--rh-border-hairline)" }} strokeWidth={1} />
          <text x={PAD.left - 6} y={y(max * f) + 3} textAnchor="end" className="rh-tabular" style={{ fill: "var(--rh-text-secondary)", fontSize: 10 }}>{format(max * f)}</text>
        </g>
      ))}
      {stacked.map((band, i) => (
        <path key={layers[i].name} d={bandPath(xs, band.lower, band.upper, y)} style={{ fill: TONE_VAR[layers[i].tone], fillOpacity: 0.55, stroke: TONE_VAR[layers[i].tone] }} strokeWidth={1} />
      ))}
      {axisLabels(labels, 6).map(({ i, text }) => (
        <text key={i} x={xs[i]} y={H - 6} textAnchor={i === labels.length - 1 ? "end" : i === 0 ? "start" : "middle"} className="rh-tabular" style={{ fill: "var(--rh-text-secondary)", fontSize: 10 }}>{text}</text>
      ))}
    </svg>
  );
}

export function AreaChart({ labels, values, tone, format = formatCount }: { labels: string[]; values: number[]; tone: Tone; format?: (n: number) => string }) {
  const max = niceMax(Math.max(0, ...values));
  const x = scaleLinear([0, Math.max(1, labels.length - 1)], [PAD.left, W - PAD.right]);
  const y = scaleLinear([0, max], [H - PAD.bottom, PAD.top]);
  const points = values.map((v, i) => ({ x: x(i), y: y(v) }));
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" aria-hidden>
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line x1={PAD.left} x2={W - PAD.right} y1={y(max * f)} y2={y(max * f)} style={{ stroke: "var(--rh-border-hairline)" }} strokeWidth={1} />
          <text x={PAD.left - 6} y={y(max * f) + 3} textAnchor="end" className="rh-tabular" style={{ fill: "var(--rh-text-secondary)", fontSize: 10 }}>{format(max * f)}</text>
        </g>
      ))}
      <path d={areaPath(points, y(0))} style={{ fill: TONE_VAR[tone], fillOpacity: 0.3 }} />
      <path d={linePath(points)} fill="none" style={{ stroke: TONE_VAR[tone] }} strokeWidth={1.5} />
      {axisLabels(labels, 6).map(({ i, text }) => (
        <text key={i} x={x(i)} y={H - 6} textAnchor={i === labels.length - 1 ? "end" : i === 0 ? "start" : "middle"} className="rh-tabular" style={{ fill: "var(--rh-text-secondary)", fontSize: 10 }}>{text}</text>
      ))}
    </svg>
  );
}

export function Donut({ slices, centre, centreNote }: { slices: { label: string; value: number; tone: Tone }[]; centre: string; centreNote: string }) {
  const arcs = donutArcs(slices.map((s) => s.value), 70, 70, 62, 44);
  return (
    <div className="flex items-center gap-4">
      <svg viewBox="0 0 140 140" className="h-[140px] w-[140px] shrink-0" aria-hidden>
        {arcs.length === 0 && <circle cx={70} cy={70} r={53} fill="none" style={{ stroke: "var(--rh-border-hairline)" }} strokeWidth={18} />}
        {arcs.map((a, i) => a.path && <path key={slices[i].label} d={a.path} fillRule="evenodd" style={{ fill: TONE_VAR[slices[i].tone] }} />)}
        <text x={70} y={72} textAnchor="middle" className="rh-tabular" style={{ fill: "var(--rh-text-primary)", fontSize: 24, fontWeight: 600 }}>{centre}</text>
        <text x={70} y={88} textAnchor="middle" style={{ fill: "var(--rh-text-secondary)", fontSize: 10 }}>{centreNote}</text>
      </svg>
      <ul className="flex flex-col gap-2 text-[12px]">
        {slices.map((s) => (
          <li key={s.label} className="flex items-center gap-2 text-rh-text">
            <span aria-hidden className="h-2.5 w-2.5 rounded-[2px]" style={{ background: TONE_VAR[s.tone] }} />
            <span>{s.label}</span>
            <span className="rh-tabular text-rh-text-2">{formatCount(s.value)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function RankedBars({ rows, tone, format = formatCount }: { rows: { label: string; value: number; detail?: string }[]; tone: Tone; format?: (n: number) => string }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className="flex flex-col gap-2.5">
      {rows.map((r) => (
        <li key={r.label} className="text-[12px]">
          <div className="mb-1 flex items-baseline justify-between gap-2">
            <span className="min-w-0 truncate text-rh-text" title={r.label}>{r.label}</span>
            <span className="rh-tabular shrink-0 text-rh-text-2">{format(r.value)}{r.detail ? ` · ${r.detail}` : ""}</span>
          </div>
          <div className="h-1.5 rounded-full bg-rh-elevated"><div className="h-1.5 rounded-full" style={{ width: `${Math.max(2, (r.value / max) * 100)}%`, background: TONE_VAR[tone] }} /></div>
        </li>
      ))}
    </ul>
  );
}

/** p50 and p95 against a scale that always reaches the 50 ms reference. The reference is the gateway budget for context only; the figures include the tool's own time. */
export function LatencyBars({ p50, p95 }: { p50: number | null; p95: number | null }) {
  const scaleMax = niceMax(Math.max(60, p50 ?? 0, p95 ?? 0));
  const pct = (v: number) => `${Math.min(100, (v / scaleMax) * 100)}%`;
  const bars: { label: string; value: number | null; tone: Tone }[] = [
    { label: "p50", value: p50, tone: "teal" },
    { label: "p95", value: p95, tone: "steel" },
  ];
  return (
    <div className="relative pt-1">
      {bars.map((b) => (
        <div key={b.label} className="mb-3 flex items-center gap-3 text-[12px]">
          <span className="w-7 text-rh-text-2">{b.label}</span>
          <div className="relative h-2 flex-1 rounded-full bg-rh-elevated">
            {b.value !== null && <div className="h-2 rounded-full" style={{ width: pct(b.value), background: TONE_VAR[b.tone] }} />}
            <div aria-hidden className="absolute -top-1 h-4 w-px" style={{ left: pct(50), background: "var(--rh-border-strong)" }} />
          </div>
          <span className="rh-tabular w-[72px] text-right text-rh-text">{b.value === null ? "no data" : `${b.value} ms`}</span>
        </div>
      ))}
      <p className="text-[11px] text-rh-text-2">Whole call as the gateway saw it, tool time included. The line marks 50 ms, the gateway's own budget, for scale only.</p>
    </div>
  );
}

const OUTCOME_TONE: Record<string, Tone> = { Allowed: "teal", Refused: "crimson", Errors: "ochre" };

export function Flow({ rows }: { rows: FlowInput[] }) {
  const width = 1000;
  const height = 260;
  const layout = flowLayout(rows, { width, height, nodeWidth: 12, gap: 8, minHeight: 5 });
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full" aria-hidden>
      {layout.links.map((l, i) => {
        const outcome = l.target.startsWith("2:") ? l.target.slice(2) : null;
        return <path key={i} d={l.path} fill="none" strokeWidth={l.width} style={{ stroke: outcome ? TONE_VAR[OUTCOME_TONE[outcome] ?? "neutral"] : "var(--rh-steel)", strokeOpacity: 0.35 }} />;
      })}
      {layout.nodes.map((n) => {
        const x = n.column === 0 ? 0 : n.column === 1 ? (width - layout.nodeWidth) / 2 : width - layout.nodeWidth;
        const anchor = n.column === 2 ? "end" : "start";
        const tx = n.column === 2 ? x - 6 : x + layout.nodeWidth + 6;
        return (
          <g key={n.id}>
            <rect x={x} y={n.y} width={layout.nodeWidth} height={n.height} rx={2} style={{ fill: n.column === 2 ? TONE_VAR[OUTCOME_TONE[n.label] ?? "neutral"] : "var(--rh-text-secondary)" }} />
            <text x={tx} y={n.y + n.height / 2 + 3} textAnchor={anchor} style={{ fill: "var(--rh-text-primary)", fontSize: 13 }}>
              {n.label.length > 28 ? `${n.label.slice(0, 27)}…` : n.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
