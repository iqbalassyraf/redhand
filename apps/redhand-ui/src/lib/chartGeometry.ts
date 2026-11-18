/**
 * Pure geometry for the dashboard's hand-drawn SVG charts (no chart library). Everything here is arithmetic on numbers, so scales, stacking,
 * donut arcs and Sankey link widths are tested in node. Inputs may be empty or all zero: nothing here ever returns NaN.
 */

export interface Point { x: number; y: number }

export function scaleLinear(domain: [number, number], range: [number, number]): (v: number) => number {
  const [d0, d1] = domain;
  const [r0, r1] = range;
  const span = d1 - d0;
  return (v: number) => (span === 0 ? r0 : r0 + ((v - d0) / span) * (r1 - r0));
}

/** The smallest 1, 2 or 5 times a power of ten that is at least `value` (so axes end on a round number); 1 for zero. */
export function niceMax(value: number): number {
  if (!(value > 0)) return 1;
  const pow = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 5, 10]) if (step * pow >= value) return step * pow;
  return 10 * pow;
}

export function linePath(points: Point[]): string {
  return points.map((p, i) => `${i === 0 ? "M" : "L"}${round(p.x)},${round(p.y)}`).join(" ");
}

/** A closed area between a line and the baseline. */
export function areaPath(points: Point[], baselineY: number): string {
  if (points.length === 0) return "";
  const first = points[0];
  const last = points[points.length - 1];
  return `${linePath(points)} L${round(last.x)},${round(baselineY)} L${round(first.x)},${round(baselineY)} Z`;
}

function round(n: number): number {
  return Math.round(n * 100) / 100;
}

/** Stacks several equal-length series: layer i spans [lower[j], upper[j]] where lower is the sum of the layers below it. */
export function stack(layers: number[][]): { lower: number[]; upper: number[] }[] {
  const length = layers.reduce((m, l) => Math.max(m, l.length), 0);
  const running = new Array<number>(length).fill(0);
  return layers.map((layer) => {
    const lower = running.slice();
    for (let j = 0; j < length; j += 1) running[j] += layer[j] ?? 0;
    return { lower, upper: running.slice() };
  });
}

/** The closed path of one stacked layer: its upper edge left to right, then its lower edge right to left. */
export function bandPath(xs: number[], lower: number[], upper: number[], y: (v: number) => number): string {
  if (xs.length === 0) return "";
  const top = xs.map((x, i) => `${i === 0 ? "M" : "L"}${round(x)},${round(y(upper[i]))}`);
  const bottom = xs.map((_, i) => xs.length - 1 - i).map((i) => `L${round(xs[i])},${round(y(lower[i]))}`);
  return `${top.join(" ")} ${bottom.join(" ")} Z`;
}

export interface Arc { start: number; end: number; fraction: number; path: string }

function polar(cx: number, cy: number, r: number, angle: number): Point {
  return { x: cx + r * Math.sin(angle), y: cy - r * Math.cos(angle) };
}

/** Donut segments clockwise from twelve o'clock. A zero total gives no arcs; a single full segment is drawn as two half arcs (one arc cannot close a circle). */
export function donutArcs(values: number[], cx: number, cy: number, outer: number, inner: number): Arc[] {
  const total = values.reduce((s, v) => s + Math.max(0, v), 0);
  if (total <= 0) return [];
  let angle = 0;
  return values.map((raw) => {
    const value = Math.max(0, raw);
    const fraction = value / total;
    const start = angle;
    const end = angle + fraction * Math.PI * 2;
    angle = end;
    if (fraction === 0) return { start, end, fraction, path: "" };
    if (fraction >= 0.9999) {
      const o1 = polar(cx, cy, outer, 0); const o2 = polar(cx, cy, outer, Math.PI);
      const i1 = polar(cx, cy, inner, 0); const i2 = polar(cx, cy, inner, Math.PI);
      return { start, end, fraction, path: `M${round(o1.x)},${round(o1.y)} A${outer},${outer} 0 1 1 ${round(o2.x)},${round(o2.y)} A${outer},${outer} 0 1 1 ${round(o1.x)},${round(o1.y)} M${round(i1.x)},${round(i1.y)} A${inner},${inner} 0 1 0 ${round(i2.x)},${round(i2.y)} A${inner},${inner} 0 1 0 ${round(i1.x)},${round(i1.y)} Z` };
    }
    const large = end - start > Math.PI ? 1 : 0;
    const o0 = polar(cx, cy, outer, start); const o1 = polar(cx, cy, outer, end);
    const i0 = polar(cx, cy, inner, start); const i1 = polar(cx, cy, inner, end);
    return {
      start, end, fraction,
      path: `M${round(o0.x)},${round(o0.y)} A${outer},${outer} 0 ${large} 1 ${round(o1.x)},${round(o1.y)} L${round(i1.x)},${round(i1.y)} A${inner},${inner} 0 ${large} 0 ${round(i0.x)},${round(i0.y)} Z`,
    };
  });
}

export interface FlowInput { agent: string; server: string; outcome: string; count: number }
export interface FlowNode { id: string; column: 0 | 1 | 2; label: string; value: number; y: number; height: number }
export interface FlowLink { source: string; target: string; value: number; sy: number; ty: number; width: number; path: string }

/**
 * A three-column flow (agent, server, outcome). Node heights are proportional to their totals with a minimum so small ones stay visible; each link
 * takes its own slice of its source and target node, so links never overlap at their ends. Empty input gives an empty layout.
 */
export function flowLayout(
  rows: FlowInput[], size: { width: number; height: number; nodeWidth: number; gap: number; minHeight: number }
): { nodes: FlowNode[]; links: FlowLink[]; nodeWidth: number } {
  const positive = rows.filter((r) => r.count > 0);
  if (positive.length === 0) return { nodes: [], links: [], nodeWidth: size.nodeWidth };

  const agentServer = new Map<string, number>();
  const serverOutcome = new Map<string, number>();
  for (const r of positive) {
    agentServer.set(`${r.agent}\u0000${r.server}`, (agentServer.get(`${r.agent}\u0000${r.server}`) ?? 0) + r.count);
    serverOutcome.set(`${r.server}\u0000${r.outcome}`, (serverOutcome.get(`${r.server}\u0000${r.outcome}`) ?? 0) + r.count);
  }
  const totals = (column: 0 | 1 | 2) => {
    const m = new Map<string, number>();
    for (const r of positive) {
      const key = column === 0 ? r.agent : column === 1 ? r.server : r.outcome;
      m.set(key, (m.get(key) ?? 0) + r.count);
    }
    return m;
  };
  const columns = ([0, 1, 2] as const).map((c) => ({ c, totals: totals(c) }));
  const grand = Math.max(...columns.map((col) => [...col.totals.values()].reduce((s, v) => s + v, 0)));
  const usable = (n: number) => size.height - size.gap * Math.max(0, n - 1);

  const nodes: FlowNode[] = [];
  for (const { c, totals: t } of columns) {
    const entries = [...t.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const scale = usable(entries.length) / grand;
    let y = 0;
    for (const [label, value] of entries) {
      const height = Math.max(size.minHeight, value * scale);
      nodes.push({ id: `${c}:${label}`, column: c, label, value, y, height });
      y += height + size.gap;
    }
  }
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const xOf = (column: number) => (column * (size.width - size.nodeWidth)) / 2;
  const sourceUsed = new Map<string, number>();
  const targetUsed = new Map<string, number>();
  const links: FlowLink[] = [];
  const addLinks = (pairs: Map<string, number>, from: 0 | 1, to: 1 | 2) => {
    const ordered = [...pairs.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    for (const [key, value] of ordered) {
      const [s, t] = key.split("\u0000");
      const source = byId.get(`${from}:${s}`);
      const target = byId.get(`${to}:${t}`);
      if (!source || !target) continue;
      const width = Math.max(1, (value / source.value) * source.height);
      const targetWidth = Math.max(1, (value / target.value) * target.height);
      const w = Math.min(width, targetWidth);
      const su = sourceUsed.get(source.id) ?? 0;
      const tu = targetUsed.get(target.id) ?? 0;
      sourceUsed.set(source.id, su + w);
      targetUsed.set(target.id, tu + w);
      const sy = source.y + su + w / 2;
      const ty = target.y + tu + w / 2;
      const x0 = xOf(from) + size.nodeWidth;
      const x1 = xOf(to);
      const mid = (x0 + x1) / 2;
      links.push({ source: source.id, target: target.id, value, sy, ty, width: w, path: `M${round(x0)},${round(sy)} C${round(mid)},${round(sy)} ${round(mid)},${round(ty)} ${round(x1)},${round(ty)}` });
    }
  };
  addLinks(agentServer, 0, 1);
  addLinks(serverOutcome, 1, 2);
  return { nodes: nodes.map((n) => ({ ...n })), links, nodeWidth: size.nodeWidth };
}
