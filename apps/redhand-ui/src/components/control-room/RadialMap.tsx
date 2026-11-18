"use client";

import React, { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bot,
  ChevronLeft,
  ChevronRight,
  Cpu,
  Database,
  Plus,
  ShieldAlert,
  Users,
  Wrench,
} from "lucide-react";
import type { SpokeCategory, TopologyNode } from "@/lib/control-room-data";
import {
  EASE_OUT_EXPO,
  STATUS_META,
  useCountUp,
  usePrefersReducedMotion,
} from "@/lib/tokens";
import { StatusPill } from "./StatusPill";

const VIEWBOX_W = 1000;
const VIEWBOX_H = 760;
const CENTER_X = 500;
const CENTER_Y = 380;

const SPOKE_ANGLES_DEG: Record<SpokeCategory, number> = {
  data: -90,
  models: -20,
  tools: 48,
  humans: 132,
  agents: 200,
};

const CHILD_ANGLE_OFFSETS_DEG: Record<SpokeCategory, number[]> = {
  data: [-24, 0, 24],
  models: [-22, 0, 22],
  tools: [-26, -9, 9, 26],
  humans: [-20, 0, 20],
  agents: [-26, -9, 9, 26],
};

const SPOKE_ICON: Record<SpokeCategory, React.ComponentType<{ className?: string }>> = {
  agents: Bot,
  tools: Wrench,
  data: Database,
  humans: Users,
  models: Cpu,
};

function degToRad(deg: number): number {
  return (deg * Math.PI) / 180;
}

function polarPoint(cx: number, cy: number, radius: number, angleDeg: number) {
  const rad = degToRad(angleDeg);
  return {
    x: Math.round((cx + radius * Math.cos(rad)) * 10) / 10,
    y: Math.round((cy + radius * Math.sin(rad)) * 10) / 10,
  };
}

function bezierConnector(
  x1: number,
  y1: number,
  x2: number,
  y2: number,
  curveBias = 0.42
): string {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const cx1 = x1 + dx * curveBias;
  const cy1 = y1 + dy * 0.14;
  const cx2 = x2 - dx * curveBias;
  const cy2 = y2 - dy * 0.14;
  return `M ${x1} ${y1} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${x2} ${y2}`;
}

export interface RadialMapProps {
  spokes: TopologyNode[];
  childNodes: TopologyNode[];
  hubStats: {
    agentsUnderControl: number;
    riskyActionsCount: number;
    blockedThreatsCount: number;
    totalEndpoints: number;
  };
  selectedNodeId?: string | null;
  highlightedSeverity?: string | null;
  threatPulseKey?: number;
  onSelectNode: (node: TopologyNode) => void;
  isDetailOpen?: boolean;
  className?: string;
}

interface PositionedNode {
  node: TopologyNode;
  x: number;
  y: number;
  angleDeg: number;
  parentX?: number;
  parentY?: number;
}

const HUB_SLIDES = [
  { key: "risky", label: "RISKY ACTIONS" },
  { key: "blocked", label: "BLOCKED THREATS" },
  { key: "endpoints", label: "MANAGED ENDPOINTS" },
] as const;

/**
 * Interactive Radial Hub-and-Spoke "Agent Control Room" topology map.
 * Supports shared-element transitions on node selection, protected/unprotected perimeter rings,
 * severity highlighting, and single-pulse threat animations.
 */
export function RadialMap({
  spokes,
  childNodes,
  hubStats,
  selectedNodeId = null,
  highlightedSeverity = null,
  threatPulseKey = 0,
  onSelectNode,
  isDetailOpen = false,
  className = "",
}: RadialMapProps) {
  const reducedMotion = usePrefersReducedMotion();
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [hubSlideIndex, setHubSlideIndex] = useState<number>(0);

  const hubSlideValue =
    hubSlideIndex === 0
      ? hubStats.riskyActionsCount
      : hubSlideIndex === 1
        ? hubStats.blockedThreatsCount
        : hubStats.totalEndpoints;

  const animatedHubNumber = useCountUp(hubSlideValue, 520, 0);
  const animatedAgentCount = useCountUp(hubStats.agentsUnderControl, 450, 0);

  const { positionedSpokes, positionedChildren, junctionPoints, ticks } = useMemo(() => {
    const spokeRadius = 186;
    const childRadius = 318;

    const spokeMap = new Map<SpokeCategory, PositionedNode>();
    const spokeList: PositionedNode[] = spokes.map((spoke) => {
      const angleDeg = SPOKE_ANGLES_DEG[spoke.category];
      const pt = polarPoint(CENTER_X, CENTER_Y, spokeRadius, angleDeg);
      const item: PositionedNode = { node: spoke, x: pt.x, y: pt.y, angleDeg };
      spokeMap.set(spoke.category, item);
      return item;
    });

    const junctions = spokeList.map((s) => {
      const pt = polarPoint(CENTER_X, CENTER_Y, 122, s.angleDeg);
      return { id: s.node.id, category: s.node.category, x: pt.x, y: pt.y };
    });

    const groupedChildren: Record<SpokeCategory, TopologyNode[]> = {
      agents: [],
      tools: [],
      data: [],
      humans: [],
      models: [],
    };
    for (const child of childNodes) {
      groupedChildren[child.category].push(child);
    }

    const childrenList: PositionedNode[] = [];
    (Object.keys(groupedChildren) as SpokeCategory[]).forEach((cat) => {
      const group = groupedChildren[cat];
      const baseAngle = SPOKE_ANGLES_DEG[cat];
      const offsets = CHILD_ANGLE_OFFSETS_DEG[cat];
      const parentSpoke = spokeMap.get(cat);
      group.forEach((child, idx) => {
        const offset = offsets[idx] ?? (idx - (group.length - 1) / 2) * 18;
        const angle = baseAngle + offset;
        const radiusOffset = idx % 2 === 0 ? childRadius : childRadius + 18;
        const pt = polarPoint(CENTER_X, CENTER_Y, radiusOffset, angle);
        childrenList.push({
          node: child,
          x: pt.x,
          y: pt.y,
          angleDeg: angle,
          parentX: parentSpoke?.x ?? CENTER_X,
          parentY: parentSpoke?.y ?? CENTER_Y,
        });
      });
    });

    const tickLines = Array.from({ length: 144 }, (_, i) => {
      const angle = i * 2.5;
      const major = i % 6 === 0;
      const p1 = polarPoint(CENTER_X, CENTER_Y, major ? 348 : 352, angle);
      const p2 = polarPoint(CENTER_X, CENTER_Y, 360, angle);
      return { i, p1, p2, major };
    });

    return {
      positionedSpokes: spokeList,
      positionedChildren: childrenList,
      junctionPoints: junctions,
      ticks: tickLines,
    };
  }, [spokes, childNodes]);

  const hoveredPositioned = useMemo(() => {
    if (!hoveredNodeId) return null;
    return (
      positionedSpokes.find((s) => s.node.id === hoveredNodeId) ??
      positionedChildren.find((c) => c.node.id === hoveredNodeId) ??
      null
    );
  }, [hoveredNodeId, positionedSpokes, positionedChildren]);

  const isHighlighted = (node: TopologyNode) => {
    if (hoveredNodeId) {
      return hoveredNodeId === node.id || hoveredNodeId === `spoke-${node.spokeId}`;
    }
    if (highlightedSeverity) {
      return node.severity === highlightedSeverity;
    }
    return true;
  };

  return (
    <div
      className={[
        "relative flex h-full w-full items-center justify-center overflow-hidden rounded-rh-xl border border-[var(--rh-glass-border)] bg-[radial-gradient(circle_at_center,rgba(17,24,39,0.72)_0%,rgba(6,9,19,0.92)_74%)] select-none",
        className,
      ].join(" ")}
    >
      {/* Responsive Canvas Box preserving 1000:760 aspect ratio */}
      <div className="relative aspect-[1000/760] w-full max-w-[980px] max-h-full">
        {/* SVG Topology Layer */}
        <svg
          viewBox={`0 0 ${VIEWBOX_W} ${VIEWBOX_H}`}
          className="h-full w-full overflow-visible"
          aria-hidden="true"
        >
          <defs>
            <radialGradient id="rh-hub-aura" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="rgba(225, 29, 72, 0.24)" />
              <stop offset="55%" stopColor="rgba(56, 189, 248, 0.08)" />
              <stop offset="100%" stopColor="rgba(6, 9, 19, 0)" />
            </radialGradient>
          </defs>

          {/* Center Aura & Concentric Orbit Rings */}
          <circle cx={CENTER_X} cy={CENTER_Y} r={240} fill="url(#rh-hub-aura)" />
          <circle
            cx={CENTER_X}
            cy={CENTER_Y}
            r={122}
            fill="none"
            stroke="rgba(148, 163, 184, 0.12)"
            strokeDasharray="3 5"
          />
          <circle
            cx={CENTER_X}
            cy={CENTER_Y}
            r={186}
            fill="none"
            stroke="rgba(148, 163, 184, 0.1)"
          />
          <circle
            cx={CENTER_X}
            cy={CENTER_Y}
            r={318}
            fill="none"
            stroke="rgba(148, 163, 184, 0.07)"
          />

          {/* Outer Azimuth Telemetry Ticks */}
          {ticks.map((t) => (
            <line
              key={t.i}
              x1={t.p1.x}
              y1={t.p1.y}
              x2={t.p2.x}
              y2={t.p2.y}
              stroke={t.major ? "rgba(148, 163, 184, 0.3)" : "rgba(148, 163, 184, 0.12)"}
              strokeWidth={t.major ? 1.4 : 1}
            />
          ))}

          {/* Spoke -> Child Connectors */}
          {positionedChildren.map((item) => {
            const highlighted = isHighlighted(item.node);
            const pathD = bezierConnector(
              item.parentX ?? CENTER_X,
              item.parentY ?? CENTER_Y,
              item.x,
              item.y
            );
            const strokeColor =
              item.node.protection === "unprotected"
                ? "rgba(244, 63, 94, 0.55)"
                : hoveredNodeId === item.node.id
                  ? "rgba(16, 185, 129, 0.75)"
                  : "rgba(148, 163, 184, 0.24)";
            return (
              <path
                key={`edge-${item.node.id}`}
                d={pathD}
                fill="none"
                stroke={strokeColor}
                strokeWidth={hoveredNodeId === item.node.id ? 2 : 1.35}
                opacity={highlighted ? 1 : 0.25}
                className="transition-opacity duration-200"
              />
            );
          })}

          {/* Center Hub -> Spoke Hub Connectors */}
          {positionedSpokes.map((s) => {
            const pathD = bezierConnector(CENTER_X, CENTER_Y, s.x, s.y, 0.35);
            const isHovered =
              hoveredNodeId === s.node.id ||
              positionedChildren.some(
                (c) => c.node.id === hoveredNodeId && c.node.spokeId === s.node.spokeId
              );
            return (
              <path
                key={`spoke-edge-${s.node.id}`}
                d={pathD}
                fill="none"
                stroke={
                  isHovered
                    ? "rgba(244, 63, 94, 0.65)"
                    : "rgba(148, 163, 184, 0.32)"
                }
                strokeWidth={isHovered ? 2.2 : 1.6}
                className="transition-[stroke,stroke-width] duration-200"
              />
            );
          })}

          {/* Single-pulse Ripple & Connector Path Flash on Threat Nodes */}
          {threatPulseKey > 0 &&
            !reducedMotion &&
            positionedChildren
              .filter((item) => item.node.hasNewThreatPulse)
              .map((item) => {
                const pathToSpoke = bezierConnector(
                  CENTER_X,
                  CENTER_Y,
                  item.parentX ?? CENTER_X,
                  item.parentY ?? CENTER_Y,
                  0.35
                );
                const pathToChild = bezierConnector(
                  item.parentX ?? CENTER_X,
                  item.parentY ?? CENTER_Y,
                  item.x,
                  item.y
                );
                return (
                  <g key={`flash-group-${item.node.id}-${threatPulseKey}`}>
                    <motion.path
                      d={pathToSpoke}
                      fill="none"
                      stroke="#F43F5E"
                      strokeWidth={2.6}
                      initial={{ pathLength: 0, opacity: 0.95 }}
                      animate={{ pathLength: 1, opacity: 0 }}
                      transition={{ duration: 0.65, ease: "easeOut" }}
                    />
                    <motion.path
                      d={pathToChild}
                      fill="none"
                      stroke="#F43F5E"
                      strokeWidth={2.6}
                      initial={{ pathLength: 0, opacity: 0.95 }}
                      animate={{ pathLength: 1, opacity: 0 }}
                      transition={{ duration: 0.75, delay: 0.12, ease: "easeOut" }}
                    />
                  </g>
                );
              })}

          {[...positionedSpokes, ...positionedChildren]
            .filter((item) => item.node.hasNewThreatPulse)
            .map((item) => {
              const r = item.node.kind === "spoke" ? 28 : 20;
              if (reducedMotion) return null;
              return (
                <motion.circle
                  key={`pulse-${item.node.id}-${threatPulseKey}`}
                  cx={item.x}
                  cy={item.y}
                  r={r}
                  fill="none"
                  stroke="#F43F5E"
                  strokeWidth={2.2}
                  initial={{ scale: 1, opacity: 0.9 }}
                  animate={{ scale: 2.2, opacity: 0 }}
                  transition={{ duration: 1.05, ease: "easeOut" }}
                  style={{ transformOrigin: `${item.x}px ${item.y}px` }}
                />
              );
            })}

          {/* Ring Indicators (Protected Emerald / Unprotected Crimson Dual Arc) */}
          {[...positionedSpokes, ...positionedChildren].map((item) => {
            const r = item.node.kind === "spoke" ? 27 : 19;
            const circumference = 2 * Math.PI * r;
            const ratio = Math.max(0, Math.min(1, item.node.protectedRatio));
            const protectedLen = circumference * ratio;
            const unprotectedLen = circumference - protectedLen;
            const dimmed = !isHighlighted(item.node);

            return (
              <g
                key={`ring-${item.node.id}`}
                opacity={dimmed ? 0.25 : 1}
                transform={`rotate(-90 ${item.x} ${item.y})`}
              >
                {unprotectedLen > 0.5 && (
                  <circle
                    cx={item.x}
                    cy={item.y}
                    r={r}
                    fill="none"
                    stroke="#F43F5E"
                    strokeWidth={item.node.kind === "spoke" ? 3 : 2.5}
                    strokeDasharray={`${unprotectedLen} ${circumference}`}
                    strokeDashoffset={-protectedLen}
                    strokeLinecap="round"
                  />
                )}
                {protectedLen > 0.5 && (
                  <circle
                    cx={item.x}
                    cy={item.y}
                    r={r}
                    fill="none"
                    stroke="#10B981"
                    strokeWidth={item.node.kind === "spoke" ? 3 : 2.5}
                    strokeDasharray={`${protectedLen} ${circumference}`}
                    strokeLinecap="round"
                  />
                )}
              </g>
            );
          })}
        </svg>

        {/* Junction "+" Markers */}
        {junctionPoints.map((jp) => (
          <div
            key={`jp-${jp.id}`}
            aria-hidden="true"
            style={{
              left: `${(jp.x / VIEWBOX_W) * 100}%`,
              top: `${(jp.y / VIEWBOX_H) * 100}%`,
            }}
            className="pointer-events-none absolute flex h-5 w-5 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border border-slate-600/60 bg-slate-950/90 text-slate-400"
          >
            <Plus className="h-3 w-3" />
          </div>
        ))}

        {/* Interactive Spoke Hubs */}
        {positionedSpokes.map((item) => {
          const Icon = SPOKE_ICON[item.node.category];
          const isSelected = selectedNodeId === item.node.id;
          const highlighted = isHighlighted(item.node);
          const labelAbove = item.node.category === "data" || item.node.category === "agents" || item.node.category === "models";

          return (
            <div
              key={item.node.id}
              style={{
                left: `${(item.x / VIEWBOX_W) * 100}%`,
                top: `${(item.y / VIEWBOX_H) * 100}%`,
              }}
              className="absolute -translate-x-1/2 -translate-y-1/2 z-20"
            >
              <motion.button
                type="button"
                layoutId={
                  isDetailOpen && isSelected
                    ? undefined
                    : `node-hero-${item.node.id}`
                }
                onClick={() => onSelectNode(item.node)}
                onMouseEnter={() => setHoveredNodeId(item.node.id)}
                onMouseLeave={() => setHoveredNodeId(null)}
                onFocus={() => setHoveredNodeId(item.node.id)}
                onBlur={() => setHoveredNodeId(null)}
                aria-label={`${item.node.name}: ${item.node.endpointCount} endpoints, ${item.node.kpis.blocked} blocked. Inspect funnel`}
                className={[
                  "group relative flex h-12 w-12 items-center justify-center rounded-full border bg-slate-950/90 text-slate-100 shadow-lg backdrop-blur-md transition-[transform,opacity,border-color] duration-rh-fast ease-rh-out hover:scale-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-400",
                  isSelected
                    ? "border-rose-400 ring-2 ring-rose-500/40"
                    : "border-white/15 hover:border-white/35",
                  highlighted ? "opacity-100" : "opacity-30",
                ].join(" ")}
              >
                <Icon className="h-5 w-5 text-slate-100 group-hover:text-rose-300 transition-colors" />
              </motion.button>

              {/* Spoke Title & Count Label */}
              <div
                className={[
                  "pointer-events-none absolute left-1/2 -translate-x-1/2 whitespace-nowrap text-center",
                  labelAbove ? "bottom-[calc(100%+10px)]" : "top-[calc(100%+10px)]",
                ].join(" ")}
              >
                <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-300">
                  {item.node.shortLabel}
                </div>
                <div className="rh-tabular font-mono text-xs font-semibold text-slate-100">
                  {item.node.endpointCount}
                </div>
              </div>
            </div>
          );
        })}

        {/* Interactive Child Nodes */}
        {positionedChildren.map((item) => {
          const isSelected = selectedNodeId === item.node.id;
          const highlighted = isHighlighted(item.node);
          const statusColor = STATUS_META[item.node.status].color;
          const Icon = SPOKE_ICON[item.node.category];

          return (
            <div
              key={item.node.id}
              style={{
                left: `${(item.x / VIEWBOX_W) * 100}%`,
                top: `${(item.y / VIEWBOX_H) * 100}%`,
              }}
              className="absolute -translate-x-1/2 -translate-y-1/2 z-10"
            >
              <motion.button
                type="button"
                layoutId={
                  isDetailOpen && isSelected
                    ? undefined
                    : `node-hero-${item.node.id}`
                }
                onClick={() => onSelectNode(item.node)}
                onMouseEnter={() => setHoveredNodeId(item.node.id)}
                onMouseLeave={() => setHoveredNodeId(null)}
                onFocus={() => setHoveredNodeId(item.node.id)}
                onBlur={() => setHoveredNodeId(null)}
                aria-label={`${item.node.name} (${item.node.protection}). Click to inspect`}
                className={[
                  "relative flex h-8 w-8 items-center justify-center rounded-full border bg-slate-900/90 text-slate-200 shadow-md transition-[transform,opacity,border-color] duration-rh-fast ease-rh-out hover:scale-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-400",
                  isSelected
                    ? "border-rose-400 ring-2 ring-rose-500/40"
                    : "border-white/15 hover:border-white/40",
                  highlighted ? "opacity-100" : "opacity-25",
                ].join(" ")}
              >
                <Icon className="h-3.5 w-3.5" />
                <span
                  aria-hidden="true"
                  className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border border-slate-950"
                  style={{ backgroundColor: statusColor }}
                />
              </motion.button>
              <div className="pointer-events-none absolute left-1/2 top-[calc(100%+6px)] -translate-x-1/2 whitespace-nowrap rounded bg-slate-950/75 px-1.5 py-0.5 text-[10px] font-medium text-slate-300 backdrop-blur-sm">
                {item.node.shortLabel}
              </div>
            </div>
          );
        })}

        {/* Center Control Hub */}
        <div
          style={{
            left: `${(CENTER_X / VIEWBOX_W) * 100}%`,
            top: `${(CENTER_Y / VIEWBOX_H) * 100}%`,
          }}
          className="absolute z-20 flex h-[168px] w-[168px] -translate-x-1/2 -translate-y-1/2 flex-col items-center justify-center rounded-full border border-white/15 bg-slate-950/90 px-4 text-center shadow-[0_0_50px_-8px_rgba(225,29,72,0.35),inset_0_1px_0_0_rgba(255,255,255,0.14)] backdrop-blur-xl"
        >
          <div className="flex items-center gap-1.5 text-[11px] font-medium text-sky-300">
            <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />
            <span className="rh-tabular font-mono font-semibold">
              {Math.round(animatedAgentCount)}
            </span>
            <span className="text-slate-300">under control</span>
          </div>

          <div className="rh-tabular mt-1 text-3xl font-bold tracking-tight text-white">
            {Math.round(animatedHubNumber).toLocaleString("en-US")}
          </div>
          <div className="mt-0.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400">
            {HUB_SLIDES[hubSlideIndex].label}
          </div>

          {/* Hub Mode Carousel */}
          <div className="mt-2.5 flex items-center gap-2 text-slate-400">
            <button
              type="button"
              onClick={() =>
                setHubSlideIndex((i) => (i - 1 + HUB_SLIDES.length) % HUB_SLIDES.length)
              }
              aria-label="Previous hub metric"
              className="rounded p-0.5 hover:bg-white/10 hover:text-white focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-rose-400"
            >
              <ChevronLeft className="h-3.5 w-3.5" />
            </button>
            <div className="flex items-center gap-1">
              {HUB_SLIDES.map((s, idx) => (
                <span
                  key={s.key}
                  className={`h-1.5 rounded-full transition-all ${
                    idx === hubSlideIndex ? "w-3 bg-rose-400" : "w-1.5 bg-slate-600"
                  }`}
                />
              ))}
            </div>
            <button
              type="button"
              onClick={() => setHubSlideIndex((i) => (i + 1) % HUB_SLIDES.length)}
              aria-label="Next hub metric"
              className="rounded p-0.5 hover:bg-white/10 hover:text-white focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-rose-400"
            >
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Hover Detail Popover */}
      <AnimatePresence>
        {hoveredPositioned && (
          <motion.div
            key={hoveredPositioned.node.id}
            initial={reducedMotion ? false : { opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15, ease: EASE_OUT_EXPO }}
            className="pointer-events-none absolute right-4 top-4 z-30 w-64 rounded-rh-md border border-white/15 bg-slate-950/90 p-3 shadow-2xl backdrop-blur-xl"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="truncate text-xs font-semibold text-white">
                {hoveredPositioned.node.name}
              </span>
              <StatusPill status={hoveredPositioned.node.protection} />
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              {hoveredPositioned.node.subtitle}
            </p>
            <div className="mt-2.5 grid grid-cols-3 gap-1.5 border-t border-white/10 pt-2 text-[11px]">
              <div>
                <div className="text-slate-500">Requests</div>
                <div className="rh-tabular font-mono font-semibold text-slate-100">
                  {hoveredPositioned.node.kpis.requests.toLocaleString("en-US")}
                </div>
              </div>
              <div>
                <div className="text-slate-500">Flagged</div>
                <div className="rh-tabular font-mono font-semibold text-amber-300">
                  {hoveredPositioned.node.kpis.flagged}
                </div>
              </div>
              <div>
                <div className="text-slate-500">Blocked</div>
                <div className="rh-tabular font-mono font-semibold text-rose-400">
                  {hoveredPositioned.node.kpis.blocked}
                </div>
              </div>
            </div>
            <div className="mt-2 text-[10px] font-medium text-rose-300">
              Click to open security funnel →
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Bottom-Left Protection Legend (Image 2 reference) */}
      <div className="absolute bottom-3 left-3 z-20 flex flex-wrap items-center gap-3 rounded-rh-sm border border-white/10 bg-slate-950/85 px-3 py-1.5 text-[11px] text-slate-300 backdrop-blur-md">
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-[2px] bg-emerald-400" />
          Protected
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-[2px] bg-rose-500" />
          Unprotected
        </span>
        <span className="hidden sm:inline text-slate-500">|</span>
        <span className="hidden sm:inline text-slate-400">
          Click any spoke or node to inspect
        </span>
      </div>
    </div>
  );
}
