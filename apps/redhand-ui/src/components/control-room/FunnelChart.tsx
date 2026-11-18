"use client";

import React, { useState } from "react";
import { motion } from "framer-motion";
import type { ActivityBucket, FunnelStage } from "@/lib/control-room-data";
import {
  EASE_OUT_EXPO,
  formatCompactNumber,
  useCountUp,
  usePrefersReducedMotion,
} from "@/lib/tokens";

const TONE_GRADIENT: Record<FunnelStage["tone"], string> = {
  crimson:
    "bg-gradient-to-t from-rose-600/80 via-rose-500/85 to-rose-400 shadow-[0_0_24px_-4px_rgba(244,63,94,0.45)]",
  neutral:
    "bg-gradient-to-t from-emerald-600/75 via-emerald-500/85 to-teal-300 shadow-[0_0_24px_-4px_rgba(16,185,129,0.38)]",
  flagged:
    "bg-gradient-to-t from-amber-600/80 via-amber-500/85 to-amber-300 shadow-[0_0_22px_-4px_rgba(245,158,11,0.4)]",
  blocked:
    "bg-gradient-to-t from-red-600/85 via-rose-500/90 to-rose-300 shadow-[0_0_22px_-4px_rgba(239,68,68,0.45)]",
  allowed:
    "bg-gradient-to-t from-emerald-600/80 via-emerald-500/90 to-emerald-300 shadow-[0_0_22px_-4px_rgba(16,185,129,0.45)]",
};

function StageCount({ count }: { count: number }) {
  const animated = useCountUp(count, 540, 0);
  return (
    <div className="rh-tabular text-2xl font-semibold tracking-tight text-slate-50">
      {formatCompactNumber(animated, 1)}
    </div>
  );
}

export interface FunnelChartProps {
  stages: FunnelStage[];
  animationKey?: string;
  loading?: boolean;
  className?: string;
}

/**
 * Campaigns-style 4-stage security pipeline funnel:
 * Requests -> Policy checked -> Flagged -> Blocked / Approved,
 * with diagonal hatched drop-off backdrop, bottom-up bar growth,
 * inter-stage connector bridges, conversion % badges, and hover inspection.
 */
export function FunnelChart({
  stages,
  animationKey = "default",
  loading = false,
  className = "",
}: FunnelChartProps) {
  const reducedMotion = usePrefersReducedMotion();
  const [hoveredStageIdx, setHoveredStageIdx] = useState<number | null>(null);

  if (loading) {
    return (
      <div className={`grid grid-cols-1 gap-3 sm:grid-cols-4 ${className}`}>
        {[1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className="h-56 animate-pulse rounded-rh-md border border-white/10 bg-slate-900/50"
          />
        ))}
      </div>
    );
  }

  return (
    <div className={`relative w-full ${className}`}>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4 sm:gap-3">
        {stages.map((stage, idx) => {
          const fillPct =
            stage.count > 0 ? Math.max(8, Math.min(100, stage.percentOfStart)) : 0;
          const prevCount = idx > 0 ? stages[idx - 1].count : stage.count;
          const droppedFromPrev = Math.max(0, prevCount - stage.count);
          const isHovered = hoveredStageIdx === idx;

          return (
            <div
              key={stage.id}
              onMouseEnter={() => setHoveredStageIdx(idx)}
              onMouseLeave={() => setHoveredStageIdx(null)}
              onFocus={() => setHoveredStageIdx(idx)}
              onBlur={() => setHoveredStageIdx(null)}
              tabIndex={0}
              aria-label={`${stage.step}. ${stage.label}: ${stage.count.toLocaleString("en-US")} (${stage.percentOfStart.toFixed(1)}% of start)`}
              className="group relative flex flex-col rounded-rh-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70"
            >
              {/* Stage Header Metrics */}
              <div className="mb-3 px-1">
                <div className="text-xs font-medium text-slate-400">
                  {stage.step}. {stage.label}
                </div>
                <StageCount count={stage.count} />
                <div className="rh-tabular mt-0.5 text-[11px] text-slate-400">
                  {stage.percentOfStart.toFixed(1).replace(/\.0$/, "")}% of start
                </div>
              </div>

              {/* Hatched Drop-off Box + Bottom-Up Luminous Bar */}
              <div
                className={[
                  "relative h-44 w-full overflow-hidden rounded-rh-md border bg-slate-950/60 transition-colors duration-rh-fast",
                  isHovered ? "border-white/25" : "border-white/10",
                ].join(" ")}
              >
                <svg
                  aria-hidden="true"
                  className="pointer-events-none absolute inset-0 h-full w-full opacity-35"
                >
                  <defs>
                    <pattern
                      id={`rh-hatch-${stage.id}`}
                      width="10"
                      height="10"
                      patternTransform="rotate(45 0 0)"
                      patternUnits="userSpaceOnUse"
                    >
                      <line
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="10"
                        stroke="rgba(148, 163, 184, 0.28)"
                        strokeWidth="1.5"
                      />
                    </pattern>
                  </defs>
                  <rect
                    width="100%"
                    height="100%"
                    fill={`url(#rh-hatch-${stage.id})`}
                  />
                </svg>

                {/* Filled Bar Growing from Zero (keyed on animationKey for node/range switches) */}
                <div className="absolute inset-x-0 bottom-0 flex h-full items-end">
                  <motion.div
                    key={`${animationKey}-${stage.id}`}
                    initial={reducedMotion ? false : { scaleY: 0, opacity: 0.6 }}
                    animate={{ scaleY: 1, opacity: 1 }}
                    transition={{
                      duration: 0.52,
                      delay: reducedMotion ? 0 : idx * 0.06,
                      ease: EASE_OUT_EXPO,
                    }}
                    style={{
                      height: `${fillPct}%`,
                      transformOrigin: "bottom",
                    }}
                    className={`relative w-full rounded-t-md ${TONE_GRADIENT[stage.tone]}`}
                  >
                    <div className="h-0.5 w-full bg-white/45" />
                  </motion.div>
                </div>

                {/* Hover / Focus Callout Overlay */}
                {isHovered && (
                  <motion.div
                    initial={reducedMotion ? false : { opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.14, ease: EASE_OUT_EXPO }}
                    className="pointer-events-none absolute inset-x-2 top-2 z-20 rounded-lg border border-white/15 bg-slate-950/90 px-2.5 py-2 text-[11px] shadow-xl backdrop-blur-md"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-slate-400">Exact count</span>
                      <span className="rh-tabular font-mono font-semibold text-white">
                        {stage.count.toLocaleString("en-US")}
                      </span>
                    </div>
                    {idx > 0 && (
                      <div className="mt-1 flex items-center justify-between gap-2">
                        <span className="text-slate-400">Filtered out</span>
                        <span className="rh-tabular font-mono text-slate-200">
                          {droppedFromPrev.toLocaleString("en-US")}
                        </span>
                      </div>
                    )}
                    <div className="mt-1 flex items-center justify-between gap-2">
                      <span className="text-slate-400">Share of start</span>
                      <span className="rh-tabular font-mono text-emerald-300">
                        {stage.percentOfStart.toFixed(1)}%
                      </span>
                    </div>
                  </motion.div>
                )}
              </div>

              {/* Inter-stage Connector Bridge + Conversion Pill */}
              {stage.conversionToNext !== null && idx < stages.length - 1 && (
                <div className="mt-2 flex items-center justify-center sm:mt-0 sm:absolute sm:-right-[28px] sm:top-[144px] sm:z-20 sm:w-[44px]">
                  <span
                    aria-hidden="true"
                    className="hidden sm:block absolute inset-x-0 top-1/2 -z-10 h-px -translate-y-1/2 bg-gradient-to-r from-amber-400/20 via-amber-400/60 to-amber-400/20"
                  />
                  <span
                    className="rh-tabular inline-flex items-center rounded-full border border-amber-400/50 bg-slate-950/95 px-2 py-0.5 font-mono text-[11px] font-semibold text-amber-200 shadow-lg"
                    title={`${stage.conversionToNext}% pass to next stage`}
                  >
                    {stage.conversionToNext.toFixed(1)}%
                  </span>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export interface ActivityBarChartProps {
  data: ActivityBucket[];
  animationKey?: string;
  loading?: boolean;
  className?: string;
}

/**
 * Hourly agent activity over time bar chart with bottom-up animated bars
 * and interactive hover inspection.
 */
export function ActivityBarChart({
  data,
  animationKey = "default",
  loading = false,
  className = "",
}: ActivityBarChartProps) {
  const reducedMotion = usePrefersReducedMotion();
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  if (loading) {
    return (
      <div
        className={`h-52 w-full animate-pulse rounded-rh-md bg-slate-900/50 ${className}`}
      />
    );
  }

  const maxTotal = Math.max(
    1,
    ...data.map((d) => d.allowed + d.flagged + d.blocked)
  );

  return (
    <div className={`relative flex flex-col gap-3 ${className}`}>
      <div className="relative flex h-48 items-end gap-2 border-b border-white/10 pb-2 pt-4">
        {/* Horizontal Dashed Reference Lines */}
        {[0.25, 0.5, 0.75, 1].map((line) => (
          <div
            key={line}
            aria-hidden="true"
            style={{ bottom: `${line * 100}%` }}
            className="pointer-events-none absolute inset-x-0 border-t border-dashed border-white/[0.06]"
          />
        ))}

        {data.map((bucket, idx) => {
          const total = bucket.allowed + bucket.flagged + bucket.blocked;
          const heightPct = Math.max(6, (total / maxTotal) * 100);
          const blockedRatio = total > 0 ? (bucket.blocked / total) * 100 : 0;
          const flaggedRatio = total > 0 ? (bucket.flagged / total) * 100 : 0;
          const isHovered = hoveredIdx === idx;

          return (
            <div
              key={bucket.label}
              onMouseEnter={() => setHoveredIdx(idx)}
              onMouseLeave={() => setHoveredIdx(null)}
              className="group relative flex h-full flex-1 flex-col items-center justify-end"
            >
              {/* Hover Tooltip */}
              {isHovered && (
                <div className="pointer-events-none absolute -top-2 z-30 -translate-y-full whitespace-nowrap rounded-lg border border-white/15 bg-slate-950/95 px-2.5 py-1.5 text-[11px] shadow-xl backdrop-blur-md">
                  <div className="font-mono font-semibold text-slate-100">
                    {bucket.label}
                  </div>
                  <div className="text-emerald-300">
                    Allowed: {bucket.allowed.toLocaleString("en-US")}
                  </div>
                  <div className="text-amber-300">Flagged: {bucket.flagged}</div>
                  <div className="text-rose-400">Blocked: {bucket.blocked}</div>
                </div>
              )}

              <motion.div
                key={`${animationKey}-${bucket.label}`}
                initial={reducedMotion ? false : { scaleY: 0, opacity: 0.6 }}
                animate={{ scaleY: 1, opacity: 1 }}
                transition={{
                  duration: 0.5,
                  delay: reducedMotion ? 0 : idx * 0.025,
                  ease: EASE_OUT_EXPO,
                }}
                style={{
                  height: `${heightPct}%`,
                  transformOrigin: "bottom",
                }}
                className={[
                  "flex w-full max-w-[26px] flex-col overflow-hidden rounded-t-md border border-white/10 transition-[filter,transform] duration-rh-fast",
                  isHovered ? "brightness-125 ring-1 ring-white/30" : "",
                ].join(" ")}
              >
                {blockedRatio > 0 && (
                  <div
                    style={{ height: `${Math.max(4, blockedRatio)}%` }}
                    className="w-full bg-rose-500"
                  />
                )}
                {flaggedRatio > 0 && (
                  <div
                    style={{ height: `${Math.max(4, flaggedRatio)}%` }}
                    className="w-full bg-amber-400"
                  />
                )}
                <div className="flex-1 w-full bg-gradient-to-t from-sky-600/80 to-emerald-400/85" />
              </motion.div>
            </div>
          );
        })}
      </div>

      {/* X-Axis Labels */}
      <div className="flex items-center justify-between gap-2 text-[10px] font-mono text-slate-400">
        {data.map((bucket) => (
          <span key={bucket.label} className="flex-1 truncate text-center">
            {bucket.label}
          </span>
        ))}
      </div>
    </div>
  );
}
