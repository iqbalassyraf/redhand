"use client";

import React from "react";
import { motion } from "framer-motion";
import { EASE_OUT_EXPO, MOTION_TIMING, useCountUp, usePrefersReducedMotion } from "@/lib/tokens";

export interface BreakdownItem {
  id: string;
  label: string;
  count: number;
  unitLabel?: string;
  color: string;
  dotClass?: string;
}

export interface SeverityBarProps {
  title?: string;
  items: BreakdownItem[];
  unitLabel?: string;
  selectedId?: string | null;
  onSelect?: (id: string | null) => void;
  loading?: boolean;
  className?: string;
}

function BreakdownCount({ count, unit }: { count: number; unit: string }) {
  const animated = useCountUp(count, 500, 0);
  return (
    <span className="rh-tabular font-mono text-xs text-sky-300/90">
      {Math.round(animated).toLocaleString("en-US")} {unit}
    </span>
  );
}

/**
 * Multi-segment horizontal proportion bar paired with interactive 2-column count tiles,
 * inspired by Prisma AIRS severity & category breakdowns. Bars animate from scaleX(0) to 1.
 */
export function SeverityBar({
  title,
  items,
  unitLabel = "Actions",
  selectedId = null,
  onSelect,
  loading = false,
  className = "",
}: SeverityBarProps) {
  const reducedMotion = usePrefersReducedMotion();
  const total = items.reduce((sum, item) => sum + Math.max(0, item.count), 0);

  return (
    <div className={`flex flex-col gap-3 ${className}`}>
      {title && (
        <div className="flex items-center justify-between">
          <h3 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">
            {title}
          </h3>
          {selectedId && onSelect && (
            <button
              type="button"
              onClick={() => onSelect(null)}
              className="text-[11px] text-rose-400 hover:text-rose-300 focus-visible:outline-none focus-visible:underline"
            >
              Clear filter
            </button>
          )}
        </div>
      )}

      {/* Multi-segment proportional bar */}
      {loading ? (
        <div className="h-2.5 w-full animate-pulse rounded-full bg-slate-800" />
      ) : (
        <div
          className="flex h-2.5 w-full items-center gap-1 overflow-hidden rounded-full bg-slate-900/80 p-0.5 border border-white/[0.06]"
          role="img"
          aria-label={
            items
              .map((it) => `${it.label}: ${it.count.toLocaleString("en-US")}`)
              .join(", ")
          }
        >
          {items.map((item, index) => {
            const pct = total > 0 ? Math.max(4, (item.count / total) * 100) : 100 / Math.max(1, items.length);
            const dimmed = selectedId !== null && selectedId !== item.id;
            return (
              <motion.div
                key={item.id}
                initial={reducedMotion ? false : { scaleX: 0 }}
                animate={{ scaleX: 1, opacity: dimmed ? 0.3 : 1 }}
                transition={{
                  duration: MOTION_TIMING.chart,
                  delay: reducedMotion ? 0 : index * 0.05,
                  ease: EASE_OUT_EXPO,
                }}
                style={{
                  width: `${pct}%`,
                  backgroundColor: item.color,
                  transformOrigin: "left",
                }}
                className="h-full rounded-full"
              />
            );
          })}
        </div>
      )}

      {/* Breakdown tiles */}
      <div className="grid grid-cols-2 gap-2">
        {items.map((item) => {
          const isSelected = selectedId === item.id;
          const isDimmed = selectedId !== null && !isSelected;
          const InteractiveTag = onSelect ? "button" : "div";
          return (
            <InteractiveTag
              key={item.id}
              type={onSelect ? "button" : undefined}
              onClick={
                onSelect
                  ? () => onSelect(isSelected ? null : item.id)
                  : undefined
              }
              className={[
                "flex flex-col gap-0.5 rounded-rh-sm border px-2.5 py-2 text-left transition-[background-color,border-color,opacity] duration-rh-fast ease-rh-out",
                isSelected
                  ? "border-rose-500/40 bg-rose-500/10"
                  : "border-white/[0.06] bg-slate-900/40",
                onSelect
                  ? "hover:border-white/20 hover:bg-slate-800/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70"
                  : "",
                isDimmed ? "opacity-50" : "opacity-100",
              ].join(" ")}
            >
              <span className="flex items-center gap-1.5 text-[11px] font-medium text-slate-300">
                <span
                  aria-hidden="true"
                  className="inline-block h-2 w-2 shrink-0 rounded-[2px]"
                  style={{ backgroundColor: item.color }}
                />
                <span className="truncate">{item.label}</span>
              </span>
              {loading ? (
                <span className="mt-1 h-4 w-16 animate-pulse rounded bg-slate-700/50" />
              ) : (
                <BreakdownCount
                  count={item.count}
                  unit={item.unitLabel ?? unitLabel}
                />
              )}
            </InteractiveTag>
          );
        })}
      </div>
    </div>
  );
}
