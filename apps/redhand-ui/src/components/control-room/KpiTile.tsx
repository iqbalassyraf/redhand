"use client";

import React from "react";
import {
  formatCompactNumber,
  STATUS_META,
  useCountUp,
  type ControlStatus,
} from "@/lib/tokens";

export type KpiFormat = "number" | "compact" | "currency" | "percent" | "latency";

export interface KpiTileProps {
  label: string;
  value: number;
  format?: KpiFormat;
  subtitle?: string;
  delta?: string;
  deltaDirection?: "up" | "down" | "neutral";
  status?: Extract<ControlStatus, "allowed" | "flagged" | "blocked" | "pending">;
  accentColor?: string;
  loading?: boolean;
  active?: boolean;
  onClick?: () => void;
  className?: string;
}

function formatKpiValue(raw: number, format: KpiFormat): string {
  switch (format) {
    case "compact":
      return formatCompactNumber(raw, 1);
    case "currency":
      return `$${raw.toLocaleString("en-US", {
        minimumFractionDigits: raw < 100 ? 2 : 0,
        maximumFractionDigits: raw < 100 ? 2 : 0,
      })}`;
    case "percent":
      return `${raw.toFixed(1)}%`;
    case "latency":
      return `${raw.toFixed(2)} ms`;
    case "number":
    default:
      return Math.round(raw).toLocaleString("en-US");
  }
}

/**
 * Clean telemetry KPI tile with animated count-up figures, status square/dot,
 * delta arrow, and skeleton loader state.
 */
export function KpiTile({
  label,
  value,
  format = "number",
  subtitle,
  delta,
  deltaDirection = "neutral",
  status,
  accentColor,
  loading = false,
  active = false,
  onClick,
  className = "",
}: KpiTileProps) {
  const decimals = format === "percent" || format === "latency" || (format === "currency" && value < 100) ? 2 : 0;
  const animatedValue = useCountUp(value, 540, decimals);
  const statusMeta = status ? STATUS_META[status] : null;
  const dotColor = accentColor ?? statusMeta?.color;

  const deltaToneClass =
    deltaDirection === "up"
      ? "text-emerald-400"
      : deltaDirection === "down"
        ? "text-rose-400"
        : "text-slate-400";

  const Wrapper = onClick ? "button" : "div";

  return (
    <Wrapper
      type={onClick ? "button" : undefined}
      onClick={onClick}
      className={[
        "group relative flex w-full flex-col justify-between rounded-rh-md border px-3.5 py-3 text-left transition-[background-color,border-color,transform] duration-rh-fast ease-rh-out",
        active
          ? "border-rose-500/45 bg-rose-500/10"
          : "border-white/[0.08] bg-slate-900/45",
        onClick
          ? "hover:border-white/20 hover:bg-slate-800/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70"
          : "",
        className,
      ].join(" ")}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-2 text-[11px] font-medium tracking-wide text-slate-400">
          {dotColor && (
            <span
              aria-hidden="true"
              className="inline-block h-2 w-2 shrink-0 rounded-[3px]"
              style={{ backgroundColor: dotColor }}
            />
          )}
          <span className="truncate">{label}</span>
        </span>
        {delta && (
          <span className={`font-mono text-[10px] font-medium ${deltaToneClass}`}>
            {delta}
          </span>
        )}
      </div>

      {loading ? (
        <div className="mt-2 h-7 w-20 animate-pulse rounded bg-slate-700/50" />
      ) : (
        <div className="rh-tabular mt-1.5 text-[22px] font-semibold leading-tight tracking-tight text-slate-50">
          {formatKpiValue(animatedValue, format)}
        </div>
      )}

      {subtitle && (
        <div className="mt-1 truncate text-[11px] text-slate-400">
          {subtitle}
        </div>
      )}
    </Wrapper>
  );
}
