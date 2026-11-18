"use client";

import React from "react";
import { STATUS_META, type ControlStatus } from "@/lib/tokens";

export interface StatusPillProps {
  status: ControlStatus;
  label?: string;
  count?: number;
  pulse?: boolean;
  size?: "sm" | "md";
  className?: string;
}

/**
 * Compact status indicator pill using RedHand semantic colors:
 * green = allowed/protected, amber = flagged, red = blocked/unprotected, slate = pending.
 */
export function StatusPill({
  status,
  label,
  count,
  pulse = false,
  size = "sm",
  className = "",
}: StatusPillProps) {
  const meta = STATUS_META[status];
  const displayLabel = label ?? meta.label;
  const paddingClass =
    size === "md" ? "px-3 py-1 text-xs gap-2" : "px-2.5 py-0.5 text-[11px] gap-1.5";

  return (
    <span
      className={[
        "inline-flex items-center rounded-full border font-medium leading-none whitespace-nowrap backdrop-blur-md",
        meta.bgClass,
        meta.borderClass,
        meta.textClass,
        paddingClass,
        className,
      ].join(" ")}
    >
      <span className="relative flex h-2 w-2 items-center justify-center">
        {pulse && (
          <span
            aria-hidden="true"
            className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-65 ${meta.dotClass}`}
          />
        )}
        <span
          aria-hidden="true"
          className={`relative inline-flex h-1.5 w-1.5 rounded-full ${meta.dotClass}`}
        />
      </span>
      <span>{displayLabel}</span>
      {typeof count === "number" && (
        <span className="rh-tabular font-mono opacity-85">
          {count.toLocaleString("en-US")}
        </span>
      )}
    </span>
  );
}
