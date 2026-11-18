"use client";

import { useEffect, useRef, useState } from "react";

export const EASE_OUT_EXPO = [0.22, 1, 0.36, 1] as const;

export const MOTION_TIMING = {
  fast: 0.18,
  normal: 0.26,
  morph: 0.3,
  chart: 0.55,
  staggerStep: 0.045,
} as const;

export const TRANSITION_DEFAULT = {
  duration: MOTION_TIMING.normal,
  ease: EASE_OUT_EXPO,
} as const;

export const SPRING_SHARED_ELEMENT = {
  type: "spring" as const,
  stiffness: 340,
  damping: 32,
  mass: 0.85,
};

export const TOKENS = {
  colors: {
    base: "#060913",
    elevated: "#0B1022",
    glass: "rgba(13, 19, 38, 0.64)",
    glassBorder: "rgba(148, 163, 184, 0.14)",
    crimson: "#E11D48",
    crimsonBright: "#F43F5E",
    allowed: "#10B981",
    flagged: "#F59E0B",
    blocked: "#EF4444",
    pending: "#94A3B8",
    textPrimary: "#F8FAFC",
    textSecondary: "#94A3B8",
    textMuted: "#64748B",
  },
  radius: {
    sm: 8,
    md: 12,
    lg: 16,
    xl: 20,
    pill: 9999,
  },
  spacing: {
    railWidth: 68,
    rightPanelWidth: 340,
    topBarHeight: 60,
  },
} as const;

export type ControlStatus =
  | "allowed"
  | "flagged"
  | "blocked"
  | "pending"
  | "live"
  | "protected"
  | "unprotected"
  | "partial"
  | "critical"
  | "medium"
  | "low";

export const STATUS_META: Record<
  ControlStatus,
  {
    label: string;
    color: string;
    bgClass: string;
    borderClass: string;
    textClass: string;
    dotClass: string;
  }
> = {
  allowed: {
    label: "Allowed",
    color: "#10B981",
    bgClass: "bg-emerald-500/15",
    borderClass: "border-emerald-400/30",
    textClass: "text-emerald-300",
    dotClass: "bg-emerald-400",
  },
  flagged: {
    label: "Flagged",
    color: "#F59E0B",
    bgClass: "bg-amber-500/15",
    borderClass: "border-amber-400/30",
    textClass: "text-amber-300",
    dotClass: "bg-amber-400",
  },
  blocked: {
    label: "Blocked",
    color: "#EF4444",
    bgClass: "bg-red-500/15",
    borderClass: "border-red-400/30",
    textClass: "text-red-300",
    dotClass: "bg-red-400",
  },
  pending: {
    label: "Pending approval",
    color: "#94A3B8",
    bgClass: "bg-slate-400/15",
    borderClass: "border-slate-400/30",
    textClass: "text-slate-300",
    dotClass: "bg-slate-400",
  },
  live: {
    label: "Live",
    color: "#10B981",
    bgClass: "bg-emerald-500/15",
    borderClass: "border-emerald-400/30",
    textClass: "text-emerald-300",
    dotClass: "bg-emerald-400",
  },
  protected: {
    label: "Protected",
    color: "#10B981",
    bgClass: "bg-emerald-500/15",
    borderClass: "border-emerald-400/30",
    textClass: "text-emerald-300",
    dotClass: "bg-emerald-400",
  },
  unprotected: {
    label: "Unprotected",
    color: "#F43F5E",
    bgClass: "bg-rose-500/15",
    borderClass: "border-rose-400/30",
    textClass: "text-rose-300",
    dotClass: "bg-rose-400",
  },
  partial: {
    label: "Partial coverage",
    color: "#F59E0B",
    bgClass: "bg-amber-500/15",
    borderClass: "border-amber-400/30",
    textClass: "text-amber-300",
    dotClass: "bg-amber-400",
  },
  critical: {
    label: "Critical",
    color: "#EF4444",
    bgClass: "bg-red-500/15",
    borderClass: "border-red-400/30",
    textClass: "text-red-300",
    dotClass: "bg-red-400",
  },
  medium: {
    label: "Medium",
    color: "#F59E0B",
    bgClass: "bg-amber-500/15",
    borderClass: "border-amber-400/30",
    textClass: "text-amber-300",
    dotClass: "bg-amber-400",
  },
  low: {
    label: "Low",
    color: "#94A3B8",
    bgClass: "bg-slate-400/15",
    borderClass: "border-slate-400/25",
    textClass: "text-slate-300",
    dotClass: "bg-slate-400",
  },
};

export function formatCompactNumber(value: number, decimals = 1): string {
  if (!Number.isFinite(value)) return "0";
  const abs = Math.abs(value);
  if (abs >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(decimals).replace(/\.0$/, "")}M`;
  }
  if (abs >= 1_000) {
    return `${(value / 1_000).toFixed(decimals).replace(/\.0$/, "")}k`;
  }
  return Math.round(value).toLocaleString("en-US");
}

export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return;
    }
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(query.matches);
    const onChange = (event: MediaQueryListEvent) => setReduced(event.matches);
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);

  return reduced;
}

export function useCountUp(
  target: number,
  durationMs = 520,
  decimals = 0
): number {
  const reducedMotion = usePrefersReducedMotion();
  const [display, setDisplay] = useState<number>(target);
  const previousRef = useRef<number>(target);
  const hasMountedRef = useRef<boolean>(false);

  useEffect(() => {
    if (reducedMotion) {
      previousRef.current = target;
      setDisplay(target);
      return;
    }

    const from = hasMountedRef.current ? previousRef.current : 0;
    hasMountedRef.current = true;
    if (from === target) {
      setDisplay(target);
      return;
    }

    let rafId = 0;
    const start = performance.now();

    const tick = (now: number) => {
      const elapsed = now - start;
      const progress = Math.min(1, elapsed / durationMs);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = from + (target - from) * eased;
      const factor = Math.pow(10, decimals);
      setDisplay(Math.round(current * factor) / factor);

      if (progress < 1) {
        rafId = requestAnimationFrame(tick);
      } else {
        previousRef.current = target;
        setDisplay(target);
      }
    };

    rafId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafId);
  }, [target, durationMs, decimals, reducedMotion]);

  return display;
}
