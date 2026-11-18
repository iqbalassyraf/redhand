"use client";

import React from "react";
import { motion, type HTMLMotionProps } from "framer-motion";
import { EASE_OUT_EXPO, MOTION_TIMING, usePrefersReducedMotion } from "@/lib/tokens";

export type GlassGlow = "none" | "subtle" | "crimson" | "allowed" | "flagged" | "blocked";

const GLOW_CLASS: Record<GlassGlow, string> = {
  none: "",
  subtle: "shadow-rh-glass",
  crimson: "shadow-rh-crimson border-rose-500/25",
  allowed: "shadow-rh-allowed border-emerald-500/25",
  flagged: "shadow-rh-flagged border-amber-500/25",
  blocked: "shadow-rh-blocked border-red-500/30",
};

export interface GlassCardProps
  extends Omit<HTMLMotionProps<"div">, "children"> {
  children: React.ReactNode;
  glow?: GlassGlow;
  interactive?: boolean;
  staggerIndex?: number;
  className?: string;
}

/**
 * Translucent dark-navy glass surface with backdrop blur, 1px translucent border,
 * and soft top inner rim glow. Supports shared-element `layoutId` transitions.
 */
export function GlassCard({
  children,
  glow = "subtle",
  interactive = false,
  staggerIndex = 0,
  className = "",
  initial,
  animate,
  transition,
  ...rest
}: GlassCardProps) {
  const reducedMotion = usePrefersReducedMotion();

  const defaultInitial = reducedMotion
    ? false
    : { opacity: 0, y: 10 };
  const defaultAnimate = reducedMotion
    ? { opacity: 1 }
    : { opacity: 1, y: 0 };
  const defaultTransition = {
    duration: MOTION_TIMING.normal,
    delay: reducedMotion ? 0 : staggerIndex * MOTION_TIMING.staggerStep,
    ease: EASE_OUT_EXPO,
  };

  return (
    <motion.div
      initial={initial ?? defaultInitial}
      animate={animate ?? defaultAnimate}
      transition={transition ?? defaultTransition}
      className={[
        "relative rounded-rh-lg bg-[var(--rh-glass-bg)] backdrop-blur-xl border border-[var(--rh-glass-border)]",
        "before:pointer-events-none before:absolute before:inset-x-4 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-white/20 before:to-transparent",
        GLOW_CLASS[glow],
        interactive
          ? "transition-[background-color,border-color,transform] duration-rh-fast ease-rh-out hover:bg-[var(--rh-glass-bg-hover)] hover:border-[var(--rh-glass-border-strong)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70 cursor-pointer"
          : "",
        className,
      ]
        .filter(Boolean)
        .join(" ")}
      {...rest}
    >
      {children}
    </motion.div>
  );
}
