"use client";

import React, { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight, Eye, EyeOff, Lock, ShieldCheck } from "lucide-react";

import { EASE_OUT_EXPO, MOTION_TIMING, usePrefersReducedMotion } from "@/lib/tokens";
import { EarlyAccessModal, type EnterpriseInterest } from "./EarlyAccessModal";

export interface EnterprisePreviewGateProps {
  badge: "ENTERPRISE" | "PREVIEW";
  title: string;
  subtitle: string;
  specBadge: string;
  valuePoints: readonly string[];
  interestId: EnterpriseInterest;
  children: React.ReactNode;
}

export function EnterprisePreviewGate({
  badge,
  title,
  subtitle,
  specBadge,
  valuePoints,
  interestId,
  children,
}: EnterprisePreviewGateProps) {
  const [waitlistOpen, setWaitlistOpen] = useState(false);
  const [peekGhost, setPeekGhost] = useState(false);
  const reducedMotion = usePrefersReducedMotion();

  return (
    <div className="flex flex-col gap-4">
      {/* Top Preview Header Strip */}
      <motion.div
        initial={reducedMotion ? false : { opacity: 0, y: -6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: MOTION_TIMING.normal, ease: EASE_OUT_EXPO }}
        className="rh-glass flex flex-wrap items-center justify-between gap-3 rounded-rh-xl border border-rh-ochre-border bg-rh-ochre-wash/25 px-4 py-3"
      >
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="inline-flex items-center gap-1 rounded-full border border-rh-ochre-border bg-rh-ochre-wash px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-rh-ochre">
            <Lock className="h-3 w-3" />
            {badge}
          </span>
          <span className="text-sm font-semibold text-rh-text">{title}</span>
          <span className="rounded-full border border-control-border bg-rh-subtle px-2.5 py-0.5 font-mono text-[10px] text-rh-text-2">
            {specBadge}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setPeekGhost((v) => !v)}
            className="inline-flex h-8 items-center gap-1.5 rounded-full border border-control-borderStrong bg-rh-elevated px-3 text-xs font-medium text-rh-text-2 transition-colors duration-rh-fast hover:bg-control-glassHover hover:text-rh-text"
          >
            {peekGhost ? <Eye className="h-3.5 w-3.5" /> : <EyeOff className="h-3.5 w-3.5" />}
            <span>{peekGhost ? "Show Access Card" : "Peek Ghost UI"}</span>
          </button>

          <button
            type="button"
            onClick={() => setWaitlistOpen(true)}
            className="inline-flex h-8 items-center gap-1.5 rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-4 text-xs font-semibold text-white shadow-rh-crimson transition-colors duration-rh-fast hover:from-control-crimson hover:to-control-crimsonDeep"
          >
            <span>Request Early Access</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </motion.div>

      {/* Ghost Configuration UI + Matte Executive Overlay Card */}
      <div className="relative min-h-[540px] rounded-rh-xl">
        <motion.div
          aria-hidden={!peekGhost}
          animate={{ opacity: peekGhost ? 0.96 : 0.42, scale: peekGhost ? 1 : 0.992 }}
          transition={reducedMotion ? { duration: 0.01 } : { duration: MOTION_TIMING.morph, ease: EASE_OUT_EXPO }}
          className={peekGhost ? "" : "pointer-events-none select-none"}
        >
          {children}
        </motion.div>

        <AnimatePresence>
          {!peekGhost && (
            <motion.div
              key="enterprise-overlay-card"
              initial={reducedMotion ? false : { opacity: 0, y: 10, scale: 0.985 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: 6, scale: 0.985 }}
              transition={{ duration: MOTION_TIMING.normal, ease: EASE_OUT_EXPO }}
              className="pointer-events-none absolute inset-0 flex items-center justify-center p-4"
            >
              <div className="rh-glass pointer-events-auto w-full max-w-lg rounded-rh-xl border border-rh-ochre-border bg-control-elevated/95 p-6 shadow-rh-glass backdrop-blur-md">
                <div className="flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-rh-ochre-border bg-rh-ochre-wash px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-rh-ochre">
                    <Lock className="h-3 w-3" />
                    10x Enterprise Native · {badge}
                  </span>
                  <span className="font-mono text-[10px] text-rh-text-muted">{specBadge}</span>
                </div>

                <h2 className="mt-3 text-lg font-bold tracking-tight text-rh-text">{title}</h2>
                <p className="mt-1.5 text-xs leading-relaxed text-rh-text-2">{subtitle}</p>

                <ul className="mt-4 flex flex-col gap-2.5 border-t border-control-border pt-4">
                  {valuePoints.map((point) => (
                    <li key={point} className="flex items-start gap-2.5 text-xs leading-snug text-rh-text">
                      <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rh-ochre" />
                      <span>{point}</span>
                    </li>
                  ))}
                </ul>

                <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-control-border pt-4">
                  <button
                    type="button"
                    onClick={() => setPeekGhost(true)}
                    className="text-xs font-medium text-rh-text-2 underline underline-offset-4 transition-colors hover:text-rh-text"
                  >
                    Inspect Read-Only Preview
                  </button>
                  <button
                    type="button"
                    onClick={() => setWaitlistOpen(true)}
                    className="inline-flex h-9 items-center gap-2 rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-5 text-xs font-semibold text-white shadow-rh-crimson transition-colors duration-rh-fast hover:from-control-crimson hover:to-control-crimsonDeep"
                  >
                    <span>Request Early Access</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <EarlyAccessModal
        open={waitlistOpen}
        onClose={() => setWaitlistOpen(false)}
        defaultInterest={interestId}
        sourceLabel={title}
      />
    </div>
  );
}
