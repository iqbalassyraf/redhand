"use client";

import React, { useState } from "react";
import Link from "next/link";
import { motion, AnimatePresence } from "framer-motion";
import {
  Activity,
  FileClock,
  GitFork,
  Hand,
  KeyRound,
  Radar,
  ScanSearch,
  ShieldCheck,
  TerminalSquare,
  UserCheck,
} from "lucide-react";
import type { ControlRoomView } from "@/lib/control-room-data";
import { EASE_OUT_EXPO, SPRING_SHARED_ELEMENT, usePrefersReducedMotion } from "@/lib/tokens";

export interface IconRailProps {
  activeView: ControlRoomView;
  onSelectView: (view: ControlRoomView) => void;
  hasSelectedNode?: boolean;
  pendingApprovalsCount?: number;
  userInitials?: string;
  userEmail?: string;
  onOpenCommandSearch?: () => void;
}

interface RailNavItem {
  id: ControlRoomView;
  label: string;
  shortcut?: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: number;
  disabled?: boolean;
}

const EXTERNAL_SHORTCUTS = [
  { href: "/passports", label: "Passports & Keys", icon: KeyRound },
  { href: "/radar", label: "Threat Radar", icon: Radar },
  { href: "/scanner", label: "MCP Scanner", icon: ScanSearch },
  { href: "/blackbox", label: "Black Box", icon: TerminalSquare },
] as const;

/**
 * Floating left icon rail with crimson brand crest, sliding active pill indicator,
 * hover/focus floating tooltips, and links to operational Sub-pages.
 */
export function IconRail({
  activeView,
  onSelectView,
  hasSelectedNode = true,
  pendingApprovalsCount = 0,
  userInitials = "RH",
  userEmail = "operator@redhand.dev",
}: IconRailProps) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const reducedMotion = usePrefersReducedMotion();

  const navItems: RailNavItem[] = [
    { id: "overview", label: "Control Room", shortcut: "1", icon: Activity },
    {
      id: "node-detail",
      label: "Node Funnel",
      shortcut: "2",
      icon: GitFork,
      disabled: !hasSelectedNode,
    },
    { id: "policies", label: "Policies", shortcut: "3", icon: ShieldCheck },
    {
      id: "approvals",
      label: "Human Approvals",
      shortcut: "4",
      icon: UserCheck,
      badge: pendingApprovalsCount,
    },
    { id: "audit-log", label: "Audit Log", shortcut: "5", icon: FileClock },
  ];

  const renderTooltip = (id: string, text: string, shortcut?: string) => (
    <AnimatePresence>
      {hoveredId === id && (
        <motion.div
          role="tooltip"
          initial={reducedMotion ? false : { opacity: 0, x: -6, scale: 0.96 }}
          animate={{ opacity: 1, x: 0, scale: 1 }}
          exit={reducedMotion ? { opacity: 0 } : { opacity: 0, x: -4, scale: 0.96 }}
          transition={{ duration: 0.14, ease: EASE_OUT_EXPO }}
          className="pointer-events-none absolute left-[calc(100%+12px)] top-1/2 z-50 -translate-y-1/2 flex items-center gap-2 whitespace-nowrap rounded-lg bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-950 shadow-xl"
        >
          <span>{text}</span>
          {shortcut && (
            <kbd className="rounded bg-slate-200 px-1.5 py-0.5 font-mono text-[10px] font-medium text-slate-700">
              {shortcut}
            </kbd>
          )}
        </motion.div>
      )}
    </AnimatePresence>
  );

  return (
    <aside
      aria-label="Primary Control Room Navigation"
      className="rh-glass relative z-30 flex h-full w-[64px] shrink-0 flex-col items-center justify-between rounded-rh-xl py-3.5"
    >
      {/* Top Crimson RedHand Crest */}
      <div className="flex flex-col items-center gap-4 w-full">
        <div className="relative">
          <button
            type="button"
            onClick={() => onSelectView("overview")}
            onMouseEnter={() => setHoveredId("brand")}
            onMouseLeave={() => setHoveredId(null)}
            onFocus={() => setHoveredId("brand")}
            onBlur={() => setHoveredId(null)}
            aria-label="RedHand Agent Control Room Overview"
            className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-rose-500 to-rose-700 text-white shadow-rh-crimson ring-1 ring-white/25 transition-transform duration-rh-fast hover:scale-105 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"
          >
            <Hand className="h-5 w-5" />
          </button>
          {renderTooltip("brand", "RedHand Control Room")}
        </div>

        {/* Main Control Room Views */}
        <nav className="flex w-full flex-col items-center gap-1.5 px-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeView === item.id;
            return (
              <div key={item.id} className="relative flex w-full justify-center">
                <button
                  type="button"
                  disabled={item.disabled}
                  onClick={() => onSelectView(item.id)}
                  onMouseEnter={() => setHoveredId(item.id)}
                  onMouseLeave={() => setHoveredId(null)}
                  onFocus={() => setHoveredId(item.id)}
                  onBlur={() => setHoveredId(null)}
                  aria-label={item.label}
                  aria-current={isActive ? "page" : undefined}
                  className={[
                    "relative flex h-10 w-10 items-center justify-center rounded-xl transition-colors duration-rh-fast focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/80",
                    isActive
                      ? "text-white"
                      : "text-slate-400 hover:bg-white/[0.06] hover:text-slate-100",
                    item.disabled ? "cursor-not-allowed opacity-35" : "cursor-pointer",
                  ].join(" ")}
                >
                  {isActive && (
                    <motion.span
                      layoutId="rh-rail-active-indicator"
                      transition={
                        reducedMotion
                          ? { duration: 0.01 }
                          : SPRING_SHARED_ELEMENT
                      }
                      className="absolute inset-0 rounded-xl bg-rose-500/20 border border-rose-400/35 shadow-[0_0_20px_-4px_rgba(225,29,72,0.5)]"
                    />
                  )}
                  <Icon className="relative z-10 h-[18px] w-[18px]" />
                  {typeof item.badge === "number" && item.badge > 0 && (
                    <span className="absolute -right-0.5 -top-0.5 z-20 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-rose-500 px-1 font-mono text-[10px] font-bold text-white shadow">
                      {item.badge}
                    </span>
                  )}
                </button>
                {renderTooltip(item.id, item.label, item.shortcut)}
              </div>
            );
          })}
        </nav>

        <div className="h-px w-8 bg-white/10" role="separator" />

        {/* Links to Operational Sub-pages */}
        <nav
          aria-label="Operational Console Pages"
          className="flex w-full flex-col items-center gap-1 px-2"
        >
          {EXTERNAL_SHORTCUTS.map((ext) => {
            const Icon = ext.icon;
            return (
              <div key={ext.href} className="relative flex w-full justify-center">
                <Link
                  href={ext.href}
                  onMouseEnter={() => setHoveredId(ext.href)}
                  onMouseLeave={() => setHoveredId(null)}
                  onFocus={() => setHoveredId(ext.href)}
                  onBlur={() => setHoveredId(null)}
                  aria-label={ext.label}
                  className="flex h-9 w-9 items-center justify-center rounded-xl text-slate-400 transition-colors duration-rh-fast hover:bg-white/[0.06] hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/80"
                >
                  <Icon className="h-4 w-4" />
                </Link>
                {renderTooltip(ext.href, ext.label)}
              </div>
            );
          })}
        </nav>
      </div>

      {/* Bottom Operator Avatar */}
      <div className="relative flex flex-col items-center gap-2">
        <button
          type="button"
          onMouseEnter={() => setHoveredId("avatar")}
          onMouseLeave={() => setHoveredId(null)}
          onFocus={() => setHoveredId("avatar")}
          onBlur={() => setHoveredId(null)}
          aria-label={`Signed in as ${userEmail}`}
          className="flex h-9 w-9 items-center justify-center rounded-full border border-white/20 bg-slate-800/90 text-xs font-bold tracking-tight text-slate-100 shadow-inner transition-colors hover:border-rose-400/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/80"
        >
          {userInitials}
        </button>
        {renderTooltip("avatar", userEmail)}
      </div>
    </aside>
  );
}
