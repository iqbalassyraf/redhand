"use client";

import React from "react";
import { motion } from "framer-motion";
import {
  Bell,
  ChevronRight,
  Plus,
  Search,
  Zap,
} from "lucide-react";
import {
  TIME_RANGE_OPTIONS,
  type ControlRoomView,
  type TimeRangeKey,
  type TopologyNode,
} from "@/lib/control-room-data";
import { SPRING_SHARED_ELEMENT, usePrefersReducedMotion } from "@/lib/tokens";
import { StatusPill } from "./StatusPill";

export interface TopBarProps {
  activeView: ControlRoomView;
  selectedNode: TopologyNode | null;
  timeRange: TimeRangeKey;
  onChangeTimeRange: (range: TimeRangeKey) => void;
  onNavigateOverview: () => void;
  onSelectView: (view: ControlRoomView) => void;
  onOpenSearch: () => void;
  onSimulateThreat: () => void;
  onOpenNewModal: () => void;
  pendingApprovalsCount: number;
  userInitials: string;
  dataSource?: "live" | "preview";
  onToggleDataSource?: () => void;
}

const VIEW_LABELS: Record<ControlRoomView, string> = {
  overview: "Overview",
  "node-detail": "Node Funnel",
  policies: "Policies",
  approvals: "Human Approvals",
  "audit-log": "Audit Log",
};

/**
 * Top glass bar with breadcrumb navigation, Cmd+K command search bar,
 * sliding time-range selector, threat simulation trigger, Live pill, notifications, and + New action.
 */
export function TopBar({
  activeView,
  selectedNode,
  timeRange,
  onChangeTimeRange,
  onNavigateOverview,
  onSelectView,
  onOpenSearch,
  onSimulateThreat,
  onOpenNewModal,
  pendingApprovalsCount,
  userInitials,
  dataSource = "live",
  onToggleDataSource,
}: TopBarProps) {
  const reducedMotion = usePrefersReducedMotion();

  return (
    <header className="rh-glass relative z-20 flex min-h-[58px] w-full flex-wrap items-center justify-between gap-3 rounded-rh-xl px-4 py-2">
      {/* Left: Breadcrumb + Search Bar */}
      <div className="flex flex-wrap items-center gap-4 min-w-0">
        <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-sm">
          <button
            type="button"
            onClick={onNavigateOverview}
            className="font-medium text-slate-400 transition-colors hover:text-slate-100 focus-visible:outline-none focus-visible:underline"
          >
            Control Room
          </button>
          <ChevronRight className="h-3.5 w-3.5 text-slate-600" aria-hidden="true" />
          {activeView === "node-detail" && selectedNode ? (
            <>
              <span className="hidden sm:inline text-slate-400 capitalize">
                {selectedNode.spokeId}
              </span>
              <ChevronRight
                className="hidden sm:inline h-3.5 w-3.5 text-slate-600"
                aria-hidden="true"
              />
              <span className="truncate font-semibold text-slate-100 max-w-[180px]">
                {selectedNode.name}
              </span>
            </>
          ) : (
            <span className="font-semibold text-slate-100">
              {VIEW_LABELS[activeView]}
            </span>
          )}
        </nav>

        {/* Cmd+K Search Trigger */}
        <button
          type="button"
          onClick={onOpenSearch}
          className="group flex h-9 w-64 xl:w-80 items-center justify-between gap-2 rounded-full border border-white/[0.1] bg-slate-950/60 px-3.5 text-xs text-slate-400 transition-colors hover:border-white/25 hover:bg-slate-900/80 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70"
        >
          <span className="flex items-center gap-2 truncate">
            <Search className="h-3.5 w-3.5 text-slate-400 group-hover:text-rose-300 transition-colors shrink-0" />
            <span className="truncate">Search agents, tools, policies...</span>
          </span>
          <kbd className="rounded bg-white/[0.08] px-1.5 py-0.5 font-mono text-[10px] font-medium text-slate-300 border border-white/10">
            ⌘K
          </kbd>
        </button>
      </div>

      {/* Right Controls: Time Range, Threat Pulse, Live Pill, Bell, + New, Avatar */}
      <div className="flex flex-wrap items-center gap-2.5">
        {/* Compact Mobile Time-Range Selector */}
        <select
          aria-label="Time range"
          value={timeRange}
          onChange={(e) => onChangeTimeRange(e.target.value as TimeRangeKey)}
          className="md:hidden h-8 rounded-full border border-white/[0.12] bg-slate-950/80 px-3 text-xs font-medium text-slate-200 focus:border-rose-400/50 focus:outline-none focus:ring-2 focus:ring-rose-500/70"
        >
          {TIME_RANGE_OPTIONS.map((opt) => (
            <option key={opt.key} value={opt.key} className="bg-slate-900 text-slate-100">
              {opt.label}
            </option>
          ))}
        </select>

        {/* Time-range pill switcher */}
        <div
          role="group"
          aria-label="Time range"
          className="hidden md:flex items-center rounded-full border border-white/[0.09] bg-slate-950/65 p-1"
        >
          {TIME_RANGE_OPTIONS.map((opt) => {
            const active = timeRange === opt.key;
            return (
              <button
                key={opt.key}
                type="button"
                onClick={() => onChangeTimeRange(opt.key)}
                aria-pressed={active}
                className={[
                  "relative rounded-full px-2.5 py-1 text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70",
                  active ? "text-white" : "text-slate-400 hover:text-slate-200",
                ].join(" ")}
              >
                {active && (
                  <motion.span
                    layoutId="rh-time-range-active"
                    transition={
                      reducedMotion ? { duration: 0.01 } : SPRING_SHARED_ELEMENT
                    }
                    className="absolute inset-0 rounded-full bg-white/[0.12] border border-white/15"
                  />
                )}
                <span className="relative z-10">{opt.label}</span>
              </button>
            );
          })}
        </div>

        {/* Threat simulation demo trigger */}
        <button
          type="button"
          onClick={onSimulateThreat}
          title="Trigger a simulated threat pulse on the topology map"
          className="inline-flex h-8 items-center gap-1.5 rounded-full border border-rose-500/35 bg-rose-500/12 px-3 text-xs font-medium text-rose-200 transition-colors hover:bg-rose-500/20 hover:border-rose-400/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70"
        >
          <Zap className="h-3.5 w-3.5 text-rose-400" />
          <span className="hidden xl:inline">Simulate Threat</span>
        </button>

        {/* Live / Preview Data Toggle */}
        {onToggleDataSource ? (
          <button
            type="button"
            onClick={onToggleDataSource}
            title={dataSource === "live" ? "Live organization data active. Click to preview sample topology." : "Sample preview active. Click to switch to live organization telemetry."}
            className={`inline-flex h-8 items-center gap-1.5 rounded-full px-3 text-xs font-semibold transition-all ${
              dataSource === "live"
                ? "border border-emerald-500/40 bg-emerald-500/15 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.25)] hover:bg-emerald-500/25"
                : "border border-amber-500/40 bg-amber-500/15 text-amber-200 hover:bg-amber-500/25"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                dataSource === "live" ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
              }`}
            />
            <span>{dataSource === "live" ? "Live Data" : "Sample Preview"}</span>
          </button>
        ) : (
          <StatusPill status="live" label="Live" pulse size="md" />
        )}

        {/* Notification Bell */}
        <button
          type="button"
          onClick={() => onSelectView("approvals")}
          aria-label={`Human approvals (${pendingApprovalsCount} pending)`}
          className="relative flex h-8 w-8 items-center justify-center rounded-full border border-white/10 bg-slate-950/60 text-slate-300 transition-colors hover:border-white/25 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70"
        >
          <Bell className="h-4 w-4" />
          {pendingApprovalsCount > 0 && (
            <span className="absolute -right-1 -top-1 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-rose-500 px-1 font-mono text-[10px] font-bold text-white shadow">
              {pendingApprovalsCount}
            </span>
          )}
        </button>

        {/* Primary Crimson "+ New" Action */}
        <button
          type="button"
          onClick={onOpenNewModal}
          className="inline-flex h-8 items-center gap-1.5 rounded-full bg-gradient-to-r from-rose-600 to-rose-500 px-3.5 text-xs font-semibold text-white shadow-rh-crimson ring-1 ring-white/20 transition-transform hover:brightness-110 active:scale-[0.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"
        >
          <Plus className="h-3.5 w-3.5" />
          <span>New</span>
        </button>

        {/* Compact Avatar Pill */}
        <div
          aria-hidden="true"
          className="hidden sm:flex h-8 w-8 items-center justify-center rounded-full border border-white/20 bg-slate-800/80 text-[11px] font-bold text-slate-100"
        >
          {userInitials}
        </div>
      </div>
    </header>
  );
}
