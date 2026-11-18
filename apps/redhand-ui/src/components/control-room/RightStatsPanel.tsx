"use client";

import React from "react";
import { motion } from "framer-motion";
import type { OverviewSnapshot } from "@/lib/control-room-data";
import { EASE_OUT_EXPO, MOTION_TIMING, usePrefersReducedMotion } from "@/lib/tokens";
import { GlassCard } from "./GlassCard";
import { KpiTile } from "./KpiTile";
import { SeverityBar } from "./SeverityBar";

export interface RightStatsPanelProps {
  snapshot: OverviewSnapshot;
  selectedSeverity: string | null;
  onSelectSeverity: (severityId: string | null) => void;
  selectedCategory: string | null;
  onSelectCategory: (categoryId: string | null) => void;
  loading?: boolean;
  className?: string;
}

/**
 * Right-hand overview telemetry panel (Image 2 Prisma AIRS layout):
 * Blocked, Flagged, Allowed & Pending Approval KPIs, gateway traffic rows,
 * Severity Breakdown (Critical/Medium/Low), and Category Breakdown.
 */
export function RightStatsPanel({
  snapshot,
  selectedSeverity,
  onSelectSeverity,
  selectedCategory,
  onSelectCategory,
  loading = false,
  className = "",
}: RightStatsPanelProps) {
  const reducedMotion = usePrefersReducedMotion();
  const { summary } = snapshot;

  const totalVerdicts =
    summary.blocked + summary.flagged + summary.allowed + summary.pendingApproval;
  const blockedPct =
    totalVerdicts > 0 ? Math.max(8, (summary.blocked / totalVerdicts) * 100) : 25;
  const flaggedPct =
    totalVerdicts > 0 ? Math.max(6, (summary.flagged / totalVerdicts) * 100) : 15;
  const pendingPct =
    totalVerdicts > 0 ? Math.max(5, (summary.pendingApproval / totalVerdicts) * 100) : 5;
  const allowedPct = Math.max(10, 100 - blockedPct - flaggedPct - pendingPct);

  const secondaryRows = [
    { label: "Inbound Traffic", value: summary.inboundTraffic, delta: summary.inboundDelta },
    { label: "Outbound Calls", value: summary.outboundCalls, delta: summary.outboundDelta },
    { label: "Logs Analyzed", value: summary.logsAnalyzed, delta: summary.logsDelta },
    { label: "MCP Servers", value: String(summary.mcpServers), delta: summary.mcpDelta },
    { label: "Active Workloads", value: summary.activeWorkloads, delta: summary.workloadsDelta },
    { label: "P99 Gate Latency", value: summary.p99Latency, delta: "AST <0.2ms" },
  ];

  return (
    <GlassCard
      staggerIndex={1}
      className={`rh-scrollbar flex w-full lg:h-full lg:w-[348px] shrink-0 flex-col gap-3 overflow-y-auto p-3.5 ${className}`}
    >
      {/* Top 4-Status Ratio Bar */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">
          <span>Control Posture</span>
          <span className="font-mono text-[10px] text-slate-400">{snapshot.label}</span>
        </div>

        <div className="flex h-2 w-full items-center gap-1 overflow-hidden rounded-full bg-slate-900/80 p-0.5 border border-white/[0.06]">
          {[
            { id: "blocked", width: blockedPct, color: "#EF4444" },
            { id: "flagged", width: flaggedPct, color: "#F59E0B" },
            { id: "allowed", width: allowedPct, color: "#10B981" },
            { id: "pending", width: pendingPct, color: "#94A3B8" },
          ].map((seg, idx) => (
            <motion.div
              key={seg.id}
              initial={reducedMotion ? false : { scaleX: 0 }}
              animate={{ scaleX: 1 }}
              transition={{
                duration: MOTION_TIMING.chart,
                delay: reducedMotion ? 0 : idx * 0.04,
                ease: EASE_OUT_EXPO,
              }}
              style={{
                width: `${seg.width}%`,
                backgroundColor: seg.color,
                transformOrigin: "left",
              }}
              className="h-full rounded-full"
            />
          ))}
        </div>
      </div>

      {/* Primary Status Counters: Blocked, Flagged, Allowed, Pending Approval */}
      <div className="grid grid-cols-2 gap-2.5">
        <KpiTile
          label="Blocked"
          value={summary.blocked}
          status="blocked"
          loading={loading}
        />
        <KpiTile
          label="Flagged"
          value={summary.flagged}
          status="flagged"
          loading={loading}
        />
        <KpiTile
          label="Allowed"
          value={summary.allowed}
          format="compact"
          status="allowed"
          loading={loading}
        />
        <KpiTile
          label="Pending Approval"
          value={summary.pendingApproval}
          status="pending"
          loading={loading}
        />
      </div>

      {/* Secondary Gateway Telemetry Grid */}
      <div className="grid grid-cols-2 gap-2">
        {secondaryRows.map((row) => (
          <div
            key={row.label}
            className="flex flex-col justify-between rounded-rh-sm border border-white/[0.06] bg-slate-900/40 px-3 py-2"
          >
            <span className="text-[11px] text-slate-400">{row.label}</span>
            <div className="mt-1 flex items-baseline justify-between gap-2">
              <span className="rh-tabular text-sm font-semibold text-slate-100">
                {row.value}
              </span>
              <span className="font-mono text-[10px] text-slate-400">
                {row.delta}
              </span>
            </div>
          </div>
        ))}
      </div>

      <div className="h-px bg-white/[0.08]" role="separator" />

      {/* Severity Breakdown (Critical / Medium / Low) */}
      <SeverityBar
        title="Severity Breakdown"
        items={snapshot.severityBreakdown}
        unitLabel="Threats"
        selectedId={selectedSeverity}
        onSelect={onSelectSeverity}
        loading={loading}
      />

      <div className="h-px bg-white/[0.08]" role="separator" />

      {/* Threat Category Breakdown */}
      <SeverityBar
        title="Category Breakdown"
        items={snapshot.categoryBreakdown}
        unitLabel="Events"
        selectedId={selectedCategory}
        onSelect={onSelectCategory}
        loading={loading}
      />
    </GlassCard>
  );
}
