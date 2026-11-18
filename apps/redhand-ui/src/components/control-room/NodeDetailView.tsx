"use client";

import React, { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ArrowLeft,
  Bot,
  ChevronDown,
  ChevronRight,
  Cpu,
  Database,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Users,
  Wrench,
} from "lucide-react";
import type {
  PolicyItem,
  SpokeCategory,
  TopologyNode,
} from "@/lib/control-room-data";
import {
  EASE_OUT_EXPO,
  formatCompactNumber,
  MOTION_TIMING,
  SPRING_SHARED_ELEMENT,
  usePrefersReducedMotion,
} from "@/lib/tokens";
import { ActivityBarChart, FunnelChart } from "./FunnelChart";
import { GlassCard } from "./GlassCard";
import { KpiTile } from "./KpiTile";
import { StatusPill } from "./StatusPill";

export interface NodeDetailViewProps {
  node: TopologyNode;
  relatedNodes: TopologyNode[];
  timeRangeLabel: string;
  timeRangeMultiplier: number;
  loading?: boolean;
  policies: PolicyItem[];
  onBack: () => void;
  onSelectNode: (node: TopologyNode) => void;
  onToggleProtection: (nodeId: string) => void;
  onTogglePolicyMode: (policyId: string) => void;
}

const SPOKE_ICON: Record<SpokeCategory, React.ComponentType<{ className?: string }>> = {
  agents: Bot,
  tools: Wrench,
  data: Database,
  humans: Users,
  models: Cpu,
};

type DetailTab = "funnel" | "traces" | "guardrails";

const TRACE_VERDICT_FILTERS = ["all", "allowed", "flagged", "blocked", "pending"] as const;

/**
 * Campaigns-style detail screen for any clicked Spoke or Child Node.
 * Features shared-element hero morphing from the clicked map node, 4-tile KPI strip,
 * 4-stage FunnelChart with conversion % pills, summary KPI sidebar card,
 * hourly ActivityBarChart, expandable trace inspector, and attached policies.
 */
export function NodeDetailView({
  node,
  relatedNodes,
  timeRangeLabel,
  timeRangeMultiplier,
  loading = false,
  policies,
  onBack,
  onSelectNode,
  onToggleProtection,
  onTogglePolicyMode,
}: NodeDetailViewProps) {
  const reducedMotion = usePrefersReducedMotion();
  const [activeTab, setActiveTab] = useState<DetailTab>("funnel");
  const [traceFilter, setTraceFilter] = useState<string>("all");
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);

  const Icon = SPOKE_ICON[node.category];

  const scaled = useMemo(() => {
    const scale = (n: number) => Math.max(n === 0 ? 0 : 1, Math.round(n * timeRangeMultiplier));
    const requests = scale(node.kpis.requests);
    const policyChecked = Math.min(requests, scale(node.kpis.policyChecked));
    const flagged = scale(node.kpis.flagged);
    const blocked = scale(node.kpis.blocked);
    const approved = scale(node.kpis.approved);
    const spendUsd = Math.round(node.kpis.spendUsd * timeRangeMultiplier * 100) / 100;

    const funnel = node.funnel.map((stage) => ({
      ...stage,
      count:
        stage.id === "requests"
          ? requests
          : stage.id === "policy_checked"
            ? policyChecked
            : stage.id === "flagged"
              ? flagged
              : stage.tone === "allowed"
                ? approved
                : blocked,
    }));

    const activitySeries = node.activitySeries.map((b) => ({
      ...b,
      allowed: scale(b.allowed),
      flagged: scale(b.flagged),
      blocked: scale(b.blocked),
      pending: scale(b.pending),
    }));

    return {
      requests,
      policyChecked,
      flagged,
      blocked,
      approved,
      pendingApproval: node.kpis.pendingApproval,
      spendUsd,
      funnel,
      activitySeries,
    };
  }, [node, timeRangeMultiplier]);

  const nodePolicies = useMemo(
    () => policies.filter((p) => p.category === node.category || p.category === "all"),
    [policies, node.category]
  );

  const filteredEvents = useMemo(
    () =>
      node.recentEvents.filter(
        (ev) => traceFilter === "all" || ev.status === traceFilter
      ),
    [node.recentEvents, traceFilter]
  );

  const policyRate =
    scaled.requests > 0
      ? Math.round((scaled.policyChecked / scaled.requests) * 1000) / 10
      : 100;
  const flagRate =
    scaled.policyChecked > 0
      ? Math.round((scaled.flagged / scaled.policyChecked) * 1000) / 10
      : 0;
  const blockRate =
    scaled.flagged > 0
      ? Math.round((scaled.blocked / scaled.flagged) * 1000) / 10
      : 0;

  const animationKey = `${node.id}-${timeRangeLabel}`;

  return (
    <motion.div
      initial={reducedMotion ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: 10 }}
      transition={{ duration: MOTION_TIMING.normal, ease: EASE_OUT_EXPO }}
      className="rh-scrollbar flex h-full w-full flex-col gap-4 overflow-y-auto pr-1"
    >
      {/* Top Header Row with Back & Shared-Element Node Morph */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <button
            type="button"
            onClick={onBack}
            className="inline-flex h-9 items-center gap-1.5 rounded-full border border-white/15 bg-slate-950/80 px-3.5 text-xs font-medium text-slate-200 transition-colors hover:border-white/30 hover:bg-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>Back to Map</span>
          </button>

          <motion.div
            layoutId={`node-hero-${node.id}`}
            transition={reducedMotion ? { duration: 0.01 } : SPRING_SHARED_ELEMENT}
            className="flex h-12 w-12 items-center justify-center rounded-2xl border border-rose-400/35 bg-slate-950/90 text-rose-300 shadow-rh-crimson"
          >
            <Icon className="h-6 w-6" />
          </motion.div>

          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-2xl font-bold tracking-tight text-white">
                {node.name}
              </h1>
              <StatusPill status={node.protection} size="md" />
              <StatusPill status={node.status} size="md" />
            </div>
            <p className="mt-0.5 text-xs text-slate-400">
              {node.frameworkOrProvider} • {node.environment} • {timeRangeLabel} • {node.subtitle}
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => onToggleProtection(node.id)}
            className="inline-flex h-9 items-center gap-1.5 rounded-full border border-white/15 bg-white/[0.06] px-4 text-xs font-semibold text-slate-100 transition-colors hover:bg-white/[0.12] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70"
          >
            <Lock className="h-3.5 w-3.5 text-emerald-400" />
            <span>
              {node.protection === "protected" ? "Enforce Strict Pin" : "Apply RedHand Guard"}
            </span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab(activeTab === "funnel" ? "traces" : "funnel")}
            className="inline-flex h-9 items-center gap-1.5 rounded-full bg-gradient-to-r from-rose-600 to-rose-500 px-4 text-xs font-semibold text-white shadow-rh-crimson hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-400"
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            <span>
              {activeTab === "funnel" ? "Inspect Traces" : "View Security Funnel"}
            </span>
          </button>
        </div>
      </div>

      {/* Top 4-Tile KPI Strip */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiTile
          label="1. Total Requests"
          value={scaled.requests}
          format="compact"
          subtitle={`${node.endpointCount} endpoints in scope`}
          status="allowed"
          loading={loading}
        />
        <KpiTile
          label="2. Policy Checked"
          value={scaled.policyChecked}
          format="compact"
          delta={`${policyRate.toFixed(1)}%`}
          deltaDirection="up"
          subtitle={`P99 gate ${node.kpis.p99LatencyMs.toFixed(2)} ms`}
          status="allowed"
          loading={loading}
        />
        <KpiTile
          label="3. Flagged Actions"
          value={scaled.flagged}
          format="number"
          delta={`${flagRate.toFixed(1)}%`}
          deltaDirection="neutral"
          subtitle="Radar & AST rules triggered"
          status="flagged"
          loading={loading}
        />
        <KpiTile
          label={node.spokeId === "humans" ? "4. Human Approved" : "4. Blocked / Halted"}
          value={node.spokeId === "humans" ? scaled.approved : scaled.blocked}
          format="number"
          delta={`${blockRate.toFixed(1)}%`}
          deltaDirection="down"
          subtitle={`${scaled.pendingApproval} pending HITL review`}
          status={node.spokeId === "humans" ? "allowed" : "blocked"}
          loading={loading}
        />
      </div>

      {/* Sliding Sub-Tab Navigation (Image 1 Board / Results style) */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.08] pb-2">
        <div className="flex items-center gap-6" role="tablist" aria-label="Node detail views">
          {[
            { id: "funnel" as const, label: "Results & Funnel" },
            { id: "traces" as const, label: `Live Traces & Decisions (${node.recentEvents.length})` },
            { id: "guardrails" as const, label: `Attached Guardrails (${nodePolicies.length})` },
          ].map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                role="tab"
                type="button"
                aria-selected={isActive}
                onClick={() => setActiveTab(tab.id)}
                className={[
                  "relative pb-2 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:text-white",
                  isActive ? "text-white" : "text-slate-400 hover:text-slate-200",
                ].join(" ")}
              >
                {tab.label}
                {isActive && (
                  <motion.span
                    layoutId="rh-node-tab-underline"
                    transition={reducedMotion ? { duration: 0.01 } : SPRING_SHARED_ELEMENT}
                    className="absolute inset-x-0 -bottom-[9px] h-0.5 rounded-full bg-rose-400 shadow-[0_0_12px_rgba(244,63,94,0.8)]"
                  />
                )}
              </button>
            );
          })}
        </div>

        {/* Peer Node Switcher Pills with Sliding Active Pill */}
        {relatedNodes.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[11px] text-slate-500">Sibling nodes:</span>
            {relatedNodes.slice(0, 5).map((peer) => {
              const isPeerActive = peer.id === node.id;
              return (
                <button
                  key={peer.id}
                  type="button"
                  onClick={() => onSelectNode(peer)}
                  className={[
                    "relative rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-rose-400",
                    isPeerActive
                      ? "border-rose-400/50 text-rose-100"
                      : "border-white/10 bg-slate-900/60 text-slate-300 hover:border-white/25 hover:text-white",
                  ].join(" ")}
                >
                  {isPeerActive && (
                    <motion.span
                      layoutId="rh-sibling-active-pill"
                      transition={reducedMotion ? { duration: 0.01 } : SPRING_SHARED_ELEMENT}
                      className="absolute inset-0 rounded-full bg-rose-500/20"
                    />
                  )}
                  <span className="relative z-10">{peer.shortLabel}</span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        {activeTab === "funnel" && (
          <motion.div
            key="tab-funnel"
            initial={reducedMotion ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -6 }}
            transition={{ duration: MOTION_TIMING.fast, ease: EASE_OUT_EXPO }}
            className="grid grid-cols-1 gap-4 xl:grid-cols-12"
          >
            {/* Funnel Card */}
            <GlassCard
              glow="subtle"
              staggerIndex={0}
              className="xl:col-span-8 flex flex-col justify-between p-5"
            >
              <div className="mb-5 flex flex-wrap items-start justify-between gap-2">
                <div>
                  <h2 className="text-base font-semibold text-white">
                    {node.name}: Guardrail enforcement funnel
                  </h2>
                  <p className="mt-0.5 text-xs text-slate-400">
                    {timeRangeLabel} • Last active {node.lastSeen} • Policy check latency P99{" "}
                    {node.kpis.p99LatencyMs.toFixed(2)} ms
                  </p>
                </div>
                <StatusPill status="live" label="Live" pulse />
              </div>

              <FunnelChart
                stages={scaled.funnel}
                animationKey={animationKey}
                loading={loading}
              />
            </GlassCard>

            {/* Right KPI Summary Card (Image 1 right card layout) */}
            <GlassCard
              glow={node.protection === "unprotected" ? "crimson" : "subtle"}
              staggerIndex={1}
              className="xl:col-span-4 flex flex-col justify-between p-5"
            >
              <div>
                <div className="text-xs font-medium text-slate-400">
                  Policy coverage ({node.environment})
                </div>
                <div className="rh-tabular mt-1 text-4xl font-bold tracking-tight text-white">
                  {policyRate.toFixed(1)}%
                </div>
                <div className="mt-1 text-xs text-slate-400">
                  risk score{" "}
                  <span className="font-mono font-semibold text-slate-200">
                    {node.riskScore}/100
                  </span>{" "}
                  • spend{" "}
                  <span className="font-mono font-semibold text-emerald-300">
                    ${scaled.spendUsd.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
                  </span>
                </div>
              </div>

              <dl className="mt-5 flex flex-col gap-3 border-t border-white/[0.08] pt-4 text-xs">
                <div className="flex items-center justify-between">
                  <dt className="text-slate-400">Requests processed</dt>
                  <dd className="rh-tabular font-mono font-semibold text-slate-100">
                    {formatCompactNumber(scaled.requests)}
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-slate-400">Policy checked</dt>
                  <dd className="rh-tabular font-mono font-semibold text-slate-100">
                    {formatCompactNumber(scaled.policyChecked)}
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-slate-400">Flagged rate</dt>
                  <dd className="rh-tabular font-mono font-semibold text-amber-300">
                    {flagRate.toFixed(1)}%
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-slate-400">Block conversion</dt>
                  <dd className="rh-tabular font-mono font-semibold text-rose-400">
                    {blockRate.toFixed(1)}%
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-slate-400">Pending human sign-off</dt>
                  <dd className="rh-tabular font-mono font-semibold text-slate-200">
                    {scaled.pendingApproval}
                  </dd>
                </div>
              </dl>
            </GlassCard>

            {/* Bottom Full-Width Activity Over Time Bar Chart */}
            <GlassCard staggerIndex={2} className="xl:col-span-12 p-5">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="text-base font-semibold text-white">
                    Activity over time
                  </h2>
                  <p className="text-xs text-slate-400">
                    Hourly breakdown of allowed, flagged, and blocked actions ({timeRangeLabel})
                  </p>
                </div>
                <div className="flex items-center gap-3 text-[11px] text-slate-300">
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-sm bg-emerald-400" /> Allowed
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-sm bg-amber-400" /> Flagged
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-sm bg-rose-500" /> Blocked
                  </span>
                </div>
              </div>
              <ActivityBarChart
                data={scaled.activitySeries}
                animationKey={animationKey}
                loading={loading}
              />
            </GlassCard>
          </motion.div>
        )}

        {activeTab === "traces" && (
          <motion.div
            key="tab-traces"
            initial={reducedMotion ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -6 }}
            transition={{ duration: MOTION_TIMING.fast, ease: EASE_OUT_EXPO }}
          >
            <GlassCard staggerIndex={0} className="p-5">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-base font-semibold text-white">
                    Gateway & Radar telemetry decisions
                  </h2>
                  <p className="text-xs text-slate-400">
                    Click any row to inspect the rule verdict and timing for {node.name}
                  </p>
                </div>

                <div className="flex items-center gap-1 rounded-full border border-white/10 bg-slate-950/70 p-1">
                  {TRACE_VERDICT_FILTERS.map((f) => {
                    const active = traceFilter === f;
                    return (
                      <button
                        key={f}
                        type="button"
                        onClick={() => setTraceFilter(f)}
                        className={[
                          "relative rounded-full px-3 py-1 text-[11px] font-medium capitalize transition-colors",
                          active ? "text-white" : "text-slate-400 hover:text-slate-200",
                        ].join(" ")}
                      >
                        {active && (
                          <motion.span
                            layoutId="rh-trace-filter-pill"
                            transition={reducedMotion ? { duration: 0.01 } : SPRING_SHARED_ELEMENT}
                            className="absolute inset-0 rounded-full bg-white/15"
                          />
                        )}
                        <span className="relative z-10">{f}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {filteredEvents.length === 0 ? (
                <div className="py-10 text-center text-xs text-slate-400">
                  No recent events with status &ldquo;{traceFilter}&rdquo; on this node.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-white/10 text-[11px] uppercase tracking-wider text-slate-400">
                        <th className="w-8 py-2.5 pr-2 font-semibold" />
                        <th className="py-2.5 pr-4 font-semibold">Time</th>
                        <th className="py-2.5 pr-4 font-semibold">Agent</th>
                        <th className="py-2.5 pr-4 font-semibold">Tool / Target</th>
                        <th className="py-2.5 pr-4 font-semibold">Rule</th>
                        <th className="py-2.5 pr-4 font-semibold">Verdict</th>
                        <th className="py-2.5 pr-4 font-semibold">Latency</th>
                        <th className="py-2.5 font-semibold">Detail</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/[0.06]">
                      {filteredEvents.map((ev) => {
                        const expanded = expandedEventId === ev.id;
                        return (
                          <React.Fragment key={ev.id}>
                            <tr
                              onClick={() =>
                                setExpandedEventId(expanded ? null : ev.id)
                              }
                              className="cursor-pointer hover:bg-white/[0.04]"
                            >
                              <td className="py-3 pr-2 text-slate-400">
                                {expanded ? (
                                  <ChevronDown className="h-3.5 w-3.5" />
                                ) : (
                                  <ChevronRight className="h-3.5 w-3.5" />
                                )}
                              </td>
                              <td className="py-3 pr-4 font-mono text-slate-400">
                                {ev.timestamp}
                              </td>
                              <td className="py-3 pr-4 font-medium text-slate-100">
                                {ev.agent}
                              </td>
                              <td className="py-3 pr-4 font-mono text-sky-300">
                                {ev.toolOrTarget}
                              </td>
                              <td className="py-3 pr-4 font-mono text-slate-300">
                                {ev.ruleId}
                              </td>
                              <td className="py-3 pr-4">
                                <StatusPill status={ev.status} />
                              </td>
                              <td className="py-3 pr-4 rh-tabular font-mono text-slate-400">
                                {ev.latencyMs.toFixed(2)} ms
                              </td>
                              <td className="py-3 text-slate-300">{ev.summary}</td>
                            </tr>
                            {expanded && (
                              <tr className="bg-slate-950/60">
                                <td colSpan={8} className="px-6 py-3">
                                  <div className="flex flex-wrap items-center justify-between gap-4 rounded-rh-sm border border-white/10 bg-slate-900/70 px-4 py-2.5 text-[11px]">
                                    <div className="flex flex-wrap items-center gap-4">
                                      <span className="text-slate-400">
                                        Severity:{" "}
                                        <strong className="uppercase text-slate-100">
                                          {ev.severity}
                                        </strong>
                                      </span>
                                      <span className="text-slate-400">
                                        Detector:{" "}
                                        <code className="font-mono text-sky-300">
                                          {ev.ruleId}
                                        </code>
                                      </span>
                                      <span className="text-slate-400">
                                        Environment:{" "}
                                        <strong className="text-slate-200">
                                          {node.environment}
                                        </strong>
                                      </span>
                                    </div>
                                    <span className="font-mono text-emerald-300">
                                      Evaluated at gateway boundary ({ev.latencyMs.toFixed(2)} ms)
                                    </span>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </GlassCard>
          </motion.div>
        )}

        {activeTab === "guardrails" && (
          <motion.div
            key="tab-guardrails"
            initial={reducedMotion ? false : { opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -6 }}
            transition={{ duration: MOTION_TIMING.fast, ease: EASE_OUT_EXPO }}
            className="grid grid-cols-1 gap-3 md:grid-cols-2"
          >
            {nodePolicies.map((pol, idx) => (
              <GlassCard
                key={pol.id}
                staggerIndex={idx}
                glow={pol.mode === "enforce" ? "subtle" : "flagged"}
                className="flex flex-col justify-between p-4"
              >
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-rose-300">
                      <ShieldCheck className="h-4 w-4 text-rose-400" />
                      <span>{pol.category}</span>
                    </div>
                    <StatusPill
                      status={
                        pol.mode === "enforce"
                          ? "allowed"
                          : pol.mode === "watch"
                            ? "flagged"
                            : "pending"
                      }
                      label={pol.mode}
                    />
                  </div>
                  <h3 className="mt-2.5 text-sm font-semibold text-white">{pol.name}</h3>
                  <p className="mt-1 text-xs leading-relaxed text-slate-400">
                    {pol.scopeSummary}
                  </p>
                </div>

                <div className="mt-4 flex items-center justify-between border-t border-white/[0.08] pt-3 text-xs">
                  <div className="flex items-center gap-3 text-slate-400">
                    <span className="rh-tabular font-mono">
                      <strong className="text-slate-100">{pol.triggered24h}</strong> hits
                    </span>
                    <span className="rh-tabular font-mono">
                      <strong className="text-rose-400">{pol.blocked24h}</strong> blocked
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => onTogglePolicyMode(pol.id)}
                    className="rounded-full border border-white/15 bg-white/[0.06] px-3 py-1 text-[11px] font-medium text-slate-200 transition-colors hover:border-white/30 hover:bg-white/[0.12] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70"
                  >
                    Switch mode
                  </button>
                </div>
              </GlassCard>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
