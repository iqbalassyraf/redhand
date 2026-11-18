"use client";

import React, { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AnimatePresence, LayoutGroup, MotionConfig, motion } from "framer-motion";
import { Plus, ShieldCheck, X } from "lucide-react";

import { CommandSearchModal } from "@/components/control-room/CommandSearchModal";
import { GlassCard } from "@/components/control-room/GlassCard";
import { IconRail } from "@/components/control-room/IconRail";
import { NodeDetailView } from "@/components/control-room/NodeDetailView";
import { RadialMap } from "@/components/control-room/RadialMap";
import { RightStatsPanel } from "@/components/control-room/RightStatsPanel";
import {
  ApprovalsView,
  AuditLogView,
  PoliciesView,
} from "@/components/control-room/SecondaryViews";
import { StatusPill } from "@/components/control-room/StatusPill";
import { TopBar } from "@/components/control-room/TopBar";
import { useAuth } from "@/lib/auth";
import {
  ALL_NODES,
  MOCK_APPROVALS,
  MOCK_AUDIT_LOG,
  MOCK_POLICIES,
  OVERVIEW_SNAPSHOTS,
  type ApprovalRequestItem,
  type ControlRoomView,
  type PolicyItem,
  type TimeRangeKey,
  type TopologyNode,
} from "@/lib/control-room-data";
import {
  EASE_OUT_EXPO,
  MOTION_TIMING,
  SPRING_SHARED_ELEMENT,
  usePrefersReducedMotion,
} from "@/lib/tokens";

type OverviewSubTab = "operational" | "topology" | "security";

const TIME_RANGE_MULTIPLIER: Record<TimeRangeKey, number> = {
  "1h": 0.06,
  "24h": 1,
  "7d": 6.4,
  "30d": 26,
};

export default function AgentControlRoomPage() {
  const { session } = useAuth();
  const reducedMotion = usePrefersReducedMotion();

  const [activeView, setActiveView] = useState<ControlRoomView>("overview");
  const [overviewTab, setOverviewTab] = useState<OverviewSubTab>("operational");
  const [timeRange, setTimeRange] = useState<TimeRangeKey>("24h");
  const [loadingRange, setLoadingRange] = useState<boolean>(false);

  const [nodes, setNodes] = useState<TopologyNode[]>(ALL_NODES);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);

  const [policies, setPolicies] = useState<PolicyItem[]>(MOCK_POLICIES);
  const [approvals, setApprovals] = useState<ApprovalRequestItem[]>(MOCK_APPROVALS);
  const [auditEntries, setAuditEntries] = useState(MOCK_AUDIT_LOG);

  const [searchOpen, setSearchOpen] = useState(false);
  const [newModalOpen, setNewModalOpen] = useState(false);
  const [threatPulseKey, setThreatPulseKey] = useState(0);
  const [extraBlockedCount, setExtraBlockedCount] = useState(0);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
  };

  useEffect(() => {
    if (!toastMessage) return undefined;
    const id = setTimeout(() => setToastMessage(null), 3200);
    return () => clearTimeout(id);
  }, [toastMessage]);

  const spokeNodes = useMemo(
    () => nodes.filter((n) => n.kind === "spoke"),
    [nodes]
  );
  const childNodes = useMemo(
    () => nodes.filter((n) => n.kind === "child"),
    [nodes]
  );

  // Global Cmd+K / Ctrl+K, Escape-to-overview, and rail 1-5 shortcuts
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearchOpen((prev) => !prev);
        return;
      }
      if (
        event.key === "Escape" &&
        !searchOpen &&
        !newModalOpen &&
        activeView === "node-detail"
      ) {
        setActiveView("overview");
        return;
      }
      const target = event.target as HTMLElement | null;
      const isEditable =
        target?.tagName === "INPUT" ||
        target?.tagName === "TEXTAREA" ||
        target?.tagName === "SELECT" ||
        target?.isContentEditable;
      if (
        isEditable ||
        searchOpen ||
        newModalOpen ||
        event.metaKey ||
        event.ctrlKey ||
        event.altKey
      ) {
        return;
      }
      if (event.key === "1") setActiveView("overview");
      else if (event.key === "2") {
        if (!selectedNodeId && spokeNodes[0]) setSelectedNodeId(spokeNodes[0].id);
        setActiveView("node-detail");
      } else if (event.key === "3") setActiveView("policies");
      else if (event.key === "4") setActiveView("approvals");
      else if (event.key === "5") setActiveView("audit-log");
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [searchOpen, newModalOpen, activeView, selectedNodeId, spokeNodes]);

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) ?? spokeNodes[0] ?? null,
    [nodes, selectedNodeId, spokeNodes]
  );

  const relatedNodes = useMemo(() => {
    if (!selectedNode) return [];
    return nodes.filter((n) => n.spokeId === selectedNode.spokeId);
  }, [nodes, selectedNode]);

  const baseSnapshot = OVERVIEW_SNAPSHOTS[timeRange];
  const snapshot = useMemo(() => {
    if (extraBlockedCount === 0) return baseSnapshot;
    return {
      ...baseSnapshot,
      hub: {
        ...baseSnapshot.hub,
        riskyActionsCount: baseSnapshot.hub.riskyActionsCount + extraBlockedCount,
        blockedThreatsCount: baseSnapshot.hub.blockedThreatsCount + extraBlockedCount,
      },
      summary: {
        ...baseSnapshot.summary,
        blocked: baseSnapshot.summary.blocked + extraBlockedCount,
      },
    };
  }, [baseSnapshot, extraBlockedCount]);

  const pendingApprovalsCount = useMemo(
    () => approvals.filter((a) => a.status === "pending").length,
    [approvals]
  );

  const userEmail = session?.email ?? "alice.chen@redhand.dev";
  const userInitials = useMemo(() => {
    const parts = userEmail.split("@")[0]?.split(/[._-]/).filter(Boolean) ?? ["RH"];
    return parts
      .slice(0, 2)
      .map((p) => p[0]?.toUpperCase() ?? "")
      .join("") || "RH";
  }, [userEmail]);

  const handleTimeRangeChange = (next: TimeRangeKey) => {
    if (next === timeRange) return;
    setLoadingRange(true);
    setTimeRange(next);
    setTimeout(() => setLoadingRange(false), reducedMotion ? 20 : 220);
  };

  const handleSelectNode = (node: TopologyNode) => {
    setSelectedNodeId(node.id);
    setActiveView("node-detail");
  };

  const handleSimulateThreat = () => {
    setThreatPulseKey((k) => k + 1);
    setExtraBlockedCount((c) => c + 1);
    setAuditEntries((prev) => [
      {
        id: `aud-sim-${Date.now()}`,
        at: new Date().toTimeString().slice(0, 8),
        actor: "AgentWall Gateway",
        actorKind: "gateway",
        action: "mcp.exfiltration_blocked",
        target: "unpinned-shell/run_cmd",
        category: "tools",
        verdict: "blocked",
        reason: "Simulated hex-escape shell payload stopped in 0.15 ms.",
      },
      ...prev,
    ]);
    showToast("Threat pulse detected on unpinned-shell MCP — blocked in 0.15 ms.");
  };

  const handleToggleProtection = (nodeId: string) => {
    setNodes((prev) =>
      prev.map((n) => {
        if (n.id !== nodeId) return n;
        const nextProtected = n.protection !== "protected";
        return {
          ...n,
          protection: nextProtected ? "protected" : "partial",
          protectedRatio: nextProtected ? 1 : 0.72,
          hasNewThreatPulse: false,
        };
      })
    );
    showToast("Updated RedHand guardrail posture for selected node.");
  };

  const handleTogglePolicyMode = (policyId: string) => {
    setPolicies((prev) =>
      prev.map((p) => {
        if (p.id !== policyId) return p;
        const nextMode =
          p.mode === "enforce" ? "watch" : p.mode === "watch" ? "off" : "enforce";
        const nextStatus =
          nextMode === "enforce"
            ? "allowed"
            : nextMode === "watch"
              ? "flagged"
              : "pending";
        return { ...p, mode: nextMode, status: nextStatus, updatedAt: "just now" };
      })
    );
  };

  const handleResolveApproval = (id: string, decision: "allowed" | "blocked") => {
    setApprovals((prev) =>
      prev.map((a) =>
        a.id === id
          ? {
              ...a,
              status: decision,
              signaturesHave:
                decision === "allowed" ? a.signaturesNeed : a.signaturesHave,
            }
          : a
      )
    );
    showToast(
      decision === "allowed"
        ? "Approval signature recorded."
        : "Action request denied and halted."
    );
  };

  const isDetailOverlay = activeView === "node-detail" && selectedNode !== null;

  return (
    <MotionConfig reducedMotion="user">
      <LayoutGroup>
        <div className="rh-control-room flex h-screen w-screen overflow-hidden p-3 gap-3 select-none">
          <a
            href="#control-room-main"
            className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-rose-600 focus:px-3.5 focus:py-2 focus:text-xs focus:font-semibold focus:text-white focus:shadow-lg"
          >
            Skip to main content
          </a>
          {/* Left Navigation Icon Rail */}
        <IconRail
          activeView={activeView}
          onSelectView={(view) => {
            if (view === "node-detail" && !selectedNodeId && spokeNodes[0]) {
              setSelectedNodeId(spokeNodes[0].id);
            }
            setActiveView(view);
          }}
          hasSelectedNode={Boolean(selectedNode)}
          pendingApprovalsCount={pendingApprovalsCount}
          userInitials={userInitials}
          userEmail={userEmail}
        />

        {/* Main Right Workspace Column */}
        <div className="flex min-w-0 flex-1 flex-col gap-3 overflow-hidden">
          <div
            role="status"
            className="rounded-rh-md border border-amber-400/30 bg-amber-500/10 px-3 py-1.5 text-center text-[11px] font-medium text-amber-200"
          >
            Demo data: this Control Room shows sample figures, not your live organization. Use{" "}
            <Link href="/passports" className="underline">Passports</Link> for real control actions.
          </div>
          <TopBar
            activeView={activeView}
            selectedNode={isDetailOverlay ? selectedNode : null}
            timeRange={timeRange}
            onChangeTimeRange={handleTimeRangeChange}
            onNavigateOverview={() => setActiveView("overview")}
            onSelectView={(v) => setActiveView(v)}
            onOpenSearch={() => setSearchOpen(true)}
            onSimulateThreat={handleSimulateThreat}
            onOpenNewModal={() => setNewModalOpen(true)}
            pendingApprovalsCount={pendingApprovalsCount}
            userInitials={userInitials}
          />

          {/* Main Stage Container */}
          <main id="control-room-main" className="relative flex min-h-0 flex-1 overflow-hidden">
            {/* Keep RadialMap + RightStatsPanel rendered for overview and faded/blurred backdrop under node-detail */}
            {(activeView === "overview" || isDetailOverlay) && (
              <motion.div
                aria-hidden={isDetailOverlay}
                animate={{
                  opacity: isDetailOverlay ? 0.18 : 1,
                  scale: isDetailOverlay && !reducedMotion ? 0.95 : 1,
                }}
                transition={{ duration: 0.28, ease: EASE_OUT_EXPO }}
                style={{
                  filter: isDetailOverlay ? "blur(10px)" : "blur(0px)",
                }}
                className={[
                  "rh-scrollbar flex h-full w-full flex-col gap-3 lg:flex-row overflow-y-auto lg:overflow-hidden",
                  isDetailOverlay ? "pointer-events-none" : "",
                ].join(" ")}
              >
                {/* Center Map Column */}
                <div className="flex min-w-0 flex-1 flex-col gap-3 min-h-[480px] lg:min-h-0 lg:overflow-hidden">
                  {/* Top Sub-Mode Tabs Bar (Image 2 style: Operational / Security / Topology) */}
                  <div className="flex flex-wrap items-center justify-between gap-2 px-1">
                    <div>
                      <h1 className="text-lg font-semibold tracking-tight text-white">
                        Agent Control Room
                      </h1>
                      <p className="text-[11px] text-slate-400">
                        Unified posture across AI agents, MCP tools, data vaults, human approvers, and models
                      </p>
                    </div>

                    <div
                      role="tablist"
                      aria-label="Control Room Focus"
                      className="flex items-center rounded-full border border-white/[0.09] bg-slate-950/75 p-1"
                    >
                      {(
                        [
                          { id: "operational", label: "Operational" },
                          { id: "topology", label: "Topology Map" },
                          { id: "security", label: "Security Alerts" },
                        ] as const
                      ).map((tab) => {
                        const active = overviewTab === tab.id;
                        return (
                          <button
                            key={tab.id}
                            role="tab"
                            type="button"
                            aria-selected={active}
                            onClick={() => {
                              setOverviewTab(tab.id);
                              if (tab.id === "security") {
                                setSelectedSeverity("critical");
                              } else {
                                setSelectedSeverity(null);
                              }
                            }}
                            className={[
                              "relative rounded-full px-3 py-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70",
                              active
                                ? "text-white"
                                : "text-slate-400 hover:text-slate-200",
                            ].join(" ")}
                          >
                            {active && (
                              <motion.span
                                layoutId="rh-overview-tab-pill"
                                transition={
                                  reducedMotion
                                    ? { duration: 0.01 }
                                    : SPRING_SHARED_ELEMENT
                                }
                                className="absolute inset-0 rounded-full bg-white/[0.12] border border-white/15"
                              />
                            )}
                            <span className="relative z-10">{tab.label}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Interactive Radial Hub-and-Spoke Map */}
                  <div className="min-h-0 flex-1">
                    <RadialMap
                      spokes={spokeNodes}
                      childNodes={childNodes}
                      hubStats={snapshot.hub}
                      selectedNodeId={isDetailOverlay ? selectedNode?.id ?? null : null}
                      highlightedSeverity={selectedSeverity}
                      threatPulseKey={threatPulseKey}
                      onSelectNode={handleSelectNode}
                      isDetailOpen={isDetailOverlay}
                    />
                  </div>
                </div>

                {/* Right Telemetry Stats Panel */}
                <RightStatsPanel
                  snapshot={snapshot}
                  selectedSeverity={selectedSeverity}
                  onSelectSeverity={setSelectedSeverity}
                  selectedCategory={selectedCategory}
                  onSelectCategory={setSelectedCategory}
                  loading={loadingRange}
                />
              </motion.div>
            )}

            {/* Shared-Element Node Detail Screen Overlay */}
            <AnimatePresence mode="wait">
              {isDetailOverlay && selectedNode && (
                <div
                  key={`detail-${selectedNode.id}`}
                  className="absolute inset-0 z-30 flex overflow-hidden rounded-rh-xl bg-slate-950/55 p-1 backdrop-blur-sm"
                >
                  <NodeDetailView
                    node={selectedNode}
                    relatedNodes={relatedNodes}
                    timeRangeLabel={baseSnapshot.label}
                    timeRangeMultiplier={TIME_RANGE_MULTIPLIER[timeRange]}
                    loading={loadingRange}
                    policies={policies}
                    onBack={() => setActiveView("overview")}
                    onSelectNode={handleSelectNode}
                    onToggleProtection={handleToggleProtection}
                    onTogglePolicyMode={handleTogglePolicyMode}
                  />
                </div>
              )}

              {activeView === "policies" && (
                <PoliciesView
                  key="view-policies"
                  policies={policies}
                  onTogglePolicyMode={handleTogglePolicyMode}
                />
              )}

              {activeView === "approvals" && (
                <ApprovalsView
                  key="view-approvals"
                  approvals={approvals}
                  onResolveApproval={handleResolveApproval}
                />
              )}

              {activeView === "audit-log" && (
                <AuditLogView key="view-audit-log" entries={auditEntries} />
              )}
            </AnimatePresence>
          </main>
        </div>

        {/* Command Search Palette (Cmd+K) */}
        <CommandSearchModal
          open={searchOpen}
          onClose={() => setSearchOpen(false)}
          nodes={nodes}
          policies={policies}
          onSelectNode={handleSelectNode}
          onSelectView={(view) => setActiveView(view)}
        />

        {/* Quick "+ New" Action Modal */}
        <AnimatePresence>
          {newModalOpen && (
            <motion.div
              role="dialog"
              aria-modal="true"
              aria-label="Quick Control Action"
              initial={reducedMotion ? false : { opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: MOTION_TIMING.fast }}
              onClick={() => setNewModalOpen(false)}
              className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 px-4 backdrop-blur-sm"
            >
              <motion.div
                initial={reducedMotion ? false : { opacity: 0, scale: 0.96, y: 8 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.96 }}
                transition={{ duration: MOTION_TIMING.fast, ease: EASE_OUT_EXPO }}
                onClick={(e) => e.stopPropagation()}
                className="w-full max-w-md"
              >
                <GlassCard glow="crimson" className="p-5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-sm font-semibold text-white">
                      <Plus className="h-4 w-4 text-rose-400" />
                      <span>Register Control Resource</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => setNewModalOpen(false)}
                      aria-label="Close modal"
                      className="rounded-lg p-1 text-slate-400 hover:bg-white/10 hover:text-white"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>

                  <p className="mt-2 text-xs leading-relaxed text-slate-400">
                    The Control Room runs with realistic mock telemetry while you evaluate the redesign. Jump directly to live operational consoles or simulate an event:
                  </p>

                  <div className="mt-4 flex flex-col gap-2">
                    <Link
                      href="/passports"
                      className="flex items-center justify-between rounded-rh-md border border-white/10 bg-slate-900/60 px-3.5 py-2.5 text-xs font-medium text-slate-100 hover:border-rose-400/40 hover:bg-rose-500/10"
                    >
                      <span>Register real Agent Passport or SDK Key</span>
                      <span className="text-rose-300">/passports →</span>
                    </Link>
                    <Link
                      href="/radar"
                      className="flex items-center justify-between rounded-rh-md border border-white/10 bg-slate-900/60 px-3.5 py-2.5 text-xs font-medium text-slate-100 hover:border-rose-400/40 hover:bg-rose-500/10"
                    >
                      <span>Configure Threat Radar & Approved Models</span>
                      <span className="text-rose-300">/radar →</span>
                    </Link>
                    <button
                      type="button"
                      onClick={() => {
                        setNewModalOpen(false);
                        handleSimulateThreat();
                      }}
                      className="flex items-center justify-between rounded-rh-md border border-rose-500/35 bg-rose-500/15 px-3.5 py-2.5 text-xs font-semibold text-rose-100 hover:bg-rose-500/25"
                    >
                      <span className="flex items-center gap-2">
                        <ShieldCheck className="h-4 w-4 text-rose-300" />
                        Trigger simulated threat pulse on map
                      </span>
                      <span>Run</span>
                    </button>
                  </div>
                </GlassCard>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Live Action Toast */}
        <AnimatePresence>
          {toastMessage && (
            <motion.div
              role="status"
              initial={reducedMotion ? false : { opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 10 }}
              transition={{ duration: MOTION_TIMING.fast, ease: EASE_OUT_EXPO }}
              className="fixed bottom-5 right-5 z-50 flex items-center gap-2.5 rounded-full border border-rose-400/35 bg-slate-950/95 px-4 py-2 text-xs font-medium text-slate-100 shadow-rh-crimson backdrop-blur-xl"
            >
              <StatusPill status="blocked" label="Alert" pulse />
              <span>{toastMessage}</span>
            </motion.div>
          )}
        </AnimatePresence>
        </div>
      </LayoutGroup>
    </MotionConfig>
  );
}
