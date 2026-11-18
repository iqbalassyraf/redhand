"use client";

import React, { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Check, FileClock, Search, ShieldCheck, UserCheck, X } from "lucide-react";
import type {
  ApprovalRequestItem,
  AuditLogEntry,
  PolicyItem,
} from "@/lib/control-room-data";
import {
  EASE_OUT_EXPO,
  SPRING_SHARED_ELEMENT,
  usePrefersReducedMotion,
} from "@/lib/tokens";
import { GlassCard } from "./GlassCard";
import { KpiTile } from "./KpiTile";
import { StatusPill } from "./StatusPill";

function FilterPillBar({
  layoutId,
  options,
  value,
  onChange,
  label,
}: {
  layoutId: string;
  options: ReadonlyArray<{ id: string; text: string }>;
  value: string;
  onChange: (next: string) => void;
  label: string;
}) {
  const reducedMotion = usePrefersReducedMotion();

  return (
    <div
      role="group"
      aria-label={label}
      className="flex flex-wrap items-center gap-1 rounded-full border border-white/10 bg-slate-950/70 p-1"
    >
      {options.map((opt) => {
        const active = value === opt.id;
        return (
          <button
            key={opt.id}
            type="button"
            aria-pressed={active}
            onClick={() => onChange(opt.id)}
            className={[
              "relative rounded-full px-3 py-1 text-[11px] font-medium capitalize transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500/70",
              active ? "text-white" : "text-slate-400 hover:text-slate-200",
            ].join(" ")}
          >
            {active && (
              <motion.span
                layoutId={layoutId}
                transition={reducedMotion ? { duration: 0.01 } : SPRING_SHARED_ELEMENT}
                className="absolute inset-0 rounded-full bg-white/15 border border-white/15"
              />
            )}
            <span className="relative z-10">{opt.text}</span>
          </button>
        );
      })}
    </div>
  );
}

const POLICY_CATEGORY_OPTIONS = [
  { id: "all", text: "All spokes" },
  { id: "agents", text: "Agents" },
  { id: "tools", text: "Tools/MCP" },
  { id: "data", text: "Data" },
  { id: "humans", text: "Humans" },
  { id: "models", text: "Models" },
] as const;

export function PoliciesView({
  policies,
  onTogglePolicyMode,
}: {
  policies: PolicyItem[];
  onTogglePolicyMode: (policyId: string) => void;
}) {
  const reducedMotion = usePrefersReducedMotion();
  const [categoryFilter, setCategoryFilter] = useState<string>("all");

  const enforced = policies.filter((p) => p.mode === "enforce").length;
  const totalTriggered = policies.reduce((acc, p) => acc + p.triggered24h, 0);
  const totalBlocked = policies.reduce((acc, p) => acc + p.blocked24h, 0);

  const visiblePolicies = useMemo(
    () =>
      policies.filter(
        (p) => categoryFilter === "all" || p.category === categoryFilter
      ),
    [policies, categoryFilter]
  );

  return (
    <motion.div
      initial={reducedMotion ? false : { opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -8 }}
      transition={{ duration: 0.24, ease: EASE_OUT_EXPO }}
      className="rh-scrollbar flex h-full w-full flex-col gap-4 overflow-y-auto pr-1"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            Guardrail Policies
          </h1>
          <p className="mt-0.5 text-xs text-slate-400">
            Active AgentWall AST, destination, and approved-model rules enforcing across spokes
          </p>
        </div>

        <FilterPillBar
          layoutId="rh-policy-cat-pill"
          label="Filter policies by spoke category"
          options={POLICY_CATEGORY_OPTIONS}
          value={categoryFilter}
          onChange={setCategoryFilter}
        />
      </div>

      {/* Policy Summary KPI Row */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiTile label="Active Policies" value={policies.length} status="allowed" />
        <KpiTile label="Enforcing Mode" value={enforced} status="allowed" />
        <KpiTile label="Triggered (24h)" value={totalTriggered} status="flagged" />
        <KpiTile label="Blocked (24h)" value={totalBlocked} status="blocked" />
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {visiblePolicies.map((pol, idx) => (
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
              <h2 className="mt-2.5 text-sm font-semibold text-white">{pol.name}</h2>
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
      </div>
    </motion.div>
  );
}

const APPROVAL_STATUS_OPTIONS = [
  { id: "all", text: "All" },
  { id: "pending", text: "Pending" },
  { id: "allowed", text: "Approved" },
  { id: "blocked", text: "Denied" },
] as const;

export function ApprovalsView({
  approvals,
  onResolveApproval,
}: {
  approvals: ApprovalRequestItem[];
  onResolveApproval: (id: string, decision: "allowed" | "blocked") => void;
}) {
  const reducedMotion = usePrefersReducedMotion();
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const pendingCount = approvals.filter((a) => a.status === "pending").length;
  const visibleApprovals = useMemo(
    () =>
      approvals.filter(
        (a) => statusFilter === "all" || a.status === statusFilter
      ),
    [approvals, statusFilter]
  );

  return (
    <motion.div
      initial={reducedMotion ? false : { opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -8 }}
      transition={{ duration: 0.24, ease: EASE_OUT_EXPO }}
      className="rh-scrollbar flex h-full w-full flex-col gap-4 overflow-y-auto pr-1"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            Human-in-the-Loop Approvals
          </h1>
          <p className="mt-0.5 text-xs text-slate-400">
            Dual-control review queue for destructive tool calls and SDK passport promotions
          </p>
        </div>
        <div className="grid grid-cols-2 gap-2.5 w-64">
          <KpiTile label="Pending" value={pendingCount} status="pending" />
          <KpiTile
            label="Resolved"
            value={approvals.length - pendingCount}
            status="allowed"
          />
        </div>
      </div>

      <div className="flex items-center justify-between">
        <FilterPillBar
          layoutId="rh-approval-filter-pill"
          label="Filter approvals by status"
          options={APPROVAL_STATUS_OPTIONS}
          value={statusFilter}
          onChange={setStatusFilter}
        />
      </div>

      <div className="flex flex-col gap-3">
        {visibleApprovals.length === 0 ? (
          <GlassCard className="p-8 text-center text-xs text-slate-400">
            No approval requests matching filter &ldquo;{statusFilter}&rdquo;.
          </GlassCard>
        ) : (
          visibleApprovals.map((item, idx) => (
            <GlassCard
              key={item.id}
              staggerIndex={idx}
              glow={
                item.status === "pending"
                  ? "flagged"
                  : item.status === "allowed"
                    ? "allowed"
                    : "blocked"
              }
              className="flex flex-wrap items-center justify-between gap-4 p-4"
            >
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <UserCheck className="h-4 w-4 text-amber-400" />
                  <span className="text-sm font-semibold text-white">
                    {item.agentName}
                  </span>
                  <span className="rounded bg-white/[0.06] px-2 py-0.5 font-mono text-[11px] text-sky-300">
                    {item.toolName}
                  </span>
                  <StatusPill status={item.status} />
                  <StatusPill status={item.severity} />
                </div>
                <p className="mt-1.5 text-xs text-slate-300">{item.justification}</p>
                <div className="mt-2 flex flex-wrap items-center gap-3 text-[11px] text-slate-400">
                  <span className="font-mono">{item.targetResource}</span>
                  <span>•</span>
                  <span>
                    Signatures:{" "}
                    <strong className="text-slate-200">
                      {item.signaturesHave}/{item.signaturesNeed}
                    </strong>
                  </span>
                  <span>•</span>
                  <span>Expires in {item.expiresIn}</span>
                </div>
              </div>

              {item.status === "pending" && (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => onResolveApproval(item.id, "blocked")}
                    className="inline-flex h-8 items-center gap-1 rounded-full border border-red-400/35 bg-red-500/15 px-3 text-xs font-semibold text-red-200 transition-colors hover:bg-red-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400"
                  >
                    <X className="h-3.5 w-3.5" />
                    <span>Deny</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => onResolveApproval(item.id, "allowed")}
                    className="inline-flex h-8 items-center gap-1 rounded-full border border-emerald-400/35 bg-emerald-500/20 px-3 text-xs font-semibold text-emerald-200 transition-colors hover:bg-emerald-500/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
                  >
                    <Check className="h-3.5 w-3.5" />
                    <span>Sign & Approve</span>
                  </button>
                </div>
              )}
            </GlassCard>
          ))
        )}
      </div>
    </motion.div>
  );
}

const AUDIT_VERDICT_OPTIONS = [
  { id: "all", text: "all" },
  { id: "allowed", text: "allowed" },
  { id: "flagged", text: "flagged" },
  { id: "blocked", text: "blocked" },
  { id: "pending", text: "pending" },
] as const;

export function AuditLogView({ entries }: { entries: AuditLogEntry[] }) {
  const reducedMotion = usePrefersReducedMotion();
  const [filter, setFilter] = useState<string>("all");
  const [query, setQuery] = useState<string>("");

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return entries.filter((e) => {
      if (filter !== "all" && e.verdict !== filter) return false;
      if (!q) return true;
      return `${e.actor} ${e.action} ${e.target} ${e.reason}`
        .toLowerCase()
        .includes(q);
    });
  }, [entries, filter, query]);

  return (
    <motion.div
      initial={reducedMotion ? false : { opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -8 }}
      transition={{ duration: 0.24, ease: EASE_OUT_EXPO }}
      className="rh-scrollbar flex h-full w-full flex-col gap-4 overflow-y-auto pr-1"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight text-white">
            <FileClock className="h-5 w-5 text-rose-400" />
            <span>Control Audit Log</span>
          </h1>
          <p className="mt-0.5 text-xs text-slate-400">
            Cryptographic trail of gateway refusals, Risk Engine freezes, and operator actions
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative flex items-center">
            <Search className="pointer-events-none absolute left-3 h-3.5 w-3.5 text-slate-400" />
            <input
              type="search"
              aria-label="Filter audit log entries"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter actor, event, target..."
              className="h-8 w-56 rounded-full border border-white/10 bg-slate-950/70 pl-8 pr-3 text-xs text-slate-100 placeholder-slate-500 focus:border-rose-400/50 focus:outline-none focus:ring-1 focus:ring-rose-500/40"
            />
          </div>

          <FilterPillBar
            layoutId="rh-audit-filter-pill"
            label="Filter audit entries by verdict"
            options={AUDIT_VERDICT_OPTIONS}
            value={filter}
            onChange={setFilter}
          />
        </div>
      </div>

      <GlassCard staggerIndex={0} className="p-4">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-[11px] uppercase tracking-wider text-slate-400">
                <th className="py-2.5 pr-4 font-semibold">Timestamp</th>
                <th className="py-2.5 pr-4 font-semibold">Actor</th>
                <th className="py-2.5 pr-4 font-semibold">Event</th>
                <th className="py-2.5 pr-4 font-semibold">Target</th>
                <th className="py-2.5 pr-4 font-semibold">Status</th>
                <th className="py-2.5 font-semibold">Reason</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {visible.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400">
                    No matching audit events found.
                  </td>
                </tr>
              ) : (
                visible.map((row) => (
                  <tr key={row.id} className="hover:bg-white/[0.03]">
                    <td className="py-3 pr-4 font-mono text-slate-400">{row.at}</td>
                    <td className="py-3 pr-4 font-medium text-slate-200">{row.actor}</td>
                    <td className="py-3 pr-4 font-mono text-sky-300">{row.action}</td>
                    <td className="py-3 pr-4 font-medium text-white">{row.target}</td>
                    <td className="py-3 pr-4">
                      <StatusPill status={row.verdict} />
                    </td>
                    <td className="py-3 text-slate-300">{row.reason}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </GlassCard>
    </motion.div>
  );
}
