"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Activity,
  FileClock,
  GitFork,
  Search,
  ShieldCheck,
  UserCheck,
  X,
} from "lucide-react";
import type {
  ControlRoomView,
  PolicyItem,
  TopologyNode,
} from "@/lib/control-room-data";
import { EASE_OUT_EXPO, MOTION_TIMING, usePrefersReducedMotion } from "@/lib/tokens";
import { StatusPill } from "./StatusPill";

export interface CommandSearchModalProps {
  open: boolean;
  onClose: () => void;
  nodes: TopologyNode[];
  policies: PolicyItem[];
  onSelectNode: (node: TopologyNode) => void;
  onSelectView: (view: ControlRoomView) => void;
}

type SearchResultItem =
  | { kind: "view"; id: ControlRoomView; title: string; subtitle: string }
  | { kind: "node"; node: TopologyNode }
  | { kind: "policy"; policy: PolicyItem };

/**
 * Spotlight command palette triggered via Cmd+K / Ctrl+K or TopBar search pill.
 */
export function CommandSearchModal({
  open,
  onClose,
  nodes,
  policies,
  onSelectNode,
  onSelectView,
}: CommandSearchModalProps) {
  const reducedMotion = usePrefersReducedMotion();
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!open) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActiveIndex(0);
      const id = setTimeout(() => inputRef.current?.focus(), 20);
      return () => clearTimeout(id);
    }
    return undefined;
  }, [open]);

  const results = useMemo<SearchResultItem[]>(() => {
    const q = query.trim().toLowerCase();
    const views: SearchResultItem[] = [
      { kind: "view", id: "overview", title: "Overview Topology Map", subtitle: "Agents under control radial view" },
      { kind: "view", id: "policies", title: "Guardrail Policies", subtitle: "AST SQL, tool pinning & model allowlist" },
      { kind: "view", id: "approvals", title: "Human Approvals Queue", subtitle: "Dual-control HITL signoff requests" },
      { kind: "view", id: "audit-log", title: "Security Audit Log", subtitle: "Immutable control & gateway decisions" },
    ];

    const matchingViews = views.filter(
      (v) =>
        v.kind === "view" &&
        (!q || v.title.toLowerCase().includes(q) || v.subtitle.toLowerCase().includes(q))
    );

    const matchingNodes: SearchResultItem[] = nodes
      .filter(
        (n) =>
          !q ||
          n.name.toLowerCase().includes(q) ||
          n.subtitle.toLowerCase().includes(q) ||
          n.spokeId.toLowerCase().includes(q)
      )
      .slice(0, 8)
      .map((node) => ({ kind: "node", node }));

    const matchingPolicies: SearchResultItem[] = policies
      .filter(
        (p) =>
          !q ||
          p.name.toLowerCase().includes(q) ||
          p.scopeSummary.toLowerCase().includes(q)
      )
      .slice(0, 4)
      .map((policy) => ({ kind: "policy", policy }));

    return [...matchingNodes, ...matchingPolicies, ...matchingViews];
  }, [query, nodes, policies]);

  const handleActivate = (item: SearchResultItem) => {
    if (item.kind === "node") {
      onSelectNode(item.node);
    } else if (item.kind === "policy") {
      onSelectView("policies");
    } else {
      onSelectView(item.id);
    }
    onClose();
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          role="dialog"
          aria-modal="true"
          aria-label="Search RedHand Control Room"
          initial={reducedMotion ? false : { opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: MOTION_TIMING.fast }}
          onClick={onClose}
          className="fixed inset-0 z-50 flex items-start justify-center bg-slate-950/70 pt-20 px-4 backdrop-blur-sm"
        >
          <motion.div
            initial={reducedMotion ? false : { opacity: 0, y: -12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -8, scale: 0.98 }}
            transition={{ duration: MOTION_TIMING.fast, ease: EASE_OUT_EXPO }}
            onClick={(e) => e.stopPropagation()}
            className="rh-glass w-full max-w-xl overflow-hidden rounded-rh-xl border border-white/15 bg-slate-950/95 shadow-2xl"
          >
            {/* Input Header */}
            <div className="flex items-center gap-3 border-b border-white/10 px-4 py-3">
              <Search className="h-4 w-4 text-rose-400 shrink-0" />
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setActiveIndex(0);
                }}
                onKeyDown={(e) => {
                  if (e.key === "ArrowDown") {
                    e.preventDefault();
                    setActiveIndex((i) => Math.min(results.length - 1, i + 1));
                  } else if (e.key === "ArrowUp") {
                    e.preventDefault();
                    setActiveIndex((i) => Math.max(0, i - 1));
                  } else if (e.key === "Enter" && results[activeIndex]) {
                    e.preventDefault();
                    handleActivate(results[activeIndex]);
                  }
                }}
                placeholder="Jump to spoke, agent, MCP tool, model or screen..."
                className="flex-1 bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={onClose}
                aria-label="Close search"
                className="rounded-lg p-1 text-slate-400 hover:bg-white/10 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Results */}
            <div className="rh-scrollbar max-h-80 overflow-y-auto p-2">
              {results.length === 0 ? (
                <div className="px-4 py-8 text-center text-xs text-slate-400">
                  No matching agents, tools, or policies for &ldquo;{query}&rdquo;.
                </div>
              ) : (
                results.map((item, idx) => {
                  const isActive = idx === activeIndex;
                  const key =
                    item.kind === "node"
                      ? `n-${item.node.id}`
                      : item.kind === "policy"
                        ? `p-${item.policy.id}`
                        : `v-${item.id}`;

                  return (
                    <button
                      key={key}
                      type="button"
                      onClick={() => handleActivate(item)}
                      onMouseEnter={() => setActiveIndex(idx)}
                      className={[
                        "flex w-full items-center justify-between gap-3 rounded-rh-md px-3 py-2.5 text-left transition-colors",
                        isActive
                          ? "bg-rose-500/15 text-white border border-rose-400/30"
                          : "border border-transparent text-slate-300 hover:bg-white/[0.05]",
                      ].join(" ")}
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        {item.kind === "node" && (
                          <GitFork className="h-4 w-4 text-emerald-400 shrink-0" />
                        )}
                        {item.kind === "policy" && (
                          <ShieldCheck className="h-4 w-4 text-rose-400 shrink-0" />
                        )}
                        {item.kind === "view" && (
                          item.id === "approvals" ? (
                            <UserCheck className="h-4 w-4 text-amber-400 shrink-0" />
                          ) : item.id === "audit-log" ? (
                            <FileClock className="h-4 w-4 text-sky-400 shrink-0" />
                          ) : (
                            <Activity className="h-4 w-4 text-rose-400 shrink-0" />
                          )
                        )}
                        <div className="min-w-0">
                          <div className="truncate text-xs font-semibold text-slate-100">
                            {item.kind === "node"
                              ? item.node.name
                              : item.kind === "policy"
                                ? item.policy.name
                                : item.title}
                          </div>
                          <div className="truncate text-[11px] text-slate-400">
                            {item.kind === "node"
                              ? `${item.node.kind.toUpperCase()} • ${item.node.subtitle}`
                              : item.kind === "policy"
                                ? item.policy.scopeSummary
                                : item.subtitle}
                          </div>
                        </div>
                      </div>
                      {item.kind === "node" && (
                        <StatusPill status={item.node.protection} />
                      )}
                      {item.kind === "policy" && (
                        <StatusPill status={item.policy.status} label={item.policy.mode} />
                      )}
                    </button>
                  );
                })
              )}
            </div>

            <div className="flex items-center justify-between border-t border-white/10 bg-slate-950/80 px-4 py-2 text-[11px] text-slate-500">
              <span>Use ↑ ↓ to navigate, ↵ to inspect funnel</span>
              <span>ESC to close</span>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
