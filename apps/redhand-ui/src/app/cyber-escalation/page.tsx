"use client";

import React from "react";
import { Cpu, GitBranch, ShieldAlert, Zap } from "lucide-react";

import { EnterprisePreviewGate } from "@/components/control-room/EnterprisePreviewGate";
import { AppShell } from "@/components/shell/AppShell";
import { useRequiredSession } from "@/lib/auth";

const GHOST_ESCALATION_RULES = [
  {
    name: "Multi-Turn Exfiltration Escalation",
    trigger: "Local ONNX Score 0.55–0.84 OR Cross-Tool Data Taint",
    model: "BYOK: Claude 3.7 Security / Sec-PaLM",
    action: "Mid-Loop Sub-Agent Quarantine + Alert",
    latency: "Async (0ms hot-path)",
  },
  {
    name: "Recursive Sub-Agent Delegation Breaker",
    trigger: "Depth > 3 OR Unapproved Delegation Target",
    model: "Deterministic + Async Cyber-Model Review",
    action: "Freeze Child Passport + Escalate to HITL",
    latency: "<2ms Trigger / Async Audit",
  },
  {
    name: "Obfuscated Payload Deep Inspection",
    trigger: "Nested Encoding / Homoglyph Drift > 20%",
    model: "Managed RedHand Cyber-Model Endpoint",
    action: "Safe Mode (Read-Only) + Black Box Capture",
    latency: "Async (0ms hot-path)",
  },
] as const;

export default function CyberEscalationPage() {
  useRequiredSession();

  return (
    <AppShell title="Cyber-Model Escalation">
      <EnterprisePreviewGate
        badge="PREVIEW"
        title="Async Deep Cyber-Model Escalation & Circuit-Breaker"
        subtitle="Route ambiguous multi-turn agent traces to BYOK or managed frontier security models asynchronously—with zero hot-path latency penalty and automated mid-loop sub-agent quarantine."
        specBadge="0ms Hot-Path Overhead · BYOK / Managed"
        interestId="cyber-escalation"
        valuePoints={[
          "Keeps your <2ms Pre-Flight and <15ms Local ONNX gateway untouched—deep cyber-models run off the synchronous call path.",
          "Supports Bring-Your-Own-Key (BYOK) frontier endpoints or RedHand-managed cyber-security models inside your VPC.",
          "Automated Sub-Agent Circuit-Breaker freezes compromised child agents mid-loop before multi-step exfiltration completes.",
        ]}
      >
        <div className="flex flex-col gap-4">
          {/* Ghost 3-Stage Escalation Pipeline */}
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <div className="rh-glass rounded-rh-lg border border-rh-teal-border p-4">
              <div className="flex items-center justify-between text-xs text-rh-teal-text">
                <span className="font-semibold">Stage 1 · Inline Core</span>
                <Zap className="h-4 w-4" />
              </div>
              <div className="mt-1.5 font-mono text-lg font-bold text-rh-text">&lt;2ms Pre-Flight</div>
              <p className="mt-1 text-[11px] text-rh-text-2">
                Regex, JSON Schema, AST &amp; EN/SEA/Malay heuristics
              </p>
            </div>

            <div className="rh-glass rounded-rh-lg border border-rh-steel-border p-4">
              <div className="flex items-center justify-between text-xs text-rh-steel-text">
                <span className="font-semibold">Stage 2 · Local Semantic</span>
                <Cpu className="h-4 w-4" />
              </div>
              <div className="mt-1.5 font-mono text-lg font-bold text-rh-text">&lt;15ms ONNX / DeBERTa</div>
              <p className="mt-1 text-[11px] text-rh-text-2">
                Quantized local classifier · 0 external API calls
              </p>
            </div>

            <div className="rh-glass rounded-rh-lg border border-rh-ochre-border bg-rh-ochre-wash/30 p-4">
              <div className="flex items-center justify-between text-xs text-rh-ochre">
                <span className="font-semibold">Stage 3 · 10x Enterprise</span>
                <ShieldAlert className="h-4 w-4" />
              </div>
              <div className="mt-1.5 font-mono text-lg font-bold text-rh-ochre">Async Cyber-Model</div>
              <p className="mt-1 text-[11px] text-rh-text-2">
                BYOK deep trace review + mid-loop quarantine
              </p>
            </div>
          </div>

          {/* Ghost Escalation Rules Table */}
          <div className="rh-glass overflow-hidden rounded-rh-xl border border-control-border">
            <div className="flex items-center justify-between border-b border-control-border px-4 py-3">
              <div className="flex items-center gap-2">
                <GitBranch className="h-4 w-4 text-rh-ochre" />
                <span className="text-xs font-semibold text-rh-text">
                  Escalation &amp; Circuit-Breaker Policies
                </span>
              </div>
              <span className="rounded-full border border-control-border bg-rh-subtle px-2.5 py-0.5 font-mono text-[10px] text-rh-text-2">
                PREVIEW RULE BUILDER
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-control-border bg-rh-subtle text-[11px] uppercase tracking-wider text-rh-text-2">
                  <tr>
                    <th className="px-4 py-2.5">Policy Rule</th>
                    <th className="px-4 py-2.5">Escalation Trigger</th>
                    <th className="px-4 py-2.5">Target Cyber-Model</th>
                    <th className="px-4 py-2.5">Automated Circuit-Breaker</th>
                    <th className="px-4 py-2.5">Hot-Path Impact</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-control-border">
                  {GHOST_ESCALATION_RULES.map((rule) => (
                    <tr key={rule.name} className="text-rh-text-2">
                      <td className="px-4 py-3 font-semibold text-rh-text">{rule.name}</td>
                      <td className="px-4 py-3 font-mono text-[11px]">{rule.trigger}</td>
                      <td className="px-4 py-3">{rule.model}</td>
                      <td className="px-4 py-3 text-rh-crimson-text">{rule.action}</td>
                      <td className="px-4 py-3 font-mono text-rh-teal-text">{rule.latency}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </EnterprisePreviewGate>
    </AppShell>
  );
}
