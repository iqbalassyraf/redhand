"use client";

import React, { useState } from "react";
import { ShieldAlert, ShieldCheck, Hand, KeyRound } from "lucide-react";
import type { AgentPostureItem, TraceTelemetryRow } from "@/lib/types";

interface FlightRecorderDockProps {
  traces: TraceTelemetryRow[];
  agents: AgentPostureItem[];
  selectedTraceId: string | null;
  onSelectTrace: (trace: TraceTelemetryRow) => void;
  onSimulateAttack: (
    scenario: "benign_read" | "prompt_injection" | "destructive_hitl"
  ) => void;
}

export function FlightRecorderDock({
  traces,
  agents,
  selectedTraceId,
  onSelectTrace,
  onSimulateAttack,
}: FlightRecorderDockProps) {
  const [activeTab, setActiveTab] = useState<"traces" | "agents" | "tokens">(
    "traces"
  );

  return (
    <section className="flex h-64 shrink-0 flex-col border-t border-[#E5E5E5] bg-[#FFFFFF]">
      {/* Chip Bar + Simulation Buttons (Red Broadcast 9999px Pills) */}
      <div className="flex items-center justify-between border-b border-[#E5E5E5] px-4 py-2.5">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab("traces")}
            className={`rounded-full px-3 py-1.5 text-[14px] leading-[20px] font-medium transition-colors ${
              activeTab === "traces"
                ? "bg-[#0F0F0F] text-[#FFFFFF]"
                : "bg-[#F2F2F2] text-[#0F0F0F] hover:bg-[#E5E5E5]"
            }`}
          >
            All Traces ({traces.length})
          </button>
          <button
            onClick={() => setActiveTab("agents")}
            className={`rounded-full px-3 py-1.5 text-[14px] leading-[20px] font-medium transition-colors ${
              activeTab === "agents"
                ? "bg-[#0F0F0F] text-[#FFFFFF]"
                : "bg-[#F2F2F2] text-[#0F0F0F] hover:bg-[#E5E5E5]"
            }`}
          >
            Agents Inventory ({agents.length})
          </button>
          <button
            onClick={() => setActiveTab("tokens")}
            className={`rounded-full px-3 py-1.5 text-[14px] leading-[20px] font-medium transition-colors ${
              activeTab === "tokens"
                ? "bg-[#0F0F0F] text-[#FFFFFF]"
                : "bg-[#F2F2F2] text-[#0F0F0F] hover:bg-[#E5E5E5]"
            }`}
          >
            Ephemeral STS Leases
          </button>
        </div>

        {/* Simulation Controls */}
        <div className="flex items-center gap-2">
          <span className="text-[12px] font-medium text-[#606060] mr-1">
            Test Scenarios:
          </span>

          <button
            onClick={() => onSimulateAttack("benign_read")}
            className="h-[36px] rounded-full border border-[#E5E5E5] bg-[#FFFFFF] hover:bg-[#F2F2F2] px-4 text-[14px] font-medium text-[#0F0F0F] transition-colors"
          >
            1. Benign Read (&lt;50ms)
          </button>

          <button
            onClick={() => onSimulateAttack("destructive_hitl")}
            className="h-[36px] rounded-full bg-[#F2F2F2] hover:bg-[#E5E5E5] px-4 text-[14px] font-medium text-[#0F0F0F] transition-colors"
          >
            2. Trigger HITL Pause
          </button>

          {/* Primary Broadcast Red Action Button (#FF0000, hover #CC0000) */}
          <button
            onClick={() => onSimulateAttack("prompt_injection")}
            className="h-[36px] rounded-full bg-[#FF0000] hover:bg-[#CC0000] px-4 text-[14px] font-medium text-[#FFFFFF] transition-colors"
          >
            3. Fire Prompt Injection
          </button>
        </div>
      </div>

      {/* Table Content Area */}
      <div className="flex-1 overflow-y-auto">
        {activeTab === "traces" && (
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#E5E5E5] bg-[#F2F2F2]/60 text-[12px] font-medium text-[#606060]">
                <th className="py-2 px-4">Time</th>
                <th className="py-2 px-3">Agent</th>
                <th className="py-2 px-3">Tool Invocation</th>
                <th className="py-2 px-3">Verdict</th>
                <th className="py-2 px-3">Detector</th>
                <th className="py-2 px-3">Latency</th>
                <th className="py-2 px-3">STS Token JTI</th>
                <th className="py-2 px-4">Target Resource</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E5E5] text-[13px]">
              {traces.map((tr) => {
                const isSelected = tr.id === selectedTraceId;
                return (
                  <tr
                    key={tr.id}
                    onClick={() => onSelectTrace(tr)}
                    className={`cursor-pointer transition-colors ${
                      isSelected ? "bg-[#F2F2F2]" : "hover:bg-[#F2F2F2]/60"
                    }`}
                  >
                    <td className="py-2.5 px-4 font-mono text-[12px] text-[#606060]">
                      {tr.occurred_at}
                    </td>
                    <td className="py-2.5 px-3 font-medium text-[#0F0F0F]">
                      {tr.agent_name}{" "}
                      <span className="text-[12px] font-normal text-[#606060]">
                        • {tr.framework}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[#0F0F0F]">
                      {tr.tool_name}()
                    </td>
                    <td className="py-2.5 px-3">
                      {tr.verdict === "blocked" ? (
                        <span className="inline-flex items-center gap-1 rounded-[2px] bg-[#FF0000] px-2 py-0.5 text-[11px] font-medium text-[#FFFFFF]">
                          <ShieldAlert className="h-3 w-3" />
                          STRIKE ({(tr.confidence_score * 100).toFixed(0)}%)
                        </span>
                      ) : tr.verdict === "hitl_paused" ? (
                        <span className="inline-flex items-center gap-1 rounded-[2px] bg-[#FB8C00] px-2 py-0.5 text-[11px] font-medium text-[#FFFFFF]">
                          <Hand className="h-3 w-3" />
                          REVIEW PENDING
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-[2px] bg-[#2BA640] px-2 py-0.5 text-[11px] font-medium text-[#FFFFFF]">
                          <ShieldCheck className="h-3 w-3" />
                          VERIFIED
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[12px] text-[#606060]">
                      {tr.detector_tier}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[12px] text-[#0F0F0F]">
                      {tr.firewall_latency_ms}ms
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[12px] text-[#065FD4]">
                      {tr.ephemeral_token_jti
                        ? `${tr.ephemeral_token_jti.slice(0, 16)}...`
                        : "—"}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[12px] text-[#065FD4] truncate max-w-xs">
                      {tr.target_resource}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {activeTab === "agents" && (
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#E5E5E5] bg-[#F2F2F2]/60 text-[12px] font-medium text-[#606060]">
                <th className="py-2 px-4">Agent Name</th>
                <th className="py-2 px-3">Metadata (Framework • Latency • Strikes)</th>
                <th className="py-2 px-3">Risk Score</th>
                <th className="py-2 px-3">Service Account</th>
                <th className="py-2 px-4">Allowed Tools</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E5E5] text-[13px]">
              {agents.map((ag) => (
                <tr key={ag.id} className="hover:bg-[#F2F2F2]/60">
                  <td className="py-2.5 px-4 font-medium text-[#0F0F0F]">
                    {ag.name}
                  </td>
                  <td className="py-2.5 px-3 text-[12px] text-[#606060]">
                    {ag.framework} • {ag.p99FirewallMs}ms p99 •{" "}
                    {ag.blockedAttacksCount} strikes
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[12px] font-medium text-[#0F0F0F]">
                    {ag.riskScore}/100
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[12px] text-[#065FD4]">
                    {ag.serviceAccount}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-[12px] text-[#606060]">
                    {ag.allowedTools.join(", ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {activeTab === "tokens" && (
          <div className="p-4 grid grid-cols-3 gap-4">
            {traces
              .filter((t) => t.ephemeral_token_jti)
              .map((t) => (
                <div
                  key={t.id}
                  className="rounded-[12px] bg-[#F2F2F2] p-3 text-[12px]"
                >
                  <div className="flex items-center justify-between font-medium text-[#2BA640] mb-1">
                    <span className="inline-flex items-center gap-1">
                      <KeyRound className="h-3.5 w-3.5" />
                      Single-Use STS Lease (Zeroized)
                    </span>
                    <span className="font-mono text-[#0F0F0F]">14ms</span>
                  </div>
                  <div className="font-mono font-medium text-[#0F0F0F] truncate">
                    {t.ephemeral_token_jti}
                  </div>
                  <div className="font-mono text-[#065FD4] truncate mt-1">
                    {t.target_resource}
                  </div>
                </div>
              ))}
          </div>
        )}
      </div>
    </section>
  );
}
