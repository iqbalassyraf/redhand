"use client";

import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Hand,
  KeyRound,
  Cloud,
  Lock,
  Layers,
  Terminal,
  Database,
  UserCheck,
  UserX,
} from "lucide-react";
import type { AgentPostureItem, TraceTelemetryRow } from "@/lib/types";

export type SimulationScenarioType =
  | "benign_read"
  | "sql_exfiltration"
  | "shell_evasion"
  | "rbac_denied"
  | "multicloud_sts"
  | "destructive_hitl";

interface FlightRecorderDockProps {
  traces: TraceTelemetryRow[];
  agents: AgentPostureItem[];
  selectedTraceId: string | null;
  onSelectTrace: (trace: TraceTelemetryRow) => void;
  onSimulateAttack: (scenario: SimulationScenarioType) => void;
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
    <section className="flex h-72 shrink-0 flex-col border-t border-[#E5E5E5] bg-[#FFFFFF]">
      {/* Chip Bar + Simulation Controls */}
      <div className="flex items-center justify-between border-b border-[#E5E5E5] px-4 py-2.5 overflow-x-auto gap-3">
        <div className="flex items-center gap-1.5 shrink-0">
          <button
            onClick={() => setActiveTab("traces")}
            className={`rounded-full px-3 py-1.5 text-[13px] leading-[18px] font-medium transition-colors ${
              activeTab === "traces"
                ? "bg-[#0F0F0F] text-[#FFFFFF]"
                : "bg-[#F2F2F2] text-[#0F0F0F] hover:bg-[#E5E5E5]"
            }`}
          >
            All Traces ({traces.length})
          </button>
          <button
            onClick={() => setActiveTab("tokens")}
            className={`rounded-full px-3 py-1.5 text-[13px] leading-[18px] font-medium transition-colors ${
              activeTab === "tokens"
                ? "bg-[#0F0F0F] text-[#FFFFFF]"
                : "bg-[#F2F2F2] text-[#0F0F0F] hover:bg-[#E5E5E5]"
            }`}
          >
            Multi-Cloud STS Leases
          </button>
          <button
            onClick={() => setActiveTab("agents")}
            className={`rounded-full px-3 py-1.5 text-[13px] leading-[18px] font-medium transition-colors ${
              activeTab === "agents"
                ? "bg-[#0F0F0F] text-[#FFFFFF]"
                : "bg-[#F2F2F2] text-[#0F0F0F] hover:bg-[#E5E5E5]"
            }`}
          >
            Agents Inventory ({agents.length})
          </button>
        </div>

        {/* 6 Pitch Simulation Controls */}
        <div className="flex items-center gap-1.5 shrink-0">
          <span className="text-[11px] font-semibold text-[#606060] uppercase mr-1 hidden xl:inline">
            Simulations:
          </span>

          <button
            onClick={() => onSimulateAttack("benign_read")}
            className="h-[32px] rounded-full border border-[#E5E5E5] bg-[#FFFFFF] hover:bg-[#F2F2F2] px-3 text-[12px] font-medium text-[#0F0F0F] transition-colors whitespace-nowrap"
            title="Valid SQL with explicit LIMIT under finance_viewer role"
          >
            1. Benign SQL (LIMIT 10)
          </button>

          <button
            onClick={() => onSimulateAttack("sql_exfiltration")}
            className="h-[32px] rounded-full bg-[#FFF0F0] hover:bg-[#FFE5E5] border border-[#FF0000]/20 px-3 text-[12px] font-medium text-[#FF0000] transition-colors whitespace-nowrap"
            title="Full table dump and sensitive column extraction (password_hash, ssn) blocked by AST"
          >
            2. SQL Exfil Blocked
          </button>

          <button
            onClick={() => onSimulateAttack("shell_evasion")}
            className="h-[32px] rounded-full bg-[#FFF0F0] hover:bg-[#FFE5E5] border border-[#FF0000]/20 px-3 text-[12px] font-medium text-[#FF0000] transition-colors whitespace-nowrap"
            title="Hex/Base64 obfuscated execution blocked by POSIX positive allowlist"
          >
            3. Shell Evasion Blocked
          </button>

          <button
            onClick={() => onSimulateAttack("rbac_denied")}
            className="h-[32px] rounded-full bg-[#FFF8E1] hover:bg-[#FFECB3] border border-[#FB8C00]/30 px-3 text-[12px] font-medium text-[#FB8C00] transition-colors whitespace-nowrap"
            title="Caller lacks required user role; agent intercepted"
          >
            4. RBAC Denied
          </button>

          <button
            onClick={() => onSimulateAttack("multicloud_sts")}
            className="h-[32px] rounded-full bg-[#F2F2F2] hover:bg-[#E5E5E5] px-3 text-[12px] font-medium text-[#0F0F0F] transition-colors whitespace-nowrap"
            title="Mints ephemeral tokens for AWS, Azure, GCP, and GitHub SaaS"
          >
            5. Multi-Cloud STS
          </button>

          <button
            onClick={() => onSimulateAttack("destructive_hitl")}
            className="h-[32px] rounded-full bg-[#FF0000] hover:bg-[#CC0000] px-3.5 text-[12px] font-medium text-[#FFFFFF] transition-colors whitespace-nowrap shadow-sm"
            title="Destructive database termination halted for Four-Eyes Quorum"
          >
            6. Four-Eyes Quorum
          </button>
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto">
        {activeTab === "traces" && (
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#E5E5E5] bg-[#F2F2F2]/60 text-[11px] font-semibold text-[#606060] uppercase">
                <th className="py-2 px-3">Time</th>
                <th className="py-2 px-3">Agent</th>
                <th className="py-2 px-3">Delegated Caller (RBAC)</th>
                <th className="py-2 px-3">Tool Invocation</th>
                <th className="py-2 px-3">Firewall Verdict</th>
                <th className="py-2 px-3">Latency</th>
                <th className="py-2 px-3">Cloud Provider &amp; Token</th>
                <th className="py-2 px-4">Target Resource</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E5E5] text-[12px]">
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
                    <td className="py-2.5 px-3 font-mono text-[11px] text-[#606060]">
                      {tr.occurred_at}
                    </td>
                    <td className="py-2.5 px-3 font-medium text-[#0F0F0F]">
                      {tr.agent_name}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-[#0F0F0F]">
                      <span className="text-[#065FD4] font-medium block">
                        {tr.delegated_user || "alice.chen@enterprise.com"}
                      </span>
                      <span className="text-[10px] text-[#606060]">
                        [{tr.delegated_roles?.join(", ") || "finance_viewer"}]
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[12px] text-[#0F0F0F]">
                      {tr.tool_name}()
                    </td>
                    <td className="py-2.5 px-3">
                      {tr.verdict === "blocked" ? (
                        <span className="inline-flex items-center gap-1 rounded bg-[#FF0000] px-1.5 py-0.5 text-[10px] font-bold text-[#FFFFFF] uppercase">
                          <ShieldAlert className="h-3 w-3" />
                          BLOCKED
                        </span>
                      ) : tr.verdict === "hitl_paused" ? (
                        <span className="inline-flex items-center gap-1 rounded bg-[#FB8C00] px-1.5 py-0.5 text-[10px] font-bold text-[#FFFFFF] uppercase">
                          <Hand className="h-3 w-3" />
                          REVIEW PENDING
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded bg-[#2BA640] px-1.5 py-0.5 text-[10px] font-bold text-[#FFFFFF] uppercase">
                          <ShieldCheck className="h-3 w-3" />
                          ALLOWED
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-[#0F0F0F]">
                      {tr.firewall_latency_ms}ms
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px]">
                      {tr.ephemeral_token_jti ? (
                        <span className="text-[#2BA640] font-medium block">
                          {tr.cloud_provider?.toUpperCase() || "JIT"} • {tr.ephemeral_token_jti.slice(0, 16)}...
                        </span>
                      ) : (
                        <span className="text-[#606060]">—</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[11px] text-[#065FD4] truncate max-w-xs">
                      {tr.target_resource}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {/* MULTI-CLOUD & SAAS STS LEASES TAB */}
        {activeTab === "tokens" && (
          <div className="p-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
            {/* AWS STS */}
            <div className="rounded-[10px] border border-[#FF9900]/30 bg-[#FF9900]/5 p-3 text-[12px] space-y-1.5">
              <div className="flex items-center justify-between font-bold text-[#FF9900]">
                <span className="inline-flex items-center gap-1.5">
                  <Cloud className="h-3.5 w-3.5" />
                  AWS STS AssumeRole
                </span>
                <span className="rounded bg-[#FF9900] px-1.5 py-0.2 text-[9px] font-bold text-[#FFFFFF]">
                  TTL 30s
                </span>
              </div>
              <div className="font-mono text-[11px] text-[#0F0F0F] truncate">
                ASIAQ4910AB78SESSION_44bc99
              </div>
              <div className="text-[10px] text-[#606060]">
                Scope: arn:aws:iam::123456789012:role/AgentWallRestricted
              </div>
              <div className="text-[10px] text-[#2BA640] font-medium">
                ✓ Inline Session Policy (Single S3 Bucket)
              </div>
            </div>

            {/* Azure Entra ID */}
            <div className="rounded-[10px] border border-[#0078D4]/30 bg-[#0078D4]/5 p-3 text-[12px] space-y-1.5">
              <div className="flex items-center justify-between font-bold text-[#0078D4]">
                <span className="inline-flex items-center gap-1.5">
                  <Cloud className="h-3.5 w-3.5" />
                  Azure Entra ID (OBO)
                </span>
                <span className="rounded bg-[#0078D4] px-1.5 py-0.2 text-[9px] font-bold text-[#FFFFFF]">
                  TTL 30s
                </span>
              </div>
              <div className="font-mono text-[11px] text-[#0F0F0F] truncate">
                agentwall_az_7f9910e42a19...
              </div>
              <div className="text-[10px] text-[#606060]">
                User: alice.chen@enterprise.com (cloud_operator)
              </div>
              <div className="text-[10px] text-[#2BA640] font-medium">
                ✓ Downscoped to /subscriptions/prod/storage
              </div>
            </div>

            {/* Google Cloud STS */}
            <div className="rounded-[10px] border border-[#4285F4]/30 bg-[#4285F4]/5 p-3 text-[12px] space-y-1.5">
              <div className="flex items-center justify-between font-bold text-[#4285F4]">
                <span className="inline-flex items-center gap-1.5">
                  <Cloud className="h-3.5 w-3.5" />
                  GCP STS (CAB)
                </span>
                <span className="rounded bg-[#4285F4] px-1.5 py-0.2 text-[9px] font-bold text-[#FFFFFF]">
                  TTL 45s
                </span>
              </div>
              <div className="font-mono text-[11px] text-[#0F0F0F] truncate">
                ya29.c.agentwall_cab_8819a...
              </div>
              <div className="text-[10px] text-[#606060]">
                Resource: //bigquery.googleapis.com/.../finops
              </div>
              <div className="text-[10px] text-[#2BA640] font-medium">
                ✓ CEL Rule: inRole:roles/bigquery.dataViewer
              </div>
            </div>

            {/* SaaS Token (GitHub / Slack) */}
            <div className="rounded-[10px] border border-[#24292E]/30 bg-[#24292E]/5 p-3 text-[12px] space-y-1.5">
              <div className="flex items-center justify-between font-bold text-[#24292E]">
                <span className="inline-flex items-center gap-1.5">
                  <KeyRound className="h-3.5 w-3.5" />
                  SaaS Ephemeral Token
                </span>
                <span className="rounded bg-[#24292E] px-1.5 py-0.2 text-[9px] font-bold text-[#FFFFFF]">
                  TTL 30s
                </span>
              </div>
              <div className="font-mono text-[11px] text-[#0F0F0F] truncate">
                ghs_4819a0bc771239aa8123...
              </div>
              <div className="text-[10px] text-[#606060]">
                Target: https://api.github.com/repos/acme/repo
              </div>
              <div className="text-[10px] text-[#2BA640] font-medium">
                ✓ Scopes: repo:read, issues:write (Fine-grained)
              </div>
            </div>
          </div>
        )}

        {/* AGENTS INVENTORY TAB */}
        {activeTab === "agents" && (
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#E5E5E5] bg-[#F2F2F2]/60 text-[11px] font-semibold text-[#606060] uppercase">
                <th className="py-2 px-4">Agent Name</th>
                <th className="py-2 px-3">Metadata (Framework • Latency • Contained)</th>
                <th className="py-2 px-3">Risk Score</th>
                <th className="py-2 px-3">Service Account</th>
                <th className="py-2 px-4">Allowed Tools</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E5E5] text-[12px]">
              {agents.map((ag) => (
                <tr key={ag.id} className="hover:bg-[#F2F2F2]/60">
                  <td className="py-2.5 px-4 font-medium text-[#0F0F0F]">
                    {ag.name}
                  </td>
                  <td className="py-2.5 px-3 text-[12px] text-[#606060]">
                    {ag.framework} • {ag.p99FirewallMs}ms p99 •{" "}
                    {ag.blockedAttacksCount} contained
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[12px] font-medium text-[#0F0F0F]">
                    {ag.riskScore}/100
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[11px] text-[#065FD4]">
                    {ag.serviceAccount}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-[11px] text-[#606060]">
                    {ag.allowedTools.join(", ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
