"use client";

import React, { useState, useEffect } from "react";
import {
  Hand,
  CheckCircle2,
  XCircle,
  Lock,
  Terminal,
  ShieldCheck,
  Sliders,
  Copy,
  Check,
  ShieldOff,
  Sparkles,
  ShieldAlert,
  AlertTriangle,
  FileCode,
  KeyRound,
  Cloud,
} from "lucide-react";
import type {
  AgentPostureItem,
  AuthenticatedUser,
  HITLInterventionItem,
  MCPFindingItem,
  MCPVettingReportItem,
  TraceTelemetryRow,
} from "@/lib/types";
import { SAMPLE_MCP_MANIFESTS } from "@/lib/mock-telemetry";

interface InterventionRailProps {
  interventions: HITLInterventionItem[];
  selectedTrace: TraceTelemetryRow | null;
  agents: AgentPostureItem[];
  currentUser?: AuthenticatedUser;
  onResolveIntervention: (
    interventionId: string,
    action: "approve" | "deny",
    modifiedArgs: Record<string, unknown>,
    comment: string,
    reviewerUserId?: string
  ) => Promise<void>;
  onToggleAgentQuarantine: (
    agentId: string,
    nextStatus: "active" | "quarantined"
  ) => Promise<void>;
}

const REVIEWER_PROFILES = [
  {
    id: "00000000-0000-0000-0000-000000000001",
    name: "Alice Chen",
    role: "SecOps Lead",
  },
  {
    id: "00000000-0000-0000-0000-000000000002",
    name: "Bob Vance",
    role: "Principal SRE",
  },
];

export function InterventionRail({
  interventions,
  selectedTrace,
  agents,
  currentUser,
  onResolveIntervention,
  onToggleAgentQuarantine,
}: InterventionRailProps) {
  const [activeTab, setActiveTab] = useState<
    "hitl" | "xray" | "posture" | "worm" | "mcp_vet"
  >("hitl");
  const reviewQueue = interventions.filter(
    (i) => i.status === "pending" || i.status === "partially_approved"
  );
  const activeIntervention = reviewQueue[0] ?? interventions[0] ?? null;

  const [selectedReviewerId, setSelectedReviewerId] = useState<string>(
    REVIEWER_PROFILES[0].id
  );
  const [argsJsonText, setArgsJsonText] = useState<string>("");
  const [comment, setComment] = useState<string>(
    "Verified database replica snapshot; overriding target to staging replica."
  );
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [copiedOcsf, setCopiedOcsf] = useState(false);

  // MCP Vetting State
  const [selectedMcpPreset, setSelectedMcpPreset] = useState<string>(
    "dangerous_community"
  );
  const [mcpManifestText, setMcpManifestText] = useState<string>(
    JSON.stringify(SAMPLE_MCP_MANIFESTS.dangerous_community.manifest, null, 2)
  );
  const [mcpReport, setMcpReport] = useState<MCPVettingReportItem | null>(null);
  const [isAuditingMcp, setIsAuditingMcp] = useState<boolean>(false);
  const [copiedMcpPolicy, setCopiedMcpPolicy] = useState<boolean>(false);

  useEffect(() => {
    if (activeIntervention) {
      setArgsJsonText(
        JSON.stringify(activeIntervention.proposed_tool_arguments, null, 2)
      );
      setJsonError(null);
      const alreadySigned =
        activeIntervention.approvals?.map((a) => a.reviewer_user_id) || [];
      if (alreadySigned.includes(REVIEWER_PROFILES[0].id)) {
        setSelectedReviewerId(REVIEWER_PROFILES[1].id);
      } else {
        setSelectedReviewerId(REVIEWER_PROFILES[0].id);
      }
    }
  }, [activeIntervention]);

  const handleDecision = async (action: "approve" | "deny") => {
    if (!activeIntervention) return;
    try {
      const parsed = JSON.parse(argsJsonText);
      setJsonError(null);
      setIsSubmitting(true);
      await onResolveIntervention(
        activeIntervention.id,
        action,
        parsed,
        comment,
        selectedReviewerId
      );
    } catch (err) {
      setJsonError(
        err instanceof Error ? err.message : "Invalid JSON tool arguments"
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCopyOcsf = () => {
    if (!selectedTrace) return;
    const ocsfFinding = {
      metadata: {
        version: "1.1.0",
        product: { name: "RedHand AgentWall", vendor_name: "RedHand Security" },
      },
      class_uid: 2001,
      class_name: "Security Finding",
      severity_id: selectedTrace.verdict === "blocked" ? 4 : 1,
      severity: selectedTrace.verdict === "blocked" ? "High" : "Informational",
      activity_name: "AI Agent Tool-Call Firewall Interception",
      finding_info: {
        title: `Agent Tool Call: ${selectedTrace.tool_name}`,
        desc: selectedTrace.thought_content,
      },
      cloud: {
        provider: selectedTrace.cloud_provider || "GCP",
        target_resource: selectedTrace.target_resource,
      },
      agent: {
        id: selectedTrace.agent_name,
        framework: selectedTrace.framework,
        delegated_user: selectedTrace.delegated_user || "alice.chen@enterprise.com",
      },
      action: selectedTrace.verdict === "blocked" ? "Denied" : "Allowed",
      disposition: selectedTrace.verdict === "blocked" ? "Blocked" : "Approved",
    };

    navigator.clipboard.writeText(JSON.stringify(ocsfFinding, null, 2));
    setCopiedOcsf(true);
    setTimeout(() => setCopiedOcsf(false), 2000);
  };

  // MCP Manifest Auditing
  const handleAuditMcp = async (manifestJsonStr?: string) => {
    setIsAuditingMcp(true);
    const jsonToAudit = manifestJsonStr || mcpManifestText;
    let manifestObj: Record<string, unknown> = {};
    try {
      manifestObj = JSON.parse(jsonToAudit);
    } catch {
      setIsAuditingMcp(false);
      return;
    }

    try {
      const res = await fetch("http://localhost:8080/v1/mcp/vet", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(manifestObj),
      });
      if (res.ok) {
        const report = await res.json();
        setMcpReport(report);
        setIsAuditingMcp(false);
        return;
      }
    } catch {
      // Fallback to client-side rule evaluation matching MCPServerAuditor
    }

    const serverName = String(manifestObj.name || manifestObj.server_name || "unnamed-mcp-server");
    const cmd = String(manifestObj.command || "").toLowerCase();
    const args = Array.isArray(manifestObj.args) ? manifestObj.args.map((a) => String(a).toLowerCase()) : [];
    const envVars = (manifestObj.env as Record<string, unknown>) || {};
    const tools = Array.isArray(manifestObj.tools) ? manifestObj.tools : [];

    const findings: MCPFindingItem[] = [];
    let score = 0;

    const dangerousCmds = ["bash", "sh", "zsh", "cmd.exe", "powershell", "python -c"];
    for (const d of dangerousCmds) {
      if (cmd.includes(d) || args.some((a) => a.includes(d))) {
        score += 40;
        findings.push({
          id: "MCP-SEC-001",
          severity: "CRITICAL",
          category: "EXECUTION_RISK",
          title: `Direct Shell or Interpreter Execution Detected (${d})`,
          description: `Server launches via dynamic shell or interpreter '${d}', exposing arbitrary execution vectors.`,
          remediation: "Package MCP server as a standalone compiled binary without interactive shell wrappers.",
        });
        break;
      }
    }

    for (const [k, v] of Object.entries(envVars)) {
      const strVal = String(v);
      if (/sk-[a-zA-Z0-9_-]{20,}/.test(strVal) || /AKIA[0-9A-Z]{16}/.test(strVal)) {
        score += 35;
        findings.push({
          id: "MCP-SEC-002",
          severity: "CRITICAL",
          category: "CREDENTIAL_EXPOSURE",
          title: `Hardcoded Static Secret in Environment Variable '${k}'`,
          description: `Environment variable '${k}' contains high-entropy static credentials.`,
          remediation: "Never pass static keys. Use AgentWall Just-In-Time Ephemeral STS brokering.",
        });
      }
    }

    const recPolicyTools: Record<string, unknown> = {};

    for (const tool of tools) {
      const t = tool as Record<string, unknown>;
      const tName = String(t.name || "unnamed_tool");
      const tDesc = String(t.description || "").toLowerCase();
      const schema = (t.inputSchema || t.schema) as Record<string, unknown> | undefined;

      if (/bash|shell|exec|terminal|eval|system|command/.test(tName.toLowerCase()) || /bash|shell|exec/.test(tDesc)) {
        score += 30;
        findings.push({
          id: "MCP-SEC-003",
          severity: "HIGH",
          category: "EXECUTION_RISK",
          tool_name: tName,
          title: `Arbitrary Command/Script Execution Tool: '${tName}'`,
          description: `Tool '${tName}' allows direct terminal or shell command execution.`,
          remediation: "Apply ShellASTGuardrail with positive allowlist (allowed_binaries: [ls, cat, grep]).",
        });
      }

      if (/write_file|delete_file|overwrite|filesystem/.test(tName.toLowerCase())) {
        score += 25;
        findings.push({
          id: "MCP-SEC-004",
          severity: "HIGH",
          category: "FILESYSTEM_RISK",
          tool_name: tName,
          title: `Destructive Filesystem Access: '${tName}'`,
          description: `Tool '${tName}' exhibits broad filesystem read/write or deletion capabilities.`,
          remediation: "Enforce chroot/path jail regex constraints in input schema.",
        });
      }

      if (!schema) {
        score += 20;
        findings.push({
          id: "MCP-SEC-006",
          severity: "HIGH",
          category: "SCHEMA_RISK",
          tool_name: tName,
          title: `Missing Input Schema in Tool '${tName}'`,
          description: `Tool specifies no parameter schema, accepting unbounded payload injection.`,
          remediation: "Define strict JSON schema with type constraints and maxLength boundaries.",
        });
      } else if (schema.additionalProperties === true) {
        score += 10;
        findings.push({
          id: "MCP-SEC-007",
          severity: "MEDIUM",
          category: "SCHEMA_RISK",
          tool_name: tName,
          title: `Permissive additionalProperties in Tool '${tName}'`,
          description: `Tool schema allows arbitrary additional fields to pass unvalidated.`,
          remediation: "Set 'additionalProperties: false' in tool JSON schema.",
        });
      }

      recPolicyTools[tName] = {
        type: /sql/.test(tName) ? "sql" : /bash|shell|exec/.test(tName) ? "shell" : "generic",
        description: `Sandboxed definition for ${tName}`,
        iam_provider: "local_sts",
        target_audience: `https://mcp.${serverName}.internal`,
        schema: {
          type: "object",
          properties: (schema?.properties as Record<string, unknown>) || {},
          required: (schema?.required as string[]) || [],
          additionalProperties: false,
        },
      };
    }

    const clampedScore = Math.min(score, 100);
    const verdict = clampedScore > 60 ? "FAIL" : clampedScore > 20 ? "WARN" : "PASS";

    setMcpReport({
      server_name: serverName,
      risk_score: clampedScore,
      verdict,
      total_tools_scanned: tools.length,
      findings,
      recommended_policy: {
        version: "1.0",
        server: serverName,
        settings: { fail_mode: "fail_closed", egress_dlp_enabled: true },
        tools: recPolicyTools,
      },
    });
    setIsAuditingMcp(false);
  };

  const handleCopyMcpPolicy = () => {
    if (!mcpReport) return;
    navigator.clipboard.writeText(JSON.stringify(mcpReport.recommended_policy, null, 2));
    setCopiedMcpPolicy(true);
    setTimeout(() => setCopiedMcpPolicy(false), 2000);
  };

  return (
    <aside className="flex h-full w-[440px] shrink-0 flex-col border-l border-[#E5E5E5] bg-[#FFFFFF]">
      {/* Red Broadcast 9999px Pill Tabs */}
      <div className="flex items-center gap-1.5 border-b border-[#E5E5E5] px-3 py-2.5 overflow-x-auto">
        <button
          onClick={() => setActiveTab("hitl")}
          className={`relative inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[13px] leading-[18px] font-medium transition-colors whitespace-nowrap ${
            activeTab === "hitl"
              ? "bg-[#0F0F0F] text-[#FFFFFF]"
              : "bg-[#F2F2F2] text-[#0F0F0F] hover:bg-[#E5E5E5]"
          }`}
        >
          <Hand className="h-3.5 w-3.5" />
          Review Queue
          {reviewQueue.length > 0 && (
            <span className="rounded-[2px] bg-[#FF0000] px-1.5 py-0.2 text-[11px] font-medium text-[#FFFFFF]">
              {reviewQueue.length}
            </span>
          )}
        </button>

        <button
          onClick={() => {
            setActiveTab("mcp_vet");
            if (!mcpReport) handleAuditMcp();
          }}
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[13px] leading-[18px] font-medium transition-colors whitespace-nowrap ${
            activeTab === "mcp_vet"
              ? "bg-[#0F0F0F] text-[#FFFFFF]"
              : "bg-[#F2F2F2] text-[#0F0F0F] hover:bg-[#E5E5E5]"
          }`}
        >
          <Sparkles className="h-3.5 w-3.5 text-[#065FD4]" />
          MCP Vetting
        </button>

        <button
          onClick={() => setActiveTab("xray")}
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[13px] leading-[18px] font-medium transition-colors whitespace-nowrap ${
            activeTab === "xray"
              ? "bg-[#0F0F0F] text-[#FFFFFF]"
              : "bg-[#F2F2F2] text-[#0F0F0F] hover:bg-[#E5E5E5]"
          }`}
        >
          <Terminal className="h-3.5 w-3.5" />
          X-Ray
        </button>

        <button
          onClick={() => setActiveTab("posture")}
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[13px] leading-[18px] font-medium transition-colors whitespace-nowrap ${
            activeTab === "posture"
              ? "bg-[#0F0F0F] text-[#FFFFFF]"
              : "bg-[#F2F2F2] text-[#0F0F0F] hover:bg-[#E5E5E5]"
          }`}
        >
          <Sliders className="h-3.5 w-3.5" />
          Posture
        </button>

        <button
          onClick={() => setActiveTab("worm")}
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[13px] leading-[18px] font-medium transition-colors whitespace-nowrap ${
            activeTab === "worm"
              ? "bg-[#0F0F0F] text-[#FFFFFF]"
              : "bg-[#F2F2F2] text-[#0F0F0F] hover:bg-[#E5E5E5]"
          }`}
        >
          <Lock className="h-3.5 w-3.5" />
          WORM
        </button>
      </div>

      {/* TAB 1: HITL CIRCUIT BREAKER APPROVAL */}
      {activeTab === "hitl" && (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {!activeIntervention ? (
            <div className="rounded-[12px] bg-[#F2F2F2] p-6 text-center">
              <ShieldCheck className="mx-auto h-7 w-7 text-[#2BA640] mb-2" />
              <div className="text-[14px] font-medium text-[#0F0F0F]">
                No Pending Interventions
              </div>
              <p className="text-[12px] text-[#606060] mt-1">
                All state-changing agent actions are currently resolved.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="rounded-[2px] bg-[#FB8C00] px-2 py-0.5 text-[12px] font-medium text-[#FFFFFF] uppercase">
                  {activeIntervention.risk_tier} •{" "}
                  {activeIntervention.status === "partially_approved"
                    ? "1 OF 2 SIGNED"
                    : "REVIEW PENDING"}
                </span>
                <span className="text-[12px] text-[#606060] uppercase font-mono">
                  Quorum:{" "}
                  <strong className="text-[#0F0F0F]">
                    {activeIntervention.approvals?.length || 0}/
                    {activeIntervention.required_approvals || 1}
                  </strong>
                </span>
              </div>

              {activeIntervention.status === "partially_approved" && (
                <div className="rounded-[8px] border border-[#FB8C00] bg-[#FFF8E1] p-3 text-[12px] text-[#0F0F0F]">
                  <strong className="font-semibold block mb-0.5">⚠️ Four-Eyes Quorum Required</strong>
                  1st signature recorded. A second independent security operator must review and sign before the ephemeral STS credential is dispatched.
                </div>
              )}

              {activeIntervention.approvals && activeIntervention.approvals.length > 0 && (
                <div className="rounded-[8px] bg-[#F2F2F2] p-3 space-y-1.5">
                  <div className="text-[11px] font-medium uppercase text-[#606060]">
                    Recorded Signatures
                  </div>
                  {activeIntervention.approvals.map((appr, idx) => {
                    const prof = REVIEWER_PROFILES.find((p) => p.id === appr.reviewer_user_id);
                    return (
                      <div key={idx} className="flex items-center justify-between text-[12px]">
                        <span className="font-medium text-[#0F0F0F]">
                          ✓ {prof ? `${prof.name} (${prof.role})` : appr.reviewer_user_id.slice(0, 8)}
                        </span>
                        <span className="text-[11px] text-[#606060] font-mono">
                          {appr.approved_at.slice(11, 19)} UTC
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}

              <div>
                <h2 className="text-[20px] leading-[28px] font-bold text-[#0F0F0F]">
                  {activeIntervention.proposed_tool_name}()
                </h2>
                <p className="text-[12px] leading-[16px] text-[#606060] mt-0.5">
                  {activeIntervention.agent_name} • {activeIntervention.framework} •{" "}
                  {activeIntervention.created_at.slice(11, 19)} UTC
                </p>
              </div>

              <div className="rounded-[12px] bg-[#F2F2F2] p-3">
                <div className="text-[12px] font-medium text-[#0F0F0F] mb-1">
                  Agent Reasoning (Thought)
                </div>
                <p className="text-[14px] leading-[20px] text-[#0F0F0F]">
                  &ldquo;{activeIntervention.agent_justification}&rdquo;
                </p>
              </div>

              <div>
                <div className="text-[12px] font-medium text-[#606060] mb-1">
                  Target Cloud Resource
                </div>
                <div className="rounded-[8px] bg-[#F2F2F2] p-2.5 text-[12px] font-mono text-[#065FD4] break-all">
                  {activeIntervention.target_cloud_resource}
                </div>
              </div>

              <div className="flex items-center justify-between rounded-[8px] border border-[#E5E5E5] px-3 py-2">
                <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-[#2BA640]">
                  <Lock className="h-3.5 w-3.5" />
                  SHA-256 State Verified
                </span>
                <span className="text-[12px] font-mono text-[#606060]">
                  {activeIntervention.state_checksum.slice(0, 14)}...
                </span>
              </div>

              <div>
                <label className="block text-[12px] font-medium text-[#0F0F0F] mb-1">
                  Proposed Tool Arguments (JSON)
                </label>
                <textarea
                  value={argsJsonText}
                  onChange={(e) => setArgsJsonText(e.target.value)}
                  disabled={
                    activeIntervention.status !== "pending" &&
                    activeIntervention.status !== "partially_approved"
                  }
                  rows={4}
                  className="w-full rounded-[8px] border border-[#E5E5E5] bg-[#F2F2F2] p-3 font-mono text-[13px] leading-[18px] text-[#0F0F0F] focus:border-[#0F0F0F] focus:bg-[#FFFFFF] focus:outline-none disabled:opacity-60"
                />
                {jsonError && (
                  <p className="mt-1 text-[12px] text-[#FF0000]">{jsonError}</p>
                )}
              </div>

              {/* Operator Identity Selection */}
              {(activeIntervention.status === "pending" ||
                activeIntervention.status === "partially_approved") && (
                <div>
                  <label className="block text-[12px] font-medium text-[#0F0F0F] mb-1.5">
                    Sign As Operator (Four-Eyes Identity)
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                    {REVIEWER_PROFILES.map((p) => {
                      const hasSigned = Boolean(
                        activeIntervention.approvals?.some((a) => a.reviewer_user_id === p.id)
                      );
                      const isSelected = selectedReviewerId === p.id;
                      return (
                        <button
                          key={p.id}
                          type="button"
                          onClick={() => setSelectedReviewerId(p.id)}
                          className={`rounded-[8px] border p-2 text-left transition-colors ${
                            isSelected
                              ? "border-[#0F0F0F] bg-[#FFFFFF] shadow-sm"
                              : "border-[#E5E5E5] bg-[#F2F2F2] text-[#606060] hover:bg-[#E5E5E5]"
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-[12px] font-semibold text-[#0F0F0F]">
                              {p.name}
                            </span>
                            {hasSigned && (
                              <span className="rounded bg-[#2BA640] px-1 py-0.2 text-[9px] font-bold text-[#FFFFFF]">
                                SIGNED
                              </span>
                            )}
                          </div>
                          <span className="text-[10px] text-[#606060]">{p.role}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              <div>
                <label className="block text-[12px] font-medium text-[#606060] mb-1">
                  Reviewer Audit Note
                </label>
                <input
                  type="text"
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  disabled={
                    activeIntervention.status !== "pending" &&
                    activeIntervention.status !== "partially_approved"
                  }
                  className="h-[40px] w-full border-b border-[#E5E5E5] bg-transparent px-1 text-[14px] text-[#0F0F0F] focus:border-[#0F0F0F] focus:outline-none disabled:opacity-60"
                />
              </div>

              {activeIntervention.status === "pending" ||
              activeIntervention.status === "partially_approved" ? (
                <div className="space-y-2 pt-2">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleDecision("approve")}
                      disabled={
                        isSubmitting ||
                        Boolean(
                          activeIntervention.approvals?.some(
                            (a) => a.reviewer_user_id === selectedReviewerId
                          )
                        )
                      }
                      className="flex h-[36px] flex-1 items-center justify-center gap-1.5 rounded-full bg-[#0F0F0F] hover:bg-[#272727] px-4 text-[14px] font-medium text-[#FFFFFF] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      <CheckCircle2 className="h-4 w-4" />
                      {activeIntervention.status === "partially_approved"
                        ? "Sign Quorum (2 of 2)"
                        : "Sign & Approve"}
                    </button>
                    <button
                      onClick={() => handleDecision("deny")}
                      disabled={isSubmitting}
                      className="flex h-[36px] flex-1 items-center justify-center gap-1.5 rounded-full border border-[#E5E5E5] bg-[#FFFFFF] hover:bg-[#F2F2F2] px-4 text-[14px] font-medium text-[#0F0F0F] transition-colors disabled:opacity-50"
                    >
                      <XCircle className="h-4 w-4 text-[#FF0000]" />
                      Deny
                    </button>
                  </div>
                </div>
              ) : (
                <div className="rounded-[8px] bg-[#F2F2F2] p-3 text-center text-[12px] text-[#606060]">
                  Resolved: <span className="font-semibold text-[#0F0F0F] uppercase">{activeIntervention.status}</span>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: PRE-INSTALL MCP SERVER VETTING */}
      {activeTab === "mcp_vet" && (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-[14px] font-bold text-[#0F0F0F]">
                MCP Server Manifest Auditor
              </span>
              <span className="rounded-[2px] bg-[#0F0F0F] px-1.5 py-0.5 text-[10px] font-bold text-[#FFFFFF]">
                STATIC AST AUDIT
              </span>
            </div>
            <p className="text-[12px] text-[#606060] mt-0.5">
              Inspect third-party MCP servers prior to installation. Flags shell wrappers, env secrets, and loose schemas.
            </p>
          </div>

          {/* Sample Preset Selector */}
          <div>
            <label className="block text-[11px] font-medium text-[#606060] uppercase mb-1">
              Test Presets
            </label>
            <div className="space-y-1.5">
              {Object.entries(SAMPLE_MCP_MANIFESTS).map(([k, item]) => (
                <button
                  key={k}
                  onClick={() => {
                    setSelectedMcpPreset(k);
                    const formatted = JSON.stringify(item.manifest, null, 2);
                    setMcpManifestText(formatted);
                    handleAuditMcp(formatted);
                  }}
                  className={`w-full rounded-[8px] border p-2 text-left text-[12px] transition-colors ${
                    selectedMcpPreset === k
                      ? "border-[#0F0F0F] bg-[#FFFFFF] font-semibold text-[#0F0F0F] shadow-sm"
                      : "border-[#E5E5E5] bg-[#F2F2F2] text-[#606060] hover:bg-[#E5E5E5]"
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>

          {/* Manifest Textarea */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-[11px] font-medium text-[#606060] uppercase">
                MCP Server Manifest JSON
              </label>
              <button
                onClick={() => handleAuditMcp()}
                disabled={isAuditingMcp}
                className="inline-flex items-center gap-1 rounded-full bg-[#0F0F0F] px-3 py-1 text-[11px] font-medium text-[#FFFFFF] hover:bg-[#272727] disabled:opacity-50"
              >
                {isAuditingMcp ? "Auditing..." : "Re-audit Manifest"}
              </button>
            </div>
            <textarea
              value={mcpManifestText}
              onChange={(e) => setMcpManifestText(e.target.value)}
              rows={6}
              className="w-full rounded-[8px] border border-[#E5E5E5] bg-[#F2F2F2] p-2.5 font-mono text-[11px] text-[#0F0F0F] focus:border-[#0F0F0F] focus:bg-[#FFFFFF] focus:outline-none"
            />
          </div>

          {/* Audit Report Results */}
          {mcpReport && (
            <div className="space-y-3 pt-1 border-t border-[#E5E5E5]">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-[13px] font-bold text-[#0F0F0F]">
                    {mcpReport.server_name}
                  </div>
                  <div className="text-[11px] text-[#606060]">
                    {mcpReport.total_tools_scanned} tools scanned • Risk Score: {mcpReport.risk_score}/100
                  </div>
                </div>

                <span
                  className={`rounded-[3px] px-2.5 py-1 text-[12px] font-bold text-[#FFFFFF] ${
                    mcpReport.verdict === "FAIL"
                      ? "bg-[#FF0000]"
                      : mcpReport.verdict === "WARN"
                        ? "bg-[#FB8C00]"
                        : "bg-[#2BA640]"
                  }`}
                >
                  {mcpReport.verdict === "FAIL"
                    ? "REJECTED (FAIL)"
                    : mcpReport.verdict === "WARN"
                      ? "WARNING (WARN)"
                      : "APPROVED (PASS)"}
                </span>
              </div>

              {/* Findings List */}
              <div className="space-y-2">
                <div className="text-[11px] font-bold uppercase text-[#606060]">
                  Security Findings ({mcpReport.findings.length})
                </div>
                {mcpReport.findings.length === 0 ? (
                  <div className="rounded-[8px] bg-[#F2F2F2] p-3 text-[12px] text-[#2BA640] font-medium">
                    ✓ Clean manifest. No dangerous primitives or exposed secrets detected.
                  </div>
                ) : (
                  mcpReport.findings.map((f, i) => (
                    <div
                      key={i}
                      className="rounded-[8px] border border-[#E5E5E5] bg-[#FFFFFF] p-2.5 text-[12px] space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-[#0F0F0F]">
                          {f.title}
                        </span>
                        <span
                          className={`rounded px-1.5 py-0.2 text-[10px] font-bold text-[#FFFFFF] ${
                            f.severity === "CRITICAL"
                              ? "bg-[#FF0000]"
                              : f.severity === "HIGH"
                                ? "bg-[#FB8C00]"
                                : "bg-[#065FD4]"
                          }`}
                        >
                          {f.severity}
                        </span>
                      </div>
                      <p className="text-[11px] text-[#606060] leading-snug">
                        {f.description}
                      </p>
                      <div className="text-[11px] text-[#065FD4] bg-[#F2F2F2] p-1.5 rounded font-mono">
                        Remediation: {f.remediation}
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* Generated AgentWall Policy */}
              <div className="rounded-[8px] bg-[#F2F2F2] p-3 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold text-[#0F0F0F]">
                    Auto-Generated Sandboxed Policy
                  </span>
                  <button
                    onClick={handleCopyMcpPolicy}
                    className="inline-flex items-center gap-1 rounded bg-[#FFFFFF] px-2 py-0.5 text-[10px] font-medium text-[#0F0F0F] border border-[#E5E5E5]"
                  >
                    {copiedMcpPolicy ? <Check className="h-3 w-3 text-[#2BA640]" /> : <Copy className="h-3 w-3" />}
                    {copiedMcpPolicy ? "Copied" : "Copy YAML"}
                  </button>
                </div>
                <pre className="overflow-x-auto text-[10px] font-mono text-[#0F0F0F] max-h-36">
                  {JSON.stringify(mcpReport.recommended_policy, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: TRACE, DELEGATED IDENTITY & OCSF SIEM INSPECTOR */}
      {activeTab === "xray" && (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {selectedTrace ? (
            <>
              <div className="space-y-3">
                <div className="flex items-center justify-between text-[12px] text-[#606060]">
                  <span className="font-mono">
                    Trace: {selectedTrace.trace_id.slice(0, 14)}...
                  </span>
                  <span className="rounded-[4px] bg-[#F2F2F2] px-2 py-0.5 font-mono text-[#0F0F0F]">
                    {selectedTrace.firewall_latency_ms}ms
                  </span>
                </div>

                {/* Delegated Identity & RBAC Info */}
                <div className="rounded-[8px] border border-[#E5E5E5] bg-[#FFFFFF] p-2.5 text-[12px] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-[#0F0F0F]">
                      Delegated Caller Identity
                    </span>
                    <span className="font-mono text-[#065FD4]">
                      {selectedTrace.delegated_user || "alice.chen@enterprise.com"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-[#606060]">
                    <span>Delegated RBAC Roles:</span>
                    <span className="font-mono text-[#0F0F0F]">
                      {selectedTrace.delegated_roles?.join(", ") || "finance_viewer, admin"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-[#606060]">
                    <span>Effective Permission Boundary:</span>
                    <span className="text-[#2BA640] font-medium">Agent ∩ Caller RBAC</span>
                  </div>
                </div>

                <div className="rounded-[12px] bg-[#F2F2F2] p-3">
                  <div className="text-[12px] font-medium text-[#606060] mb-1">
                    1. Tool Invocation &amp; Arguments
                  </div>
                  <p className="text-[13px] font-mono text-[#0F0F0F]">
                    {selectedTrace.tool_name}({JSON.stringify(selectedTrace.tool_arguments)})
                  </p>
                </div>

                <div className="rounded-[12px] bg-[#F2F2F2] p-3">
                  <div className="text-[12px] font-medium text-[#606060] mb-1">
                    2. Agent Reasoning Intent
                  </div>
                  <p className="text-[13px] text-[#0F0F0F]">
                    &ldquo;{selectedTrace.thought_content}&rdquo;
                  </p>
                </div>

                <div className="rounded-[12px] bg-[#F2F2F2] p-3">
                  <div className="text-[12px] font-medium text-[#606060] mb-1">
                    3. Cloud / SaaS STS Credential Lease
                  </div>
                  <div className="text-[12px] font-mono text-[#065FD4]">
                    {selectedTrace.ephemeral_token_jti ? (
                      <span className="inline-flex items-center gap-1.5 text-[#2BA640] font-medium">
                        <KeyRound className="h-3.5 w-3.5" />
                        JIT Token: {selectedTrace.ephemeral_token_jti}
                      </span>
                    ) : (
                      <span className="text-[#FF0000] font-medium">
                        ✕ Zero Token Minted (Execution Blocked)
                      </span>
                    )}
                  </div>
                </div>

                {/* Granular SQL / AST Guardrail Metrics */}
                <div className="rounded-[8px] bg-[#F2F2F2] p-3 text-[12px] space-y-1">
                  <div className="text-[11px] font-bold uppercase text-[#606060]">
                    Enforced Governance Bounds
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-[#606060]">Max Row Extraction:</span>
                    <strong className="text-[#0F0F0F]">50 Rows (Hard Cap)</strong>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-[#606060]">Forbidden Columns:</span>
                    <strong className="text-[#0F0F0F]">password_hash, ssn, secret_key</strong>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-[#606060]">Shell Binary Policy:</span>
                    <strong className="text-[#0F0F0F]">Strict Positive Allowlist (Deny-Default)</strong>
                  </div>
                </div>

                {/* OCSF Payload */}
                <div className="flex items-center justify-between pt-2">
                  <span className="text-[13px] font-medium text-[#0F0F0F]">
                    OCSF v1.1.0 Telemetry Finding
                  </span>
                  <button
                    onClick={handleCopyOcsf}
                    className="inline-flex items-center gap-1 rounded-full bg-[#F2F2F2] hover:bg-[#E5E5E5] px-2.5 py-1 text-[11px] font-medium text-[#0F0F0F]"
                  >
                    {copiedOcsf ? <Check className="h-3 w-3 text-[#2BA640]" /> : <Copy className="h-3 w-3 text-[#606060]" />}
                    {copiedOcsf ? "Copied" : "Copy JSON"}
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="text-center text-[14px] text-[#606060] py-8">
              Select a telemetry row below to inspect its trace.
            </div>
          )}
        </div>
      )}

      {/* TAB 4: LIVE AGENT POSTURE & QUARANTINE */}
      {activeTab === "posture" && (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          <div className="text-[12px] text-[#606060]">
            Quarantining an agent causes AgentWall to reject all incoming tool invocations with HTTP 403.
          </div>

          {agents.map((ag) => {
            const isQuarantined = ag.status === "quarantined";
            return (
              <div
                key={ag.id}
                className="rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-3.5 space-y-3"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="text-[14px] font-medium text-[#0F0F0F]">
                      {ag.name}
                    </div>
                    <div className="text-[12px] text-[#606060]">
                      {ag.framework} • {ag.environment} • Risk {ag.riskScore}/100
                    </div>
                  </div>
                  <span
                    className={`rounded-[2px] px-2 py-0.5 text-[11px] font-medium uppercase text-[#FFFFFF] ${
                      isQuarantined ? "bg-[#FF0000]" : "bg-[#2BA640]"
                    }`}
                  >
                    {ag.status}
                  </span>
                </div>

                <div className="text-[12px] font-mono text-[#606060] bg-[#F2F2F2] p-2 rounded-[8px]">
                  Allowlist: {ag.allowedTools.join(", ")}
                </div>

                <button
                  onClick={() =>
                    onToggleAgentQuarantine(
                      ag.id,
                      isQuarantined ? "active" : "quarantined"
                    )
                  }
                  className={`flex h-[36px] w-full items-center justify-center gap-1.5 rounded-full px-4 text-[14px] font-medium transition-colors ${
                    isQuarantined
                      ? "bg-[#0F0F0F] text-[#FFFFFF] hover:bg-[#272727]"
                      : "bg-[#FF0000] text-[#FFFFFF] hover:bg-[#CC0000]"
                  }`}
                >
                  <ShieldOff className="h-4 w-4" />
                  {isQuarantined
                    ? "Lift Quarantine & Restore Agent"
                    : "Quarantine Agent Immediately"}
                </button>
              </div>
            );
          })}
        </div>
      )}

      {/* TAB 5: WORM AUDIT LEDGER */}
      {activeTab === "worm" && (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          <div className="flex items-center justify-between">
            <span className="rounded-[2px] bg-[#2BA640] px-2 py-0.5 text-[12px] font-medium text-[#FFFFFF] uppercase">
              WORM COMPLIANCE ACTIVE
            </span>
            <span className="text-[12px] text-[#606060] uppercase font-mono">
              ISO 42001 Verified
            </span>
          </div>

          <div className="rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-3.5 space-y-3">
            <div className="flex items-center gap-2 text-[14px] font-medium text-[#0F0F0F]">
              <Lock className="h-4 w-4 text-[#2BA640]" />
              Cryptographic Hash Chain (Tamper-Proof)
            </div>
            <div className="text-[12px] text-[#606060] leading-[18px]">
              Every tool call, AST verdict, and human sign-off is committed to a backward-linked SHA-256 block ledger.
            </div>

            <div className="rounded-[8px] bg-[#F2F2F2] p-2.5 space-y-1 font-mono text-[11px]">
              <div className="text-[#606060]">Current Block Height: #00000142</div>
              <div className="text-[#0F0F0F] break-all">
                Merkle Root: 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
              </div>
              <div className="text-[#606060] break-all">
                Prev Block:  4bf92f3577b34da6a3ce929d0e0e4736f82109ba221980ca8127391ab9128032
              </div>
            </div>
          </div>

          <div className="rounded-[8px] bg-[#F2F2F2] p-3 text-[12px] text-[#0F0F0F] flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-[#2BA640] shrink-0" />
            <span>142/142 blocks cryptographically verified with 0 Merkle discrepancies.</span>
          </div>
        </div>
      )}
    </aside>
  );
}
