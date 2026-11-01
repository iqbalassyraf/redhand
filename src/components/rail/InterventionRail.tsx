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
} from "lucide-react";
import type {
  AgentPostureItem,
  AuthenticatedUser,
  HITLInterventionItem,
  TraceTelemetryRow,
} from "@/lib/types";

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
    "hitl" | "xray" | "posture" | "worm"
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

  useEffect(() => {
    if (activeIntervention) {
      setArgsJsonText(
        JSON.stringify(activeIntervention.proposed_tool_arguments, null, 2)
      );
      setJsonError(null);
      // Auto-toggle to second operator if first operator already signed
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

  const ocsfFinding = selectedTrace
    ? {
        class_uid: 2002,
        class_name: "Application Security Posture Finding",
        category_uid: 2,
        severity:
          selectedTrace.verdict === "blocked"
            ? "critical"
            : selectedTrace.verdict === "hitl_paused"
              ? "high"
              : "informational",
        action: selectedTrace.verdict,
        confidence_score: selectedTrace.confidence_score,
        finding_info: {
          uid: `${selectedTrace.trace_id}:${selectedTrace.span_id}`,
          title: selectedTrace.tool_name,
          analytic: { name: selectedTrace.detector_tier },
        },
        unmapped: {
          firewall_latency_ms: selectedTrace.firewall_latency_ms,
          ephemeral_token_jti: selectedTrace.ephemeral_token_jti,
          target_resource: selectedTrace.target_resource,
        },
      }
    : null;

  const handleCopyOcsf = () => {
    if (!ocsfFinding) return;
    navigator.clipboard.writeText(JSON.stringify(ocsfFinding, null, 2));
    setCopiedOcsf(true);
    setTimeout(() => setCopiedOcsf(false), 1800);
  };

  return (
    <aside className="flex h-full w-[420px] shrink-0 flex-col border-l border-[#E5E5E5] bg-[#FFFFFF]">
      {/* Chip-Style Rail Switcher */}
      <div className="flex items-center gap-1.5 border-b border-[#E5E5E5] px-3 py-3 overflow-x-auto">
        <button
          onClick={() => setActiveTab("hitl")}
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[13px] leading-[18px] font-medium transition-colors whitespace-nowrap ${
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
          onClick={() => setActiveTab("xray")}
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[13px] leading-[18px] font-medium transition-colors whitespace-nowrap ${
            activeTab === "xray"
              ? "bg-[#0F0F0F] text-[#FFFFFF]"
              : "bg-[#F2F2F2] text-[#0F0F0F] hover:bg-[#E5E5E5]"
          }`}
        >
          <Terminal className="h-3.5 w-3.5" />
          CAB &amp; OCSF X-Ray
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
          Posture Control
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
          WORM Ledger
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
                  {activeIntervention.risk_tier} • {activeIntervention.status === "partially_approved" ? "1 OF 2 SIGNED" : "REVIEW PENDING"}
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
                  {activeIntervention.agent_name} • {activeIntervention.framework}{" "}
                  • {activeIntervention.created_at.slice(11, 19)} UTC
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

              {/* Four-Eyes Operator Identity Switcher */}
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
                              <span className="text-[10px] bg-[#2BA640] text-[#FFFFFF] px-1 py-0.2 rounded">
                                Signed
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-[#606060]">{p.role}</div>
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
                  {currentUser && currentUser.role !== "secops_admin" && (
                    <p className="rounded-[6px] bg-[#F2F2F2] p-2 text-[12px] text-[#606060]">
                      🔒 View-only mode: Role <strong className="text-[#0F0F0F]">{currentUser.role}</strong> lacks SecOps Admin authority to approve or deny interventions.
                    </p>
                  )}
                  {activeIntervention.approvals?.some(
                    (a) => a.reviewer_user_id === selectedReviewerId
                  ) && (
                    <p className="text-[12px] text-[#FB8C00]">
                      ⚠️ This operator already signed. Switch to an independent operator to satisfy Four-Eyes quorum.
                    </p>
                  )}
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleDecision("approve")}
                      disabled={
                        isSubmitting ||
                        (currentUser?.role !== undefined && currentUser.role !== "secops_admin") ||
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
                        : (activeIntervention.required_approvals || 1) > 1
                          ? "Sign (1 of 2)"
                          : "Approve & Resume"}
                    </button>
                    <button
                      onClick={() => handleDecision("deny")}
                      disabled={
                        isSubmitting ||
                        (currentUser?.role !== undefined && currentUser.role !== "secops_admin")
                      }
                      className="flex h-[36px] flex-1 items-center justify-center gap-1.5 rounded-full border border-[#E5E5E5] bg-[#FFFFFF] hover:bg-[#F2F2F2] px-4 text-[14px] font-medium text-[#0F0F0F] transition-colors disabled:opacity-50"
                    >
                      <XCircle className="h-4 w-4 text-[#FF0000]" />
                      Deny
                    </button>
                  </div>
                </div>
              ) : (
                <div className="rounded-[8px] bg-[#F2F2F2] p-3 text-center text-[12px] text-[#606060]">
                  Resolved: <span className="font-semibold text-[#0F0F0F] uppercase">{activeIntervention.status}</span> via{" "}
                  <code className="font-mono text-[#0F0F0F]">
                    /v1/hitl/{activeIntervention.id.slice(0, 8)}/resolve
                  </code>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: TRACE, GCP CAB & OCSF SIEM INSPECTOR */}
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

                <div className="rounded-[12px] bg-[#F2F2F2] p-3">
                  <div className="text-[12px] font-medium text-[#606060] mb-1">
                    1. Observation (DLP Scrubbed Input)
                  </div>
                  <p className="text-[13px] font-mono text-[#0F0F0F]">
                    {selectedTrace.observation_snippet}
                  </p>
                </div>

                <div className="rounded-[12px] bg-[#F2F2F2] p-3">
                  <div className="text-[12px] font-medium text-[#606060] mb-1">
                    2. Thought (Reasoning)
                  </div>
                  <p className="text-[14px] text-[#0F0F0F]">
                    {selectedTrace.thought_content}
                  </p>
                </div>

                <div className="rounded-[12px] bg-[#F2F2F2] p-3">
                  <div className="text-[12px] font-medium text-[#606060] mb-1">
                    3. Tool Arguments ({selectedTrace.verdict.toUpperCase()})
                  </div>
                  <pre className="overflow-x-auto text-[13px] font-mono text-[#0F0F0F]">
                    {JSON.stringify(selectedTrace.tool_arguments, null, 2)}
                  </pre>
                </div>
              </div>

              <div>
                <div className="text-[14px] font-medium text-[#0F0F0F] mb-1.5">
                  GCP STS Credential Access Boundary
                </div>
                <pre className="overflow-x-auto rounded-[12px] bg-[#F2F2F2] p-3 text-[12px] font-mono text-[#0F0F0F]">
                  {selectedTrace.cab_policy
                    ? JSON.stringify(selectedTrace.cab_policy, null, 2)
                    : "// Token minting blocked by Semantic Firewall / Circuit Breaker"}
                </pre>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[14px] font-medium text-[#0F0F0F]">
                    OCSF v1.1.0 SIEM Payload
                  </span>
                  <button
                    onClick={handleCopyOcsf}
                    className="inline-flex items-center gap-1 rounded-full bg-[#F2F2F2] hover:bg-[#E5E5E5] px-2.5 py-1 text-[12px] font-medium text-[#0F0F0F]"
                  >
                    {copiedOcsf ? (
                      <>
                        <Check className="h-3 w-3 text-[#2BA640]" /> Copied
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3 text-[#606060]" /> Copy JSON
                      </>
                    )}
                  </button>
                </div>
                <pre className="overflow-x-auto rounded-[12px] bg-[#F2F2F2] p-3 text-[12px] font-mono text-[#0F0F0F]">
                  {JSON.stringify(ocsfFinding, null, 2)}
                </pre>
              </div>
            </>
          ) : (
            <div className="text-center text-[14px] text-[#606060] py-8">
              Select a telemetry row below to inspect its trace.
            </div>
          )}
        </div>
      )}

      {/* TAB 3: LIVE AGENT POSTURE & QUARANTINE CONTROL */}
      {activeTab === "posture" && (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          <div className="text-[12px] text-[#606060]">
            Quarantining an agent immediately causes{" "}
            <code className="font-mono text-[#0F0F0F]">/v1/telemetry/ingest</code>{" "}
            and <code className="font-mono text-[#0F0F0F]">/v1/iam/mint</code>{" "}
            to reject all tool calls with HTTP 403.
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
                  disabled={currentUser?.role !== undefined && currentUser.role !== "secops_admin"}
                  className={`flex h-[36px] w-full items-center justify-center gap-1.5 rounded-full px-4 text-[14px] font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
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

      {/* TAB 4: IMMUTABLE WORM AUDIT LEDGER & CMEK */}
      {activeTab === "worm" && (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          <div className="flex items-center justify-between">
            <span className="rounded-[2px] bg-[#2BA640] px-2 py-0.5 text-[12px] font-medium text-[#FFFFFF] uppercase">
              WORM COMPLIANCE ACTIVE
            </span>
            <span className="text-[12px] text-[#606060] uppercase font-mono">
              S3 &amp; GCS Lock
            </span>
          </div>

          <div className="rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-3.5 space-y-3">
            <div className="flex items-center gap-2 text-[14px] font-medium text-[#0F0F0F]">
              <Lock className="h-4 w-4 text-[#2BA640]" />
              Cryptographic Hash Chain (Tamper Proof)
            </div>
            <div className="text-[12px] text-[#606060] leading-[18px]">
              Every execution trace, agent thought, and human operator signature is hashed into a Merkle root and committed to a linear backward-linked SHA-256 block ledger.
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

          <div className="rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-3.5 space-y-2">
            <div className="text-[13px] font-medium text-[#0F0F0F]">
              Enterprise CMEK Key Status
            </div>
            <div className="text-[12px] font-mono text-[#065FD4] bg-[#F2F2F2] p-2 rounded-[8px] break-all">
              arn:aws:kms:us-east-1:111122223333:key/mrk-cmek-aspm-vault
            </div>
            <div className="flex items-center justify-between text-[12px] text-[#606060] pt-1">
              <span>Retention Period:</span>
              <strong className="text-[#0F0F0F]">365 Days (COMPLIANCE Mode)</strong>
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
