"use client";

import React from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Database,
  FileText,
  KeyRound,
  Hand,
  Cloud,
  CheckCircle2,
} from "lucide-react";

/**
 * 1. UNTRUSTED INPUT / INGESTION VECTOR NODE
 */
export function InputVectorNode({ data }: NodeProps) {
  const isPoisoned = Boolean(data.isPoisoned);
  return (
    <div
      className={`w-64 rounded-[12px] bg-[#FFFFFF] p-3 border shadow-sm ${
        isPoisoned ? "border-[#FF0000]" : "border-[#E5E5E5]"
      }`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="inline-flex items-center gap-1.5 rounded-[4px] bg-[#F2F2F2] px-2 py-0.5 text-[12px] font-medium text-[#0F0F0F]">
          <FileText className="h-3.5 w-3.5 text-[#606060]" />
          {String(data.vectorType || "RAG INGESTION")}
        </span>
        {isPoisoned ? (
          <span className="rounded-[2px] bg-[#FF0000] px-1.5 py-0.5 text-[11px] font-bold text-[#FFFFFF]">
            CONTAINED
          </span>
        ) : (
          <span className="rounded-[2px] bg-[#F2F2F2] px-1.5 py-0.5 text-[11px] font-medium text-[#606060]">
            EXTERNAL
          </span>
        )}
      </div>

      <div className="text-[14px] leading-[20px] font-medium text-[#0F0F0F] line-clamp-2 mb-1">
        {String(data.label)}
      </div>

      <div className="text-[12px] leading-[16px] font-mono text-[#606060] line-clamp-2 bg-[#F2F2F2] p-2 rounded-[8px]">
        {String(data.preview)}
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!h-2.5 !w-2.5 !border-2 !border-[#FFFFFF] !bg-[#606060]"
      />
    </div>
  );
}

/**
 * 2. AGENT POSTURE NODE (Radial Arc Ring + Channel Metadata)
 */
export function AgentRingNode({ data }: NodeProps) {
  const riskScore = Number(data.riskScore ?? 50);
  const isPaused = Number(data.hitlPendingCount ?? 0) > 0;
  const radius = 20;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset =
    circumference -
    (Math.min(100, Math.max(0, riskScore)) / 100) * circumference;

  const ringColor =
    riskScore >= 75 ? "#FF0000" : isPaused || riskScore >= 40 ? "#FB8C00" : "#2BA640";

  return (
    <div
      className={`w-72 rounded-[12px] bg-[#FFFFFF] p-3.5 border shadow-sm ${
        isPaused ? "border-[#FB8C00]" : "border-[#E5E5E5]"
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-[#FFFFFF] !bg-[#606060]"
      />

      <div className="flex items-start gap-3">
        <div className="relative flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-[#F2F2F2]">
          <svg className="h-12 w-12 -rotate-90 transform" viewBox="0 0 48 48">
            <circle
              cx="24"
              cy="24"
              r={radius}
              stroke="#E5E5E5"
              strokeWidth="3.5"
              fill="transparent"
            />
            <circle
              cx="24"
              cy="24"
              r={radius}
              stroke={ringColor}
              strokeWidth="3.5"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              fill="transparent"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-[11px] font-mono font-bold text-[#0F0F0F]">
              {riskScore}
            </span>
          </div>
        </div>

        <div className="min-w-0 flex-1">
          <div className="text-[14px] leading-[20px] font-medium text-[#0F0F0F] line-clamp-2">
            {String(data.label)}
          </div>
          <div className="text-[12px] leading-[16px] text-[#606060] mt-0.5 truncate">
            {String(data.framework)} • {String(data.environment)}
          </div>
          <div className="text-[12px] leading-[16px] text-[#606060] mt-0.5">
            {String(data.p99FirewallMs)}ms p99 • {String(data.blockedAttacksCount)} contained
          </div>
        </div>
      </div>

      {isPaused && (
        <div className="mt-3 flex items-center justify-between rounded-[4px] bg-[#FFF8E1] border border-[#FB8C00]/40 px-2.5 py-1 text-[12px] font-medium text-[#0F0F0F]">
          <span className="flex items-center gap-1.5">
            <Hand className="h-3.5 w-3.5 text-[#FB8C00]" />
            Four-Eyes HITL Circuit Breaker
          </span>
          <span className="text-[11px] font-mono text-[#606060]">PAUSED</span>
        </div>
      )}

      <Handle
        type="source"
        position={Position.Right}
        className="!h-2.5 !w-2.5 !border-2 !border-[#FFFFFF] !bg-[#0F0F0F]"
      />
    </div>
  );
}

/**
 * 3. ZERO-TRUST AGENTWALL & AST GUARD GATE NODE
 */
export function GuardGateNode({ data }: NodeProps) {
  const verdict = String(data.verdict ?? "allow");

  return (
    <div
      className={`w-72 rounded-[12px] bg-[#FFFFFF] p-3.5 border shadow-sm ${
        verdict === "blocked"
          ? "border-[#FF0000]"
          : verdict === "hitl_paused"
            ? "border-[#FB8C00]"
            : "border-[#2BA640]"
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-[#FFFFFF] !bg-[#606060]"
      />

      <div className="flex items-center justify-between mb-2">
        <span className="inline-flex items-center gap-1.5 text-[12px] font-bold text-[#0F0F0F]">
          {verdict === "blocked" ? (
            <ShieldAlert className="h-4 w-4 text-[#FF0000]" />
          ) : verdict === "hitl_paused" ? (
            <Hand className="h-4 w-4 text-[#FB8C00]" />
          ) : (
            <ShieldCheck className="h-4 w-4 text-[#2BA640]" />
          )}
          AgentWall AST Gate
        </span>

        <span className="rounded-[4px] bg-[#0F0F0F] px-2 py-0.5 text-[11px] font-mono font-medium text-[#FFFFFF]">
          {String(data.latencyMs || 0.16)}ms
        </span>
      </div>

      <div className="text-[13px] leading-[18px] font-mono font-semibold text-[#0F0F0F] truncate mb-1">
        {String(data.toolName)}()
      </div>

      <div className="text-[11px] leading-[16px] text-[#606060]">
        AST Allowlists • Delegated RBAC • Row Cap 50
      </div>

      <div className="mt-2.5 pt-2 border-t border-[#E5E5E5] flex items-center justify-between text-[11px]">
        <span className="text-[#606060]">Firewall Decision</span>
        {verdict === "blocked" ? (
          <span className="rounded-[3px] bg-[#FF0000] px-1.5 py-0.5 text-[10px] font-bold text-[#FFFFFF] tracking-wider uppercase">
            BLOCKED
          </span>
        ) : verdict === "hitl_paused" ? (
          <span className="rounded-[3px] bg-[#FB8C00] px-1.5 py-0.5 text-[10px] font-bold text-[#FFFFFF] tracking-wider uppercase">
            REVIEW PENDING
          </span>
        ) : (
          <span className="rounded-[3px] bg-[#2BA640] px-1.5 py-0.5 text-[10px] font-bold text-[#FFFFFF] tracking-wider uppercase">
            CONTAINED &amp; ALLOWED
          </span>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!h-2.5 !w-2.5 !border-2 !border-[#FFFFFF] !bg-[#0F0F0F]"
      />
    </div>
  );
}

/**
 * 4. MULTI-CLOUD TARGET RESOURCE & JIT EPHEMERAL STS NODE
 */
export function CloudResourceNode({ data }: NodeProps) {
  const tokenJti = data.tokenJti ? String(data.tokenJti) : null;
  const cloudProvider = String(data.cloudProvider || "gcp").toLowerCase();

  const providerBadge =
    cloudProvider === "aws"
      ? { label: "AWS STS", bg: "bg-[#FF9900]/10 text-[#FF9900] border-[#FF9900]/30" }
      : cloudProvider === "azure"
        ? { label: "AZURE ENTRA ID", bg: "bg-[#0078D4]/10 text-[#0078D4] border-[#0078D4]/30" }
        : cloudProvider === "saas"
          ? { label: "SAAS TOKEN", bg: "bg-[#24292E]/10 text-[#24292E] border-[#24292E]/30" }
          : { label: "GCP STS CAB", bg: "bg-[#4285F4]/10 text-[#4285F4] border-[#4285F4]/30" };

  return (
    <div className="w-72 rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-3.5 shadow-sm">
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-[#FFFFFF] !bg-[#606060]"
      />

      <div className="flex items-center justify-between mb-2">
        <span className={`inline-flex items-center gap-1.5 rounded-[4px] border px-2 py-0.5 text-[11px] font-bold ${providerBadge.bg}`}>
          <Cloud className="h-3.5 w-3.5" />
          {String(data.serviceType || providerBadge.label)}
        </span>
        {tokenJti ? (
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-[#2BA640]">
            <KeyRound className="h-3 w-3" />
            JIT Active (30s)
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-[11px] text-[#606060]">
            <Lock className="h-3 w-3" />
            0 Standing IAM
          </span>
        )}
      </div>

      <div className="text-[13px] leading-[18px] font-semibold text-[#0F0F0F] mb-1">
        {String(data.label)}
      </div>

      <div className="text-[11px] leading-[15px] font-mono text-[#065FD4] break-all bg-[#F2F2F2] p-2 rounded-[8px] mb-2">
        {String(data.resourceUri)}
      </div>

      <div className="text-[11px] leading-[15px] text-[#606060] flex items-center justify-between">
        <span>Bound Scope:</span>
        <span className="text-[#0F0F0F] font-mono font-medium truncate max-w-[150px]">{String(data.cabRole)}</span>
      </div>
    </div>
  );
}
