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
      className={`w-64 rounded-[12px] bg-rh-card p-3 border ${
        isPoisoned ? "border-rh-crimson" : "border-rh-hairline"
      }`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="inline-flex items-center gap-1.5 rounded-[4px] bg-rh-elevated px-2 py-0.5 text-[12px] font-medium text-rh-text">
          <FileText className="h-3.5 w-3.5 text-rh-text-2" />
          {String(data.vectorType || "RAG INGESTION")}
        </span>
        {isPoisoned ? (
          <span className="rounded-[2px] bg-rh-crimson px-1.5 py-0.5 text-[11px] font-bold text-rh-canvas">
            CONTAINED
          </span>
        ) : (
          <span className="rounded-[2px] bg-rh-elevated px-1.5 py-0.5 text-[11px] font-medium text-rh-text-2">
            EXTERNAL
          </span>
        )}
      </div>

      <div className="text-[14px] leading-[20px] font-medium text-rh-text line-clamp-2 mb-1">
        {String(data.label)}
      </div>

      <div className="text-[12px] leading-[16px] font-mono text-rh-text-2 line-clamp-2 bg-rh-elevated p-2 rounded-[8px]">
        {String(data.preview)}
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!h-2.5 !w-2.5 !border-2 !border-rh-card !bg-rh-text-2"
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
    riskScore >= 75 ? "var(--rh-crimson)" : isPaused || riskScore >= 40 ? "var(--rh-ochre)" : "var(--rh-teal)";

  return (
    <div
      className={`w-72 rounded-[12px] bg-rh-card p-3.5 border ${
        isPaused ? "border-rh-ochre" : "border-rh-hairline"
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-rh-card !bg-rh-text-2"
      />

      <div className="flex items-start gap-3">
        <div className="relative flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-rh-elevated">
          <svg className="h-12 w-12 -rotate-90 transform" viewBox="0 0 48 48">
            <circle
              cx="24"
              cy="24"
              r={radius}
              stroke="var(--rh-border-hairline)"
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
            <span className="text-[11px] font-mono font-bold text-rh-text">
              {riskScore}
            </span>
          </div>
        </div>

        <div className="min-w-0 flex-1">
          <div className="text-[14px] leading-[20px] font-medium text-rh-text line-clamp-2">
            {String(data.label)}
          </div>
          <div className="text-[12px] leading-[16px] text-rh-text-2 mt-0.5 truncate">
            {String(data.framework)} • {String(data.environment)}
          </div>
          <div className="text-[12px] leading-[16px] text-rh-text-2 mt-0.5">
            {String(data.p99FirewallMs)}ms p99 • {String(data.blockedAttacksCount)} contained
          </div>
        </div>
      </div>

      {isPaused && (
        <div className="mt-3 flex items-center justify-between rounded-[4px] bg-rh-ochre-wash border border-rh-ochre/40 px-2.5 py-1 text-[12px] font-medium text-rh-text">
          <span className="flex items-center gap-1.5">
            <Hand className="h-3.5 w-3.5 text-rh-ochre" />
            Four-Eyes HITL Circuit Breaker
          </span>
          <span className="text-[11px] font-mono text-rh-text-2">PAUSED</span>
        </div>
      )}

      <Handle
        type="source"
        position={Position.Right}
        className="!h-2.5 !w-2.5 !border-2 !border-rh-card !bg-rh-teal"
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
      className={`w-72 rounded-[12px] bg-rh-card p-3.5 border ${
        verdict === "blocked"
          ? "border-rh-crimson"
          : verdict === "hitl_paused"
            ? "border-rh-ochre"
            : "border-rh-teal"
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-rh-card !bg-rh-text-2"
      />

      <div className="flex items-center justify-between mb-2">
        <span className="inline-flex items-center gap-1.5 text-[12px] font-bold text-rh-text">
          {verdict === "blocked" ? (
            <ShieldAlert className="h-4 w-4 text-rh-crimson-text" />
          ) : verdict === "hitl_paused" ? (
            <Hand className="h-4 w-4 text-rh-ochre" />
          ) : (
            <ShieldCheck className="h-4 w-4 text-rh-teal-text" />
          )}
          AgentWall AST Gate
        </span>

        <span className="rounded-[4px] bg-rh-teal px-2 py-0.5 text-[11px] font-mono font-medium text-rh-canvas">
          {String(data.latencyMs || 0.16)}ms
        </span>
      </div>

      <div className="text-[13px] leading-[18px] font-mono font-semibold text-rh-text truncate mb-1">
        {String(data.toolName)}()
      </div>

      <div className="text-[11px] leading-[16px] text-rh-text-2">
        AST Allowlists • Delegated RBAC • Row Cap 50
      </div>

      <div className="mt-2.5 pt-2 border-t border-rh-hairline flex items-center justify-between text-[11px]">
        <span className="text-rh-text-2">Firewall Decision</span>
        {verdict === "blocked" ? (
          <span className="rounded-[3px] bg-rh-crimson px-1.5 py-0.5 text-[10px] font-bold text-rh-canvas tracking-wider uppercase">
            BLOCKED
          </span>
        ) : verdict === "hitl_paused" ? (
          <span className="rounded-[3px] bg-rh-ochre px-1.5 py-0.5 text-[10px] font-bold text-rh-canvas tracking-wider uppercase">
            REVIEW PENDING
          </span>
        ) : (
          <span className="rounded-[3px] bg-rh-teal px-1.5 py-0.5 text-[10px] font-bold text-rh-canvas tracking-wider uppercase">
            CONTAINED &amp; ALLOWED
          </span>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!h-2.5 !w-2.5 !border-2 !border-rh-card !bg-rh-teal"
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
      ? { label: "AWS STS", bg: "bg-rh-ochre/10 text-rh-ochre border-rh-ochre/30" }
      : cloudProvider === "azure"
        ? { label: "AZURE ENTRA ID", bg: "bg-rh-steel/10 text-rh-steel-text border-rh-steel/30" }
        : cloudProvider === "saas"
          ? { label: "SAAS TOKEN", bg: "bg-rh-elevated/10 text-rh-text border-rh-strong/30" }
          : { label: "GCP STS CAB", bg: "bg-rh-steel/10 text-rh-steel-text border-rh-steel/30" };

  return (
    <div className="w-72 rounded-[12px] border border-rh-hairline bg-rh-card p-3.5">
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-rh-card !bg-rh-text-2"
      />

      <div className="flex items-center justify-between mb-2">
        <span className={`inline-flex items-center gap-1.5 rounded-[4px] border px-2 py-0.5 text-[11px] font-bold ${providerBadge.bg}`}>
          <Cloud className="h-3.5 w-3.5" />
          {String(data.serviceType || providerBadge.label)}
        </span>
        {tokenJti ? (
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-rh-teal-text">
            <KeyRound className="h-3 w-3" />
            JIT Active (30s)
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-[11px] text-rh-text-2">
            <Lock className="h-3 w-3" />
            0 Standing IAM
          </span>
        )}
      </div>

      <div className="text-[13px] leading-[18px] font-semibold text-rh-text mb-1">
        {String(data.label)}
      </div>

      <div className="text-[11px] leading-[15px] font-mono text-rh-steel-text break-all bg-rh-elevated p-2 rounded-[8px] mb-2">
        {String(data.resourceUri)}
      </div>

      <div className="text-[11px] leading-[15px] text-rh-text-2 flex items-center justify-between">
        <span>Bound Scope:</span>
        <span className="text-rh-text font-mono font-medium truncate max-w-[150px]">{String(data.cabRole)}</span>
      </div>
    </div>
  );
}
