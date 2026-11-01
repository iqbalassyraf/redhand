"use client";

import React from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Cpu,
  Database,
  FileText,
  KeyRound,
  Hand,
} from "lucide-react";

/**
 * 1. UNTRUSTED INPUT / INGESTION VECTOR NODE (Red Broadcast Flat Card)
 */
export function InputVectorNode({ data }: NodeProps) {
  const isPoisoned = Boolean(data.isPoisoned);
  return (
    <div
      className={`w-64 rounded-[12px] bg-[#FFFFFF] p-3 border ${
        isPoisoned ? "border-[#FF0000]" : "border-[#E5E5E5]"
      }`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="inline-flex items-center gap-1.5 rounded-[4px] bg-[#F2F2F2] px-2 py-0.5 text-[12px] font-medium text-[#0F0F0F]">
          <FileText className="h-3.5 w-3.5 text-[#606060]" />
          {String(data.vectorType || "RAG INGESTION")}
        </span>
        {isPoisoned ? (
          <span className="rounded-[2px] bg-[#FF0000] px-1.5 py-0.5 text-[11px] font-medium text-[#FFFFFF]">
            STRIKE
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
 * 2. AGENT POSTURE NODE (Clean 36px Avatar + Radial Arc + "Channel • Views • Time" Metadata)
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
      className={`w-72 rounded-[12px] bg-[#FFFFFF] p-3.5 border ${
        isPaused ? "border-[#FB8C00]" : "border-[#E5E5E5]"
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-[#FFFFFF] !bg-[#606060]"
      />

      <div className="flex items-start gap-3">
        {/* Clean 48px Radial Risk Avatar */}
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

        {/* Title + Metadata in "Channel • Views • Time" compact format */}
        <div className="min-w-0 flex-1">
          <div className="text-[14px] leading-[20px] font-medium text-[#0F0F0F] line-clamp-2">
            {String(data.label)}
          </div>
          <div className="text-[12px] leading-[16px] text-[#606060] mt-0.5 truncate">
            {String(data.framework)} • {String(data.environment)}
          </div>
          <div className="text-[12px] leading-[16px] text-[#606060] mt-0.5">
            {String(data.p99FirewallMs)}ms p99 • {String(data.blockedAttacksCount)} strikes
          </div>
        </div>
      </div>

      {isPaused && (
        <div className="mt-3 flex items-center justify-between rounded-[4px] bg-[#FFF8E1] border border-[#FB8C00]/40 px-2.5 py-1 text-[12px] font-medium text-[#0F0F0F]">
          <span className="flex items-center gap-1.5">
            <Hand className="h-3.5 w-3.5 text-[#FB8C00]" />
            Review Pending (HITL)
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
 * 3. @guard INTERCEPTOR & <50MS ONNX SEMANTIC FIREWALL GATE NODE
 */
export function GuardGateNode({ data }: NodeProps) {
  const verdict = String(data.verdict ?? "allow");

  return (
    <div
      className={`w-64 rounded-[12px] bg-[#FFFFFF] p-3.5 border ${
        verdict === "blocked"
          ? "border-[#FF0000]"
          : verdict === "hitl_paused"
            ? "border-[#FB8C00]"
            : "border-[#E5E5E5]"
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-[#FFFFFF] !bg-[#606060]"
      />

      <div className="flex items-center justify-between mb-2">
        <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-[#0F0F0F]">
          {verdict === "blocked" ? (
            <ShieldAlert className="h-4 w-4 text-[#FF0000]" />
          ) : verdict === "hitl_paused" ? (
            <Hand className="h-4 w-4 text-[#FB8C00]" />
          ) : (
            <ShieldCheck className="h-4 w-4 text-[#2BA640]" />
          )}
          @redhand.guard
        </span>

        {/* Duration-badge style latency indicator */}
        <span className="rounded-[4px] bg-[#0F0F0F] px-2 py-0.5 text-[12px] font-medium text-[#FFFFFF]">
          {String(data.latencyMs)}ms
        </span>
      </div>

      <div className="text-[14px] leading-[20px] font-mono font-medium text-[#0F0F0F] truncate mb-1">
        {String(data.toolName)}()
      </div>

      <div className="text-[12px] leading-[16px] text-[#606060]">
        {String(data.detectorTier)} • {String(data.riskTier)}
      </div>

      <div className="mt-2 pt-2 border-t border-[#E5E5E5] flex items-center justify-between text-[12px]">
        <span className="text-[#606060]">Verdict</span>
        {verdict === "blocked" ? (
          <span className="rounded-[2px] bg-[#FF0000] px-1.5 py-0.5 text-[11px] font-medium text-[#FFFFFF] uppercase">
            BLOCKED
          </span>
        ) : verdict === "hitl_paused" ? (
          <span className="rounded-[2px] bg-[#FB8C00] px-1.5 py-0.5 text-[11px] font-medium text-[#FFFFFF] uppercase">
            REVIEW PENDING
          </span>
        ) : (
          <span className="rounded-[2px] bg-[#2BA640] px-1.5 py-0.5 text-[11px] font-medium text-[#FFFFFF] uppercase">
            VERIFIED
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
 * 4. GCP CLOUD TARGET RESOURCE & EPHEMERAL STS CAB NODE
 */
export function CloudResourceNode({ data }: NodeProps) {
  const tokenJti = data.tokenJti ? String(data.tokenJti) : null;

  return (
    <div className="w-72 rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-3.5">
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-[#FFFFFF] !bg-[#606060]"
      />

      <div className="flex items-center justify-between mb-2">
        <span className="inline-flex items-center gap-1.5 rounded-[4px] bg-[#F2F2F2] px-2 py-0.5 text-[12px] font-medium text-[#0F0F0F]">
          <Database className="h-3.5 w-3.5 text-[#606060]" />
          {String(data.serviceType || "GCP RESOURCE")}
        </span>
        {tokenJti ? (
          <span className="inline-flex items-center gap-1 text-[12px] font-medium text-[#2BA640]">
            <KeyRound className="h-3.5 w-3.5" />
            JIT Active
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-[12px] text-[#606060]">
            <Lock className="h-3.5 w-3.5" />
            0 Standing IAM
          </span>
        )}
      </div>

      <div className="text-[14px] leading-[20px] font-medium text-[#0F0F0F] mb-1">
        {String(data.label)}
      </div>

      <div className="text-[12px] leading-[16px] font-mono text-[#065FD4] break-all bg-[#F2F2F2] p-2 rounded-[8px] mb-2">
        {String(data.resourceUri)}
      </div>

      <div className="text-[12px] leading-[16px] text-[#606060]">
        CAB Role: <span className="text-[#0F0F0F] font-medium">{String(data.cabRole)}</span>
      </div>
    </div>
  );
}
