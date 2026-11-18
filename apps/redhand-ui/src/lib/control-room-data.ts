import type { ControlStatus } from "./tokens";

export type TimeRangeKey = "1h" | "24h" | "7d" | "30d";

export type ControlRoomView =
  | "overview"
  | "node-detail"
  | "policies"
  | "approvals"
  | "audit-log";

export type SpokeCategory = "agents" | "tools" | "data" | "humans" | "models";

export type ProtectionState = "protected" | "unprotected" | "partial";

export interface FunnelStage {
  id: "requests" | "policy_checked" | "flagged" | "resolved";
  step: number;
  label: string;
  count: number;
  percentOfStart: number;
  conversionToNext: number | null;
  tone: "crimson" | "neutral" | "flagged" | "blocked" | "allowed";
}

export interface ActivityBucket {
  label: string;
  allowed: number;
  flagged: number;
  blocked: number;
  pending: number;
}

export interface NodeTraceEvent {
  id: string;
  timestamp: string;
  agent: string;
  toolOrTarget: string;
  status: "allowed" | "flagged" | "blocked" | "pending";
  severity: "critical" | "medium" | "low";
  ruleId: string;
  summary: string;
  latencyMs: number;
}

export interface TopologyNode {
  id: string;
  spokeId: SpokeCategory;
  name: string;
  shortLabel: string;
  subtitle: string;
  kind: "spoke" | "child";
  category: SpokeCategory;
  protection: ProtectionState;
  protectedRatio: number;
  status: "allowed" | "flagged" | "blocked" | "pending";
  severity: "critical" | "medium" | "low";
  riskScore: number;
  endpointCount: number;
  hasNewThreatPulse?: boolean;
  frameworkOrProvider: string;
  environment: "production" | "staging" | "development";
  lastSeen: string;
  kpis: {
    requests: number;
    policyChecked: number;
    flagged: number;
    blocked: number;
    approved: number;
    pendingApproval: number;
    p99LatencyMs: number;
    spendUsd: number;
  };
  funnel: FunnelStage[];
  activitySeries: ActivityBucket[];
  recentEvents: NodeTraceEvent[];
}

export interface OverviewSnapshot {
  label: string;
  hub: {
    agentsUnderControl: number;
    riskyActionsCount: number;
    blockedThreatsCount: number;
    totalEndpoints: number;
  };
  summary: {
    blocked: number;
    flagged: number;
    allowed: number;
    pendingApproval: number;
    inboundTraffic: string;
    inboundDelta: string;
    outboundCalls: string;
    outboundDelta: string;
    logsAnalyzed: string;
    logsDelta: string;
    mcpServers: number;
    mcpDelta: string;
    activeWorkloads: string;
    workloadsDelta: string;
    p99Latency: string;
  };
  severityBreakdown: Array<{
    id: "critical" | "medium" | "low";
    label: string;
    count: number;
    color: string;
    dotClass: string;
  }>;
  categoryBreakdown: Array<{
    id: string;
    label: string;
    count: number;
    color: string;
    dotClass: string;
  }>;
}

export interface PolicyItem {
  id: string;
  name: string;
  category: SpokeCategory | "all";
  mode: "enforce" | "watch" | "off";
  status: ControlStatus;
  scopeSummary: string;
  triggered24h: number;
  blocked24h: number;
  updatedAt: string;
}

export interface ApprovalRequestItem {
  id: string;
  agentName: string;
  agentId: string;
  toolName: string;
  targetResource: string;
  requestedBy: string;
  riskTier: "critical" | "destructive" | "state_mutation";
  severity: "critical" | "medium" | "low";
  status: "pending" | "allowed" | "blocked";
  signaturesHave: number;
  signaturesNeed: number;
  justification: string;
  createdAt: string;
  expiresIn: string;
}

export interface AuditLogEntry {
  id: string;
  at: string;
  actor: string;
  actorKind: "human" | "gateway" | "risk_engine" | "sdk";
  action: string;
  target: string;
  category: SpokeCategory;
  verdict: "allowed" | "flagged" | "blocked" | "pending";
  reason: string;
}

export const TIME_RANGE_OPTIONS: Array<{ key: TimeRangeKey; label: string }> = [
  { key: "1h", label: "Past 1 hour" },
  { key: "24h", label: "Past 24 hours" },
  { key: "7d", label: "Past 7 days" },
  { key: "30d", label: "Past 30 days" },
];

export const OVERVIEW_SNAPSHOTS: Record<TimeRangeKey, OverviewSnapshot> = {
  "1h": {
    label: "Past 1 hour",
    hub: {
      agentsUnderControl: 18,
      riskyActionsCount: 11,
      blockedThreatsCount: 28,
      totalEndpoints: 132,
    },
    summary: {
      blocked: 28,
      flagged: 19,
      allowed: 2840,
      pendingApproval: 4,
      inboundTraffic: "184 MB",
      inboundDelta: "up 3%",
      outboundCalls: "2.8K",
      outboundDelta: "up 4%",
      logsAnalyzed: "38.4 KB",
      logsDelta: "up 2%",
      mcpServers: 9,
      mcpDelta: "0%",
      activeWorkloads: "1.6K",
      workloadsDelta: "down 2%",
      p99Latency: "0.16 ms",
    },
    severityBreakdown: [
      { id: "critical", label: "Critical", count: 14, color: "#EF4444", dotClass: "bg-red-500" },
      { id: "medium", label: "Medium", count: 9, color: "#F59E0B", dotClass: "bg-amber-400" },
      { id: "low", label: "Low", count: 24, color: "#94A3B8", dotClass: "bg-slate-400" },
    ],
    categoryBreakdown: [
      { id: "prompt_injection", label: "Prompt Injection", count: 15, color: "#E11D48", dotClass: "bg-rose-500" },
      { id: "scope_rbac", label: "Scope & RBAC", count: 13, color: "#38BDF8", dotClass: "bg-sky-400" },
      { id: "dlp_secrets", label: "DLP & Secrets", count: 10, color: "#10B981", dotClass: "bg-emerald-400" },
      { id: "unapproved_model", label: "Unapproved Model", count: 9, color: "#F59E0B", dotClass: "bg-amber-400" },
    ],
  },
  "24h": {
    label: "Past 24 hours",
    hub: {
      agentsUnderControl: 18,
      riskyActionsCount: 60,
      blockedThreatsCount: 314,
      totalEndpoints: 132,
    },
    summary: {
      blocked: 314,
      flagged: 162,
      allowed: 46920,
      pendingApproval: 14,
      inboundTraffic: "2.5 GB",
      inboundDelta: "down 5%",
      outboundCalls: "46.9K",
      outboundDelta: "up 8%",
      logsAnalyzed: "456.8 KB",
      logsDelta: "up 12%",
      mcpServers: 9,
      mcpDelta: "0%",
      activeWorkloads: "1.6K",
      workloadsDelta: "down 13%",
      p99Latency: "0.16 ms",
    },
    severityBreakdown: [
      { id: "critical", label: "Critical", count: 154, color: "#EF4444", dotClass: "bg-red-500" },
      { id: "medium", label: "Medium", count: 79, color: "#F59E0B", dotClass: "bg-amber-400" },
      { id: "low", label: "Low", count: 243, color: "#94A3B8", dotClass: "bg-slate-400" },
    ],
    categoryBreakdown: [
      { id: "prompt_injection", label: "Prompt Injection", count: 162, color: "#E11D48", dotClass: "bg-rose-500" },
      { id: "scope_rbac", label: "Scope & RBAC", count: 154, color: "#38BDF8", dotClass: "bg-sky-400" },
      { id: "dlp_secrets", label: "DLP & Secrets", count: 81, color: "#10B981", dotClass: "bg-emerald-400" },
      { id: "unapproved_model", label: "Unapproved Model", count: 79, color: "#F59E0B", dotClass: "bg-amber-400" },
    ],
  },
  "7d": {
    label: "Past 7 days",
    hub: {
      agentsUnderControl: 18,
      riskyActionsCount: 248,
      blockedThreatsCount: 1940,
      totalEndpoints: 132,
    },
    summary: {
      blocked: 1940,
      flagged: 1120,
      allowed: 312400,
      pendingApproval: 14,
      inboundTraffic: "16.8 GB",
      inboundDelta: "up 9%",
      outboundCalls: "315K",
      outboundDelta: "up 14%",
      logsAnalyzed: "3.1 MB",
      logsDelta: "up 6%",
      mcpServers: 9,
      mcpDelta: "up 1",
      activeWorkloads: "1.8K",
      workloadsDelta: "up 4%",
      p99Latency: "0.17 ms",
    },
    severityBreakdown: [
      { id: "critical", label: "Critical", count: 942, color: "#EF4444", dotClass: "bg-red-500" },
      { id: "medium", label: "Medium", count: 598, color: "#F59E0B", dotClass: "bg-amber-400" },
      { id: "low", label: "Low", count: 1520, color: "#94A3B8", dotClass: "bg-slate-400" },
    ],
    categoryBreakdown: [
      { id: "prompt_injection", label: "Prompt Injection", count: 1012, color: "#E11D48", dotClass: "bg-rose-500" },
      { id: "scope_rbac", label: "Scope & RBAC", count: 880, color: "#38BDF8", dotClass: "bg-sky-400" },
      { id: "dlp_secrets", label: "DLP & Secrets", count: 618, color: "#10B981", dotClass: "bg-emerald-400" },
      { id: "unapproved_model", label: "Unapproved Model", count: 550, color: "#F59E0B", dotClass: "bg-amber-400" },
    ],
  },
  "30d": {
    label: "Past 30 days",
    hub: {
      agentsUnderControl: 21,
      riskyActionsCount: 890,
      blockedThreatsCount: 7420,
      totalEndpoints: 146,
    },
    summary: {
      blocked: 7420,
      flagged: 4190,
      allowed: 1284000,
      pendingApproval: 14,
      inboundTraffic: "68.4 GB",
      inboundDelta: "up 21%",
      outboundCalls: "1.29M",
      outboundDelta: "up 19%",
      logsAnalyzed: "14.2 MB",
      logsDelta: "up 15%",
      mcpServers: 11,
      mcpDelta: "up 3",
      activeWorkloads: "2.1K",
      workloadsDelta: "up 11%",
      p99Latency: "0.16 ms",
    },
    severityBreakdown: [
      { id: "critical", label: "Critical", count: 3610, color: "#EF4444", dotClass: "bg-red-500" },
      { id: "medium", label: "Medium", count: 2390, color: "#F59E0B", dotClass: "bg-amber-400" },
      { id: "low", label: "Low", count: 5610, color: "#94A3B8", dotClass: "bg-slate-400" },
    ],
    categoryBreakdown: [
      { id: "prompt_injection", label: "Prompt Injection", count: 4020, color: "#E11D48", dotClass: "bg-rose-500" },
      { id: "scope_rbac", label: "Scope & RBAC", count: 3540, color: "#38BDF8", dotClass: "bg-sky-400" },
      { id: "dlp_secrets", label: "DLP & Secrets", count: 2110, color: "#10B981", dotClass: "bg-emerald-400" },
      { id: "unapproved_model", label: "Unapproved Model", count: 1940, color: "#F59E0B", dotClass: "bg-amber-400" },
    ],
  },
};

function buildSeries(base: number, spikeHour: number, blockBase: number): ActivityBucket[] {
  const hours = ["00:00", "02:00", "04:00", "06:00", "08:00", "10:00", "12:00", "14:00", "16:00", "18:00", "20:00", "22:00"];
  return hours.map((label, idx) => {
    const wave = Math.sin((idx / hours.length) * Math.PI) * 0.65 + 0.55;
    const spike = idx === spikeHour ? 2.4 : 1;
    const allowed = Math.round(base * wave);
    const flagged = Math.round((blockBase * 0.6 + idx) * spike);
    const blocked = Math.round(blockBase * wave * spike);
    const pending = idx >= 9 ? Math.max(1, Math.round(blockBase * 0.12)) : 0;
    return { label, allowed, flagged, blocked, pending };
  });
}

function buildFunnel(
  requests: number,
  policyChecked: number,
  flagged: number,
  resolved: number,
  resolvedTone: "blocked" | "allowed"
): FunnelStage[] {
  const pct = (n: number, d: number) => (d > 0 ? Math.round((n / d) * 1000) / 10 : 0);
  return [
    {
      id: "requests",
      step: 1,
      label: "Requests",
      count: requests,
      percentOfStart: 100,
      conversionToNext: pct(policyChecked, requests),
      tone: "crimson",
    },
    {
      id: "policy_checked",
      step: 2,
      label: "Policy checked",
      count: policyChecked,
      percentOfStart: pct(policyChecked, requests),
      conversionToNext: pct(flagged, policyChecked),
      tone: "neutral",
    },
    {
      id: "flagged",
      step: 3,
      label: "Flagged",
      count: flagged,
      percentOfStart: pct(flagged, requests),
      conversionToNext: pct(resolved, flagged),
      tone: "flagged",
    },
    {
      id: "resolved",
      step: 4,
      label: resolvedTone === "blocked" ? "Blocked / Halted" : "Approved",
      count: resolved,
      percentOfStart: pct(resolved, requests),
      conversionToNext: null,
      tone: resolvedTone,
    },
  ];
}

export const SPOKE_NODES: TopologyNode[] = [
  {
    id: "spoke-agents",
    spokeId: "agents",
    name: "Agents",
    shortLabel: "AGENTS",
    subtitle: "18 registered passports across prod & staging",
    kind: "spoke",
    category: "agents",
    protection: "partial",
    protectedRatio: 0.82,
    status: "allowed",
    severity: "medium",
    riskScore: 42,
    endpointCount: 18,
    hasNewThreatPulse: false,
    frameworkOrProvider: "LangGraph, Vertex ADK, CrewAI",
    environment: "production",
    lastSeen: "4s ago",
    kpis: {
      requests: 19420,
      policyChecked: 19180,
      flagged: 94,
      blocked: 62,
      approved: 19264,
      pendingApproval: 5,
      p99LatencyMs: 0.16,
      spendUsd: 142.8,
    },
    funnel: buildFunnel(19420, 19180, 94, 62, "blocked"),
    activitySeries: buildSeries(1480, 7, 7),
    recentEvents: [
      {
        id: "ev-ag-1",
        timestamp: "19:44:12",
        agent: "FinOps SQL Remediator",
        toolOrTarget: "execute_sql",
        status: "blocked",
        severity: "critical",
        ruleId: "AST-SQL-004",
        summary: "Blocked full-table query on users lacking LIMIT clause",
        latencyMs: 0.14,
      },
      {
        id: "ev-ag-2",
        timestamp: "19:41:03",
        agent: "Shadow Script Runner",
        toolOrTarget: "bash_exec",
        status: "blocked",
        severity: "critical",
        ruleId: "PASS-SDK-ONLY",
        summary: "Reported-only SDK passport denied gateway access",
        latencyMs: 0.08,
      },
      {
        id: "ev-ag-3",
        timestamp: "19:38:45",
        agent: "SecOps Incident Triager",
        toolOrTarget: "read_wiki_structure",
        status: "allowed",
        severity: "low",
        ruleId: "PASS-ALLOW",
        summary: "Verified read-only MCP call within passport scope",
        latencyMs: 0.15,
      },
    ],
  },
  {
    id: "spoke-tools",
    spokeId: "tools",
    name: "Tools / MCP",
    shortLabel: "TOOLS / MCP",
    subtitle: "9 MCP servers pinned with AST & egress controls",
    kind: "spoke",
    category: "tools",
    protection: "partial",
    protectedRatio: 0.78,
    status: "blocked",
    severity: "critical",
    riskScore: 68,
    endpointCount: 41,
    hasNewThreatPulse: true,
    frameworkOrProvider: "MCP 2025-06-18",
    environment: "production",
    lastSeen: "2s ago",
    kpis: {
      requests: 15840,
      policyChecked: 15840,
      flagged: 214,
      blocked: 138,
      approved: 15488,
      pendingApproval: 4,
      p99LatencyMs: 0.18,
      spendUsd: 0,
    },
    funnel: buildFunnel(15840, 15840, 214, 138, "blocked"),
    activitySeries: buildSeries(1210, 8, 13),
    recentEvents: [
      {
        id: "ev-tl-1",
        timestamp: "19:46:01",
        agent: "SecOps Incident Triager",
        toolOrTarget: "unpinned-shell/run_cmd",
        status: "blocked",
        severity: "critical",
        ruleId: "SHLEX-EVADE",
        summary: "POSIX lexer stopped base64 pipe obfuscation",
        latencyMs: 0.17,
      },
      {
        id: "ev-tl-2",
        timestamp: "19:40:19",
        agent: "Support Triage Bot",
        toolOrTarget: "github-enterprise/create_issue",
        status: "flagged",
        severity: "medium",
        ruleId: "RAD-DST-001",
        summary: "Unfamiliar external domain flagged in payload",
        latencyMs: 0.21,
      },
    ],
  },
  {
    id: "spoke-data",
    spokeId: "data",
    name: "Data",
    shortLabel: "DATA",
    subtitle: "SQL warehouses, PII vaults, and S3 telemetry buckets",
    kind: "spoke",
    category: "data",
    protection: "protected",
    protectedRatio: 0.94,
    status: "allowed",
    severity: "low",
    riskScore: 24,
    endpointCount: 28,
    hasNewThreatPulse: false,
    frameworkOrProvider: "CloudSQL, GCS, Supabase",
    environment: "production",
    lastSeen: "9s ago",
    kpis: {
      requests: 7420,
      policyChecked: 7420,
      flagged: 52,
      blocked: 34,
      approved: 7334,
      pendingApproval: 2,
      p99LatencyMs: 0.19,
      spendUsd: 18.4,
    },
    funnel: buildFunnel(7420, 7420, 52, 34, "blocked"),
    activitySeries: buildSeries(610, 5, 4),
    recentEvents: [
      {
        id: "ev-dt-1",
        timestamp: "19:42:55",
        agent: "FinOps SQL Remediator",
        toolOrTarget: "Core Ledger DB",
        status: "allowed",
        severity: "low",
        ruleId: "DLP-SCRUB",
        summary: "Read query passed AST LIMIT check; zero secrets leaked",
        latencyMs: 0.16,
      },
      {
        id: "ev-dt-2",
        timestamp: "19:33:14",
        agent: "Night Watch Crawler",
        toolOrTarget: "Customer PII Store",
        status: "blocked",
        severity: "critical",
        ruleId: "CANARY-TRIP",
        summary: "Honeytoken credential read triggered instant freeze",
        latencyMs: 0.11,
      },
    ],
  },
  {
    id: "spoke-humans",
    spokeId: "humans",
    name: "Humans",
    shortLabel: "HUMANS",
    subtitle: "Delegated RBAC & dual-control HITL approvers",
    kind: "spoke",
    category: "humans",
    protection: "protected",
    protectedRatio: 1,
    status: "pending",
    severity: "medium",
    riskScore: 18,
    endpointCount: 16,
    hasNewThreatPulse: false,
    frameworkOrProvider: "Supabase Auth + Telegram",
    environment: "production",
    lastSeen: "1m ago",
    kpis: {
      requests: 1280,
      policyChecked: 1280,
      flagged: 48,
      blocked: 14,
      approved: 34,
      pendingApproval: 3,
      p99LatencyMs: 0.12,
      spendUsd: 0,
    },
    funnel: buildFunnel(1280, 1280, 48, 34, "allowed"),
    activitySeries: buildSeries(110, 6, 3),
    recentEvents: [
      {
        id: "ev-hm-1",
        timestamp: "19:45:02",
        agent: "FinOps SQL Remediator",
        toolOrTarget: "delete_production_snapshot",
        status: "pending",
        severity: "critical",
        ruleId: "HITL-4EYES",
        summary: "Awaiting second admin signature from Marcus Vance",
        latencyMs: 0.12,
      },
    ],
  },
  {
    id: "spoke-models",
    spokeId: "models",
    name: "Models",
    shortLabel: "MODELS",
    subtitle: "Approved LLM routing, spend caps & shadow-model detection",
    kind: "spoke",
    category: "models",
    protection: "partial",
    protectedRatio: 0.72,
    status: "flagged",
    severity: "medium",
    riskScore: 54,
    endpointCount: 29,
    hasNewThreatPulse: true,
    frameworkOrProvider: "Anthropic, OpenAI, Google",
    environment: "production",
    lastSeen: "1s ago",
    kpis: {
      requests: 4240,
      policyChecked: 3980,
      flagged: 79,
      blocked: 66,
      approved: 4095,
      pendingApproval: 0,
      p99LatencyMs: 0.14,
      spendUsd: 294.6,
    },
    funnel: buildFunnel(4240, 3980, 79, 66, "blocked"),
    activitySeries: buildSeries(340, 9, 8),
    recentEvents: [
      {
        id: "ev-md-1",
        timestamp: "19:46:40",
        agent: "Night Research Worker",
        toolOrTarget: "openai/gpt-mystery",
        status: "flagged",
        severity: "medium",
        ruleId: "RAD-MOD-001",
        summary: "Model reported outside Approved Models allowlist",
        latencyMs: 0.14,
      },
    ],
  },
];

export const CHILD_NODES: TopologyNode[] = [
  // Agents spoke children
  {
    id: "ag-finops",
    spokeId: "agents",
    name: "FinOps SQL Remediator",
    shortLabel: "FinOps SQL",
    subtitle: "LangGraph • production • daily spend $68.40",
    kind: "child",
    category: "agents",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "low",
    riskScore: 19,
    endpointCount: 8,
    frameworkOrProvider: "LangGraph",
    environment: "production",
    lastSeen: "4s ago",
    kpis: {
      requests: 8420,
      policyChecked: 8420,
      flagged: 24,
      blocked: 16,
      approved: 8380,
      pendingApproval: 1,
      p99LatencyMs: 0.15,
      spendUsd: 68.4,
    },
    funnel: buildFunnel(8420, 8420, 24, 16, "blocked"),
    activitySeries: buildSeries(680, 6, 3),
    recentEvents: SPOKE_NODES[0].recentEvents,
  },
  {
    id: "ag-secops",
    spokeId: "agents",
    name: "SecOps Incident Triager",
    shortLabel: "SecOps Triage",
    subtitle: "Vertex ADK • production • Risk Ladder 35",
    kind: "child",
    category: "agents",
    protection: "protected",
    protectedRatio: 1,
    status: "flagged",
    severity: "medium",
    riskScore: 35,
    endpointCount: 6,
    frameworkOrProvider: "Vertex ADK",
    environment: "production",
    lastSeen: "11s ago",
    kpis: {
      requests: 6180,
      policyChecked: 6180,
      flagged: 38,
      blocked: 21,
      approved: 6121,
      pendingApproval: 2,
      p99LatencyMs: 0.17,
      spendUsd: 49.2,
    },
    funnel: buildFunnel(6180, 6180, 38, 21, "blocked"),
    activitySeries: buildSeries(490, 7, 4),
    recentEvents: SPOKE_NODES[0].recentEvents,
  },
  {
    id: "ag-support",
    spokeId: "agents",
    name: "Support Triage Bot",
    shortLabel: "Support Bot",
    subtitle: "CrewAI • staging • Safe Mode armed",
    kind: "child",
    category: "agents",
    protection: "protected",
    protectedRatio: 0.9,
    status: "allowed",
    severity: "low",
    riskScore: 22,
    endpointCount: 3,
    frameworkOrProvider: "CrewAI",
    environment: "staging",
    lastSeen: "35s ago",
    kpis: {
      requests: 3910,
      policyChecked: 3910,
      flagged: 14,
      blocked: 7,
      approved: 3889,
      pendingApproval: 0,
      p99LatencyMs: 0.14,
      spendUsd: 25.2,
    },
    funnel: buildFunnel(3910, 3910, 14, 7, "blocked"),
    activitySeries: buildSeries(310, 4, 2),
    recentEvents: SPOKE_NODES[0].recentEvents,
  },
  {
    id: "ag-shadow",
    spokeId: "agents",
    name: "Shadow Script Runner",
    shortLabel: "night-sdk",
    subtitle: "Custom SDK • reported_only • awaiting promotion",
    kind: "child",
    category: "agents",
    protection: "unprotected",
    protectedRatio: 0.1,
    status: "blocked",
    severity: "critical",
    riskScore: 86,
    endpointCount: 1,
    hasNewThreatPulse: true,
    frameworkOrProvider: "Custom MCP",
    environment: "development",
    lastSeen: "2s ago",
    kpis: {
      requests: 910,
      policyChecked: 670,
      flagged: 18,
      blocked: 18,
      approved: 0,
      pendingApproval: 2,
      p99LatencyMs: 0.09,
      spendUsd: 0,
    },
    funnel: buildFunnel(910, 670, 18, 18, "blocked"),
    activitySeries: buildSeries(72, 10, 5),
    recentEvents: SPOKE_NODES[0].recentEvents,
  },

  // Tools/MCP spoke children
  {
    id: "tl-deepwiki",
    spokeId: "tools",
    name: "deepwiki MCP",
    shortLabel: "deepwiki",
    subtitle: "Pinned toolset • read_wiki_structure allowed",
    kind: "child",
    category: "tools",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "low",
    riskScore: 12,
    endpointCount: 4,
    frameworkOrProvider: "MCP HTTP/SSE",
    environment: "production",
    lastSeen: "3s ago",
    kpis: {
      requests: 5210,
      policyChecked: 5210,
      flagged: 19,
      blocked: 12,
      approved: 5179,
      pendingApproval: 0,
      p99LatencyMs: 0.14,
      spendUsd: 0,
    },
    funnel: buildFunnel(5210, 5210, 19, 12, "blocked"),
    activitySeries: buildSeries(420, 5, 2),
    recentEvents: SPOKE_NODES[1].recentEvents,
  },
  {
    id: "tl-cloudsql",
    spokeId: "tools",
    name: "cloudsql-admin MCP",
    shortLabel: "cloudsql",
    subtitle: "AST SQL guardrail + 4-eyes delete lock",
    kind: "child",
    category: "tools",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "medium",
    riskScore: 28,
    endpointCount: 11,
    frameworkOrProvider: "GCP Cloud SQL",
    environment: "production",
    lastSeen: "7s ago",
    kpis: {
      requests: 4480,
      policyChecked: 4480,
      flagged: 41,
      blocked: 28,
      approved: 4411,
      pendingApproval: 2,
      p99LatencyMs: 0.16,
      spendUsd: 0,
    },
    funnel: buildFunnel(4480, 4480, 41, 28, "blocked"),
    activitySeries: buildSeries(360, 7, 4),
    recentEvents: SPOKE_NODES[1].recentEvents,
  },
  {
    id: "tl-github",
    spokeId: "tools",
    name: "github-enterprise MCP",
    shortLabel: "github-ent",
    subtitle: "Fine-grained PR & issue scope enforcement",
    kind: "child",
    category: "tools",
    protection: "protected",
    protectedRatio: 0.92,
    status: "flagged",
    severity: "medium",
    riskScore: 39,
    endpointCount: 12,
    frameworkOrProvider: "GitHub App",
    environment: "production",
    lastSeen: "19s ago",
    kpis: {
      requests: 3890,
      policyChecked: 3890,
      flagged: 64,
      blocked: 22,
      approved: 3804,
      pendingApproval: 1,
      p99LatencyMs: 0.19,
      spendUsd: 0,
    },
    funnel: buildFunnel(3890, 3890, 64, 22, "blocked"),
    activitySeries: buildSeries(310, 6, 4),
    recentEvents: SPOKE_NODES[1].recentEvents,
  },
  {
    id: "tl-shell",
    spokeId: "tools",
    name: "unpinned-shell MCP",
    shortLabel: "shell-mcp",
    subtitle: "Drift detected on schema hash • strict pin active",
    kind: "child",
    category: "tools",
    protection: "unprotected",
    protectedRatio: 0.2,
    status: "blocked",
    severity: "critical",
    riskScore: 91,
    endpointCount: 6,
    hasNewThreatPulse: true,
    frameworkOrProvider: "POSIX Host",
    environment: "staging",
    lastSeen: "2s ago",
    kpis: {
      requests: 2260,
      policyChecked: 2260,
      flagged: 90,
      blocked: 76,
      approved: 2094,
      pendingApproval: 1,
      p99LatencyMs: 0.17,
      spendUsd: 0,
    },
    funnel: buildFunnel(2260, 2260, 90, 76, "blocked"),
    activitySeries: buildSeries(180, 9, 9),
    recentEvents: SPOKE_NODES[1].recentEvents,
  },

  // Data spoke children
  {
    id: "dt-ledger",
    spokeId: "data",
    name: "Core Ledger DB",
    shortLabel: "Ledger DB",
    subtitle: "Finance PostgreSQL • row limit & column mask",
    kind: "child",
    category: "data",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "low",
    riskScore: 14,
    endpointCount: 9,
    frameworkOrProvider: "PostgreSQL",
    environment: "production",
    lastSeen: "5s ago",
    kpis: {
      requests: 3420,
      policyChecked: 3420,
      flagged: 12,
      blocked: 9,
      approved: 3399,
      pendingApproval: 1,
      p99LatencyMs: 0.15,
      spendUsd: 10.2,
    },
    funnel: buildFunnel(3420, 3420, 12, 9, "blocked"),
    activitySeries: buildSeries(280, 5, 2),
    recentEvents: SPOKE_NODES[2].recentEvents,
  },
  {
    id: "dt-pii",
    spokeId: "data",
    name: "Customer PII Store",
    shortLabel: "PII Vault",
    subtitle: "DLP secret scrub + canary tripwire armed",
    kind: "child",
    category: "data",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "medium",
    riskScore: 31,
    endpointCount: 7,
    frameworkOrProvider: "Supabase",
    environment: "production",
    lastSeen: "18s ago",
    kpis: {
      requests: 2140,
      policyChecked: 2140,
      flagged: 24,
      blocked: 17,
      approved: 2099,
      pendingApproval: 1,
      p99LatencyMs: 0.18,
      spendUsd: 8.2,
    },
    funnel: buildFunnel(2140, 2140, 24, 17, "blocked"),
    activitySeries: buildSeries(175, 7, 3),
    recentEvents: SPOKE_NODES[2].recentEvents,
  },
  {
    id: "dt-unclassified",
    spokeId: "data",
    name: "Unclassified Bucket",
    shortLabel: "scratch-s3",
    subtitle: "Missing destination allowlist rule",
    kind: "child",
    category: "data",
    protection: "unprotected",
    protectedRatio: 0.35,
    status: "flagged",
    severity: "medium",
    riskScore: 63,
    endpointCount: 5,
    frameworkOrProvider: "AWS S3",
    environment: "staging",
    lastSeen: "42s ago",
    kpis: {
      requests: 1860,
      policyChecked: 1860,
      flagged: 16,
      blocked: 8,
      approved: 1836,
      pendingApproval: 0,
      p99LatencyMs: 0.21,
      spendUsd: 0,
    },
    funnel: buildFunnel(1860, 1860, 16, 8, "blocked"),
    activitySeries: buildSeries(155, 8, 2),
    recentEvents: SPOKE_NODES[2].recentEvents,
  },

  // Humans spoke children
  {
    id: "hm-owner",
    spokeId: "humans",
    name: "Alice Chen (Owner)",
    shortLabel: "Alice C.",
    subtitle: "Org owner • dual-key signoff active",
    kind: "child",
    category: "humans",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "low",
    riskScore: 5,
    endpointCount: 6,
    frameworkOrProvider: "Supabase Auth",
    environment: "production",
    lastSeen: "2m ago",
    kpis: {
      requests: 540,
      policyChecked: 540,
      flagged: 18,
      blocked: 6,
      approved: 14,
      pendingApproval: 1,
      p99LatencyMs: 0.11,
      spendUsd: 0,
    },
    funnel: buildFunnel(540, 540, 18, 14, "allowed"),
    activitySeries: buildSeries(45, 6, 2),
    recentEvents: SPOKE_NODES[3].recentEvents,
  },
  {
    id: "hm-secops",
    spokeId: "humans",
    name: "Marcus Vance (SecOps)",
    shortLabel: "Marcus V.",
    subtitle: "Security operator • HITL queue reviewer",
    kind: "child",
    category: "humans",
    protection: "protected",
    protectedRatio: 1,
    status: "pending",
    severity: "medium",
    riskScore: 12,
    endpointCount: 5,
    frameworkOrProvider: "Telegram HITL",
    environment: "production",
    lastSeen: "1m ago",
    kpis: {
      requests: 420,
      policyChecked: 420,
      flagged: 20,
      blocked: 5,
      approved: 13,
      pendingApproval: 2,
      p99LatencyMs: 0.12,
      spendUsd: 0,
    },
    funnel: buildFunnel(420, 420, 20, 13, "allowed"),
    activitySeries: buildSeries(36, 7, 1),
    recentEvents: SPOKE_NODES[3].recentEvents,
  },
  {
    id: "hm-admin",
    spokeId: "humans",
    name: "Priya Nair (Admin)",
    shortLabel: "Priya N.",
    subtitle: "Passport promotion & SDK key custodian",
    kind: "child",
    category: "humans",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "low",
    riskScore: 8,
    endpointCount: 5,
    frameworkOrProvider: "Supabase Auth",
    environment: "production",
    lastSeen: "8m ago",
    kpis: {
      requests: 320,
      policyChecked: 320,
      flagged: 10,
      blocked: 3,
      approved: 7,
      pendingApproval: 0,
      p99LatencyMs: 0.11,
      spendUsd: 0,
    },
    funnel: buildFunnel(320, 320, 10, 7, "allowed"),
    activitySeries: buildSeries(29, 4, 1),
    recentEvents: SPOKE_NODES[3].recentEvents,
  },

  // Models spoke children
  {
    id: "md-claude",
    spokeId: "models",
    name: "anthropic/claude-sonnet-4",
    shortLabel: "claude-sonnet",
    subtitle: "Approved allowlist • spend $182.10 today",
    kind: "child",
    category: "models",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "low",
    riskScore: 11,
    endpointCount: 12,
    frameworkOrProvider: "Anthropic",
    environment: "production",
    lastSeen: "1s ago",
    kpis: {
      requests: 2180,
      policyChecked: 2180,
      flagged: 12,
      blocked: 8,
      approved: 2160,
      pendingApproval: 0,
      p99LatencyMs: 0.13,
      spendUsd: 182.1,
    },
    funnel: buildFunnel(2180, 2180, 12, 8, "blocked"),
    activitySeries: buildSeries(180, 6, 2),
    recentEvents: SPOKE_NODES[4].recentEvents,
  },
  {
    id: "md-gpt4o",
    spokeId: "models",
    name: "openai/gpt-4o",
    shortLabel: "gpt-4o",
    subtitle: "Approved allowlist • spend $84.50 today",
    kind: "child",
    category: "models",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "low",
    riskScore: 16,
    endpointCount: 9,
    frameworkOrProvider: "OpenAI",
    environment: "production",
    lastSeen: "6s ago",
    kpis: {
      requests: 1410,
      policyChecked: 1410,
      flagged: 18,
      blocked: 14,
      approved: 1378,
      pendingApproval: 0,
      p99LatencyMs: 0.14,
      spendUsd: 84.5,
    },
    funnel: buildFunnel(1410, 1410, 18, 14, "blocked"),
    activitySeries: buildSeries(115, 7, 2),
    recentEvents: SPOKE_NODES[4].recentEvents,
  },
  {
    id: "md-mystery",
    spokeId: "models",
    name: "openai/gpt-mystery",
    shortLabel: "gpt-mystery",
    subtitle: "Unapproved shadow model • Radar RAD-MOD-001",
    kind: "child",
    category: "models",
    protection: "unprotected",
    protectedRatio: 0.08,
    status: "flagged",
    severity: "critical",
    riskScore: 84,
    endpointCount: 3,
    hasNewThreatPulse: true,
    frameworkOrProvider: "Unlisted OpenAI",
    environment: "staging",
    lastSeen: "1s ago",
    kpis: {
      requests: 650,
      policyChecked: 390,
      flagged: 49,
      blocked: 44,
      approved: 557,
      pendingApproval: 0,
      p99LatencyMs: 0.15,
      spendUsd: 28,
    },
    funnel: buildFunnel(650, 390, 49, 44, "blocked"),
    activitySeries: buildSeries(45, 9, 5),
    recentEvents: SPOKE_NODES[4].recentEvents,
  },
];

export const ALL_NODES: TopologyNode[] = [...SPOKE_NODES, ...CHILD_NODES];

export const MOCK_POLICIES: PolicyItem[] = [
  {
    id: "pol-1",
    name: "AST SQL Injection & Exfiltration Guard",
    category: "data",
    mode: "enforce",
    status: "allowed",
    scopeSummary: "Requires explicit LIMIT clause; blocks SELECT * and credential columns",
    triggered24h: 112,
    blocked24h: 98,
    updatedAt: "12m ago",
  },
  {
    id: "pol-2",
    name: "MCP Tool Schema & Hash Pinning",
    category: "tools",
    mode: "enforce",
    status: "blocked",
    scopeSummary: "Strict SHA-256 verification on tool descriptions before execution",
    triggered24h: 76,
    blocked24h: 76,
    updatedAt: "1h ago",
  },
  {
    id: "pol-3",
    name: "Reported-Only SDK Quarantine",
    category: "agents",
    mode: "enforce",
    status: "allowed",
    scopeSummary: "Blocks gateway STS token minting until an admin promotes the passport",
    triggered24h: 18,
    blocked24h: 18,
    updatedAt: "4h ago",
  },
  {
    id: "pol-4",
    name: "Approved Models Allowlist (RAD-MOD-001)",
    category: "models",
    mode: "watch",
    status: "flagged",
    scopeSummary: "Flags SDK spans from unlisted provider/model pairs & sends Telegram alert",
    triggered24h: 79,
    blocked24h: 0,
    updatedAt: "26m ago",
  },
  {
    id: "pol-5",
    name: "Destination Domain Allowlist (RAD-DST-001)",
    category: "tools",
    mode: "enforce",
    status: "allowed",
    scopeSummary: "Refuses calls containing hostnames outside agent approved destinations",
    triggered24h: 44,
    blocked24h: 39,
    updatedAt: "2h ago",
  },
  {
    id: "pol-6",
    name: "Destructive Action Dual-Signoff (HITL)",
    category: "humans",
    mode: "enforce",
    status: "pending",
    scopeSummary: "Pauses critical state mutations until 2 operators approve with cryptographic hash",
    triggered24h: 14,
    blocked24h: 6,
    updatedAt: "9m ago",
  },
];

export const MOCK_APPROVALS: ApprovalRequestItem[] = [
  {
    id: "hitl-901",
    agentName: "FinOps SQL Remediator",
    agentId: "ag-finops",
    toolName: "delete_production_snapshot",
    targetResource: "//sqladmin.googleapis.com/instances/core-ledger-prod-01",
    requestedBy: "alice.chen@acme.io",
    riskTier: "critical",
    severity: "critical",
    status: "pending",
    signaturesHave: 1,
    signaturesNeed: 2,
    justification: "Reclaim 420 GB orphaned snapshot storage on core-ledger-prod-01.",
    createdAt: "2m ago",
    expiresIn: "58m",
  },
  {
    id: "hitl-902",
    agentName: "Shadow Script Runner (night-sdk)",
    agentId: "ag-shadow",
    toolName: "passport.promote",
    targetResource: "passport://development/night-sdk",
    requestedBy: "ci-runner@acme.io",
    riskTier: "destructive",
    severity: "critical",
    status: "pending",
    signaturesHave: 0,
    signaturesNeed: 1,
    justification: "Promote reported-only SDK passport to managed gateway access.",
    createdAt: "6m ago",
    expiresIn: "54m",
  },
  {
    id: "hitl-903",
    agentName: "SecOps Incident Triager",
    agentId: "ag-secops",
    toolName: "rotate_iam_service_key",
    targetResource: "iam://projects/redhand-staging/serviceAccounts/agent-worker",
    requestedBy: "marcus.vance@acme.io",
    riskTier: "state_mutation",
    severity: "medium",
    status: "pending",
    signaturesHave: 1,
    signaturesNeed: 2,
    justification: "Rotate leaked staging key detected by DLP scrubber.",
    createdAt: "14m ago",
    expiresIn: "46m",
  },
];

export const MOCK_AUDIT_LOG: AuditLogEntry[] = [
  {
    id: "aud-101",
    at: "19:46:40",
    actor: "Radar / Approved Models",
    actorKind: "risk_engine",
    action: "model.unapproved_detected",
    target: "openai/gpt-mystery",
    category: "models",
    verdict: "flagged",
    reason: "Reported by night-model SDK batch; Telegram alert dispatched.",
  },
  {
    id: "aud-102",
    at: "19:46:01",
    actor: "AgentWall Gateway",
    actorKind: "gateway",
    action: "mcp.call_blocked",
    target: "unpinned-shell/run_cmd",
    category: "tools",
    verdict: "blocked",
    reason: "POSIX shlex lexer detected base64 pipe evasion.",
  },
  {
    id: "aud-103",
    at: "19:44:12",
    actor: "AgentWall Gateway",
    actorKind: "gateway",
    action: "sql.exfiltration_blocked",
    target: "Core Ledger DB (users)",
    category: "data",
    verdict: "blocked",
    reason: "AST check refused query missing LIMIT and selecting ssn.",
  },
  {
    id: "aud-104",
    at: "19:41:03",
    actor: "AgentWall Core",
    actorKind: "gateway",
    action: "agent_auth.reported_only_refused",
    target: "night-sdk",
    category: "agents",
    verdict: "blocked",
    reason: "Passport is reported_only; admin must promote before gateway use.",
  },
  {
    id: "aud-105",
    at: "19:33:14",
    actor: "Risk Engine",
    actorKind: "risk_engine",
    action: "passport.canary_freeze",
    target: "Night Watch Crawler",
    category: "agents",
    verdict: "blocked",
    reason: "Honeytoken trip score reached 100 (Freeze threshold 80).",
  },
  {
    id: "aud-106",
    at: "19:29:05",
    actor: "Alice Chen (Owner)",
    actorKind: "human",
    action: "hitl.signature_added",
    target: "FinOps SQL Remediator",
    category: "humans",
    verdict: "pending",
    reason: "First of two required signatures recorded (HMAC verified).",
  },
  {
    id: "aud-107",
    at: "19:15:48",
    actor: "AgentWall Gateway",
    actorKind: "gateway",
    action: "mcp.call_allowed",
    target: "deepwiki/read_wiki_structure",
    category: "tools",
    verdict: "allowed",
    reason: "Scope verified; tool pin SHA matched (0.14 ms).",
  },
];
