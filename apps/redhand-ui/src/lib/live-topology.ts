import type {
  ControlAuditEntry,
  Me,
  Passport,
} from "./api";
import type {
  ActivityBucket,
  AuditLogEntry,
  FunnelStage,
  OverviewSnapshot,
  PolicyItem,
  ProtectionState,
  TimeRangeKey,
  TopologyNode,
} from "./control-room-data";
import {
  formatBytes,
  REASON_LABELS,
  type InsightsPoint,
  type InsightsReason,
  type InsightsServer,
  type InsightsSummary,
  type InsightsTool,
} from "./insights";

function computeFunnel(
  requests: number,
  flagged: number,
  blocked: number,
  approved: number
): FunnelStage[] {
  const reqCount = Math.max(0, requests);
  const checked = reqCount;
  const flagCount = Math.max(0, flagged);
  const blockCount = Math.max(0, blocked);
  const appCount = Math.max(0, approved);

  const pct = (part: number, whole: number) =>
    whole > 0 ? Math.round((part / whole) * 1000) / 10 : 0;

  return [
    {
      id: "requests",
      step: 1,
      label: "Requests",
      count: reqCount,
      percentOfStart: 100,
      conversionToNext: pct(checked, reqCount),
      tone: "crimson",
    },
    {
      id: "policy_checked",
      step: 2,
      label: "Policy checked",
      count: checked,
      percentOfStart: pct(checked, reqCount),
      conversionToNext: pct(flagCount, checked),
      tone: "neutral",
    },
    {
      id: "flagged",
      step: 3,
      label: "Flagged",
      count: flagCount,
      percentOfStart: pct(flagCount, reqCount),
      conversionToNext: pct(blockCount, flagCount),
      tone: "flagged",
    },
    {
      id: "resolved",
      step: 4,
      label: "Blocked / Approved",
      count: blockCount + appCount,
      percentOfStart: pct(blockCount + appCount, reqCount),
      conversionToNext: null,
      tone: blockCount > 0 ? "blocked" : "allowed",
    },
  ];
}

function generateActivityBuckets(
  summary: InsightsSummary | null
): ActivityBucket[] {
  if (summary?.series && summary.series.length > 0) {
    return summary.series.slice(-6).map((point: InsightsPoint) => ({
      label: point.bucket_start.slice(11, 16) || point.bucket_start,
      allowed: point.allowed,
      flagged: point.errors,
      blocked: point.refused,
      pending: 0,
    }));
  }
  const hours = ["12:00", "14:00", "16:00", "18:00", "20:00", "22:00"];
  return hours.map((h) => ({
    label: h,
    allowed: 0,
    flagged: 0,
    blocked: 0,
    pending: 0,
  }));
}

export function buildLiveTopology(
  passports: Passport[],
  summary: InsightsSummary | null,
  me: Me | null,
  audit: ControlAuditEntry[] = [],
  timeRange: TimeRangeKey = "24h"
): {
  nodes: TopologyNode[];
  snapshot: OverviewSnapshot;
  policies: PolicyItem[];
  auditEntries: AuditLogEntry[];
} {
  const totalCalls = summary?.totals.decisions ?? 0;
  const totalRefusals = summary?.totals.refused ?? 0;
  const totalFindings = summary?.totals.errors ?? 0;
  const totalBytes = summary?.totals.bytes_returned ?? 0;

  const allowedCalls = summary?.totals.allowed ?? Math.max(0, totalCalls - totalRefusals);
  const riskyEndpoints = totalRefusals + totalFindings;

  // 1. Spoke nodes definitions
  const spokeAgents: TopologyNode = {
    id: "spoke-agents",
    spokeId: "agents",
    name: "AGENTS",
    shortLabel: "Agents",
    subtitle: `${passports.length} registered agents`,
    kind: "spoke",
    category: "agents",
    protection: "protected",
    protectedRatio: passports.filter((p) => !p.reported_only).length / Math.max(1, passports.length),
    status: totalRefusals > 0 ? "blocked" : totalFindings > 0 ? "flagged" : "allowed",
    severity: totalRefusals > 0 ? "critical" : totalFindings > 0 ? "medium" : "low",
    riskScore: totalRefusals > 0 ? 84 : totalFindings > 0 ? 46 : 12,
    endpointCount: passports.length,
    frameworkOrProvider: "Autonomous Orchestrators",
    environment: "production",
    lastSeen: "live",
    kpis: {
      requests: totalCalls,
      policyChecked: totalCalls,
      flagged: totalFindings,
      blocked: totalRefusals,
      approved: allowedCalls,
      pendingApproval: 0,
      p99LatencyMs: summary?.latency.p95_ms ? Math.round(summary.latency.p95_ms) : 12,
      spendUsd: 0,
    },
    funnel: computeFunnel(totalCalls, totalFindings, totalRefusals, allowedCalls),
    activitySeries: generateActivityBuckets(summary),
    recentEvents: [],
  };

  const toolsCount = summary?.tools.length ?? 0;
  const spokeTools: TopologyNode = {
    id: "spoke-tools",
    spokeId: "tools",
    name: "TOOLS & MCP",
    shortLabel: "Tools",
    subtitle: `${toolsCount} MCP tool interfaces`,
    kind: "spoke",
    category: "tools",
    protection: "protected",
    protectedRatio: 1,
    status: (summary?.tools.some((t: InsightsTool) => t.refused > 0) ?? false) ? "flagged" : "allowed",
    severity: (summary?.tools.some((t: InsightsTool) => t.refused > 0) ?? false) ? "medium" : "low",
    riskScore: 28,
    endpointCount: toolsCount,
    frameworkOrProvider: "Model Context Protocol",
    environment: "production",
    lastSeen: "live",
    kpis: {
      requests: totalCalls,
      policyChecked: totalCalls,
      flagged: totalFindings,
      blocked: totalRefusals,
      approved: allowedCalls,
      pendingApproval: 0,
      p99LatencyMs: 8,
      spendUsd: 0,
    },
    funnel: computeFunnel(totalCalls, totalFindings, totalRefusals, allowedCalls),
    activitySeries: generateActivityBuckets(summary),
    recentEvents: [],
  };

  const serversCount = summary?.servers.length ?? 0;
  const spokeData: TopologyNode = {
    id: "spoke-data",
    spokeId: "data",
    name: "DATASETS",
    shortLabel: "Data",
    subtitle: `${serversCount} data endpoints`,
    kind: "spoke",
    category: "data",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "low",
    riskScore: 10,
    endpointCount: Math.max(1, serversCount),
    frameworkOrProvider: "Database & Storage",
    environment: "production",
    lastSeen: "live",
    kpis: {
      requests: totalCalls,
      policyChecked: totalCalls,
      flagged: 0,
      blocked: 0,
      approved: allowedCalls,
      pendingApproval: 0,
      p99LatencyMs: 6,
      spendUsd: 0,
    },
    funnel: computeFunnel(totalCalls, 0, 0, allowedCalls),
    activitySeries: generateActivityBuckets(summary),
    recentEvents: [],
  };

  const spokeHumans: TopologyNode = {
    id: "spoke-humans",
    spokeId: "humans",
    name: "USERS & APPROVALS",
    shortLabel: "Users",
    subtitle: me?.email ? `${me.email} (${me.role ?? "operator"})` : "Security operators",
    kind: "spoke",
    category: "humans",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "low",
    riskScore: 5,
    endpointCount: 1,
    frameworkOrProvider: "RBAC & Step-up Auth",
    environment: "production",
    lastSeen: "live",
    kpis: {
      requests: 12,
      policyChecked: 12,
      flagged: 0,
      blocked: 0,
      approved: 12,
      pendingApproval: 0,
      p99LatencyMs: 4,
      spendUsd: 0,
    },
    funnel: computeFunnel(12, 0, 0, 12),
    activitySeries: generateActivityBuckets(summary),
    recentEvents: [],
  };

  const spokeModels: TopologyNode = {
    id: "spoke-models",
    spokeId: "models",
    name: "MODELS",
    shortLabel: "Models",
    subtitle: "Verified LLM runtimes",
    kind: "spoke",
    category: "models",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "low",
    riskScore: 14,
    endpointCount: 3,
    frameworkOrProvider: "Anthropic / OpenAI / Google",
    environment: "production",
    lastSeen: "live",
    kpis: {
      requests: totalCalls,
      policyChecked: totalCalls,
      flagged: totalFindings,
      blocked: totalRefusals,
      approved: allowedCalls,
      pendingApproval: 0,
      p99LatencyMs: 14,
      spendUsd: 0,
    },
    funnel: computeFunnel(totalCalls, totalFindings, totalRefusals, allowedCalls),
    activitySeries: generateActivityBuckets(summary),
    recentEvents: [],
  };

  const nodes: TopologyNode[] = [
    spokeAgents,
    spokeTools,
    spokeData,
    spokeHumans,
    spokeModels,
  ];

  // 2. Child nodes for Agents
  passports.forEach((p) => {
    const isFrozen = p.status === "frozen";
    const isRevoked = p.status === "revoked";
    const isBlocked = isFrozen || isRevoked;
    const protection: ProtectionState = p.reported_only ? "unprotected" : "protected";

    // distribute some of the traffic to this agent
    const share = Math.max(1, Math.floor(totalCalls / Math.max(1, passports.length)));
    const agentBlocked = isBlocked ? 1 : 0;

    const childNode: TopologyNode = {
      id: p.id,
      spokeId: "agents",
      name: p.name || p.external_agent_id,
      shortLabel: (p.name || p.external_agent_id).slice(0, 10),
      subtitle: `${p.framework || "custom"} · ${p.environment || "prod"}`,
      kind: "child",
      category: "agents",
      protection,
      protectedRatio: p.reported_only ? 0 : 1,
      status: isBlocked ? "blocked" : "allowed",
      severity: isBlocked ? "critical" : "low",
      riskScore: isBlocked ? 92 : 14,
      endpointCount: 1,
      frameworkOrProvider: p.framework || "custom",
      environment: (p.environment as "production" | "staging" | "development") || "production",
      lastSeen: p.last_seen_at ? new Date(p.last_seen_at).toLocaleTimeString() : "active",
      kpis: {
        requests: share,
        policyChecked: share,
        flagged: 0,
        blocked: agentBlocked,
        approved: Math.max(0, share - agentBlocked),
        pendingApproval: 0,
        p99LatencyMs: 12,
        spendUsd: 0,
      },
      funnel: computeFunnel(share, 0, agentBlocked, Math.max(0, share - agentBlocked)),
      activitySeries: generateActivityBuckets(summary),
      recentEvents: [],
    };
    nodes.push(childNode);
  });

  // 3. Child nodes for Tools
  if (summary?.tools && summary.tools.length > 0) {
    summary.tools.slice(0, 5).forEach((t: InsightsTool) => {
      const toolBlocked = t.refused;
      const childNode: TopologyNode = {
        id: `tool-${t.tool}`,
        spokeId: "tools",
        name: t.tool,
        shortLabel: t.tool.slice(0, 10),
        subtitle: `${t.calls} calls · MCP Tool`,
        kind: "child",
        category: "tools",
        protection: "protected",
        protectedRatio: 1,
        status: toolBlocked > 0 ? "flagged" : "allowed",
        severity: toolBlocked > 0 ? "medium" : "low",
        riskScore: toolBlocked > 0 ? 55 : 12,
        endpointCount: 1,
        frameworkOrProvider: "Model Context Protocol",
        environment: "production",
        lastSeen: "live",
        kpis: {
          requests: t.calls,
          policyChecked: t.calls,
          flagged: t.refused,
          blocked: t.refused,
          approved: Math.max(0, t.calls - t.refused),
          pendingApproval: 0,
          p99LatencyMs: 9,
          spendUsd: 0,
        },
        funnel: computeFunnel(t.calls, t.refused, t.refused, Math.max(0, t.calls - t.refused)),
        activitySeries: generateActivityBuckets(summary),
        recentEvents: [],
      };
      nodes.push(childNode);
    });
  }

  // 4. Child nodes for Servers / Data
  if (summary?.servers && summary.servers.length > 0) {
    summary.servers.slice(0, 4).forEach((s: InsightsServer) => {
      const childNode: TopologyNode = {
        id: `server-${s.server}`,
        spokeId: "data",
        name: s.server,
        shortLabel: s.server.slice(0, 10),
        subtitle: `${s.decisions} interactions`,
        kind: "child",
        category: "data",
        protection: "protected",
        protectedRatio: 1,
        status: "allowed",
        severity: "low",
        riskScore: 10,
        endpointCount: 1,
        frameworkOrProvider: "MCP Host",
        environment: "production",
        lastSeen: "live",
        kpis: {
          requests: s.decisions,
          policyChecked: s.decisions,
          flagged: s.errors,
          blocked: s.refused,
          approved: s.allowed,
          pendingApproval: 0,
          p99LatencyMs: 6,
          spendUsd: 0,
        },
        funnel: computeFunnel(s.decisions, s.errors, s.refused, s.allowed),
        activitySeries: generateActivityBuckets(summary),
        recentEvents: [],
      };
      nodes.push(childNode);
    });
  }

  // 5. Child node for operator
  nodes.push({
    id: "user-current-operator",
    spokeId: "humans",
    name: me?.email?.split("@")[0] || "operator",
    shortLabel: (me?.email?.split("@")[0] || "operator").slice(0, 10),
    subtitle: me?.role ? `${me.role} · Active session` : "Primary Security Operator",
    kind: "child",
    category: "humans",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "low",
    riskScore: 5,
    endpointCount: 1,
    frameworkOrProvider: "RedHand RBAC",
    environment: "production",
    lastSeen: "active now",
    kpis: {
      requests: 8,
      policyChecked: 8,
      flagged: 0,
      blocked: 0,
      approved: 8,
      pendingApproval: 0,
      p99LatencyMs: 3,
      spendUsd: 0,
    },
    funnel: computeFunnel(8, 0, 0, 8),
    activitySeries: generateActivityBuckets(summary),
    recentEvents: [],
  });

  // 6. Child node for primary model
  nodes.push({
    id: "model-claude-3-7-sonnet",
    spokeId: "models",
    name: "Claude 3.7 Sonnet",
    shortLabel: "Claude 3.7",
    subtitle: "Anthropic · RS256 Approved",
    kind: "child",
    category: "models",
    protection: "protected",
    protectedRatio: 1,
    status: "allowed",
    severity: "low",
    riskScore: 8,
    endpointCount: 1,
    frameworkOrProvider: "Anthropic API",
    environment: "production",
    lastSeen: "live",
    kpis: {
      requests: totalCalls,
      policyChecked: totalCalls,
      flagged: totalFindings,
      blocked: totalRefusals,
      approved: allowedCalls,
      pendingApproval: 0,
      p99LatencyMs: 14,
      spendUsd: 0,
    },
    funnel: computeFunnel(totalCalls, totalFindings, totalRefusals, allowedCalls),
    activitySeries: generateActivityBuckets(summary),
    recentEvents: [],
  });

  // Category breakdown
  const categoryBreakdown = (summary?.reasons && summary.reasons.length > 0)
    ? summary.reasons.map((r: InsightsReason, i: number) => {
        const colors = [
          "text-sky-400",
          "text-emerald-400",
          "text-indigo-400",
          "text-rose-400",
          "text-amber-400",
        ];
        const dots = [
          "bg-sky-400",
          "bg-emerald-400",
          "bg-indigo-400",
          "bg-rose-400",
          "bg-amber-400",
        ];
        const label = REASON_LABELS[r.reason] || r.reason.replace(/_/g, " ");
        return {
          id: r.reason,
          label,
          count: r.count,
          color: colors[i % colors.length] || "text-sky-400",
          dotClass: dots[i % dots.length] || "bg-sky-400",
        };
      })
    : [
        { id: "url_security", label: "Url-Security", count: totalCalls > 0 ? Math.round(totalCalls * 0.4) : 0, color: "text-sky-400", dotClass: "bg-sky-400" },
        { id: "data_rule", label: "Data-Rule", count: totalCalls > 0 ? Math.round(totalCalls * 0.3) : 0, color: "text-emerald-400", dotClass: "bg-emerald-400" },
        { id: "toxic_content", label: "Toxic-Content", count: totalFindings, color: "text-indigo-400", dotClass: "bg-indigo-400" },
        { id: "prompt_injection", label: "Prompt-Injection", count: totalRefusals, color: "text-rose-400", dotClass: "bg-rose-400" },
      ];

  const snapshot: OverviewSnapshot = {
    label: timeRange === "1h" ? "Past 1 hour" : timeRange === "7d" ? "Past 7 days" : timeRange === "30d" ? "Past 30 days" : "Past 24 hours",
    hub: {
      agentsUnderControl: passports.length,
      riskyActionsCount: riskyEndpoints,
      blockedThreatsCount: totalRefusals,
      totalEndpoints: nodes.length,
    },
    summary: {
      blocked: totalRefusals,
      flagged: totalFindings,
      allowed: allowedCalls,
      pendingApproval: 0,
      inboundTraffic: formatBytes(totalBytes),
      inboundDelta: "live",
      outboundCalls: `${totalCalls} calls`,
      outboundDelta: "live",
      logsAnalyzed: formatBytes(totalBytes),
      logsDelta: "live",
      mcpServers: serversCount,
      mcpDelta: `${toolsCount} tools`,
      activeWorkloads: `${passports.length} workloads`,
      workloadsDelta: "live",
      p99Latency: summary?.latency.p95_ms ? `${Math.round(summary.latency.p95_ms)} ms` : "12 ms",
    },
    severityBreakdown: [
      {
        id: "critical",
        label: "Critical",
        count: totalRefusals,
        color: "text-rose-400",
        dotClass: "bg-rose-500",
      },
      {
        id: "medium",
        label: "Medium",
        count: totalFindings,
        color: "text-amber-400",
        dotClass: "bg-amber-400",
      },
      {
        id: "low",
        label: "Low",
        count: allowedCalls,
        color: "text-emerald-400",
        dotClass: "bg-emerald-400",
      },
    ],
    categoryBreakdown,
  };

  const policies: PolicyItem[] = [
    {
      id: "pol-safe-mode",
      name: "Autonomous Safe Mode",
      category: "agents",
      mode: summary?.controls.safe_mode ? "enforce" : "watch",
      status: summary?.controls.safe_mode ? "allowed" : "flagged",
      scopeSummary: "Blocks state mutations and shell commands",
      triggered24h: totalRefusals,
      blocked24h: totalRefusals,
      updatedAt: "live",
    },
    {
      id: "pol-radar",
      name: "Threat Radar Real-time Intercept",
      category: "tools",
      mode: summary?.controls.radar_mode === "block" ? "enforce" : summary?.controls.radar_mode === "observe" ? "watch" : "off",
      status: "allowed",
      scopeSummary: "Inspects inbound agent tool arguments",
      triggered24h: totalFindings,
      blocked24h: totalRefusals,
      updatedAt: "live",
    },
    {
      id: "pol-approved-models",
      name: "Approved Models Enforcer",
      category: "models",
      mode: "enforce",
      status: "allowed",
      scopeSummary: "Restricts execution to verified models",
      triggered24h: 0,
      blocked24h: 0,
      updatedAt: "live",
    },
  ];

  const auditEntries: AuditLogEntry[] = audit.map((entry) => ({
    id: entry.id,
    at: new Date(entry.created_at).toLocaleTimeString(),
    actor: entry.actor_user_id || "AgentWall Gateway",
    actorKind: entry.actor_user_id ? "human" : "gateway",
    action: entry.action,
    target: entry.target_id || entry.target_type,
    category: "agents",
    verdict: entry.action.includes("freeze") || entry.action.includes("revoke") || entry.action.includes("block")
      ? "blocked"
      : "allowed",
    reason: entry.reason || "Policy rule evaluated by redhand-core",
  }));

  return { nodes, snapshot, policies, auditEntries };
}
