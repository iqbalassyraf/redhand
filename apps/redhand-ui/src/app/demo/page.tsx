"use client";

import React, { useState, useCallback, useMemo, useEffect } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MarkerType,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Search, Menu, Bell, ShieldCheck, Radio, Sparkles } from "lucide-react";
import { RedHandCrest } from "@/components/brand/RedHandCrest";

import {
  InputVectorNode,
  AgentRingNode,
  GuardGateNode,
  CloudResourceNode,
} from "@/components/canvas/CustomNodes";
import { InterventionRail } from "@/components/rail/InterventionRail";
import {
  FlightRecorderDock,
  type SimulationScenarioType,
} from "@/components/dock/FlightRecorderDock";
import {
  ENTERPRISE_USERS,
  INITIAL_AGENTS,
  INITIAL_HITL_INTERVENTIONS,
  INITIAL_TRACES,
} from "@/lib/mock-telemetry";
import { apiFetch, ApiError, CORE_API_BASE } from "@/lib/api";
import { useAuth, useRequiredSession } from "@/lib/auth";
import type {
  AgentPostureItem,
  AuthenticatedUser,
  FirewallVerdict,
  HITLInterventionItem,
  TraceTelemetryRow,
} from "@/lib/types";

const FILTER_CHIPS = [
  "All",
  "Live Agents",
  "Review Pending (HITL)",
  "AST Guardrails (<0.2ms)",
  "Multi-Cloud & SaaS Tokens",
  "Delegated RBAC Intersections",
];

type SnapshotAgentRow = {
  id: string;
  external_agent_id?: string;
  name?: string;
  framework?: string;
  environment?: string;
  status?: string;
  scopes?: Array<{ server: string; tool: string }>;
};

function toAgentPosture(row: SnapshotAgentRow): AgentPostureItem {
  const known = ["LangGraph", "CrewAI", "Vertex ADK", "Custom MCP"] as const;
  const framework = (known as readonly string[]).includes(row.framework ?? "")
    ? (row.framework as AgentPostureItem["framework"])
    : "Custom MCP";
  const environment = (["production", "staging", "development"] as const).includes(
    row.environment as AgentPostureItem["environment"]
  )
    ? (row.environment as AgentPostureItem["environment"])
    : "production";
  const status: AgentPostureItem["status"] = row.status === "active" ? "active" : "frozen";
  return {
    id: row.id,
    external_agent_id: row.external_agent_id ?? row.id,
    name: row.name ?? row.id,
    framework,
    environment,
    status,
    riskScore: status === "active" ? 30 : 95,
    activeLeaseCount: 0,
    blockedAttacksCount: 0,
    hitlPendingCount: 0,
    p99FirewallMs: 0,
    serviceAccount: "",
    allowedTools: (row.scopes ?? []).map((s) => `${s.server}/${s.tool}`),
  };
}

export default function RedHandCommandCenterPage() {
  const session = useRequiredSession();
  const { signOut } = useAuth();
  const token = session?.token ?? null;
  const [currentUser, setCurrentUser] = useState<AuthenticatedUser>(
    ENTERPRISE_USERS[0]
  );
  const [agents, setAgents] = useState<AgentPostureItem[]>(INITIAL_AGENTS);
  const [interventions, setInterventions] = useState<HITLInterventionItem[]>(
    INITIAL_HITL_INTERVENTIONS
  );
  const [traces, setTraces] = useState<TraceTelemetryRow[]>(INITIAL_TRACES);
  const [selectedTrace, setSelectedTrace] = useState<TraceTelemetryRow | null>(
    INITIAL_TRACES[0]
  );
  const [selectedChip, setSelectedChip] = useState<string>("All");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [engineConnected, setEngineConnected] = useState<boolean>(false);

  const [activeGateVerdict, setActiveGateVerdict] =
    useState<FirewallVerdict>("allow");
  const [activeGateLatency, setActiveGateLatency] = useState<number>(0.16);
  const [activeGateTool, setActiveGateTool] = useState<string>("execute_sql");
  const [statusMessage, setStatusMessage] = useState<string>(
    "AgentWall Active • AST Semantic Guardrails & Delegated RBAC Enforced (<0.2ms)"
  );

  // Connect to redhand-core SSE stream & snapshot when backend is running on port 8000
  useEffect(() => {
    let eventSource: EventSource | null = null;
    let isMounted = true;

    async function syncSnapshot() {
      if (!token) return;
      try {
        const data = await apiFetch<{
          agents?: SnapshotAgentRow[];
          hitl_interventions?: Array<Record<string, unknown>>;
        }>("/v1/state/snapshot", token);
        if (!isMounted) return;
        setEngineConnected(true);
        if (Array.isArray(data.agents)) {
          setAgents(data.agents.map(toAgentPosture));
        }

        const hitlRows = data.hitl_interventions;
        if (Array.isArray(hitlRows) && hitlRows.length > 0) {
          setInterventions((prev) => {
            const map = new Map(prev.map((i) => [i.id, i]));
            for (const r of hitlRows) {
              const item: HITLInterventionItem = {
                id: String(r.id),
                trace_id: String(r.trace_id || ""),
                span_id: String(r.span_id || ""),
                agent_id: String(r.agent_id || ""),
                agent_name: "FinOps CloudSQL Remediator",
                framework: "LangGraph",
                status: (r.status as HITLInterventionItem["status"]) || "pending",
                risk_tier: (r.risk_tier as HITLInterventionItem["risk_tier"]) || "destructive",
                proposed_tool_name: String(r.proposed_tool_name || ""),
                proposed_tool_arguments:
                  (r.proposed_tool_arguments as Record<string, unknown>) || {},
                target_cloud_resource: String(r.target_cloud_resource || ""),
                requested_iam_permissions:
                  (r.requested_iam_permissions as string[]) || [],
                agent_justification: String(r.agent_justification || ""),
                serialized_agent_state:
                  (r.serialized_agent_state as Record<string, unknown>) || {},
                state_checksum: String(r.state_checksum || ""),
                resume_webhook_url: String(r.resume_webhook_url || ""),
                required_approvals: Number(r.required_approvals || 1),
                approvals:
                  (r.approvals as Array<{
                    reviewer_user_id: string;
                    reviewer_comment?: string;
                    approved_at: string;
                  }>) || [],
                policy_rule_id: String(r.policy_rule_id || ""),
                created_at: String(r.created_at || new Date().toISOString()),
                expires_at: String(r.expires_at || new Date().toISOString()),
              };
              map.set(item.id, item);
            }
            return Array.from(map.values());
          });
        }
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          signOut("/login");
          return;
        }
        if (isMounted) setEngineConnected(false);
      }
    }

    async function openStream() {
      if (!token) return;
      // EventSource cannot send headers, so exchange the token for a one-time ticket.
      const { ticket } = await apiFetch<{ ticket: string }>("/v1/state/stream-ticket", token, {
        method: "POST",
      });
      if (!isMounted) return;
      eventSource = new EventSource(
        `${CORE_API_BASE}/v1/state/stream?ticket=${encodeURIComponent(ticket)}`
      );
      eventSource.onopen = () => {
        if (isMounted) setEngineConnected(true);
      };
      eventSource.onmessage = (evt) => {
        try {
          const parsed = JSON.parse(evt.data);
          if (parsed.event === "execution_traces.upserted" && Array.isArray(parsed.data)) {
            const row = parsed.data[0];
            if (row) {
              const liveTrace: TraceTelemetryRow = {
                id: String(row.id),
                trace_id: String(row.trace_id),
                span_id: String(row.span_id),
                agent_name: "FinOps CloudSQL Remediator",
                framework: "LangGraph",
                step_type: row.step_type || "action",
                tool_name: String(row.tool_name || "agent_step"),
                tool_arguments: row.tool_arguments || {},
                observation_snippet: JSON.stringify(
                  row.observation_payload || "Live SDK Telemetry Span"
                ),
                thought_content: String(
                  row.thought_content || "Executed via AgentWall Proxy"
                ),
                risk_tier: row.tool_risk_tier || "read_only",
                verdict: row.firewall_verdict || "allow",
                detector_tier: "sqlglot_ast_guardrail",
                confidence_score: row.firewall_verdict === "blocked" ? 0.999 : 0.001,
                firewall_latency_ms: Number(row.firewall_latency_ms || 0.16),
                ephemeral_token_jti: row.ephemeral_token_jti || null,
                target_resource: "https://warehouse.data.internal",
                cab_policy: null,
                cloud_provider: "local",
                delegated_user: currentUser.email,
                delegated_roles: currentUser.delegatedRoles,
                occurred_at: new Date().toTimeString().split(" ")[0],
              };
              setTraces((prev) => [liveTrace, ...prev]);
              setSelectedTrace(liveTrace);
              setActiveGateTool(liveTrace.tool_name);
              setActiveGateLatency(liveTrace.firewall_latency_ms);
              setActiveGateVerdict(liveTrace.verdict);
            }
          }
          if (parsed.event && parsed.event.startsWith("hitl_interventions.")) {
            syncSnapshot();
          }
        } catch {
          // Ignore keepalives
        }
      };
      eventSource.onerror = () => {
        if (isMounted) setEngineConnected(false);
      };
    }

    syncSnapshot();
    openStream().catch(() => {
      if (isMounted) setEngineConnected(false);
    });

    return () => {
      isMounted = false;
      eventSource?.close();
    };
  }, [currentUser, token, signOut]);

  const nodeTypes = useMemo(
    () => ({
      inputVector: InputVectorNode,
      agentRing: AgentRingNode,
      guardGate: GuardGateNode,
      cloudResource: CloudResourceNode,
    }),
    []
  );

  const pendingHitlCount = interventions.filter(
    (i) => i.status === "pending" || i.status === "partially_approved"
  ).length;

  // Filter traces based on active chip and search query
  const filteredTraces = useMemo(() => {
    return traces.filter((tr) => {
      if (
        selectedChip === "Review Pending (HITL)" &&
        tr.verdict !== "hitl_paused"
      ) {
        return false;
      }
      if (
        selectedChip === "AST Guardrails (<0.2ms)" &&
        tr.verdict !== "blocked"
      ) {
        return false;
      }
      if (
        selectedChip === "Multi-Cloud & SaaS Tokens" &&
        !tr.ephemeral_token_jti
      ) {
        return false;
      }
      if (
        selectedChip === "Delegated RBAC Intersections" &&
        (!tr.delegated_roles || tr.delegated_roles.length === 0)
      ) {
        return false;
      }
      if (searchQuery.trim() !== "") {
        const q = searchQuery.toLowerCase();
        const hay = `${tr.agent_name} ${tr.tool_name} ${tr.trace_id} ${tr.target_resource} ${tr.verdict} ${tr.delegated_user}`.toLowerCase();
        return hay.includes(q);
      }
      return true;
    });
  }, [traces, selectedChip, searchQuery]);

  // Target resource dynamically updates based on active tool
  const currentCloudResource = useMemo(() => {
    if (activeGateTool === "azure_blob_inspect") {
      return {
        serviceType: "AZURE BLOB STORAGE",
        label: "prod-logs (Azure)",
        resourceUri: "https://management.azure.com/subscriptions/prod/storage",
        cabRole: "Entra ID OBO: cloud_operator",
        cloudProvider: "azure",
        tokenJti: activeGateVerdict === "allow" ? "rh_az_sts_7f9910e42a19" : null,
      };
    }
    if (activeGateTool === "github_read_issue") {
      return {
        serviceType: "GITHUB REPOSITORY",
        label: "acme/agentic-repo",
        resourceUri: "https://api.github.com/repos/acme/agentic-repo",
        cabRole: "Fine-Grained App: repo:read",
        cloudProvider: "saas",
        tokenJti: activeGateVerdict === "allow" ? "ghs_4819a0bc7712" : null,
      };
    }
    if (activeGateTool === "run_shell_cmd") {
      return {
        serviceType: "HOST CONTAINMENT",
        label: "node-diagnostics.internal",
        resourceUri: "https://node-diagnostics.internal/api/shell",
        cabRole: "Positive Allowlist: ls, cat, grep",
        cloudProvider: "vault",
        tokenJti: activeGateVerdict === "allow" ? "vault_lease_9f82c1" : null,
      };
    }
    if (activeGateTool === "delete_production_database") {
      return {
        serviceType: "GCP CLOUD SQL",
        label: "core-ledger-prod-01",
        resourceUri: "//sqladmin.googleapis.com/instances/core-ledger-prod-01",
        cabRole: "inRole:roles/cloudsql.admin",
        cloudProvider: "gcp",
        tokenJti: null,
      };
    }
    return {
      serviceType: "ENTERPRISE WAREHOUSE",
      label: "warehouse.data.internal",
      resourceUri: "https://warehouse.data.internal/api/sql",
      cabRole: "Row Cap: 50 | Role: finance_viewer",
      cloudProvider: "local",
      tokenJti: activeGateVerdict === "allow" ? "aw_jit_8819a0bc4123" : null,
    };
  }, [activeGateTool, activeGateVerdict]);

  const nodes: Node[] = useMemo(
    () => [
      {
        id: "input-rag",
        type: "inputVector",
        position: { x: 30, y: 70 },
        data: {
          vectorType: "UNTRUSTED CONTEXT",
          label: "Inbound Intent & Delegated User Context",
          preview:
            activeGateVerdict === "blocked"
              ? "ATTACK: SELECT id, password_hash, ssn FROM users; (No LIMIT clause)"
              : `Caller: ${currentUser.name} [${currentUser.delegatedRoles.join(", ")}]`,
          isPoisoned: activeGateVerdict === "blocked",
        },
      },
      {
        id: "agent-finops",
        type: "agentRing",
        position: { x: 340, y: 50 },
        data: {
          label: agents[0].name,
          external_agent_id: agents[0].external_agent_id,
          framework: agents[0].framework,
          environment: agents[0].environment,
          riskScore: agents[0].riskScore,
          status: agents[0].status,
          p99FirewallMs: agents[0].p99FirewallMs,
          blockedAttacksCount: agents[0].blockedAttacksCount,
          hitlPendingCount: pendingHitlCount,
        },
      },
      {
        id: "agent-secops",
        type: "agentRing",
        position: { x: 340, y: 240 },
        data: {
          label: agents[1].name,
          external_agent_id: agents[1].external_agent_id,
          framework: agents[1].framework,
          environment: agents[1].environment,
          riskScore: agents[1].riskScore,
          status: agents[1].status,
          p99FirewallMs: agents[1].p99FirewallMs,
          blockedAttacksCount: agents[1].blockedAttacksCount,
          hitlPendingCount: 0,
        },
      },
      {
        id: "guard-gate-main",
        type: "guardGate",
        position: { x: 690, y: 60 },
        data: {
          toolName: activeGateTool,
          latencyMs: activeGateLatency,
          detectorTier: "sqlglot_ast_guardrail",
          riskTier:
            activeGateTool === "delete_production_database"
              ? "destructive"
              : "read_only",
          verdict: activeGateVerdict,
        },
      },
      {
        id: "cloud-resource-main",
        type: "cloudResource",
        position: { x: 1020, y: 50 },
        data: currentCloudResource,
      },
    ],
    [
      agents,
      activeGateVerdict,
      activeGateLatency,
      activeGateTool,
      pendingHitlCount,
      currentUser,
      currentCloudResource,
    ]
  );

  const edges: Edge[] = useMemo(() => {
    const mainEdgeColor =
      activeGateVerdict === "blocked"
        ? "var(--rh-crimson)"
        : activeGateVerdict === "hitl_paused"
          ? "var(--rh-ochre)"
          : "var(--rh-teal)";

    return [
      {
        id: "e-input-agent",
        source: "input-rag",
        target: "agent-finops",
        animated: true,
        style: {
          stroke: activeGateVerdict === "blocked" ? "var(--rh-crimson)" : "var(--rh-text-secondary)",
          strokeWidth: 1.8,
        },
        markerEnd: { type: MarkerType.ArrowClosed, color: "var(--rh-text-secondary)" },
      },
      {
        id: "e-agent-guard",
        source: "agent-finops",
        target: "guard-gate-main",
        animated: true,
        label:
          activeGateVerdict === "blocked"
            ? "CONTAINED (<0.2ms)"
            : activeGateVerdict === "hitl_paused"
              ? "FOUR-EYES PAUSED"
              : "AST APPROVED (<0.2ms)",
        labelStyle: { fill: "var(--rh-text-primary)", fontWeight: 600, fontSize: 11 },
        labelBgStyle: { fill: "var(--rh-surface-elevated)", fillOpacity: 1 },
        style: { stroke: mainEdgeColor, strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: mainEdgeColor },
      },
      {
        id: "e-guard-cloud",
        source: "guard-gate-main",
        target: "cloud-resource-main",
        animated: activeGateVerdict === "allow",
        label:
          activeGateVerdict === "allow"
            ? "JIT STS DISPATCHED (30s)"
            : "ZERO CREDENTIAL DISPATCHED",
        labelStyle: { fill: "var(--rh-text-secondary)", fontWeight: 500, fontSize: 11 },
        labelBgStyle: { fill: "var(--rh-surface-elevated)", fillOpacity: 1 },
        style: {
          stroke: activeGateVerdict === "allow" ? "var(--rh-teal)" : "var(--rh-border-hairline)",
          strokeWidth: 2,
          strokeDasharray: activeGateVerdict === "allow" ? undefined : "5 4",
        },
      },
    ];
  }, [activeGateVerdict]);

  const handleResolveIntervention = useCallback(
    async (
      interventionId: string,
      action: "approve" | "deny",
      modifiedArgs: Record<string, unknown>,
      comment: string
    ) => {
      // The reviewer is whoever is signed in; core records the authenticated operator.
      const activeReviewer = session?.email ?? "operator";
      let resolvedStatus: "approved" | "partially_approved" | "denied";

      try {
        const body = await apiFetch<{ status: "approved" | "partially_approved" | "denied" }>(
          `/v1/hitl/${interventionId}/resolve`,
          token,
          {
            method: "POST",
            body: {
              action,
              reviewer_comment: comment,
              modified_tool_arguments: modifiedArgs,
            },
          }
        );
        resolvedStatus = body.status;
      } catch (err) {
        setStatusMessage(
          `Resolution not recorded • ${err instanceof Error ? err.message : "redhand-core unreachable"}`
        );
        return;
      }

      setInterventions((prev) =>
        prev.map((item) => {
          if (item.id !== interventionId) return item;
          const currentApprovals = item.approvals || [];
          const nextApprovals =
            action === "approve"
              ? [
                  ...currentApprovals.filter(
                    (a) => a.reviewer_user_id !== activeReviewer
                  ),
                  {
                    reviewer_user_id: activeReviewer,
                    reviewer_comment: comment,
                    approved_at: new Date().toISOString(),
                  },
                ]
              : currentApprovals;

          return {
            ...item,
            status: resolvedStatus,
            approvals: nextApprovals,
            proposed_tool_arguments: modifiedArgs,
          };
        })
      );

      if (resolvedStatus === "partially_approved") {
        setActiveGateVerdict("hitl_paused");
        setStatusMessage(
          "Four-Eyes Quorum In Progress • 1st signature verified • Awaiting 2nd operator signature"
        );
      } else if (resolvedStatus === "approved") {
        setActiveGateVerdict("allow");
        setStatusMessage(
          `Approved • Quorum verified • Ephemeral STS token minted for ${JSON.stringify(modifiedArgs)}`
        );
      } else {
        setActiveGateVerdict("blocked");
        setStatusMessage(
          "Denied by operator • Execution aborted and structured policy notice returned to agent"
        );
      }
    },
    [session, token]
  );

  const handleToggleAgentQuarantine = useCallback(
    async (agentId: string, nextStatus: "active" | "frozen") => {
      try {
        if (nextStatus === "frozen") {
          await apiFetch(`/v1/passports/${agentId}/freeze`, token, { method: "POST", body: {} });
        } else {
          if (!window.confirm("Unfreeze this agent? It will be able to call its tools again.")) return;
          await apiFetch(`/v1/passports/${agentId}/unfreeze`, token, {
            method: "POST",
            body: { confirm: true },
          });
        }
      } catch (err) {
        setStatusMessage(
          `Agent status not changed • ${err instanceof Error ? err.message : "redhand-core unreachable"}`
        );
        return;
      }

      setAgents((prev) =>
        prev.map((ag) =>
          ag.id === agentId
            ? {
                ...ag,
                status: nextStatus,
                riskScore: nextStatus === "frozen" ? 95 : 42,
              }
            : ag
        )
      );
      setStatusMessage(
        `Agent passport updated • Status set to ${nextStatus.toUpperCase()}`
      );
    },
    [token]
  );

  // 6 Scenarios matching the 6 security fixes
  const handleSimulateAttack = useCallback(
    (scenario: SimulationScenarioType) => {
      const nowTime = new Date().toTimeString().split(" ")[0] + ".104";

      if (scenario === "benign_read") {
        const newTrace: TraceTelemetryRow = {
          id: `tr-${Date.now()}`,
          trace_id: "77c10923fae8411290bc1129a740991a",
          span_id: "1109ab8823cd1029",
          agent_name: "FinOps CloudSQL Remediator",
          framework: "LangGraph",
          step_type: "action",
          tool_name: "execute_sql",
          tool_arguments: {
            query: "SELECT id, email, created_at FROM users WHERE status = 'active' LIMIT 10;",
            max_rows: 10,
          },
          observation_snippet: "Returned 10 verified records under row cap.",
          thought_content: "Executing analytical SQL query with mandatory LIMIT 10 clause under finance_viewer role.",
          risk_tier: "read_only",
          verdict: "allow",
          detector_tier: "sqlglot_ast_guardrail",
          confidence_score: 0.001,
          firewall_latency_ms: 0.16,
          ephemeral_token_jti: "aw_jit_8819a0bc4123",
          target_resource: "https://warehouse.data.internal",
          cab_policy: null,
          cloud_provider: "local",
          delegated_user: currentUser.email,
          delegated_roles: currentUser.delegatedRoles,
          occurred_at: nowTime,
        };
        setTraces((prev) => [newTrace, ...prev]);
        setSelectedTrace(newTrace);
        setActiveGateTool("execute_sql");
        setActiveGateLatency(0.16);
        setActiveGateVerdict("allow");
        setStatusMessage(
          "AST Verified • SQL with explicit LIMIT 10 approved under finance_viewer delegated RBAC (0.16ms)"
        );
      } else if (scenario === "sql_exfiltration") {
        const newTrace: TraceTelemetryRow = {
          id: `tr-${Date.now()}`,
          trace_id: "ff0192837465aabbccddeeff00112233",
          span_id: "9988776655443322",
          agent_name: "FinOps CloudSQL Remediator",
          framework: "LangGraph",
          step_type: "system_halt",
          tool_name: "execute_sql",
          tool_arguments: {
            query: "SELECT id, username, password_hash, ssn FROM users;",
          },
          observation_snippet: "Exfiltration payload attempting full table dump and sensitive column extraction.",
          thought_content: "Attempted query lacking LIMIT clause and requesting prohibited columns [password_hash, ssn].",
          risk_tier: "destructive",
          verdict: "blocked",
          detector_tier: "sqlglot_ast_guardrail",
          confidence_score: 0.9998,
          firewall_latency_ms: 0.14,
          ephemeral_token_jti: null,
          target_resource: "https://warehouse.data.internal",
          cab_policy: null,
          cloud_provider: "local",
          delegated_user: currentUser.email,
          delegated_roles: currentUser.delegatedRoles,
          occurred_at: nowTime,
        };
        setTraces((prev) => [newTrace, ...prev]);
        setSelectedTrace(newTrace);
        setActiveGateTool("execute_sql");
        setActiveGateLatency(0.14);
        setActiveGateVerdict("blocked");
        setStatusMessage(
          "Contained • Full-table dump exfiltration (no LIMIT) and forbidden columns [password_hash, ssn] blocked in 0.14ms"
        );
      } else if (scenario === "shell_evasion") {
        const newTrace: TraceTelemetryRow = {
          id: `tr-${Date.now()}`,
          trace_id: "cc448822001199338877665544332211",
          span_id: "7766554433221100",
          agent_name: "SecOps RAG Incident Triager",
          framework: "Vertex ADK",
          step_type: "system_halt",
          tool_name: "run_shell_cmd",
          tool_arguments: {
            command: "cat /\\x65\\x74\\x63/passwd | base64 --decode",
          },
          observation_snippet: "Obfuscated shell command utilizing hex escape and base64 pipe evasion.",
          thought_content: "Halted by POSIX shlex anti-evasion lexer and positive allowlist (deny-by-default).",
          risk_tier: "critical",
          verdict: "blocked",
          detector_tier: "shlex_posix_lexer",
          confidence_score: 0.9995,
          firewall_latency_ms: 0.17,
          ephemeral_token_jti: null,
          target_resource: "https://node-diagnostics.internal",
          cab_policy: null,
          cloud_provider: "vault",
          delegated_user: currentUser.email,
          delegated_roles: currentUser.delegatedRoles,
          occurred_at: nowTime,
        };
        setTraces((prev) => [newTrace, ...prev]);
        setSelectedTrace(newTrace);
        setActiveGateTool("run_shell_cmd");
        setActiveGateLatency(0.17);
        setActiveGateVerdict("blocked");
        setStatusMessage(
          "Contained • Shell obfuscation (hex escape '\\x65' & base64 pipe) blocked by positive allowlist (0.17ms)"
        );
      } else if (scenario === "rbac_denied") {
        const newTrace: TraceTelemetryRow = {
          id: `tr-${Date.now()}`,
          trace_id: "ee119922883377446655001122334455",
          span_id: "3322114455667788",
          agent_name: "SecOps RAG Incident Triager",
          framework: "Vertex ADK",
          step_type: "system_halt",
          tool_name: "azure_blob_inspect",
          tool_arguments: { container_name: "prod-logs" },
          observation_snippet: `Caller '${currentUser.email}' lacks required role [cloud_operator, admin].`,
          thought_content: "Caller RBAC intersection evaluated: agent is allowed, but human user is unauthorized.",
          risk_tier: "read_only",
          verdict: "blocked",
          detector_tier: "delegated_rbac_engine",
          confidence_score: 1.0,
          firewall_latency_ms: 0.08,
          ephemeral_token_jti: null,
          target_resource: "https://management.azure.com",
          cab_policy: null,
          cloud_provider: "azure",
          delegated_user: currentUser.email,
          delegated_roles: currentUser.delegatedRoles,
          occurred_at: nowTime,
        };
        setTraces((prev) => [newTrace, ...prev]);
        setSelectedTrace(newTrace);
        setActiveGateTool("azure_blob_inspect");
        setActiveGateLatency(0.08);
        setActiveGateVerdict("blocked");
        setStatusMessage(
          `Per-User RBAC Denied • Caller '${currentUser.email}' with roles [${currentUser.delegatedRoles.join(", ")}] lacks required [cloud_operator] (0.08ms)`
        );
      } else if (scenario === "multicloud_sts") {
        const newTrace: TraceTelemetryRow = {
          id: `tr-${Date.now()}`,
          trace_id: "31d90012fae8471290bc1129a740192b",
          span_id: "4410ab9912cd8812",
          agent_name: "SecOps RAG Incident Triager",
          framework: "Vertex ADK",
          step_type: "action",
          tool_name: "azure_blob_inspect",
          tool_arguments: { container_name: "prod-logs" },
          observation_snippet: "Container metadata verified. 4 log blobs indexed.",
          thought_content: "Querying Azure Blob Storage with JIT Entra ID On-Behalf-Of (OBO) token.",
          risk_tier: "read_only",
          verdict: "allow",
          detector_tier: "schema_validator",
          confidence_score: 0.005,
          firewall_latency_ms: 0.15,
          ephemeral_token_jti: "rh_az_sts_7f9910e42a19",
          target_resource: "https://management.azure.com",
          cab_policy: null,
          cloud_provider: "azure",
          delegated_user: "alice.chen@enterprise.com",
          delegated_roles: ["cloud_operator", "admin"],
          occurred_at: nowTime,
        };
        setTraces((prev) => [newTrace, ...prev]);
        setSelectedTrace(newTrace);
        setActiveGateTool("azure_blob_inspect");
        setActiveGateLatency(0.15);
        setActiveGateVerdict("allow");
        setStatusMessage(
          "Multi-Cloud STS Minted • Ephemeral Azure Entra ID OBO token issued with 30s TTL (0.15ms)"
        );
      } else {
        const newInterventionId = crypto.randomUUID();
        const newIntervention: HITLInterventionItem = {
          id: newInterventionId,
          trace_id: "aa8811223344556677889900aabbccdd",
          span_id: "1234567890abcdef",
          agent_id: agents[0].id,
          agent_name: agents[0].name,
          framework: agents[0].framework,
          status: "pending",
          risk_tier: "destructive",
          proposed_tool_name: "delete_production_database",
          proposed_tool_arguments: {
            db_name: "core-ledger-prod-01",
            skip_final_snapshot: true,
            region: "asia-southeast1",
          },
          target_cloud_resource:
            "//sqladmin.googleapis.com/instances/core-ledger-prod-01",
          requested_iam_permissions: ["inRole:roles/cloudsql.admin"],
          agent_justification:
            "Autonomous cost-remediation loop selected core-ledger-prod-01 for immediate deletion.",
          serialized_agent_state: {
            graph_node: "remediation_step_4",
            retry_count: 0,
            checkpoint_ts: Date.now(),
          },
          state_checksum:
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
          resume_webhook_url: "http://localhost:8099/webhooks/agent-resume",
          required_approvals: 2,
          created_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
        };
        setInterventions((prev) => [newIntervention, ...prev]);
        setActiveGateTool("delete_production_database");
        setActiveGateLatency(0.12);
        setActiveGateVerdict("hitl_paused");
        setStatusMessage(
          "Four-Eyes Review Pending • Destructive database termination paused for dual human operator signatures"
        );
      }
    },
    [currentUser, agents]
  );

  if (!session) return null;

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-rh-card text-rh-text select-none">
      <div
        role="status"
        className="shrink-0 bg-rh-ochre-wash px-4 py-1.5 text-center text-[12px] font-medium text-rh-ochre"
      >
        {engineConnected
          ? "Live: agents and the review queue come from redhand-core. Traces, the canvas and simulations are sample data."
          : "Demo data: not connected to redhand-core. Everything on this page is sample data."}{" "}
        Use the Passports page for real control actions.
      </div>
      {/* 1. TOP NAVIGATION BAR */}
      <header className="flex h-[56px] shrink-0 items-center justify-between border-b border-rh-hairline bg-rh-card px-4">
        <div className="flex items-center gap-4">
          <button
            className="flex h-[40px] w-[40px] items-center justify-center rounded-full text-rh-text-2 hover:bg-rh-elevated"
            aria-label="Menu"
          >
            <Menu className="h-5 w-5 text-rh-text" />
          </button>

          <div className="flex items-center gap-2">
            <RedHandCrest size="sm" />
            <span className="text-[20px] leading-[28px] font-bold tracking-tight text-rh-text">
              redhand
            </span>
            <span className="text-[11px] font-bold uppercase tracking-wider text-rh-text-2 bg-rh-elevated px-1.5 py-0.5 rounded">
              ASPM
            </span>
          </div>
          <nav className="flex gap-1 text-[13px]">
            <a href="/passports" className="whitespace-nowrap rounded-full px-3 py-1.5 font-medium text-rh-text-2 hover:bg-rh-elevated">
              Passports
            </a>
            <span className="whitespace-nowrap rounded-full bg-rh-teal px-3 py-1.5 font-semibold text-rh-canvas">
              Command center
            </span>
          </nav>
        </div>

        {/* Center Search Input */}
        <div className="flex w-full max-w-[500px] items-center">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter traces by agent, tool, user identity, or cloud resource..."
            className="h-[38px] flex-1 rounded-l-full border border-rh-hairline bg-rh-card px-4 text-[13px] text-rh-text placeholder-rh-muted focus:border-rh-strong focus:outline-none"
          />
          <button
            onClick={() => setSearchQuery("")}
            className="flex h-[38px] w-[56px] items-center justify-center rounded-r-full border border-l-0 border-rh-hairline bg-rh-subtle hover:bg-rh-elevated"
            aria-label="Search"
          >
            <Search className="h-4 w-4 text-rh-text-2" />
          </button>
        </div>

        {/* Right Metadata + Engine Sync Indicator */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              signOut("/login");
            }}
            className="whitespace-nowrap text-[12px] text-rh-text-2 hover:underline"
            title={session.email}
          >
            Sign out
          </button>

          <span className="inline-flex h-[34px] items-center gap-1.5 rounded-full bg-rh-elevated px-3.5 text-[12px] font-medium text-rh-text">
            {engineConnected ? (
              <>
                <Radio className="h-3.5 w-3.5 text-rh-teal-text" />
                Live Engine
              </>
            ) : (
              <>
                <ShieldCheck className="h-4 w-4 text-rh-teal-text" />
                AgentWall Active
              </>
            )}
          </span>

          {/* Enterprise SSO User & Delegated RBAC Selector */}
          <div className="relative flex items-center gap-2 rounded-full border border-rh-hairline bg-rh-elevated py-1 px-3 hover:bg-rh-strong transition-colors cursor-pointer">
            <div className="flex h-6 w-6 items-center justify-center rounded-full bg-rh-teal text-[10px] font-bold text-rh-canvas">
              {currentUser.avatarInitials}
            </div>
            <div className="flex flex-col text-left">
              <span className="text-[12px] font-semibold text-rh-text leading-tight">
                {currentUser.name}
              </span>
              <span className="text-[9px] uppercase tracking-wider text-rh-text-2 font-mono">
                {currentUser.role.replace("_", " ")} [{currentUser.delegatedRoles.join(", ")}]
              </span>
            </div>
            <select
              value={currentUser.id}
              onChange={(e) => {
                const found = ENTERPRISE_USERS.find(
                  (u) => u.id === e.target.value
                );
                if (found) setCurrentUser(found);
              }}
              className="absolute inset-0 opacity-0 cursor-pointer"
              title="Simulation persona (demo only; does not change who you are signed in as)"
            >
              {ENTERPRISE_USERS.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.name} — {u.role.toUpperCase()} (Roles: {u.delegatedRoles.join(", ")})
                </option>
              ))}
            </select>
          </div>

          <button
            className="relative flex h-[38px] w-[38px] items-center justify-center rounded-full text-rh-text-2 hover:bg-rh-elevated"
            aria-label="Notifications"
          >
            <Bell className="h-5 w-5 text-rh-text" />
            {pendingHitlCount > 0 && (
              <span className="absolute right-1 top-1 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-rh-crimson px-1 text-[10px] font-bold text-rh-canvas">
                {pendingHitlCount}
              </span>
            )}
          </button>
        </div>
      </header>

      {/* 2. CHIP FILTER BAR */}
      <div className="flex items-center justify-between border-b border-rh-hairline bg-rh-card px-4 py-2">
        <div className="flex items-center gap-1.5 overflow-x-auto">
          {FILTER_CHIPS.map((chip) => {
            const isSelected = selectedChip === chip;
            return (
              <button
                key={chip}
                onClick={() => setSelectedChip(chip)}
                className={`rounded-full px-3 py-1 text-[13px] leading-[18px] font-medium transition-colors whitespace-nowrap ${
                  isSelected
                    ? "bg-rh-teal text-rh-canvas"
                    : "bg-rh-elevated text-rh-text hover:bg-rh-strong"
                }`}
              >
                {chip}
              </button>
            );
          })}
        </div>

        <div className="hidden lg:flex items-center gap-2 text-[12px] text-rh-text-2">
          <span
            className={`h-2 w-2 rounded-full ${
              activeGateVerdict === "blocked"
                ? "bg-rh-crimson"
                : activeGateVerdict === "hitl_paused"
                  ? "bg-rh-ochre"
                  : "bg-rh-teal"
            }`}
          />
          <span className="font-medium text-rh-text">{statusMessage}</span>
        </div>
      </div>

      {/* 3. MIDDLE WORKSPACE: CANVAS + INTERVENTION RAIL */}
      <div className="flex flex-1 min-h-0 overflow-hidden">
        <div className="relative flex-1 h-full bg-rh-subtle">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.16 }}
            proOptions={{ hideAttribution: true }}
          >
            <Background color="var(--rh-border-hairline)" gap={20} size={1} />
            <Controls position="bottom-left" />
          </ReactFlow>
        </div>

        <InterventionRail
          interventions={interventions}
          selectedTrace={selectedTrace}
          agents={agents}
          currentUser={currentUser}
          onResolveIntervention={handleResolveIntervention}
          onToggleAgentQuarantine={handleToggleAgentQuarantine}
        />
      </div>

      {/* 4. BOTTOM DOCK: FLIGHT RECORDER & SIMULATION DOCK */}
      <FlightRecorderDock
        traces={filteredTraces}
        agents={agents}
        selectedTraceId={selectedTrace?.id ?? null}
        onSelectTrace={(t) => setSelectedTrace(t)}
        onSimulateAttack={handleSimulateAttack}
      />
    </div>
  );
}
