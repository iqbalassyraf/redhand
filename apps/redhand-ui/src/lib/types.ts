export type FirewallVerdict =
  | "allow"
  | "redacted"
  | "flagged"
  | "blocked"
  | "hitl_paused";

export type RiskTier =
  | "read_only"
  | "state_mutation"
  | "destructive"
  | "critical";

export type SeverityLevel = "low" | "medium" | "high" | "critical";

export interface AgentPostureItem {
  id: string;
  external_agent_id: string;
  name: string;
  framework: "LangGraph" | "CrewAI" | "Vertex ADK" | "Custom MCP";
  environment: "production" | "staging" | "development";
  status: "active" | "frozen" | "revoked" | "expired";
  riskScore: number; // 0-100 for radial arc ring
  activeLeaseCount: number;
  blockedAttacksCount: number;
  hitlPendingCount: number;
  p99FirewallMs: number;
  serviceAccount: string;
  allowedTools: string[];
}

export interface HITLInterventionItem {
  id: string;
  trace_id: string;
  span_id: string;
  agent_id: string;
  agent_name: string;
  framework: string;
  status: "pending" | "partially_approved" | "approved" | "denied" | "resumed";
  risk_tier: RiskTier;
  proposed_tool_name: string;
  proposed_tool_arguments: Record<string, unknown>;
  target_cloud_resource: string;
  requested_iam_permissions: string[];
  agent_justification: string;
  serialized_agent_state: Record<string, unknown>;
  state_checksum: string;
  resume_webhook_url: string;
  required_approvals?: number;
  approvals?: Array<{
    reviewer_user_id: string;
    reviewer_comment?: string;
    approved_at: string;
  }>;
  policy_rule_id?: string;
  created_at: string;
  expires_at: string;
}

export type EnterpriseRole =
  | "secops_admin"
  | "security_auditor"
  | "agent_developer"
  | "contractor_intern";

export interface AuthenticatedUser {
  id: string;
  name: string;
  email: string;
  role: EnterpriseRole;
  idpProvider: "okta" | "entra_id" | "google_workspace" | "github";
  avatarInitials: string;
  delegatedRoles: string[];
}

export interface WORMAuditBlockItem {
  block_index: number;
  block_id: string;
  timestamp: string;
  previous_block_hash: string;
  block_hash: string;
  merkle_root: string;
  record_count: number;
  cmek_key_arn: string | null;
  retention_until: string;
  tamper_status: "verified" | "compromised";
}

export interface TraceTelemetryRow {
  id: string;
  trace_id: string;
  span_id: string;
  agent_name: string;
  framework: string;
  step_type: "observation" | "thought" | "action" | "system_halt";
  tool_name: string;
  tool_arguments: Record<string, unknown>;
  observation_snippet: string;
  thought_content: string;
  risk_tier: RiskTier;
  verdict: FirewallVerdict;
  detector_tier: string;
  confidence_score: number;
  firewall_latency_ms: number;
  ephemeral_token_jti: string | null;
  target_resource: string;
  cab_policy: Record<string, unknown> | null;
  cloud_provider?: "aws" | "azure" | "gcp" | "saas" | "vault" | "local";
  delegated_user?: string;
  delegated_roles?: string[];
  occurred_at: string;
}

export interface MCPFindingItem {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category:
    | "EXECUTION_RISK"
    | "CREDENTIAL_EXPOSURE"
    | "FILESYSTEM_RISK"
    | "SCHEMA_RISK"
    | "NETWORK_RISK";
  tool_name?: string | null;
  title: string;
  description: string;
  remediation: string;
}

export interface MCPVettingReportItem {
  server_name: string;
  risk_score: number;
  verdict: "PASS" | "WARN" | "FAIL";
  total_tools_scanned: number;
  findings: MCPFindingItem[];
  recommended_policy: Record<string, unknown>;
}
