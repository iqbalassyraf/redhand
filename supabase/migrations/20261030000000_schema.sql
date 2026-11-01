-- =============================================================================
-- RedHand Core Database Schema (PostgreSQL / Supabase)
-- Architecture: Multi-tenant ASPM & Agentic Runtime Protection
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- 1. ENUMS & CUSTOM TYPES
-- -----------------------------------------------------------------------------
CREATE TYPE agent_environment AS ENUM ('development', 'staging', 'production');
CREATE TYPE agent_status AS ENUM ('active', 'suspended', 'quarantined', 'decommissioned');

CREATE TYPE step_type AS ENUM ('observation', 'thought', 'action', 'tool_result', 'system_halt');
CREATE TYPE risk_tier AS ENUM ('read_only', 'state_mutation', 'destructive', 'critical');

CREATE TYPE firewall_verdict AS ENUM ('allow', 'redacted', 'flagged', 'blocked', 'hitl_paused');
CREATE TYPE security_event_type AS ENUM (
    'prompt_injection_direct',
    'prompt_injection_indirect',
    'iam_scope_violation',
    'unregistered_tool_invocation',
    'dlp_secret_leak_prevented',
    'anomalous_token_velocity',
    'hitl_circuit_tripped'
);
CREATE TYPE severity_level AS ENUM ('low', 'medium', 'high', 'critical');

CREATE TYPE hitl_status AS ENUM ('pending', 'approved', 'denied', 'expired', 'resumed', 'failed');

-- -----------------------------------------------------------------------------
-- 2. MULTI-TENANCY FOUNDATION: ORGANIZATIONS & MEMBERSHIPS
-- -----------------------------------------------------------------------------
CREATE TABLE public.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    siem_webhook_url TEXT,
    default_hitl_timeout_seconds INTEGER NOT NULL DEFAULT 3600,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE public.organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'security_operator', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, user_id)
);

-- API Keys used by redhand-sdk to authenticate against redhand-core
CREATE TABLE public.sdk_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,        -- e.g., "rh_live_9f8a" for UI identification
    key_hash TEXT NOT NULL UNIQUE,   -- SHA-256 hash of the bearer token
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Helper function for RLS: Returns all organization_ids the current authenticated user belongs to
CREATE OR REPLACE FUNCTION public.get_user_organization_ids()
RETURNS SETOF UUID
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT organization_id
    FROM public.organization_members
    WHERE user_id = auth.uid();
$$;

-- -----------------------------------------------------------------------------
-- 3. CORE TABLE: AGENTS
-- Identities, declarative permission boundaries, and topology metadata
-- -----------------------------------------------------------------------------
CREATE TABLE public.agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    external_agent_id TEXT NOT NULL,                  -- Developer-defined ID (e.g., "finops-remediator-v2")
    name TEXT NOT NULL,
    description TEXT,
    framework TEXT NOT NULL DEFAULT 'custom',         -- e.g., 'langchain', 'langgraph', 'crewai', 'adk'
    environment agent_environment NOT NULL DEFAULT 'development',
    status agent_status NOT NULL DEFAULT 'active',
    
    -- Declarative Least-Privilege Boundary
    allowed_tools TEXT[] NOT NULL DEFAULT '{}',       -- Explicit allowlist of tool names
    gcp_service_account_email TEXT,                   -- Base identity for STS downscoping
    iam_access_boundary_template JSONB DEFAULT '{}'::jsonb, -- Pre-verified CAB template rules
    
    -- React Flow Visual Topology Coordinates & Metadata
    canvas_position JSONB DEFAULT '{"x": 0, "y": 0}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    last_heartbeat_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, external_agent_id, environment)
);

-- -----------------------------------------------------------------------------
-- 4. CORE TABLE: EXECUTION TRACES
-- OpenTelemetry-aligned logs of the probabilistic decision tree
-- (Observation -> Thought -> Action -> Tool Result)
-- -----------------------------------------------------------------------------
CREATE TABLE public.execution_traces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    
    -- OTel Distributed Tracing Correlation
    session_id UUID NOT NULL,                         -- Groups a multi-turn agent run
    trace_id TEXT NOT NULL,                           -- W3C Trace Context 32-hex-char ID
    span_id TEXT NOT NULL,                            -- W3C Span 16-hex-char ID
    parent_span_id TEXT,                              -- Links Action -> Thought -> Observation
    step_sequence INTEGER NOT NULL DEFAULT 0,         -- Monotonic ordering within a trace
    
    -- Reasoning Payload
    step_type step_type NOT NULL,
    model_provider TEXT,                              -- e.g., 'google-vertex', 'anthropic', 'openai'
    model_name TEXT,                                  -- e.g., 'gemini-2.5-pro'
    
    observation_payload JSONB,                        -- Untrusted input / RAG context / prior tool output
    thought_content TEXT,                             -- Raw chain-of-thought or reasoning rationale
    tool_name TEXT,                                   -- Populated when step_type = 'action'
    tool_arguments JSONB,                             -- Structured parameters passed to the tool
    tool_risk_tier risk_tier DEFAULT 'read_only',
    
    -- Guardrail & Latency Metrics
    firewall_verdict firewall_verdict NOT NULL DEFAULT 'allow',
    firewall_latency_ms NUMERIC(8, 2),                -- Enforces monitoring of the <50ms SLA
    execution_latency_ms NUMERIC(10, 2),
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    
    -- Ephemeral IAM audit link
    ephemeral_token_jti TEXT,                         -- Unique identifier/hash of single-use STS token
    
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, trace_id, span_id)
);

-- -----------------------------------------------------------------------------
-- 5. CORE TABLE: SECURITY EVENTS
-- Semantic Firewall blocks, prompt injections, and IAM boundary violations
-- -----------------------------------------------------------------------------
CREATE TABLE public.security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    execution_trace_id UUID REFERENCES public.execution_traces(id) ON DELETE SET NULL,
    
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    
    event_type security_event_type NOT NULL,
    severity severity_level NOT NULL,
    verdict firewall_verdict NOT NULL,
    
    -- Classifier / Firewall Forensics
    detector_tier TEXT NOT NULL,                      -- e.g., 'tier0_ast', 'tier1_onnx_deberta', 'iam_broker'
    confidence_score NUMERIC(5, 4) CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),
    firewall_latency_ms NUMERIC(8, 2) NOT NULL,
    
    trigger_snippet TEXT,                             -- Redacted/sanitized excerpt that tripped the sensor
    matched_rule_id TEXT,                             -- Policy ID or heuristic signature name
    mitigation_action TEXT NOT NULL,                  -- Explanation returned to operator/SIEM
    
    ocsf_payload JSONB NOT NULL DEFAULT '{}'::jsonb,  -- Pre-formatted OCSF security finding for SIEM export
    siem_exported BOOLEAN NOT NULL DEFAULT FALSE,
    
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 6. CORE TABLE: HITL INTERVENTIONS
-- Durable execution state for the Human-in-the-Loop circuit breaker
-- -----------------------------------------------------------------------------
CREATE TABLE public.hitl_interventions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES public.agents(id) ON DELETE CASCADE,
    execution_trace_id UUID REFERENCES public.execution_traces(id) ON DELETE SET NULL,
    security_event_id UUID REFERENCES public.security_events(id) ON DELETE SET NULL,
    
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    
    status hitl_status NOT NULL DEFAULT 'pending',
    risk_tier risk_tier NOT NULL,
    
    -- Action Context Inspected by Human Operator
    proposed_tool_name TEXT NOT NULL,
    proposed_tool_arguments JSONB NOT NULL,
    target_cloud_resource TEXT,                       -- e.g., '//storage.googleapis.com/projects/_/buckets/prod-pii'
    requested_iam_permissions TEXT[] DEFAULT '{}',    -- e.g., ARRAY['storage.objects.delete']
    agent_justification TEXT,                         -- Extracted from the agent's preceding Thought span
    
    -- Durable Execution Checkpoint State
    serialized_agent_state JSONB NOT NULL,            -- LangGraph/CrewAI checkpoint dictionary to rehydrate run
    state_checksum TEXT NOT NULL,                     -- SHA-256 integrity hash of serialized_agent_state
    
    -- Asynchronous Webhook Orchestration
    resume_webhook_url TEXT NOT NULL,                 -- Endpoint triggered to wake up the suspended agent run
    notification_webhook_url TEXT,                    -- Outbound Slack/PagerDuty/Teams alert URL
    
    -- Audit & Resolution Metadata
    reviewer_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    reviewer_comment TEXT,
    modified_tool_arguments JSONB,                    -- Allows human to edit args before approving
    
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    denied_at TIMESTAMPTZ,
    resumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Ensure mutual exclusivity of approval and denial timestamps
    CONSTRAINT hitl_resolution_consistency CHECK (
        NOT (approved_at IS NOT NULL AND denied_at IS NOT NULL)
    )
);

-- -----------------------------------------------------------------------------
-- 7. PERFORMANCE INDEXES
-- -----------------------------------------------------------------------------
CREATE INDEX idx_org_members_user ON public.organization_members(user_id);
CREATE INDEX idx_sdk_keys_hash ON public.sdk_api_keys(key_hash) WHERE is_active = TRUE;

CREATE INDEX idx_agents_org_status ON public.agents(organization_id, status);
CREATE INDEX idx_agents_external_id ON public.agents(organization_id, external_agent_id);

CREATE INDEX idx_traces_org_time ON public.execution_traces(organization_id, occurred_at DESC);
CREATE INDEX idx_traces_agent_session ON public.execution_traces(agent_id, session_id, step_sequence);
CREATE INDEX idx_traces_trace_id ON public.execution_traces(organization_id, trace_id);

CREATE INDEX idx_sec_events_org_time ON public.security_events(organization_id, occurred_at DESC);
CREATE INDEX idx_sec_events_severity ON public.security_events(organization_id, severity, occurred_at DESC);
CREATE INDEX idx_sec_events_unexported ON public.security_events(organization_id) WHERE siem_exported = FALSE;

CREATE INDEX idx_hitl_org_pending ON public.hitl_interventions(organization_id, created_at DESC) WHERE status = 'pending';
CREATE INDEX idx_hitl_agent_status ON public.hitl_interventions(agent_id, status);

-- -----------------------------------------------------------------------------
-- 8. AUTOMATIC UPDATED_AT TRIGGERS
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.trigger_set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER set_organizations_updated_at
    BEFORE UPDATE ON public.organizations
    FOR EACH ROW EXECUTE FUNCTION public.trigger_set_updated_at();

CREATE TRIGGER set_agents_updated_at
    BEFORE UPDATE ON public.agents
    FOR EACH ROW EXECUTE FUNCTION public.trigger_set_updated_at();

CREATE TRIGGER set_hitl_updated_at
    BEFORE UPDATE ON public.hitl_interventions
    FOR EACH ROW EXECUTE FUNCTION public.trigger_set_updated_at();

-- -----------------------------------------------------------------------------
-- 9. ROW LEVEL SECURITY (RLS) POLICIES
-- -----------------------------------------------------------------------------
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sdk_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.execution_traces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hitl_interventions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own organizations"
    ON public.organizations FOR SELECT
    USING (id IN (SELECT public.get_user_organization_ids()));

CREATE POLICY "Users can view members of their organizations"
    ON public.organization_members FOR SELECT
    USING (organization_id IN (SELECT public.get_user_organization_ids()));

CREATE POLICY "Users can view SDK keys in their organizations"
    ON public.sdk_api_keys FOR SELECT
    USING (organization_id IN (SELECT public.get_user_organization_ids()));

CREATE POLICY "Admins can manage SDK keys"
    ON public.sdk_api_keys FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM public.organization_members
            WHERE organization_id = public.sdk_api_keys.organization_id
              AND user_id = auth.uid()
              AND role IN ('owner', 'admin')
        )
    );

CREATE POLICY "Users can view agents in their organizations"
    ON public.agents FOR SELECT
    USING (organization_id IN (SELECT public.get_user_organization_ids()));

CREATE POLICY "Operators and Admins can update agent posture"
    ON public.agents FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM public.organization_members
            WHERE organization_id = public.agents.organization_id
              AND user_id = auth.uid()
              AND role IN ('owner', 'admin', 'security_operator')
        )
    );

CREATE POLICY "Users can view execution traces in their organizations"
    ON public.execution_traces FOR SELECT
    USING (organization_id IN (SELECT public.get_user_organization_ids()));

CREATE POLICY "Users can view security events in their organizations"
    ON public.security_events FOR SELECT
    USING (organization_id IN (SELECT public.get_user_organization_ids()));

CREATE POLICY "Users can view HITL interventions in their organizations"
    ON public.hitl_interventions FOR SELECT
    USING (organization_id IN (SELECT public.get_user_organization_ids()));

CREATE POLICY "Security operators can approve or deny HITL interventions"
    ON public.hitl_interventions FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM public.organization_members
            WHERE organization_id = public.hitl_interventions.organization_id
              AND user_id = auth.uid()
              AND role IN ('owner', 'admin', 'security_operator')
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.organization_members
            WHERE organization_id = public.hitl_interventions.organization_id
              AND user_id = auth.uid()
              AND role IN ('owner', 'admin', 'security_operator')
        )
    );

-- -----------------------------------------------------------------------------
-- 10. SUPABASE REALTIME PUBLICATIONS
-- -----------------------------------------------------------------------------
ALTER PUBLICATION supabase_realtime ADD TABLE public.agents;
ALTER PUBLICATION supabase_realtime ADD TABLE public.execution_traces;
ALTER PUBLICATION supabase_realtime ADD TABLE public.security_events;
ALTER PUBLICATION supabase_realtime ADD TABLE public.hitl_interventions;

