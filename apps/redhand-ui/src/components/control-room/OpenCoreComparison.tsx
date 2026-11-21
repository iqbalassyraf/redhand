"use client";

import React from "react";
import {
  Activity,
  ArrowRight,
  Check,
  Cpu,
  ExternalLink,
  GitBranch,
  KeyRound,
  Lock,
  Shield,
  ShieldAlert,
  Sparkles,
  Zap,
} from "lucide-react";

export interface OpenCoreComparisonProps {
  onRequestEarlyAccess: () => void;
  githubUrl?: string;
}

const CORE_HIGHLIGHTS: Array<{ title: string; detail: string }> = [
  {
    title: "<2ms Deterministic Pre-Flight Gateway",
    detail: "Regex, JSON Schema, SQL AST, POSIX Shell allowlists, EN & SEA/Malay heuristics",
  },
  {
    title: "<15ms Local Semantic Firewall",
    detail: "Quantized ONNX / DeBERTa-v3 classifier running locally with zero external API calls",
  },
  {
    title: "Deterministic Tool-Call Policy Engine",
    detail: "Fail-closed YAML policies, destination canonicalization, and loop throttling",
  },
  {
    title: "LangGraph, CrewAI & MCP Middleware",
    detail: "@guard Python decorators, CLI manifest scanner, and MCP tool pinning",
  },
  {
    title: "OpenTelemetry (OTEL) Native Export",
    detail: "Structured OTLP spans, Prometheus /metrics, and local WORM audit logging",
  },
];

const ENTERPRISE_HIGHLIGHTS: Array<{ title: string; detail: string }> = [
  {
    title: "Everything in Open-Source Core",
    detail: "Full inline <2ms & <15ms gateway protection plus centralized fleet management",
  },
  {
    title: "Dynamic Ephemeral IAM Broker",
    detail: "60-second single-turn AWS STS, GCP IAM, and Microsoft Entra ID downscoped tokens",
  },
  {
    title: "Async Deep Cyber-Model Escalation",
    detail: "BYOK or managed frontier security models inspecting multi-turn context off the hot path",
  },
  {
    title: "Automated Sub-Agent Circuit-Breaker",
    detail: "Mid-loop quarantine, Risk Engine scoring ladder, and <2s global Passport revocation",
  },
  {
    title: "SIEM Connectors & STIX/TAXII Feeds",
    detail: "Native OCSF v1.1.0 streaming to Microsoft Sentinel, Splunk & Google SecOps",
  },
  {
    title: "Enterprise SSO, SCIM 2.0 & RBAC",
    detail: "Four-eyes HITL approvals, immutable cloud Black Box, and tenant isolation",
  },
];

export function OpenCoreComparison({
  onRequestEarlyAccess,
  githubUrl = "https://github.com/iqbalassyraf/redhand",
}: OpenCoreComparisonProps) {
  return (
    <section aria-labelledby="two-tier-heading" className="w-full">
      {/* 3-Stage Execution Pipeline Strip (5-second architectural scan) */}
      <div className="mb-6 grid grid-cols-1 gap-3 md:grid-cols-3">
        <div className="rh-glass flex items-center gap-3 rounded-rh-lg border border-control-border px-4 py-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-rh-teal-border bg-rh-teal-wash text-rh-teal-text">
            <Zap className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold text-rh-teal-text">&lt;2ms</span>
              <span className="text-xs font-semibold text-rh-text">Pre-Flight Gateway</span>
            </div>
            <p className="truncate text-[11px] text-rh-text-2">
              AST, Regex, Schema &amp; EN/Malay rules
            </p>
          </div>
        </div>

        <div className="rh-glass flex items-center gap-3 rounded-rh-lg border border-control-border px-4 py-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-rh-steel-border bg-rh-steel-wash text-rh-steel-text">
            <Cpu className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold text-rh-steel-text">&lt;15ms</span>
              <span className="text-xs font-semibold text-rh-text">Local Semantic Firewall</span>
            </div>
            <p className="truncate text-[11px] text-rh-text-2">
              Quantized ONNX/DeBERTa · 0 API calls
            </p>
          </div>
        </div>

        <div className="rh-glass flex items-center gap-3 rounded-rh-lg border border-rh-ochre-border bg-rh-ochre-wash/40 px-4 py-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-rh-ochre-border bg-rh-ochre-wash text-rh-ochre">
            <ShieldAlert className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold text-rh-ochre">ASYNC</span>
              <span className="text-xs font-semibold text-rh-text">10x Enterprise Escalation</span>
            </div>
            <p className="truncate text-[11px] text-rh-text-2">
              60s IAM, Cyber-Model &amp; Circuit-Breaker
            </p>
          </div>
        </div>
      </div>

      {/* Section Title */}
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <span className="text-[11px] font-semibold uppercase tracking-widest text-rh-text-muted">
            Two-Tier Open-Core Architecture
          </span>
          <h2 id="two-tier-heading" className="mt-1 text-xl font-bold tracking-tight text-rh-text sm:text-2xl">
            Run the Deterministic Core Free. Scale to 10x Enterprise Control.
          </h2>
        </div>
        <span className="rounded-full border border-control-border bg-rh-subtle px-3 py-1 text-[11px] font-medium text-rh-text-2">
          No pricing lock-in · Request Early Access for Design Partner cohorts
        </span>
      </div>

      {/* Side-by-Side Tier Comparison */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Tier 1: RedHand Open-Source Core */}
        <div className="rh-glass flex flex-col justify-between rounded-rh-xl border border-control-border p-6 shadow-rh-glass">
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-rh-teal-border bg-rh-teal-wash text-rh-teal-text">
                  <Shield className="h-4 w-4" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-rh-text">RedHand Open-Source Core</h3>
                  <p className="text-[11px] text-rh-text-2">Inline MCP &amp; Tool-Call Firewall</p>
                </div>
              </div>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-rh-teal-border bg-rh-teal-wash px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider text-rh-teal-text">
                <GitBranch className="h-3 w-3" />
                Apache 2.0 · Free Forever
              </span>
            </div>

            <p className="mt-4 text-xs leading-relaxed text-rh-text-2">
              Self-contained, deterministic interception engine you can embed in minutes. Zero
              cloud dependencies, zero per-call LLM costs, and sub-15ms total overhead.
            </p>

            <ul className="mt-5 flex flex-col gap-3">
              {CORE_HIGHLIGHTS.map((item) => (
                <li key={item.title} className="flex items-start gap-2.5">
                  <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-rh-teal-wash text-rh-teal-text">
                    <Check className="h-3 w-3" />
                  </span>
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-rh-text">{item.title}</div>
                    <div className="text-[11px] leading-snug text-rh-text-2">{item.detail}</div>
                  </div>
                </li>
              ))}
            </ul>
          </div>

          <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-control-border pt-4">
            <code className="rounded-rh-sm border border-control-border bg-rh-subtle px-2.5 py-1 font-mono text-[11px] text-rh-text-2">
              pip install redhand-sdk
            </code>
            <a
              href={githubUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-9 items-center gap-2 rounded-full border border-control-borderStrong bg-rh-elevated px-4 text-xs font-semibold text-rh-text transition-colors hover:border-rh-teal-border hover:bg-control-glassHover"
            >
              <span>Star on GitHub</span>
              <ExternalLink className="h-3.5 w-3.5 text-rh-text-2" />
            </a>
          </div>
        </div>

        {/* Tier 2: RedHand 10x Enterprise Native */}
        <div className="rh-glass relative flex flex-col justify-between rounded-rh-xl border border-control-crimsonBorder p-6 shadow-rh-crimson">
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-control-crimsonBright to-control-crimsonDeep text-white shadow-rh-crimson">
                  <KeyRound className="h-4 w-4" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-rh-text">RedHand 10x Enterprise Native</h3>
                  <p className="text-[11px] text-rh-text-2">
                    Commercial Control Plane &amp; Zero-Standing-Privilege Broker
                  </p>
                </div>
              </div>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-rh-ochre-border bg-rh-ochre-wash px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider text-rh-ochre">
                <Lock className="h-3 w-3" />
                Commercial · Early Access
              </span>
            </div>

            <p className="mt-4 text-xs leading-relaxed text-rh-text-2">
              Built for security teams running autonomous agent fleets in production. Eliminates
              long-lived cloud credentials and automates mid-loop quarantine across multi-agent
              workflows.
            </p>

            <ul className="mt-5 flex flex-col gap-3">
              {ENTERPRISE_HIGHLIGHTS.map((item) => (
                <li key={item.title} className="flex items-start gap-2.5">
                  <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-control-crimsonSoft text-rh-crimson-text">
                    <Sparkles className="h-3 w-3" />
                  </span>
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-rh-text">{item.title}</div>
                    <div className="text-[11px] leading-snug text-rh-text-2">{item.detail}</div>
                  </div>
                </li>
              ))}
            </ul>
          </div>

          <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-control-border pt-4">
            <span className="flex items-center gap-1.5 text-[11px] text-rh-text-2">
              <Activity className="h-3.5 w-3.5 text-rh-ochre" />
              Design Partner Waitlist Open
            </span>
            <button
              type="button"
              onClick={onRequestEarlyAccess}
              className="inline-flex h-9 items-center gap-2 rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-5 text-xs font-semibold text-white shadow-rh-crimson transition hover:brightness-110"
            >
              <span>Request Early Access</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
