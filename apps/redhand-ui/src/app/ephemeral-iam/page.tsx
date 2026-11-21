"use client";

import React from "react";
import { Cloud, KeyRound, ShieldCheck, Timer } from "lucide-react";

import { EnterprisePreviewGate } from "@/components/control-room/EnterprisePreviewGate";
import { AppShell } from "@/components/shell/AppShell";
import { useRequiredSession } from "@/lib/auth";

const GHOST_IAM_POLICIES = [
  {
    agent: "helpdesk-triage-agent",
    provider: "AWS STS",
    role: "arn:aws:iam::482910394812:role/redhand-turn-support-ro",
    ttl: "60s single-turn",
    scope: "s3:GetObject (kb-bucket/*)",
    status: "AUTO-ROTATE",
  },
  {
    agent: "finops-reconciler",
    provider: "GCP IAM",
    role: "sa-finops-downscoped@prod-ledger.iam.gserviceaccount.com",
    ttl: "45s single-turn",
    scope: "bigquery.jobs.create (read-only dataset)",
    status: "ACTIVE BROKER",
  },
  {
    agent: "hr-onboarding-copilot",
    provider: "Microsoft Entra ID",
    role: "obo-graph-user-read-basic",
    ttl: "60s single-turn",
    scope: "User.ReadBasic.All (Zero-Standing)",
    status: "ACTIVE BROKER",
  },
] as const;

export default function EphemeralIamPage() {
  useRequiredSession();

  return (
    <AppShell title="Ephemeral IAM Broker">
      <EnterprisePreviewGate
        badge="ENTERPRISE"
        title="Dynamic Ephemeral IAM Broker"
        subtitle="Eliminate long-lived API keys and static IAM roles. RedHand mints 60-second, single-turn downscoped cloud credentials per tool call and revokes them automatically on mid-loop quarantine."
        specBadge="60s Turn-Scoped · AWS STS / GCP IAM / Entra ID"
        interestId="ephemeral-iam"
        valuePoints={[
          "Zero standing privileges: agents never hold raw AWS keys, GCP service account JSONs, or OAuth refresh tokens.",
          "Just-in-time session policies downscoped to the exact S3 prefix, BigQuery dataset, or Graph scope of the current turn.",
          "Instant cryptographic revocation: Passport freeze or Risk Engine escalation invalidates downstream token minting in ≤2s.",
        ]}
      >
        <div className="flex flex-col gap-4">
          {/* Ghost KPI Row */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="rh-glass rounded-rh-lg border border-control-border p-4">
              <div className="flex items-center justify-between text-xs text-rh-text-2">
                <span>Max Credential TTL</span>
                <Timer className="h-4 w-4 text-rh-ochre" />
              </div>
              <div className="mt-2 font-mono text-2xl font-bold text-rh-text">60s</div>
              <div className="mt-1 text-[11px] text-rh-text-muted">Single-turn cryptographic expiration</div>
            </div>
            <div className="rh-glass rounded-rh-lg border border-control-border p-4">
              <div className="flex items-center justify-between text-xs text-rh-text-2">
                <span>Standing Cloud Secrets</span>
                <KeyRound className="h-4 w-4 text-rh-teal-text" />
              </div>
              <div className="mt-2 font-mono text-2xl font-bold text-rh-teal-text">0</div>
              <div className="mt-1 text-[11px] text-rh-text-muted">100% brokered via RedHand STS</div>
            </div>
            <div className="rh-glass rounded-rh-lg border border-control-border p-4">
              <div className="flex items-center justify-between text-xs text-rh-text-2">
                <span>Connected Cloud Providers</span>
                <Cloud className="h-4 w-4 text-rh-steel-text" />
              </div>
              <div className="mt-2 font-mono text-2xl font-bold text-rh-text">3</div>
              <div className="mt-1 text-[11px] text-rh-text-muted">AWS STS · GCP IAM · Entra ID</div>
            </div>
          </div>

          {/* Ghost IAM Policy Table */}
          <div className="rh-glass overflow-hidden rounded-rh-xl border border-control-border">
            <div className="flex items-center justify-between border-b border-control-border px-4 py-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-rh-teal-text" />
                <span className="text-xs font-semibold text-rh-text">
                  Turn-Scoped Downscoping Policies
                </span>
              </div>
              <span className="rounded-full border border-control-border bg-rh-subtle px-2.5 py-0.5 font-mono text-[10px] text-rh-text-2">
                PREVIEW SCHEMA
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-control-border bg-rh-subtle text-[11px] uppercase tracking-wider text-rh-text-2">
                  <tr>
                    <th className="px-4 py-2.5">Agent Passport</th>
                    <th className="px-4 py-2.5">Cloud Provider</th>
                    <th className="px-4 py-2.5">Target Role / Principal</th>
                    <th className="px-4 py-2.5">Turn TTL</th>
                    <th className="px-4 py-2.5">Downscoped Boundary</th>
                    <th className="px-4 py-2.5">Broker State</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-control-border">
                  {GHOST_IAM_POLICIES.map((row) => (
                    <tr key={row.agent} className="text-rh-text-2">
                      <td className="px-4 py-3 font-mono font-semibold text-rh-text">{row.agent}</td>
                      <td className="px-4 py-3">{row.provider}</td>
                      <td className="px-4 py-3 font-mono text-[11px]">{row.role}</td>
                      <td className="px-4 py-3 font-mono text-rh-ochre">{row.ttl}</td>
                      <td className="px-4 py-3 font-mono text-[11px]">{row.scope}</td>
                      <td className="px-4 py-3">
                        <span className="rounded-full border border-rh-teal-border bg-rh-teal-wash px-2 py-0.5 font-mono text-[10px] font-semibold text-rh-teal-text">
                          {row.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </EnterprisePreviewGate>
    </AppShell>
  );
}
