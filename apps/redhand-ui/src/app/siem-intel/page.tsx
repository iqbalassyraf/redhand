"use client";

import React from "react";
import { motion } from "framer-motion";
import { Database, Globe, Radio, ShieldCheck } from "lucide-react";

import { EnterprisePreviewGate } from "@/components/control-room/EnterprisePreviewGate";
import { AppShell } from "@/components/shell/AppShell";
import { useRequiredSession } from "@/lib/auth";
import { EASE_OUT_EXPO, MOTION_TIMING, usePrefersReducedMotion } from "@/lib/tokens";

const GHOST_SIEM_CONNECTORS = [
  {
    name: "Microsoft Sentinel",
    protocol: "Azure Monitor Logs · OCSF v1.1.0",
    events: "Passports, WORM Black Box, Honeytrips",
    status: "STREAMING",
  },
  {
    name: "Splunk Enterprise Security",
    protocol: "HEC TLS Mutual Auth · OCSF v1.1.0",
    events: "Gateway Refusals, Risk Ladder, Radar",
    status: "STREAMING",
  },
  {
    name: "Google SecOps (Chronicle)",
    protocol: "Ingestion API v2 · UDM Mapped",
    events: "Full Audit Chain + Ephemeral IAM Minting",
    status: "READY",
  },
] as const;

const GHOST_THREAT_FEEDS = [
  {
    feed: "RedHand AI-Agent IOC Feed",
    protocol: "TAXII 2.1 · STIX Bundles",
    indicators: "14,280 Exfil Domains & Prompt Sigs",
    cadence: "Every 5 min → <2ms Cache",
  },
  {
    feed: "MISP / Enterprise SOC Internal",
    protocol: "TAXII 2.1 · Private Collection",
    indicators: "Org-Specific C2 & Malicious MCP Hashes",
    cadence: "Real-Time Push",
  },
] as const;

export default function SiemIntelPage() {
  useRequiredSession();
  const reducedMotion = usePrefersReducedMotion();

  return (
    <AppShell title="SIEM & Threat Intel">
      <EnterprisePreviewGate
        badge="ENTERPRISE"
        title="Enterprise SIEM Connectors & STIX/TAXII Threat Intel"
        subtitle="Stream tamper-evident OCSF v1.1.0 agent telemetry directly into your existing SOC, and auto-sync STIX/TAXII 2.1 indicators into the <2ms gateway destination allowlist."
        specBadge="OCSF v1.1.0 · STIX/TAXII 2.1"
        interestId="siem-intel"
        valuePoints={[
          "Zero-ETL OCSF v1.1.0 connectors for Microsoft Sentinel, Splunk HEC, and Google SecOps with cryptographic WORM verification.",
          "Ingest STIX/TAXII 2.1 threat feeds to block newly discovered exfiltration domains and poisoned MCP server hashes in <2ms.",
          "Maps every autonomous freeze, honeytoken trip, and human approval to ISO/IEC 42001 & NIST AI 600-1 audit fields.",
        ]}
      >
        <div className="flex flex-col gap-4">
          {/* Ghost SIEM Connectors Table */}
          <div className="rh-glass overflow-hidden rounded-rh-xl border border-control-border">
            <div className="flex items-center justify-between border-b border-control-border px-4 py-3">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-rh-steel-text" />
                <span className="text-xs font-semibold text-rh-text">
                  OCSF v1.1.0 SIEM Streaming Connectors
                </span>
              </div>
              <span className="rounded-full border border-control-border bg-rh-subtle px-2.5 py-0.5 font-mono text-[10px] text-rh-text-2">
                PREVIEW CONNECTORS
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-control-border bg-rh-subtle text-[11px] uppercase tracking-wider text-rh-text-2">
                  <tr>
                    <th className="px-4 py-2.5">Destination</th>
                    <th className="px-4 py-2.5">Transport &amp; Schema</th>
                    <th className="px-4 py-2.5">Included Streams</th>
                    <th className="px-4 py-2.5">State</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-control-border">
                  {GHOST_SIEM_CONNECTORS.map((item, idx) => (
                    <motion.tr
                      key={item.name}
                      initial={reducedMotion ? false : { opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{
                        duration: MOTION_TIMING.normal,
                        delay: reducedMotion ? 0 : idx * MOTION_TIMING.staggerStep,
                        ease: EASE_OUT_EXPO,
                      }}
                      className="text-rh-text-2"
                    >
                      <td className="px-4 py-3 font-semibold text-rh-text">{item.name}</td>
                      <td className="px-4 py-3 font-mono text-[11px]">{item.protocol}</td>
                      <td className="px-4 py-3">{item.events}</td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center gap-1.5 rounded-full border border-rh-teal-border bg-rh-teal-wash px-2 py-0.5 font-mono text-[10px] font-semibold text-rh-teal-text">
                          <span className="h-1.5 w-1.5 rounded-full bg-rh-teal-text" />
                          {item.status}
                        </span>
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Ghost STIX/TAXII Feeds Table */}
          <div className="rh-glass overflow-hidden rounded-rh-xl border border-control-border">
            <div className="flex items-center justify-between border-b border-control-border px-4 py-3">
              <div className="flex items-center gap-2">
                <Radio className="h-4 w-4 text-rh-ochre" />
                <span className="text-xs font-semibold text-rh-text">
                  STIX/TAXII 2.1 Threat Intelligence Feeds
                </span>
              </div>
              <span className="flex items-center gap-1 text-[11px] text-rh-teal-text">
                <ShieldCheck className="h-3.5 w-3.5" />
                Auto-synced to Gateway Cache
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-control-border bg-rh-subtle text-[11px] uppercase tracking-wider text-rh-text-2">
                  <tr>
                    <th className="px-4 py-2.5">Feed Source</th>
                    <th className="px-4 py-2.5">Protocol</th>
                    <th className="px-4 py-2.5">Active Indicators</th>
                    <th className="px-4 py-2.5">Enforcement Sync</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-control-border">
                  {GHOST_THREAT_FEEDS.map((feed, idx) => (
                    <motion.tr
                      key={feed.feed}
                      initial={reducedMotion ? false : { opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{
                        duration: MOTION_TIMING.normal,
                        delay: reducedMotion ? 0 : (idx + 3) * MOTION_TIMING.staggerStep,
                        ease: EASE_OUT_EXPO,
                      }}
                      className="text-rh-text-2"
                    >
                      <td className="px-4 py-3 font-semibold text-rh-text">
                        <span className="inline-flex items-center gap-1.5">
                          <Globe className="h-3.5 w-3.5 text-rh-text-muted" />
                          {feed.feed}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px]">{feed.protocol}</td>
                      <td className="rh-tabular px-4 py-3">{feed.indicators}</td>
                      <td className="px-4 py-3 font-mono text-rh-ochre">{feed.cadence}</td>
                    </motion.tr>
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
