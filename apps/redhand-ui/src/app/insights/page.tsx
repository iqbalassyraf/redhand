"use client";

/**
 * Insights: the dashboard's home page (dashboard redesign S3). Real numbers only: everything here is computed by redhand-core from what the
 * gateway reported to the Black Box (`GET /v1/insights/summary`). The sample-data canvas lives at /demo. The UI is never a security boundary:
 * a hidden button only saves a click, core still authorizes every request.
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { RefreshCw, ShieldCheck } from "lucide-react";

import { AppShell } from "@/components/shell/AppShell";
import { AreaChart, ChartCard, Donut, Flow, LatencyBars, RankedBars, StackedArea } from "@/components/charts/charts";
import { Button, Card, Chip, EmptyState, ErrorState, KpiTile } from "@/components/ui/primitives";
import { ApiError, blackboxApi, downloadBlackBoxExport, insightsApi, meApi, riskApi, type AgentRiskSummary, type Me } from "@/lib/api";
import { useRequiredSession } from "@/lib/auth";
import {
  WINDOW_OPTIONS, bucketLabel, controlChips, formatBytes, formatCount, formatMs, hasCalls, outcomeSlices, percent, reasonRows, seriesSummary,
  windowLabel, type InsightsSummary, type InsightsWindow, type Tone,
} from "@/lib/insights";

const REFRESH_MS = 30_000;
const RISK_TONE: Record<string, Tone> = { low: "teal", medium: "ochre", high: "crimson", critical: "crimson" };

export default function InsightsPage() {
  const session = useRequiredSession();
  const token = session?.token ?? null;
  const [window_, setWindow] = useState<InsightsWindow>("24h");
  const [agentId, setAgentId] = useState<string>("");
  const [summary, setSummary] = useState<InsightsSummary | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [risk, setRisk] = useState<AgentRiskSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const data = await insightsApi.summary(token, window_);
      setSummary(data);
      setError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        window.location.href = "/login";
        return;
      }
      // Never zeros: a failed read keeps the page honest about it.
      setError(
        err instanceof ApiError && err.status === 404
          ? "This core does not serve Insights yet. Update redhand-core."
          : err instanceof ApiError && err.status === 503
            ? "Insights could not be read. Try again in a moment."
            : "Insights could not be loaded."
      );
    } finally {
      setLoading(false);
    }
  }, [token, window_]);

  useEffect(() => {
    void load();
  }, [load]);

  // Refresh while the tab is visible; stop when hidden (a page nobody looks at should not poll).
  useEffect(() => {
    if (!token) return undefined;
    const tick = () => {
      if (document.visibilityState === "visible") void load();
    };
    const id = window.setInterval(tick, REFRESH_MS);
    return () => window.clearInterval(id);
  }, [token, load]);

  useEffect(() => {
    if (!token) return;
    meApi.get(token).then(setMe).catch(() => setMe(null));
  }, [token]);

  // Risk scores need the security operator role: a viewer is not asked (no failed request), and on an older core the table simply has no risk column.
  const role = me?.role;
  useEffect(() => {
    if (!token || !role || role === "viewer") {
      setRisk(null);
      return;
    }
    riskApi.list(token).then((r) => setRisk(r.agents)).catch(() => setRisk(null));
  }, [token, role]);

  const canExport = me?.role === "owner" || me?.role === "admin" || me?.role === "security_operator";

  const verifyChain = async () => {
    if (!token) return;
    setVerifying(true);
    setNotice(null);
    try {
      const newest = await blackboxApi.events(token, { limit: 1 });
      const seq = newest.events[0]?.seq;
      if (!seq) {
        setNotice("The Black Box has no events to verify yet.");
        return;
      }
      const result = await blackboxApi.verify(token, 1, seq);
      setNotice(result.ok ? `Verified: ${result.checked} event(s) from seq 1 to ${seq}, chain intact.` : `Verification FAILED at seq ${result.broken_seq}. The record was altered.`);
    } catch {
      setNotice("The chain could not be verified right now.");
    } finally {
      setVerifying(false);
    }
  };

  const exportCsv = async () => {
    if (!token) return;
    try {
      await downloadBlackBoxExport(token, { format: "csv", includePayloads: false });
      setNotice("Export downloaded. It was recorded in the audit log. Handle it as customer data.");
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : "The export could not be created.");
    }
  };

  const riskById = useMemo(() => new Map((risk ?? []).map((r) => [r.agent_id, r])), [risk]);
  const agents = useMemo(() => (summary?.agents ?? []).filter((a) => !agentId || a.agent_id === agentId), [summary, agentId]);
  const labels = useMemo(() => (summary?.series ?? []).map((p) => bucketLabel(p.bucket_start, window_)), [summary, window_]);

  if (!session) return null;

  const actions = (
    <>
      <Button onClick={() => void verifyChain()} disabled={verifying} aria-label="Verify the Black Box chain">
        <ShieldCheck className="h-3.5 w-3.5" /> {verifying ? "Verifying…" : "Verify chain"}
      </Button>
    </>
  );

  return (
    <AppShell title="Insights" organization={me?.organization_name} role={me?.role} actions={actions}>
      {/* Filter row */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div role="tablist" aria-label="Time window" className="rh-glass flex rounded-full p-0.5">
          {WINDOW_OPTIONS.map((o) => (
            <button
              key={o.value}
              role="tab"
              aria-selected={window_ === o.value}
              onClick={() => setWindow(o.value)}
              className={`rounded-full px-3 py-1 text-[12px] font-medium transition-colors ${window_ === o.value ? "bg-control-crimson text-white shadow-rh-crimson" : "text-rh-text-2 hover:text-rh-text"}`}
            >
              {o.label}
            </button>
          ))}
        </div>
        <select
          aria-label="Agent"
          value={agentId}
          onChange={(e) => setAgentId(e.target.value)}
          className="rounded-[8px] border border-rh-hairline bg-rh-card px-2 py-1.5 text-[12px] text-rh-text"
        >
          <option value="">All agents</option>
          {(summary?.agents ?? []).map((a) => <option key={a.agent_id} value={a.agent_id}>{a.name ?? a.agent_id.slice(0, 8)}</option>)}
        </select>
        <span className="rounded-full border border-rh-hairline px-2.5 py-1 text-[11px] text-rh-text-2">Time zone: UTC</span>
        <div className="ml-auto flex items-center gap-2">
          {canExport && <Button onClick={() => void exportCsv()}>Export CSV</Button>}
          <Button onClick={() => void load()} disabled={loading} aria-label="Refresh">
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          </Button>
        </div>
      </div>

      {notice && <div role="status" className="mb-4 rounded-[8px] border border-rh-hairline bg-rh-elevated px-4 py-2.5 text-[13px] text-rh-text">{notice}</div>}
      {error && <div className="mb-4"><ErrorState message={error} onRetry={() => void load()} /></div>}

      {summary && (
        <>
          {/* Control strip */}
          <div className="mb-4 flex flex-wrap items-center gap-2" aria-label="Organization controls">
            {controlChips(summary).map((c) => <Chip key={c.label} tone={c.tone}>{c.label}</Chip>)}
            <Link href="/passports" className="ml-1 text-[12px] text-rh-text-2 underline underline-offset-2 hover:text-rh-text">Manage on Passports</Link>
          </div>

          {/* KPI tiles */}
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
            <KpiTile label="Gateway decisions" value={formatCount(summary.totals.decisions)} tone="steel" note={windowLabel(window_)} />
            <KpiTile label="Allowed" value={formatCount(summary.totals.allowed)} tone="teal" note={`${percent(summary.totals.allowed, summary.totals.decisions)}% of decisions`} />
            <KpiTile label="Refused" value={formatCount(summary.totals.refused)} tone="crimson" note={`${percent(summary.totals.refused, summary.totals.decisions)}% of decisions`} />
            <KpiTile label="Errors" value={formatCount(summary.totals.errors)} tone="ochre" note="allowed, then failed" />
            <KpiTile label="Agents" value={`${formatCount(summary.passports.managed_active)} / ${formatCount(summary.passports.reported_only)}`} note="managed active / reported only" />
          </div>

          {!hasCalls(summary) ? (
            <Card><EmptyState title={`No gateway calls in the ${windowLabel(window_).toLowerCase()}`} detail="Calls appear here as agents use the gateway. Agents that only report through the SDK are not counted: they have no gateway access." /></Card>
          ) : (
            <>
              <Card title="Top agents" subtitle="Most active agents by gateway decisions" className="mb-4">
                <div className="relative overflow-x-auto">
                  <table className="w-full min-w-[520px] text-left text-[13px]">
                    <thead>
                      <tr className="text-[12px] text-rh-text-2">
                        <th className="border-b border-rh-hairline px-2 py-1.5 font-medium">Agent</th>
                        <th className="border-b border-rh-hairline px-2 py-1.5 font-medium">Framework</th>
                        <th className="border-b border-rh-hairline px-2 py-1.5 text-right font-medium">Decisions</th>
                        <th className="border-b border-rh-hairline px-2 py-1.5 text-right font-medium">Refused</th>
                        {risk && <th className="border-b border-rh-hairline px-2 py-1.5 font-medium">Risk</th>}
                        <th className="border-b border-rh-hairline px-2 py-1.5 font-medium"><span className="sr-only">Incident view</span></th>
                      </tr>
                    </thead>
                    <tbody>
                      {agents.map((a) => {
                        const r = riskById.get(a.agent_id);
                        return (
                          <tr key={a.agent_id}>
                            <td className="border-b border-rh-hairline px-2 py-2 text-rh-text">{a.name ?? a.agent_id.slice(0, 8)}</td>
                            <td className="border-b border-rh-hairline px-2 py-2 text-rh-text-2">{a.framework ?? "unknown"}</td>
                            <td className="rh-tabular border-b border-rh-hairline px-2 py-2 text-right text-rh-text">{formatCount(a.decisions)}</td>
                            <td className="rh-tabular border-b border-rh-hairline px-2 py-2 text-right text-rh-text">{formatCount(a.refused)} <span className="text-rh-text-2">({percent(a.refused, a.decisions)}%)</span></td>
                            {risk && <td className="border-b border-rh-hairline px-2 py-2">{r ? <Chip tone={RISK_TONE[r.level] ?? "neutral"}>{r.level} · {r.score}</Chip> : <span className="text-rh-text-2">–</span>}</td>}
                            <td className="border-b border-rh-hairline px-2 py-2 text-right"><Link href={`/passports/${a.agent_id}/timeline`} className="text-[12px] text-rh-text-2 underline underline-offset-2 hover:text-rh-text">Timeline</Link></td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </Card>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
                <ChartCard
                  title="Gateway decisions over time" subtitle="Allowed, refused and errors" summary={seriesSummary(summary)}
                  table={{ headers: ["Time (UTC)", "Allowed", "Refused", "Errors"], rows: summary.series.map((p, i) => [labels[i], formatCount(p.allowed), formatCount(p.refused), formatCount(p.errors)]) }}
                >
                  <StackedArea labels={labels} layers={[
                    { name: "allowed", tone: "steel", values: summary.series.map((p) => p.allowed) },
                    { name: "refused", tone: "crimson", values: summary.series.map((p) => p.refused) },
                    { name: "errors", tone: "ochre", values: summary.series.map((p) => p.errors) },
                  ]} />
                </ChartCard>

                <ChartCard
                  title="Data returned to agents" subtitle="Result size on allowed calls" summary={`${formatBytes(summary.totals.bytes_returned)} returned to agents in the ${windowLabel(window_).toLowerCase()}.`}
                  table={{ headers: ["Time (UTC)", "Returned"], rows: summary.series.map((p, i) => [labels[i], formatBytes(p.bytes)]) }}
                >
                  <AreaChart labels={labels} values={summary.series.map((p) => p.bytes)} tone="teal" format={formatBytes} />
                </ChartCard>

                <ChartCard
                  title="Outcomes" subtitle="Share of gateway decisions"
                  summary={`${percent(summary.totals.allowed, summary.totals.decisions)}% of decisions were allowed.`}
                  table={{ headers: ["Outcome", "Decisions"], rows: outcomeSlices(summary.totals).map((s) => [s.label, formatCount(s.value)]) }}
                >
                  <Donut slices={outcomeSlices(summary.totals)} centre={`${percent(summary.totals.allowed, summary.totals.decisions)}%`} centreNote="allowed" />
                </ChartCard>

                <ChartCard
                  title="Call duration" subtitle="Allowed calls: p50 and p95"
                  summary={`Allowed calls took ${formatMs(summary.latency.p50_ms)} at the median and ${formatMs(summary.latency.p95_ms)} at the 95th percentile, tool time included.`}
                  table={{ headers: ["Measure", "Value"], rows: [["p50", formatMs(summary.latency.p50_ms)], ["p95", formatMs(summary.latency.p95_ms)], ["Samples", formatCount(summary.latency.samples)]] }}
                  empty={summary.latency.samples === 0 ? "No allowed calls with a timing in this window." : undefined}
                >
                  <LatencyBars p50={summary.latency.p50_ms} p95={summary.latency.p95_ms} />
                </ChartCard>

                <ChartCard
                  title="Why calls were refused" subtitle="Most common reasons" summary={`${reasonRows(summary.reasons).length} refusal reasons.`}
                  table={{ headers: ["Reason", "Count"], rows: reasonRows(summary.reasons).map((r) => [r.label, formatCount(r.count)]) }}
                  empty={summary.reasons.length === 0 ? "Nothing was refused in this window." : undefined}
                >
                  <RankedBars rows={reasonRows(summary.reasons).map((r) => ({ label: r.label, value: r.count }))} tone="crimson" />
                </ChartCard>

                <ChartCard
                  title="Most called tools" subtitle="By server and tool" summary={`${summary.tools.length} most called tools.`}
                  table={{ headers: ["Tool", "Calls", "Refused"], rows: summary.tools.map((t) => [`${t.server} / ${t.tool}`, formatCount(t.calls), formatCount(t.refused)]) }}
                  empty={summary.tools.length === 0 ? "No tool calls in this window." : undefined}
                >
                  <RankedBars rows={summary.tools.map((t) => ({ label: `${t.server} / ${t.tool}`, value: t.calls, detail: t.refused ? `${formatCount(t.refused)} refused` : undefined }))} tone="steel" />
                </ChartCard>
              </div>

              <div className="mt-4">
                <ChartCard
                  title="Agent, server and outcome" subtitle="Where the top agents' calls went and how they ended"
                  summary="Flow from the most active agents to the servers they called and the outcome of each call."
                  table={{ headers: ["Agent", "Server", "Outcome", "Decisions"], rows: summary.flow.map((f) => [summary.agents.find((a) => a.agent_id === f.agent_id)?.name ?? f.agent_id.slice(0, 8), f.server || "(none)", f.decision === "ALLOW" ? "Allowed" : f.decision === "BLOCK" ? "Refused" : "Errors", formatCount(f.count)]) }}
                  empty={summary.flow.length === 0 ? "No flows to draw yet." : undefined}
                >
                  <Flow rows={summary.flow
                    .filter((f) => !agentId || f.agent_id === agentId)
                    .map((f) => ({
                      agent: summary.agents.find((a) => a.agent_id === f.agent_id)?.name ?? f.agent_id.slice(0, 8),
                      server: f.server || "(none)",
                      outcome: f.decision === "ALLOW" ? "Allowed" : f.decision === "BLOCK" ? "Refused" : "Errors",
                      count: f.count,
                    }))} />
                </ChartCard>
              </div>
            </>
          )}
        </>
      )}
      {!summary && !error && <p className="text-[13px] text-rh-text-2">Loading…</p>}
    </AppShell>
  );
}
