"use client";

/**
 * Incident view (Phase 4.5 B3): one agent's story in one place, newest first, with a one-click Freeze and review.
 * Everything here comes from redhand-core's /v1/agents/{id}/timeline; the wording is in src/lib/timeline.ts. The page is not a security
 * boundary: core decides who may read it and who may freeze.
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft, Download, OctagonX } from "lucide-react";

import { ApiError, downloadTimelineExport, passportsApi, riskApi, timelineApi, type AgentRiskSummary } from "@/lib/api";
import { useRequiredSession } from "@/lib/auth";
import { AppShell } from "@/components/shell/AppShell";
import { LEVEL_LABEL, LEVEL_STYLE } from "@/lib/riskForm";
import {
  FILTERS,
  FREEZE_REASON,
  TIMELINE_LIMITS_TEXT,
  dayKey,
  describeItem,
  matchesFilter,
  type FilterId,
  type TimelineItem,
  type TimelineResponse,
  type Tone,
} from "@/lib/timeline";

const TONE_DOT: Readonly<Record<Tone, string>> = {
  bad: "bg-rh-crimson",
  warn: "bg-rh-ochre",
  info: "bg-rh-steel",
  quiet: "bg-rh-strong",
};

type LoadState = "loading" | "ready" | "forbidden" | "missing" | "failed";

export default function AgentTimelinePage() {
  const session = useRequiredSession();
  const params = useParams<{ id: string }>();
  const agentId = params.id;
  const [state, setState] = useState<LoadState>("loading");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [data, setData] = useState<TimelineResponse | null>(null);
  const [risk, setRisk] = useState<AgentRiskSummary | null>(null);
  const [filter, setFilter] = useState<FilterId>("all");
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [freezing, setFreezing] = useState(false);
  const [reason, setReason] = useState(FREEZE_REASON);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!session) return;
    setState("loading");
    setError(null);
    try {
      const [timeline, detail] = await Promise.all([
        timelineApi.get(session.token, agentId),
        riskApi.detail(session.token, agentId).catch(() => null),  // a score is helpful, not required
      ]);
      setData(timeline);
      setRisk(detail ? detail.agent : null);
      setState("ready");
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) setState("forbidden");
      else if (e instanceof ApiError && e.status === 404) setState("missing");
      else {
        setError(e instanceof Error ? e.message : "The timeline could not be read. Try again shortly.");
        setState("failed");
      }
    }
  }, [session, agentId]);

  useEffect(() => {
    void load();
  }, [load]);

  const loadOlder = async () => {
    if (!session || !data?.next_before) return;
    setLoadingOlder(true);
    try {
      const older = await timelineApi.get(session.token, agentId, data.next_before);
      setData({ ...older, items: [...data.items, ...older.items] });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Older items could not be read.");
    } finally {
      setLoadingOlder(false);
    }
  };

  const freeze = async () => {
    if (!session || !data) return;
    setBusy(true);
    setError(null);
    try {
      await passportsApi.freeze(session.token, agentId, reason.trim() || FREEZE_REASON);
      setFreezing(false);
      setNotice(`${data.agent.name} frozen. Its next call is refused; unfreeze it on the Passports page once you have reviewed.`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "The agent could not be frozen.");
    } finally {
      setBusy(false);
    }
  };

  const exportAs = async (format: "json" | "csv") => {
    if (!session) return;
    setError(null);
    try {
      await downloadTimelineExport(session.token, agentId, format);
      setNotice(`Incident summary downloaded (${format.toUpperCase()}). The export is recorded in this timeline.`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "The export could not be downloaded.");
    }
  };

  const shown = useMemo(() => (data ? data.items.filter((i) => matchesFilter(i, filter)) : []), [data, filter]);
  const days = useMemo(() => {
    const groups: { day: string; items: TimelineItem[] }[] = [];
    for (const item of shown) {
      const day = dayKey(item.at);
      if (groups.length === 0 || groups[groups.length - 1].day !== day) groups.push({ day, items: [] });
      groups[groups.length - 1].items.push(item);
    }
    return groups;
  }, [shown]);

  if (!session) return null;

  return (
    <AppShell title="Incident timeline" role={session.role}>
    <div className="mx-auto max-w-[960px] text-rh-text">
      <Link href="/passports" className="mb-4 inline-flex items-center gap-1 text-[12px] text-rh-text-2 hover:text-rh-text">
        <ArrowLeft className="h-3.5 w-3.5" /> Passports
      </Link>

      {state === "forbidden" && (
        <div role="alert" className="rh-glass rounded-rh-md p-4 text-[12px]">
          Your role cannot see the incident view. Ask an owner or admin to give you the security operator role.
        </div>
      )}
      {state === "missing" && (
        <div role="alert" className="rh-glass rounded-rh-md p-4 text-[12px]">
          This agent was not found in your organization.
        </div>
      )}
      {state === "loading" && <p className="text-[12px] text-rh-text-2">Loading the timeline…</p>}
      {error && (
        <div role="alert" className="mb-3 rounded-[8px] border border-rh-crimson bg-rh-crimson-wash px-3 py-2 text-[12px] text-rh-crimson-text">{error}</div>
      )}
      {notice && (
        <div role="status" className="mb-3 rounded-[8px] border border-rh-teal bg-rh-teal-wash px-3 py-2 text-[12px] text-rh-teal-text">{notice}</div>
      )}

      {state === "ready" && data && (
        <>
          <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <h1 className="break-words text-[20px] font-semibold">Timeline for {data.agent.name}</h1>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-[12px]">
                <span className="rounded-full border border-rh-hairline px-2 py-0.5">{data.agent.status}</span>
                {risk && (
                  <span className={`rounded-full px-2 py-0.5 ${LEVEL_STYLE[risk.level]}`}>
                    risk {risk.score} · {LEVEL_LABEL[risk.level]}
                  </span>
                )}
                {risk?.released_at && (
                  <span className="text-rh-text-2">A person released this agent on {new Date(risk.released_at).toLocaleString()}.</span>
                )}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {(["json", "csv"] as const).map((format) => (
                <button
                  key={format}
                  onClick={() => void exportAs(format)}
                  className="inline-flex items-center gap-1 rounded-full border border-rh-hairline px-2.5 py-1 text-[12px] hover:bg-rh-elevated"
                >
                  <Download className="h-3.5 w-3.5" /> Export {format.toUpperCase()}
                </button>
              ))}
            {data.agent.status === "active" && !freezing && (
              <button
                onClick={() => setFreezing(true)}
                className="inline-flex items-center gap-1.5 rounded-full border border-rh-crimson px-3 py-1.5 text-[12px] font-medium text-rh-crimson-text hover:bg-rh-crimson-wash"
              >
                <OctagonX className="h-4 w-4" /> Freeze and review
              </button>
            )}
            </div>
          </header>

          {freezing && (
            <section aria-label="Freeze and review" className="mb-4 rounded-[10px] border border-rh-crimson bg-rh-crimson-wash p-3 text-[12px]">
              <p className="mb-2">
                Freezing refuses every call from {data.agent.name}, from its next call. Nothing is deleted; you can unfreeze it on the Passports
                page after your review.
              </p>
              <label className="mb-1 block font-medium" htmlFor="freeze-reason">Reason (kept in the audit log)</label>
              <input
                id="freeze-reason"
                value={reason}
                maxLength={500}
                onChange={(e) => setReason(e.target.value)}
                className="mb-2 w-full rounded-[6px] border border-rh-hairline px-2 py-1"
              />
              <div className="flex gap-2">
                <button
                  disabled={busy}
                  onClick={() => void freeze()}
                  className="rounded-full bg-control-crimson px-3 py-1 font-medium text-white shadow-rh-crimson transition hover:bg-control-crimsonDeep disabled:opacity-40"
                >
                  Freeze now
                </button>
                <button disabled={busy} onClick={() => setFreezing(false)} className="rounded-full border border-rh-hairline px-3 py-1">
                  Cancel
                </button>
              </div>
            </section>
          )}

          <div className="mb-3 flex flex-wrap gap-1" role="group" aria-label="Show">
            {FILTERS.map((f) => (
              <button
                key={f.id}
                onClick={() => setFilter(f.id)}
                aria-pressed={filter === f.id}
                className={`rounded-full border px-2.5 py-1 text-[12px] transition-colors ${
                  filter === f.id
                    ? "border-control-crimsonBorder bg-control-crimson text-white shadow-rh-crimson"
                    : "border-rh-hairline bg-rh-card hover:bg-rh-elevated"
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          <p className="mb-4 text-[11px] text-rh-text-2">{TIMELINE_LIMITS_TEXT}</p>

          {days.length === 0 && <p className="text-[12px] text-rh-text-2">Nothing to show for this filter.</p>}
          <ol aria-label="Timeline" className="space-y-4">
            {days.map((group) => (
              <li key={group.day}>
                <h2 className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-rh-text-2">{group.day}</h2>
                <ol className="rh-glass divide-y divide-rh-hairline rounded-rh-md">
                  {group.items.map((item, index) => {
                    const d = describeItem(item);
                    return (
                      <li key={`${item.kind}-${item.at}-${item.seq ?? item.finding_id ?? index}`} className="flex gap-3 p-3">
                        <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${TONE_DOT[d.tone]}`} aria-hidden="true" />
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-baseline justify-between gap-x-3">
                            <span className="break-words text-[13px] font-medium">{d.title}</span>
                            <time dateTime={item.at} className="text-[11px] text-rh-text-2">{new Date(item.at).toLocaleTimeString()}</time>
                          </div>
                          {d.detail && <p className="mt-0.5 break-words text-[12px] text-rh-text">{d.detail}</p>}
                          {d.link && (
                            <Link href={d.link.href} className="mt-0.5 inline-block text-[12px] text-rh-steel-text hover:underline">
                              {d.link.label}
                            </Link>
                          )}
                        </div>
                      </li>
                    );
                  })}
                </ol>
              </li>
            ))}
          </ol>

          {data.next_before && (
            <button
              disabled={loadingOlder}
              onClick={() => void loadOlder()}
              className="mt-4 rounded-full border border-rh-hairline px-3 py-1 text-[12px] hover:bg-rh-elevated disabled:opacity-40"
            >
              {loadingOlder ? "Loading…" : "Load older"}
            </button>
          )}
        </>
      )}
    </div>
    </AppShell>
  );
}
