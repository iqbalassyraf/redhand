"use client";

/**
 * One event in detail. The captured payload is fetched only for roles the server says may read it, and every
 * read is recorded in the audit log. Payload text is untrusted: it is rendered as plain text only.
 */

import React, { useEffect, useState } from "react";
import { X } from "lucide-react";

import { ApiError, type BlackBoxEvent, type EventPayload, type PayloadExcerpt, blackboxApi } from "@/lib/api";

function pretty(excerpt: PayloadExcerpt): string {
  if (excerpt.truncated) return excerpt.text;
  try {
    return JSON.stringify(JSON.parse(excerpt.text), null, 2);
  } catch {
    return excerpt.text;
  }
}

function Excerpt({ title, excerpt }: { title: string; excerpt: PayloadExcerpt | null }) {
  return (
    <div className="mb-3">
      <div className="mb-1 font-semibold">{title}</div>
      {excerpt ? (
        <>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-[8px] bg-rh-subtle p-2 font-mono text-[11px]">
            {pretty(excerpt)}
          </pre>
          {excerpt.truncated ? (
            <div className="mt-1 text-rh-ochre">Cut to 2 KB; the original was {excerpt.original_bytes} bytes.</div>
          ) : null}
        </>
      ) : (
        <div className="text-rh-text-2">Not captured.</div>
      )}
    </div>
  );
}

interface Props {
  event: BlackBoxEvent;
  token: string;
  canViewPayload: boolean;
  onClose: () => void;
  onUnauthorized: () => void;
}

export function EventDrawer({ event, token, canViewPayload, onClose, onUnauthorized }: Props) {
  const [payload, setPayload] = useState<EventPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setPayload(null);
    setError(null);
  }, [event.seq]);

  const show = async () => {
    setLoading(true);
    setError(null);
    try {
      setPayload(await blackboxApi.payload(token, event.seq));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized();
        return;
      }
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <aside className="rh-glass fixed right-0 top-0 z-40 h-full w-full max-w-md overflow-auto border-l border-control-border p-4 text-[12px]" aria-label="Event detail">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-[15px] font-bold">Event {event.seq}</h2>
        <button onClick={onClose} aria-label="Close" className="rounded-full p-1 hover:bg-rh-elevated">
          <X className="h-4 w-4" />
        </button>
      </div>
      <dl className="mb-4 grid grid-cols-[110px_1fr] gap-y-1">
        <dt className="text-rh-text-2">Time</dt><dd>{new Date(event.occurred_at).toLocaleString()}</dd>
        <dt className="text-rh-text-2">Decision</dt><dd>{event.decision}</dd>
        <dt className="text-rh-text-2">Server</dt><dd>{event.server || "—"}</dd>
        <dt className="text-rh-text-2">Tool</dt><dd className="font-mono">{event.tool_name || event.method}</dd>
        <dt className="text-rh-text-2">Reasons</dt><dd>{event.reasons.join("; ") || "—"}</dd>
        <dt className="text-rh-text-2">Upstream</dt><dd>{event.upstream_status ?? "—"}</dd>
        <dt className="text-rh-text-2">Argument names</dt><dd className="font-mono">{event.argument_keys.join(", ") || "—"}</dd>
      </dl>

      {canViewPayload ? (
        payload ? (
          <>
            <Excerpt title="Arguments (redacted)" excerpt={payload.arguments_redacted} />
            <Excerpt title="Result (redacted)" excerpt={payload.result_excerpt} />
          </>
        ) : (
          <div>
            <button
              onClick={show} disabled={loading}
              className="rounded-full border border-rh-hairline px-3 py-1.5 font-semibold hover:bg-rh-elevated disabled:opacity-50"
            >
              {loading ? "Loading…" : "Show captured payload"}
            </button>
            <p className="mt-2 text-rh-text-2">Viewing a payload is recorded in the audit log.</p>
          </div>
        )
      ) : (
        <p className="text-rh-text-2">Only admins can read captured payloads.</p>
      )}
      {error ? <div className="mt-3 rounded-[8px] border border-rh-crimson bg-rh-crimson-wash px-3 py-2 text-rh-crimson-text">{error}</div> : null}
    </aside>
  );
}
