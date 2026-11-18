"use client";

/**
 * Organization data (Phase 4.5 D1, ADR 0027): the owner exports everything, requests deletion (address name typed back, 7-day grace) or cancels.
 * This page and the export are the only things that still work while deletion is pending. redhand-core decides every step.
 */

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";


import { ApiError, lifecycleApi, meApi, type DeletionStatus, type Me } from "@/lib/api";
import { useAuth, useRequiredSession } from "@/lib/auth";
import { AppShell } from "@/components/shell/AppShell";
import { ORG_TEXT, exportFilename, pendingText, slugMatches } from "@/lib/lifecycle";
import { isNoOrganizationMessage } from "@/lib/onboarding";

const button = "rounded-full bg-control-crimson px-4 py-2 text-[13px] font-semibold text-white shadow-rh-crimson transition hover:bg-control-crimsonDeep disabled:opacity-50";
const quiet = "rounded-full border border-rh-hairline px-4 py-2 text-[13px] font-semibold disabled:opacity-50";

export default function OrganizationPage() {
  const session = useRequiredSession();
  const { signOut } = useAuth();
  const [me, setMe] = useState<Me | null>(null);
  const [status, setStatus] = useState<DeletionStatus | null>(null);
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const token = session?.token ?? null;

  const fail = useCallback((err: unknown) => {
    if (err instanceof ApiError && err.status === 401) {
      signOut("/login");
      return;
    }
    if (err instanceof ApiError && err.status === 403 && isNoOrganizationMessage(err.message)) {
      window.location.href = "/welcome";
      return;
    }
    setError(err instanceof Error ? err.message : "Something went wrong.");
  }, [signOut]);

  const load = useCallback(async () => {
    if (!token) return;
    try {
      const who = await meApi.get(token);
      setMe(who);
      setStatus(who.role === "owner" ? await lifecycleApi.status(token) : null);
    } catch (err) {
      fail(err);
    }
  }, [token, fail]);

  useEffect(() => { void load(); }, [load]);

  if (!session) return null;

  async function act(run: () => Promise<void>) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await run();
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  }

  const download = () => act(async () => {
    const data = await lifecycleApi.exportData(session.token);
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = exportFilename(me?.organization_slug ?? "", new Date());
    link.click();
    URL.revokeObjectURL(url);
    setNotice(ORG_TEXT.exportDone);
  });

  const requestDeletion = () => act(async () => {
    if (!me || !slugMatches(typed, me.organization_slug ?? "")) return;
    if (!window.confirm(ORG_TEXT.deleteConfirm)) return;
    setStatus(await lifecycleApi.requestDeletion(session.token, typed.trim()));
    setTyped("");
  });

  const cancel = () => act(async () => {
    setStatus(await lifecycleApi.cancelDeletion(session.token));
    setNotice(ORG_TEXT.cancelDone);
  });

  const pendingUntil = status?.requested ? status.purge_after : me?.deletion_purge_after ?? null;

  return (
    <AppShell title="Organization" organization={me?.organization_name} role={me?.role}>
      <div className="mx-auto flex max-w-[720px] flex-col gap-4 px-4 py-6">
        <h2 className="text-[18px] font-semibold">{ORG_TEXT.title}</h2>
        {pendingUntil && (
          <p role="status" className="rounded-[8px] bg-rh-crimson-wash p-3 text-[13px] text-rh-crimson-text">{pendingText(pendingUntil)}</p>
        )}
        {error && <p role="alert" className="rounded-[8px] bg-rh-crimson-wash p-3 text-[13px] text-rh-crimson-text">{error}</p>}
        {notice && <p role="status" className="rounded-[8px] bg-rh-teal-wash p-3 text-[13px] text-rh-teal-text">{notice}</p>}

        {me && me.role !== "owner" && <p className="text-[13px] text-rh-text-2">{ORG_TEXT.notOwner}</p>}

        {me?.role === "owner" && (
          <>
            <section className="rh-glass rounded-rh-md p-4" aria-label={ORG_TEXT.exportTitle}>
              <h2 className="text-[15px] font-semibold">{ORG_TEXT.exportTitle}</h2>
              <p className="mb-3 mt-1 text-[12px] text-rh-text-2">{ORG_TEXT.exportIntro}</p>
              <button className={quiet} disabled={busy} onClick={() => void download()}>{ORG_TEXT.exportButton}</button>
            </section>

            <section className="rh-glass rounded-rh-md border-control-crimsonBorder p-4" aria-label={ORG_TEXT.deleteTitle}>
              <h2 className="text-[15px] font-semibold">{ORG_TEXT.deleteTitle}</h2>
              <p className="mb-3 mt-1 text-[12px] text-rh-text-2">{ORG_TEXT.deleteIntro}</p>
              {pendingUntil ? (
                <button className={quiet} disabled={busy} onClick={() => void cancel()}>{ORG_TEXT.cancelButton}</button>
              ) : (
                <div className="flex flex-col gap-2">
                  <label className="text-[12px] font-semibold text-rh-text-2" htmlFor="confirm-slug">
                    {ORG_TEXT.deleteLabel} (<span className="font-mono">{me.organization_slug}</span>)
                  </label>
                  <input id="confirm-slug" className="rounded-[8px] border border-rh-hairline px-3 py-2 font-mono text-[14px]" value={typed}
                    onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
                  <div>
                    <button className={button} disabled={busy || !slugMatches(typed, me.organization_slug ?? "")} onClick={() => void requestDeletion()}>
                      {ORG_TEXT.deleteButton}
                    </button>
                  </div>
                </div>
              )}
            </section>
          </>
        )}
        <Link href="/passports" className="text-[13px] text-rh-text-2 underline">Back to Passports</Link>
      </div>
    </AppShell>
  );
}
