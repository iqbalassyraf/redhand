"use client";

/**
 * First sign-in with no organization (Phase 4.5 D1): create one with a sign-up code, or open an invite link. redhand-core decides (the code is single-use,
 * expiring and rate-limited); this page only collects the two values and says plainly what happened.
 */

import React, { useState } from "react";

import { RedHandCrest } from "@/components/brand/RedHandCrest";

import { ApiError, onboardingApi } from "@/lib/api";
import { useAuth, useRequiredSession } from "@/lib/auth";
import { CREATE_TEXT, parseCode, parseOrgName, tokenFromPasted } from "@/lib/onboarding";

const input = "rounded-[8px] border border-control-border bg-rh-subtle px-3 py-2 text-[14px] text-rh-text focus:border-control-crimson focus:outline-none";

export default function WelcomePage() {
  const session = useRequiredSession();
  const { signOut } = useAuth();
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [invite, setInvite] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!session) return null;

  async function create(e: React.FormEvent) {
    e.preventDefault();
    const org = parseOrgName(name);
    const secret = parseCode(code);
    if (org === "invalid" || secret === "invalid") {
      setError(org === "invalid" ? "Enter a name for the organization (up to 100 characters)." : CREATE_TEXT.refused);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onboardingApi.createOrganization(session!.token, { name: org, code: secret });
      window.location.href = "/";
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        signOut("/login");
        return;
      }
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  function openInvite(e: React.FormEvent) {
    e.preventDefault();
    const token = tokenFromPasted(invite);
    if (token === "invalid") {
      setError("That does not look like an invite link or token.");
      return;
    }
    window.location.href = `/join?token=${encodeURIComponent(token)}`;
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="rh-glass w-full max-w-[440px] rounded-rh-lg p-6">
        <div className="mb-4 flex items-center gap-2.5">
          <RedHandCrest size="md" />
          <span className="text-[20px] font-bold tracking-tight text-rh-text">redhand</span>
        </div>
        <p className="mb-4 text-[13px] text-rh-text-2">{session.email}: {CREATE_TEXT.noOrganization}</p>

        <h1 className="text-[16px] font-semibold text-rh-text">{CREATE_TEXT.title}</h1>
        <p className="mb-3 mt-1 text-[12px] text-rh-text-2">{CREATE_TEXT.intro}</p>
        <form onSubmit={create} className="flex flex-col gap-3">
          <label className="text-[12px] font-semibold text-rh-text-2" htmlFor="org-name">Organization name</label>
          <input id="org-name" className={input} value={name} maxLength={100} onChange={(e) => setName(e.target.value)} autoComplete="organization" />
          <label className="text-[12px] font-semibold text-rh-text-2" htmlFor="org-code">Sign-up code</label>
          <input id="org-code" className={`${input} font-mono`} value={code} onChange={(e) => setCode(e.target.value)} autoComplete="off" spellCheck={false} placeholder="rh_inv_..." />
          <button disabled={busy} className="rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-4 py-2 text-[13px] font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-50">
            {busy ? "Creating..." : "Create organization"}
          </button>
        </form>

        <hr className="my-5 border-control-border" />
        <h2 className="text-[14px] font-semibold text-rh-text">I have an invite link</h2>
        <form onSubmit={openInvite} className="mt-2 flex flex-col gap-3">
          <label className="sr-only" htmlFor="invite-link">Invite link or token</label>
          <input id="invite-link" className={`${input} font-mono`} value={invite} onChange={(e) => setInvite(e.target.value)} autoComplete="off" spellCheck={false} placeholder="Paste the invite link" />
          <button className="rounded-full border border-control-borderStrong bg-control-glass px-4 py-2 text-[13px] font-semibold text-rh-text transition-colors hover:bg-control-glassHover">Continue</button>
        </form>

        {error && <div role="alert" className="mt-4 rounded-[8px] border border-rh-crimson bg-rh-crimson-wash p-3 text-[13px] text-rh-crimson-text">{error}</div>}
        <button onClick={() => { signOut("/login"); }} className="mt-4 text-[12px] text-rh-text-2 underline hover:text-rh-text">Sign out</button>
      </div>
    </main>
  );
}
