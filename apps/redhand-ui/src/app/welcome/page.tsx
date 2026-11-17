"use client";

/**
 * First sign-in with no organization (Phase 4.5 D1): create one with a sign-up code, or open an invite link. redhand-core decides (the code is single-use,
 * expiring and rate-limited); this page only collects the two values and says plainly what happened.
 */

import React, { useState } from "react";
import { Hand } from "lucide-react";

import { ApiError, onboardingApi } from "@/lib/api";
import { useAuth, useRequiredSession } from "@/lib/auth";
import { CREATE_TEXT, parseCode, parseOrgName, tokenFromPasted } from "@/lib/onboarding";

const input = "rounded-[8px] border border-[#E5E5E5] px-3 py-2 text-[14px]";

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
      window.location.href = "/passports";
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        signOut();
        window.location.href = "/login";
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
    <main className="flex min-h-screen items-center justify-center bg-[#F8F8F8] px-4 py-10">
      <div className="w-full max-w-[440px] rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-6">
        <div className="mb-4 flex items-center gap-2">
          <div className="flex h-7 w-9 items-center justify-center rounded-[8px] bg-[#FF0000]">
            <Hand className="h-4 w-4 text-[#FFFFFF]" />
          </div>
          <span className="text-[20px] font-bold tracking-tight">RedHand</span>
        </div>
        <p className="mb-4 text-[13px] text-[#606060]">{session.email}: {CREATE_TEXT.noOrganization}</p>

        <h1 className="text-[16px] font-semibold">{CREATE_TEXT.title}</h1>
        <p className="mb-3 mt-1 text-[12px] text-[#606060]">{CREATE_TEXT.intro}</p>
        <form onSubmit={create} className="flex flex-col gap-3">
          <label className="text-[12px] font-semibold text-[#606060]" htmlFor="org-name">Organization name</label>
          <input id="org-name" className={input} value={name} maxLength={100} onChange={(e) => setName(e.target.value)} autoComplete="organization" />
          <label className="text-[12px] font-semibold text-[#606060]" htmlFor="org-code">Sign-up code</label>
          <input id="org-code" className={`${input} font-mono`} value={code} onChange={(e) => setCode(e.target.value)} autoComplete="off" spellCheck={false} placeholder="rh_inv_..." />
          <button disabled={busy} className="rounded-full bg-[#FF0000] px-4 py-2 text-[13px] font-semibold text-[#FFFFFF] disabled:opacity-50">
            {busy ? "Creating..." : "Create organization"}
          </button>
        </form>

        <hr className="my-5 border-[#E5E5E5]" />
        <h2 className="text-[14px] font-semibold">I have an invite link</h2>
        <form onSubmit={openInvite} className="mt-2 flex flex-col gap-3">
          <label className="sr-only" htmlFor="invite-link">Invite link or token</label>
          <input id="invite-link" className={`${input} font-mono`} value={invite} onChange={(e) => setInvite(e.target.value)} autoComplete="off" spellCheck={false} placeholder="Paste the invite link" />
          <button className="rounded-full border border-[#E5E5E5] px-4 py-2 text-[13px] font-semibold hover:bg-[#F2F2F2]">Continue</button>
        </form>

        {error && <div role="alert" className="mt-4 rounded-[8px] bg-[#FDECEC] p-3 text-[13px] text-[#B42318]">{error}</div>}
        <button onClick={() => { signOut(); window.location.href = "/login"; }} className="mt-4 text-[12px] text-[#606060] underline">Sign out</button>
      </div>
    </main>
  );
}
