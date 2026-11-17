"use client";

/**
 * Accepting an invite link (Phase 4.5 D1). Not signed in: the token is kept for this tab only (sessionStorage, cleared on use) and the person is sent to sign in
 * or create an account first. Signed in: an explicit "Accept" button, so opening a link never joins anything by itself.
 */

import React, { useEffect, useState } from "react";
import { Hand } from "lucide-react";

import { ApiError, onboardingApi } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { JOIN_TEXT, PENDING_INVITE_KEY, ROLE_LABEL, parseInviteToken, type Role } from "@/lib/onboarding";

function storage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export default function JoinPage() {
  const { session, ready, signOut } = useAuth();
  const [token, setToken] = useState<string | "invalid" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Read the link once: the secret then leaves the address bar (history, screenshots) and lives only in this component's state.
  useEffect(() => {
    const fromUrl = new URLSearchParams(window.location.search).get("token");
    setToken(parseInviteToken(fromUrl ?? storage()?.getItem(PENDING_INVITE_KEY)));
    if (fromUrl) window.history.replaceState(null, "", "/join");
  }, []);

  // Not signed in: keep it for this tab so the person can sign in or create an account and come back (the login page returns here).
  useEffect(() => {
    if (ready && !session && token !== null && token !== "invalid") storage()?.setItem(PENDING_INVITE_KEY, token);
  }, [ready, session, token]);

  async function accept() {
    if (!session || token === null || token === "invalid") return;
    setBusy(true);
    setError(null);
    try {
      const joined = await onboardingApi.acceptInvite(session.token, token);
      storage()?.removeItem(PENDING_INVITE_KEY);
      setError(null);
      window.location.href = `/passports?joined=${encodeURIComponent((ROLE_LABEL as Record<string, string>)[joined.role as Role] ?? joined.role)}`;
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        signOut();
        window.location.href = "/login";
        return;
      }
      setError(err instanceof Error ? err.message : JOIN_TEXT.refused);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#F8F8F8] px-4">
      <div className="w-full max-w-[400px] rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-6">
        <div className="mb-4 flex items-center gap-2">
          <div className="flex h-7 w-9 items-center justify-center rounded-[8px] bg-[#FF0000]">
            <Hand className="h-4 w-4 text-[#FFFFFF]" />
          </div>
          <span className="text-[20px] font-bold tracking-tight">RedHand</span>
        </div>
        <h1 className="text-[16px] font-semibold">{JOIN_TEXT.title}</h1>
        {token === null ? null : token === "invalid" ? (
          <p role="alert" className="mt-3 rounded-[8px] bg-[#FDECEC] p-3 text-[13px] text-[#B42318]">{JOIN_TEXT.refused}</p>
        ) : !ready ? null : session ? (
          <>
            <p className="mb-3 mt-1 text-[12px] text-[#606060]">{JOIN_TEXT.intro}</p>
            <p className="mb-3 text-[13px]">Signed in as {session.email}.</p>
            <button onClick={accept} disabled={busy} className="rounded-full bg-[#FF0000] px-4 py-2 text-[13px] font-semibold text-[#FFFFFF] disabled:opacity-50">
              {busy ? "Joining..." : "Accept invite"}
            </button>
          </>
        ) : (
          <>
            <p className="mb-3 mt-1 text-[13px] text-[#606060]">{JOIN_TEXT.signInFirst}</p>
            <a href="/login" className="inline-block rounded-full bg-[#FF0000] px-4 py-2 text-[13px] font-semibold text-[#FFFFFF]">Sign in or create an account</a>
          </>
        )}
        {error && <div role="alert" className="mt-4 rounded-[8px] bg-[#FDECEC] p-3 text-[13px] text-[#B42318]">{error}</div>}
      </div>
    </main>
  );
}
