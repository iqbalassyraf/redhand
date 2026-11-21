"use client";

/**
 * Accepting an invite link (Phase 4.5 D1). Not signed in: the token is kept for this tab only (sessionStorage, cleared on use) and the person is sent to sign in
 * or create an account first. Signed in: an explicit "Accept" button, so opening a link never joins anything by itself.
 */

import React, { useEffect, useState } from "react";

import { RedHandCrest } from "@/components/brand/RedHandCrest";

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
        signOut("/login");
        return;
      }
      setError(err instanceof Error ? err.message : JOIN_TEXT.refused);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="rh-glass w-full max-w-[400px] rounded-rh-lg p-6">
        <div className="mb-4 flex items-center gap-2.5">
          <RedHandCrest size="md" />
          <span className="text-[20px] font-bold tracking-tight text-rh-text">redhand</span>
        </div>
        <h1 className="text-[16px] font-semibold text-rh-text">{JOIN_TEXT.title}</h1>
        {token === null ? null : token === "invalid" ? (
          <p role="alert" className="mt-3 rounded-[8px] border border-rh-crimson bg-rh-crimson-wash p-3 text-[13px] text-rh-crimson-text">{JOIN_TEXT.refused}</p>
        ) : !ready ? null : session ? (
          <>
            <p className="mb-3 mt-1 text-[12px] text-rh-text-2">{JOIN_TEXT.intro}</p>
            <p className="mb-3 text-[13px] text-rh-text">Signed in as {session.email}.</p>
            <button onClick={accept} disabled={busy} className="rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-4 py-2 text-[13px] font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-50">
              {busy ? "Joining..." : "Accept invite"}
            </button>
          </>
        ) : (
          <>
            <p className="mb-3 mt-1 text-[13px] text-rh-text-2">{JOIN_TEXT.signInFirst}</p>
            <a href="/login" className="inline-block rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-4 py-2 text-[13px] font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep">Sign in or create an account</a>
          </>
        )}
        {error && <div role="alert" className="mt-4 rounded-[8px] border border-rh-crimson bg-rh-crimson-wash p-3 text-[13px] text-rh-crimson-text">{error}</div>}
      </div>
    </main>
  );
}
