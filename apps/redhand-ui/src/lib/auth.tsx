"use client";

/**
 * Operator session for the dashboard.
 *
 * Production: Supabase Auth (email + password) when NEXT_PUBLIC_SUPABASE_URL and
 * NEXT_PUBLIC_SUPABASE_ANON_KEY are set. Development: redhand-core's /v1/dev/login, which
 * only exists when core runs in development mode on its in-memory store.
 *
 * The access token is kept in sessionStorage (cleared when the tab closes). Moving to
 * httpOnly cookies via a server-side session is a tracked follow-up.
 */

import React, { useCallback, useContext, useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import { createClient } from "@supabase/supabase-js";

import { apiFetch } from "@/lib/api";
import { AuthContext, type AuthContextValue, type OperatorSession } from "@/lib/authContext";
import type { RecoveryTokens } from "@/lib/passwordReset";

const STORAGE_KEY = "redhand.operator.session";

export type { OperatorSession, AuthContextValue } from "@/lib/authContext";

export const AUTH_PROVIDER: "supabase" | "clerk" = process.env.NEXT_PUBLIC_AUTH_PROVIDER === "clerk" ? "clerk" : "supabase";

// The Clerk code is only loaded when the build is in Clerk mode (and never during server rendering): Supabase mode ships none of it.
const ClerkAuthProvider = dynamic(() => import("@/components/clerk/ClerkAuthProvider"), { ssr: false });


const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

function readStoredSession(): OperatorSession | null {
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as OperatorSession) : null;
  } catch {
    return null;
  }
}

function storeSession(session: OperatorSession | null): void {
  try {
    if (session) window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    else window.sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage unavailable (private mode): the session lives in memory only.
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  if (AUTH_PROVIDER === "clerk") return <ClerkAuthProvider>{children}</ClerkAuthProvider>;
  return <SupabaseAuthProvider>{children}</SupabaseAuthProvider>;
}

function SupabaseAuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<OperatorSession | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    setSession(readStoredSession());
    setReady(true);
  }, []);

  const update = useCallback((next: OperatorSession | null) => {
    storeSession(next);
    setSession(next);
  }, []);

  const signInWithPassword = useCallback(
    async (email: string, password: string) => {
      if (!SUPABASE_URL || !SUPABASE_ANON_KEY) throw new Error("Supabase is not configured.");
      const client = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        auth: { persistSession: false },
      });
      const { data, error } = await client.auth.signInWithPassword({ email, password });
      if (error || !data.session) throw new Error(error?.message || "Sign-in failed.");
      update({ token: data.session.access_token, email, role: null, mode: "supabase" });
    },
    [update]
  );

  const signUpWithPassword = useCallback(
    async (email: string, password: string) => {
      if (!SUPABASE_URL || !SUPABASE_ANON_KEY) throw new Error("Supabase is not configured.");
      const client = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: false } });
      const { data, error } = await client.auth.signUp({ email, password, options: { emailRedirectTo: `${window.location.origin}/login` } });
      // Supabase answers the same way for an address that already has an account: say nothing about which it was.
      if (error) throw new Error("Could not create the account. Use a longer password or try again in a minute.");
      if (data.session) {
        update({ token: data.session.access_token, email, role: null, mode: "supabase" });
        return { confirm: false };
      }
      return { confirm: true };
    },
    [update]
  );

  const requestPasswordReset = useCallback(async (email: string) => {
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) throw new Error("Supabase is not configured.");
    const client = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: false } });
    const { error } = await client.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/reset-password`,
    });
    // Supabase answers success for unknown emails. Only a rate limit or outage reaches here; say so without
    // revealing anything about the account.
    if (error) throw new Error("Could not send the email right now. Wait a minute and try again.");
  }, []);

  const completePasswordReset = useCallback(async (tokens: RecoveryTokens, newPassword: string) => {
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) throw new Error("Supabase is not configured.");
    const client = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });
    const { error: sessionError } = await client.auth.setSession({
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
    });
    if (sessionError) throw new Error("This reset link is invalid or has expired. Request a new one.");
    const { error } = await client.auth.updateUser({ password: newPassword });
    if (error) throw new Error(error.message || "Could not change the password.");
    // The recovery session is single-purpose: end it everywhere so the user signs in with the new password.
    await client.auth.signOut({ scope: "global" });
  }, []);

  const signInDevelopment = useCallback(
    async (user: string) => {
      const res = await apiFetch<{ access_token: string; email: string; role: string }>(
        "/v1/dev/login",
        null,
        { method: "POST", body: { user } }
      );
      update({ token: res.access_token, email: res.email, role: res.role, mode: "development" });
    },
    [update]
  );

  const signOut = useCallback(
    (redirectTo?: string) => {
      update(null);
      if (redirectTo) window.location.href = redirectTo;
    },
    [update]
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      ready,
      provider: "supabase",
      supabaseConfigured: Boolean(SUPABASE_URL && SUPABASE_ANON_KEY),
      signInWithPassword,
      signInDevelopment,
      signUpWithPassword,
      requestPasswordReset,
      completePasswordReset,
      signOut,
    }),
    [session, ready, signInWithPassword, signInDevelopment, signUpWithPassword, requestPasswordReset, completePasswordReset, signOut]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>.");
  return ctx;
}

/** Redirects to /login when there is no session. Returns the session once available. */
export function useRequiredSession(): OperatorSession | null {
  const { session, ready } = useAuth();
  useEffect(() => {
    if (ready && !session) window.location.href = "/login";
  }, [ready, session]);
  return session;
}
