"use client";

import React, { useState } from "react";
import dynamic from "next/dynamic";

import { RedHandCrest } from "@/components/brand/RedHandCrest";
import { useAuth } from "@/lib/auth";
import { PENDING_INVITE_KEY } from "@/lib/onboarding";

// Clerk's screens load only in a Clerk build.
const ClerkLogin = dynamic(() => import("@/components/clerk/ClerkLogin"), { ssr: false });

const DEV_USERS: Array<{ id: string; label: string }> = [
  { id: "owner", label: "Owner" },
  { id: "admin", label: "Admin" },
  { id: "operator", label: "Security operator" },
  { id: "operator2", label: "Security operator #2" },
  { id: "viewer", label: "Viewer" },
];

export default function LoginPage() {
  const { provider, supabaseConfigured, signInWithPassword, signInDevelopment, signUpWithPassword, requestPasswordReset } = useAuth();
  const [mode, setMode] = useState<"signin" | "forgot" | "signup">("signin");
  const [notice, setNotice] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      let pending = false;
      try { pending = Boolean(window.sessionStorage.getItem(PENDING_INVITE_KEY)); } catch { /* storage unavailable: go to the control room */ }
      window.location.href = pending ? "/join" : "/";
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  if (provider === "clerk") {
    return (
      <main className="flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-8">
        <div className="flex items-center gap-2.5">
          <RedHandCrest size="md" />
          <span className="text-[20px] font-bold tracking-tight text-rh-text">redhand</span>
        </div>
        <ClerkLogin />
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="rh-glass w-full max-w-[380px] rounded-rh-lg p-6">
        <div className="mb-6 flex items-center gap-2.5">
          <RedHandCrest size="md" />
          <span className="text-[20px] font-bold tracking-tight text-rh-text">redhand</span>
        </div>

        {supabaseConfigured && mode === "forgot" ? (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setError(null);
              setNotice(null);
              try {
                await requestPasswordReset(email);
                setNotice(
                  "If an account exists for that email, a reset link is on its way. The link works once and expires quickly."
                );
              } catch (err) {
                setError(err instanceof Error ? err.message : "Could not send the email.");
              } finally {
                setBusy(false);
              }
            }}
            className="flex flex-col gap-3"
          >
            <label className="text-[12px] font-semibold text-rh-text-2" htmlFor="reset-email">
              Email
            </label>
            <input
              id="reset-email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="h-[38px] rounded-[8px] border border-control-border bg-rh-subtle px-3 text-[14px] text-rh-text focus:border-control-crimson focus:outline-none"
            />
            <button
              type="submit"
              disabled={busy}
              className="mt-2 h-[38px] rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson text-[14px] font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-50"
            >
              Send reset link
            </button>
            <button
              type="button"
              onClick={() => {
                setMode("signin");
                setError(null);
                setNotice(null);
              }}
              className="text-[13px] text-rh-text-2 underline hover:text-rh-text"
            >
              Back to sign in
            </button>
          </form>
        ) : supabaseConfigured && mode === "signup" ? (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setError(null);
              setNotice(null);
              try {
                const result = await signUpWithPassword(email, password);
                if (result.confirm) {
                  setNotice("Almost there: open the link we e-mailed you to confirm the address, then sign in here.");
                  setMode("signin");
                } else {
                  window.location.href = "/"; // no organization yet: the page sends you to create or join one
                }
              } catch (err) {
                setError(err instanceof Error ? err.message : "Could not create the account.");
              } finally {
                setBusy(false);
              }
            }}
            className="flex flex-col gap-3"
          >
            <h1 className="text-[15px] font-semibold text-rh-text">Create an account</h1>
            <label className="text-[12px] font-semibold text-rh-text-2" htmlFor="signup-email">Email</label>
            <input id="signup-email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)}
              className="h-[38px] rounded-[8px] border border-control-border bg-rh-subtle px-3 text-[14px] text-rh-text focus:border-control-crimson focus:outline-none" />
            <label className="text-[12px] font-semibold text-rh-text-2" htmlFor="signup-password">Password (at least 10 characters)</label>
            <input id="signup-password" type="password" autoComplete="new-password" required minLength={10} value={password} onChange={(e) => setPassword(e.target.value)}
              className="h-[38px] rounded-[8px] border border-control-border bg-rh-subtle px-3 text-[14px] text-rh-text focus:border-control-crimson focus:outline-none" />
            <p className="text-[12px] text-rh-text-2">
              An account lets you join a team you were invited to, or create an organization with a sign-up code. RedHand is invite-only for now.
            </p>
            <button type="submit" disabled={busy} className="mt-1 h-[38px] rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson text-[14px] font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-50">
              Create account
            </button>
            <button type="button" onClick={() => { setMode("signin"); setError(null); }} className="text-[13px] text-rh-text-2 underline hover:text-rh-text">Back to sign in</button>
          </form>
        ) : supabaseConfigured ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              run(() => signInWithPassword(email, password));
            }}
            className="flex flex-col gap-3"
          >
            <label className="text-[12px] font-semibold text-rh-text-2" htmlFor="email">
              Email
            </label>
            <input
              id="email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="h-[38px] rounded-[8px] border border-control-border bg-rh-subtle px-3 text-[14px] text-rh-text focus:border-control-crimson focus:outline-none"
            />
            <label className="text-[12px] font-semibold text-rh-text-2" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="h-[38px] rounded-[8px] border border-control-border bg-rh-subtle px-3 text-[14px] text-rh-text focus:border-control-crimson focus:outline-none"
            />
            <button
              type="submit"
              disabled={busy}
              className="mt-2 h-[38px] rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson text-[14px] font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-50"
            >
              Sign in
            </button>
            <button
              type="button"
              onClick={() => {
                setMode("forgot");
                setError(null);
              }}
              className="text-[13px] text-rh-text-2 underline hover:text-rh-text"
            >
              Forgot password?
            </button>
            <button
              type="button"
              onClick={() => {
                setMode("signup");
                setError(null);
                setNotice(null);
              }}
              className="text-[13px] text-rh-text-2 underline hover:text-rh-text"
            >
              Create an account
            </button>
          </form>
        ) : (
          <div className="flex flex-col gap-2">
            <p className="mb-2 rounded-[8px] border border-control-ochreBorder bg-rh-ochre-wash p-3 text-[12px] text-rh-ochre">
              Development sign-in. Supabase is not configured, so redhand-core must be running
              in development mode with its in-memory store. Never use this in production.
            </p>
            {DEV_USERS.map((u) => (
              <button
                key={u.id}
                disabled={busy}
                onClick={() => run(() => signInDevelopment(u.id))}
                className="h-[38px] rounded-full border border-control-borderStrong bg-control-glass text-[14px] font-medium text-rh-text transition-colors hover:bg-control-glassHover disabled:opacity-50"
              >
                Continue as {u.label}
              </button>
            ))}
          </div>
        )}

        {notice && (
          <p role="status" className="mt-4 text-[13px] text-rh-text">
            {notice}
          </p>
        )}
        {error && (
          <p role="alert" className="mt-4 text-[13px] text-rh-crimson-text">
            {error}
          </p>
        )}
      </div>
    </main>
  );
}
