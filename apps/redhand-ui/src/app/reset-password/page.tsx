"use client";

import React, { useEffect, useState } from "react";

import { RedHandCrest } from "@/components/brand/RedHandCrest";

import { useAuth } from "@/lib/auth";
import {
  MIN_PASSWORD_LENGTH,
  recoveryTokensFromHash,
  validateNewPassword,
  type RecoveryTokens,
} from "@/lib/passwordReset";

type Stage = "reading" | "invalid" | "form" | "done";

export default function ResetPasswordPage() {
  const { provider, completePasswordReset } = useAuth();
  const [stage, setStage] = useState<Stage>("reading");
  const [tokens, setTokens] = useState<RecoveryTokens | null>(null);
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const found = recoveryTokensFromHash(window.location.hash);
    // Remove the one-time tokens from the address bar and history straight away.
    window.history.replaceState(null, "", window.location.pathname);
    setTokens(found);
    setStage(found ? "form" : "invalid");
  }, []);

  if (provider === "clerk") {
    return (
      <main className="flex min-h-screen items-center justify-center px-4">
        <div className="rh-glass w-full max-w-[380px] rounded-rh-lg p-6 text-[13px] text-rh-text">
          <p className="mb-3">Password resets are handled on the sign-in screen: choose "Forgot password?" there.</p>
          <a href="/login" className="underline">Go to sign in</a>
        </div>
      </main>
    );
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!tokens) return;
    const problem = validateNewPassword(password, confirmation);
    if (problem) {
      setError(problem);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await completePasswordReset(tokens, password);
      setTokens(null);
      setPassword("");
      setConfirmation("");
      setStage("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not change the password.");
    } finally {
      setBusy(false);
    }
  }

  const input =
    "h-[38px] rounded-[8px] border border-control-border bg-rh-subtle px-3 text-[14px] text-rh-text focus:border-control-crimson focus:outline-none";

  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="rh-glass w-full max-w-[380px] rounded-rh-lg p-6">
        <div className="mb-6 flex items-center gap-2.5">
          <RedHandCrest size="md" />
          <span className="text-[20px] font-bold tracking-tight text-rh-text">redhand</span>
        </div>

        {stage === "reading" && <p className="text-[13px] text-rh-text-2">Checking your link…</p>}

        {stage === "invalid" && (
          <div className="flex flex-col gap-3">
            <p role="alert" className="text-[13px] text-rh-crimson-text">
              This reset link is invalid or has expired. Reset links work once.
            </p>
            <a href="/login" className="text-[13px] text-rh-text-2 underline">
              Request a new link from the sign-in page
            </a>
          </div>
        )}

        {stage === "form" && (
          <form onSubmit={submit} className="flex flex-col gap-3">
            <label className="text-[12px] font-semibold text-rh-text-2" htmlFor="new-password">
              New password ({MIN_PASSWORD_LENGTH}+ characters)
            </label>
            <input
              id="new-password"
              type="password"
              autoComplete="new-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={input}
            />
            <label className="text-[12px] font-semibold text-rh-text-2" htmlFor="confirm-password">
              Confirm new password
            </label>
            <input
              id="confirm-password"
              type="password"
              autoComplete="new-password"
              required
              value={confirmation}
              onChange={(e) => setConfirmation(e.target.value)}
              className={input}
            />
            <button
              type="submit"
              disabled={busy}
              className="mt-2 h-[38px] rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson text-[14px] font-semibold text-white shadow-rh-crimson transition hover:to-control-crimsonDeep disabled:opacity-50"
            >
              Set new password
            </button>
          </form>
        )}

        {stage === "done" && (
          <div className="flex flex-col gap-3">
            <p role="status" className="text-[13px] text-rh-text">
              Your password was changed and every other session was signed out.
            </p>
            <a href="/login" className="text-[13px] font-semibold underline">
              Go to sign in
            </a>
          </div>
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
