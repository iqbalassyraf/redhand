"use client";

import React, { useEffect, useState } from "react";
import { Hand } from "lucide-react";

import { useAuth } from "@/lib/auth";
import {
  MIN_PASSWORD_LENGTH,
  recoveryTokensFromHash,
  validateNewPassword,
  type RecoveryTokens,
} from "@/lib/passwordReset";

type Stage = "reading" | "invalid" | "form" | "done";

export default function ResetPasswordPage() {
  const { completePasswordReset } = useAuth();
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
    "h-[38px] rounded-[8px] border border-[#E5E5E5] px-3 text-[14px] focus:border-[#0F0F0F] focus:outline-none";

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#F8F8F8] px-4">
      <div className="w-full max-w-[380px] rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-6">
        <div className="mb-6 flex items-center gap-2">
          <div className="flex h-7 w-9 items-center justify-center rounded-[8px] bg-[#FF0000]">
            <Hand className="h-4 w-4 text-[#FFFFFF]" />
          </div>
          <span className="text-[20px] font-bold tracking-tight">RedHand</span>
        </div>

        {stage === "reading" && <p className="text-[13px] text-[#606060]">Checking your link…</p>}

        {stage === "invalid" && (
          <div className="flex flex-col gap-3">
            <p role="alert" className="text-[13px] text-[#CC0000]">
              This reset link is invalid or has expired. Reset links work once.
            </p>
            <a href="/login" className="text-[13px] text-[#606060] underline">
              Request a new link from the sign-in page
            </a>
          </div>
        )}

        {stage === "form" && (
          <form onSubmit={submit} className="flex flex-col gap-3">
            <label className="text-[12px] font-semibold text-[#606060]" htmlFor="new-password">
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
            <label className="text-[12px] font-semibold text-[#606060]" htmlFor="confirm-password">
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
              className="mt-2 h-[38px] rounded-full bg-[#0F0F0F] text-[14px] font-semibold text-[#FFFFFF] disabled:opacity-50"
            >
              Set new password
            </button>
          </form>
        )}

        {stage === "done" && (
          <div className="flex flex-col gap-3">
            <p role="status" className="text-[13px] text-[#0F0F0F]">
              Your password was changed and every other session was signed out.
            </p>
            <a href="/login" className="text-[13px] font-semibold underline">
              Go to sign in
            </a>
          </div>
        )}

        {error && (
          <p role="alert" className="mt-4 text-[13px] text-[#CC0000]">
            {error}
          </p>
        )}
      </div>
    </main>
  );
}
