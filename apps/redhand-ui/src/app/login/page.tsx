"use client";

import React, { useState } from "react";
import { Hand } from "lucide-react";

import { useAuth } from "@/lib/auth";

const DEV_USERS: Array<{ id: string; label: string }> = [
  { id: "owner", label: "Owner" },
  { id: "admin", label: "Admin" },
  { id: "operator", label: "Security operator" },
  { id: "operator2", label: "Security operator #2" },
  { id: "viewer", label: "Viewer" },
];

export default function LoginPage() {
  const { supabaseConfigured, signInWithPassword, signInDevelopment } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      window.location.href = "/passports";
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#F8F8F8] px-4">
      <div className="w-full max-w-[380px] rounded-[12px] border border-[#E5E5E5] bg-[#FFFFFF] p-6">
        <div className="mb-6 flex items-center gap-2">
          <div className="flex h-7 w-9 items-center justify-center rounded-[8px] bg-[#FF0000]">
            <Hand className="h-4 w-4 text-[#FFFFFF]" />
          </div>
          <span className="text-[20px] font-bold tracking-tight">RedHand</span>
        </div>

        {supabaseConfigured ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              run(() => signInWithPassword(email, password));
            }}
            className="flex flex-col gap-3"
          >
            <label className="text-[12px] font-semibold text-[#606060]" htmlFor="email">
              Email
            </label>
            <input
              id="email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="h-[38px] rounded-[8px] border border-[#E5E5E5] px-3 text-[14px] focus:border-[#0F0F0F] focus:outline-none"
            />
            <label className="text-[12px] font-semibold text-[#606060]" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="h-[38px] rounded-[8px] border border-[#E5E5E5] px-3 text-[14px] focus:border-[#0F0F0F] focus:outline-none"
            />
            <button
              type="submit"
              disabled={busy}
              className="mt-2 h-[38px] rounded-full bg-[#0F0F0F] text-[14px] font-semibold text-[#FFFFFF] disabled:opacity-50"
            >
              Sign in
            </button>
          </form>
        ) : (
          <div className="flex flex-col gap-2">
            <p className="mb-2 rounded-[8px] bg-[#FFF4E5] p-3 text-[12px] text-[#8A4B00]">
              Development sign-in. Supabase is not configured, so redhand-core must be running
              in development mode with its in-memory store. Never use this in production.
            </p>
            {DEV_USERS.map((u) => (
              <button
                key={u.id}
                disabled={busy}
                onClick={() => run(() => signInDevelopment(u.id))}
                className="h-[38px] rounded-full border border-[#E5E5E5] text-[14px] font-medium hover:bg-[#F2F2F2] disabled:opacity-50"
              >
                Continue as {u.label}
              </button>
            ))}
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
