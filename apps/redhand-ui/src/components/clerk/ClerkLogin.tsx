"use client";

/** Clerk's sign-in and sign-up (Google and e-mail) inside our centred card. After sign-in: the invite page if an invite is waiting, else Passports (which sends a person with no organization to /welcome). */

import React, { useEffect, useState } from "react";
import { SignIn, SignUp } from "@clerk/nextjs";

import { useAuth } from "@/lib/auth";
import { PENDING_INVITE_KEY } from "@/lib/onboarding";

function destination(): string {
  try {
    return window.sessionStorage.getItem(PENDING_INVITE_KEY) ? "/join" : "/";
  } catch {
    return "/";
  }
}

export default function ClerkLogin() {
  const { session, ready } = useAuth();
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [after, setAfter] = useState("/");

  useEffect(() => setAfter(destination()), []);
  useEffect(() => {
    if (ready && session) window.location.href = destination();
  }, [ready, session]);

  return (
    <div className="flex flex-col items-center gap-3">
      <div role="tablist" aria-label="Sign in or create an account" className="rh-glass flex rounded-full p-1">
        {(["signin", "signup"] as const).map((m) => (
          <button
            key={m}
            role="tab"
            aria-selected={mode === m}
            onClick={() => setMode(m)}
            className={`rounded-full px-4 py-1.5 text-[13px] font-medium transition-colors ${mode === m ? "bg-control-crimson text-white shadow-rh-crimson" : "text-rh-text-2 hover:text-rh-text"}`}
          >
            {m === "signin" ? "Sign in" : "Create an account"}
          </button>
        ))}
      </div>
      {mode === "signin" ? (
        <SignIn routing="hash" forceRedirectUrl={after} signUpForceRedirectUrl={after} />
      ) : (
        <SignUp routing="hash" forceRedirectUrl={after} signInForceRedirectUrl={after} />
      )}
    </div>
  );
}
