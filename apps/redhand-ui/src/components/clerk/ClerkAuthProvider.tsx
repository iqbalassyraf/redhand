"use client";

/**
 * Sign-in through Clerk (ADR 0032). Clerk owns the account, the session cookie and the sign-in screens; this provider hands the rest of the
 * dashboard the same `session` shape it already uses, whose token is a Clerk session token from the JWT template `redhand` (audience
 * `redhand-core`, with e-mail and email_verified). redhand-core verifies that token and maps the person to its own operator id; nothing here is a
 * security boundary. The token lives in memory only (never in storage) and is renewed before it expires.
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { ClerkProvider, useAuth as useClerkAuth, useClerk, useUser } from "@clerk/nextjs";

import { AuthContext, type AuthContextValue, type OperatorSession } from "@/lib/authContext";
import { nextRefreshDelayMs } from "@/lib/clerkToken";
import { clerkAppearance } from "@/components/clerk/appearance";

export const CLERK_TOKEN_TEMPLATE = "redhand";

function unsupported(): Promise<never> {
  return Promise.reject(new Error("This sign-in method is handled by Clerk."));
}

function Bridge({ children }: { children: React.ReactNode }) {
  const { isLoaded, isSignedIn, getToken } = useClerkAuth();
  const { user } = useUser();
  const clerk = useClerk();
  const [token, setToken] = useState<string | null>(null);
  const [tokenReady, setTokenReady] = useState(false);

  useEffect(() => {
    if (!isLoaded) return undefined;
    if (!isSignedIn) {
      setToken(null);
      setTokenReady(true);
      return undefined;
    }
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const fetchToken = async () => {
      let delay = nextRefreshDelayMs(null);
      try {
        const next = await getToken({ template: CLERK_TOKEN_TEMPLATE });
        if (cancelled) return;
        setToken(next);
        delay = nextRefreshDelayMs(next);
      } catch {
        if (cancelled) return;
        setToken(null); // no token means no access: every page then asks the person to sign in again
      } finally {
        if (!cancelled) {
          setTokenReady(true);
          timer = setTimeout(() => void fetchToken(), delay);
        }
      }
    };
    void fetchToken();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [isLoaded, isSignedIn, getToken]);

  const email = user?.primaryEmailAddress?.emailAddress ?? "";
  const session = useMemo<OperatorSession | null>(() => (token ? { token, email, role: null, mode: "clerk" } : null), [token, email]);

  const signOut = useCallback(
    (redirectTo?: string) => {
      setToken(null);
      return clerk.signOut(redirectTo ? { redirectUrl: redirectTo } : undefined);
    },
    [clerk]
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      ready: isLoaded && tokenReady,
      provider: "clerk",
      supabaseConfigured: false,
      signInWithPassword: unsupported,
      signInDevelopment: unsupported,
      signUpWithPassword: unsupported,
      requestPasswordReset: unsupported,
      completePasswordReset: unsupported,
      signOut,
    }),
    [session, isLoaded, tokenReady, signOut]
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export default function ClerkAuthProvider({ children }: { children: React.ReactNode }) {
  const publishableKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
  if (!publishableKey) {
    return <p role="alert" className="p-6 text-[13px] text-rh-text">Sign-in is not configured: NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY is missing.</p>;
  }
  return (
    <ClerkProvider publishableKey={publishableKey} appearance={clerkAppearance} signInUrl="/login" signUpUrl="/login" afterSignOutUrl="/login">
      <Bridge>{children}</Bridge>
    </ClerkProvider>
  );
}
