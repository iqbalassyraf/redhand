"use client";

import { createContext } from "react";

import type { RecoveryTokens } from "@/lib/passwordReset";

export interface OperatorSession {
  token: string;
  email: string;
  role: string | null;
  mode: "supabase" | "development" | "clerk";
}

export interface AuthContextValue {
  session: OperatorSession | null;
  ready: boolean;
  /** Who signs people in (ADR 0032): decided at build time by NEXT_PUBLIC_AUTH_PROVIDER. */
  provider: "supabase" | "clerk";
  supabaseConfigured: boolean;
  signInWithPassword: (email: string, password: string) => Promise<void>;
  signInDevelopment: (user: string) => Promise<void>;
  /** Creates an account with Supabase Auth. `confirm` is true when the person must click a link in an e-mail before signing in. */
  signUpWithPassword: (email: string, password: string) => Promise<{ confirm: boolean }>;
  /** Emails a reset link. Resolves the same way whether or not the account exists. */
  requestPasswordReset: (email: string) => Promise<void>;
  /** Sets a new password using the one-time recovery session from the emailed link. */
  completePasswordReset: (tokens: RecoveryTokens, newPassword: string) => Promise<void>;
  /** Ends the session. With `redirectTo`, navigates there once the session is really gone (Clerk ends it with a request, which a navigation must not cut off). */
  signOut: (redirectTo?: string) => void | Promise<void>;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
