"use client";

import React, { useState } from "react";
import Link from "next/link";
import { ArrowRight, ExternalLink, Hand, Lock, ShieldCheck, Terminal } from "lucide-react";

import { EarlyAccessModal } from "./EarlyAccessModal";
import { OpenCoreComparison } from "./OpenCoreComparison";

export interface PublicLandingViewProps {
  /** When opened inside an authenticated session for demo walkthroughs, shows a button to return to the live Control Room. */
  isAuthenticated?: boolean;
  onReturnToConsole?: () => void;
}

export function PublicLandingView({
  isAuthenticated = false,
  onReturnToConsole,
}: PublicLandingViewProps) {
  const [waitlistOpen, setWaitlistOpen] = useState(false);

  return (
    <div className="rh-dark min-h-screen w-full overflow-x-hidden bg-control-base text-rh-text">
      {/* Top Executive Navigation */}
      <header className="sticky top-0 z-30 border-b border-control-border bg-rh-chrome/85 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-control-crimsonBright to-control-crimsonDeep text-white shadow-rh-crimson ring-1 ring-control-borderStrong">
              <Hand className="h-4 w-4" />
            </div>
            <div>
              <span className="text-base font-bold tracking-tight text-rh-text">RedHand</span>
              <span className="ml-2 hidden rounded-full border border-control-border bg-rh-subtle px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-rh-text-2 sm:inline-block">
                Open-Core Security
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <a
              href="https://github.com/iqbalassyraf/redhand"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden h-9 items-center gap-1.5 rounded-full border border-control-border bg-rh-subtle px-3.5 text-xs font-semibold text-rh-text-2 transition-colors hover:border-control-borderStrong hover:text-rh-text sm:inline-flex"
            >
              <span>GitHub</span>
              <ExternalLink className="h-3 w-3" />
            </a>

            {isAuthenticated && onReturnToConsole ? (
              <button
                type="button"
                onClick={onReturnToConsole}
                className="inline-flex h-9 items-center gap-1.5 rounded-full border border-control-borderStrong bg-rh-elevated px-4 text-xs font-semibold text-rh-text transition-colors hover:bg-control-glassHover"
              >
                <span>Back to Control Room</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            ) : (
              <Link
                href="/login"
                className="inline-flex h-9 items-center gap-1.5 rounded-full border border-control-borderStrong bg-rh-elevated px-4 text-xs font-semibold text-rh-text transition-colors hover:bg-control-glassHover"
              >
                <span>Console Sign In</span>
              </Link>
            )}

            <button
              type="button"
              onClick={() => setWaitlistOpen(true)}
              className="inline-flex h-9 items-center gap-1.5 rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-4 text-xs font-semibold text-white shadow-rh-crimson transition hover:brightness-110"
            >
              <span>Request Early Access</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="mx-auto flex max-w-6xl flex-col gap-12 px-4 py-10 sm:px-6 sm:py-14">
        {/* Hero Section (5-second executive clarity) */}
        <section className="flex flex-col items-start justify-between gap-8 lg:flex-row lg:items-center">
          <div className="max-w-2xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-control-crimsonBorder bg-control-crimsonSoft px-3 py-1 text-[11px] font-semibold text-rh-crimson-text">
              <ShieldCheck className="h-3.5 w-3.5" />
              <span>Agent Passports · Inline MCP Gateway · Sub-2s Kill Switch</span>
            </div>

            <h1 className="mt-4 text-3xl font-bold tracking-tight text-rh-text sm:text-4xl lg:text-[42px] lg:leading-[1.12]">
              Runtime Security &amp; Least-Privilege Control for AI Agents.
            </h1>

            <p className="mt-4 text-sm leading-relaxed text-rh-text-2 sm:text-base">
              RedHand sits inline between your autonomous agents and their MCP tools. Stop prompt
              injection, unpinned tool poisoning, and runaway loops in milliseconds—without putting
              an LLM on the hot path.
            </p>

            <div className="mt-6 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => setWaitlistOpen(true)}
                className="inline-flex h-10 items-center gap-2 rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-6 text-xs font-semibold text-white shadow-rh-crimson transition hover:brightness-110"
              >
                <span>Request Early Access</span>
                <ArrowRight className="h-4 w-4" />
              </button>

              {isAuthenticated && onReturnToConsole ? (
                <button
                  type="button"
                  onClick={onReturnToConsole}
                  className="inline-flex h-10 items-center gap-2 rounded-full border border-control-borderStrong bg-rh-elevated px-5 text-xs font-semibold text-rh-text transition-colors hover:bg-control-glassHover"
                >
                  <Terminal className="h-3.5 w-3.5 text-rh-teal-text" />
                  <span>Open Live Control Room</span>
                </button>
              ) : (
                <Link
                  href="/login"
                  className="inline-flex h-10 items-center gap-2 rounded-full border border-control-borderStrong bg-rh-elevated px-5 text-xs font-semibold text-rh-text transition-colors hover:bg-control-glassHover"
                >
                  <Terminal className="h-3.5 w-3.5 text-rh-teal-text" />
                  <span>Launch Console Demo</span>
                </Link>
              )}
            </div>
          </div>

          {/* Right Quick Proof Card */}
          <div className="rh-glass w-full max-w-md rounded-rh-xl border border-control-border p-5 shadow-rh-glass">
            <div className="flex items-center justify-between border-b border-control-border pb-3">
              <span className="text-xs font-bold uppercase tracking-wider text-rh-text-2">
                Gateway Guarantee
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-rh-teal-border bg-rh-teal-wash px-2 py-0.5 font-mono text-[10px] font-semibold text-rh-teal-text">
                FAIL-CLOSED
              </span>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-3">
              <div className="rounded-rh-md border border-control-border bg-rh-subtle p-3">
                <div className="font-mono text-lg font-bold text-rh-teal-text">&lt;2ms</div>
                <div className="mt-0.5 text-[11px] font-medium text-rh-text-2">
                  Deterministic pre-flight AST &amp; regex checks
                </div>
              </div>
              <div className="rounded-rh-md border border-control-border bg-rh-subtle p-3">
                <div className="font-mono text-lg font-bold text-rh-steel-text">&lt;15ms</div>
                <div className="mt-0.5 text-[11px] font-medium text-rh-text-2">
                  Local ONNX / DeBERTa semantic firewall
                </div>
              </div>
              <div className="rounded-rh-md border border-control-border bg-rh-subtle p-3">
                <div className="font-mono text-lg font-bold text-rh-ochre">60s</div>
                <div className="mt-0.5 text-[11px] font-medium text-rh-text-2">
                  Turn-scoped AWS / GCP / Entra IAM TTL
                </div>
              </div>
              <div className="rounded-rh-md border border-control-border bg-rh-subtle p-3">
                <div className="font-mono text-lg font-bold text-rh-crimson-text">&le;2s</div>
                <div className="mt-0.5 text-[11px] font-medium text-rh-text-2">
                  Global Passport freeze &amp; kill switch
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Two-Tier Open-Core Architecture Comparison */}
        <OpenCoreComparison onRequestEarlyAccess={() => setWaitlistOpen(true)} />

        {/* Security Boundary Footnote */}
        <footer className="flex flex-wrap items-center justify-between gap-4 border-t border-control-border pt-6 text-xs text-rh-text-2">
          <div className="flex items-center gap-2">
            <Lock className="h-3.5 w-3.5 text-rh-text-muted" />
            <span>
              RedHand controls agents connected through the RedHand Gateway. No raw credentials
              stored in control-plane logs.
            </span>
          </div>
          <div className="flex items-center gap-4">
            <a
              href="https://github.com/iqbalassyraf/redhand"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-rh-text"
            >
              Apache 2.0 Core
            </a>
            <button
              type="button"
              onClick={() => setWaitlistOpen(true)}
              className="font-semibold text-rh-ochre hover:underline"
            >
              Join Design Partner Waitlist
            </button>
          </div>
        </footer>
      </main>

      <EarlyAccessModal
        open={waitlistOpen}
        onClose={() => setWaitlistOpen(false)}
        sourceLabel="Public Architecture Page"
      />
    </div>
  );
}
