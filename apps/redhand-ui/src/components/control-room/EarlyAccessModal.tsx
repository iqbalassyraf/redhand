"use client";

import React, { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { CheckCircle2, Lock, ShieldCheck, X } from "lucide-react";

import { EASE_OUT_EXPO, MOTION_TIMING, usePrefersReducedMotion } from "@/lib/tokens";

export type EnterpriseInterest =
  | "ephemeral-iam"
  | "cyber-escalation"
  | "siem-intel"
  | "vpc-self-hosted";

export interface EarlyAccessModalProps {
  open: boolean;
  onClose: () => void;
  defaultInterest?: EnterpriseInterest;
  sourceLabel?: string;
}

const INTEREST_OPTIONS: Array<{ id: EnterpriseInterest; label: string; detail: string }> = [
  {
    id: "ephemeral-iam",
    label: "Dynamic Ephemeral IAM Broker",
    detail: "60s turn-scoped AWS STS, GCP IAM & Entra ID tokens",
  },
  {
    id: "cyber-escalation",
    label: "Async Deep Cyber-Model Escalation",
    detail: "BYOK frontier model routing & mid-loop quarantine",
  },
  {
    id: "siem-intel",
    label: "SIEM & STIX/TAXII Threat Intel",
    detail: "OCSF v1.1.0 streaming to Sentinel, Splunk & SecOps",
  },
  {
    id: "vpc-self-hosted",
    label: "In-VPC / Air-Gapped Control Plane",
    detail: "Helm chart, SSO/SCIM 2.0 & dedicated tenant isolation",
  },
];

const STACK_OPTIONS = ["MCP / Claude", "LangGraph", "CrewAI", "n8n", "Custom"] as const;

export function EarlyAccessModal({
  open,
  onClose,
  defaultInterest,
  sourceLabel = "RedHand 10x Enterprise",
}: EarlyAccessModalProps) {
  const [email, setEmail] = useState("");
  const [org, setOrg] = useState("");
  const [stack, setStack] = useState<string>("MCP / Claude");
  const [interests, setInterests] = useState<EnterpriseInterest[]>(
    defaultInterest ? [defaultInterest] : ["ephemeral-iam", "cyber-escalation"]
  );
  const [submitted, setSubmitted] = useState(false);
  const reducedMotion = usePrefersReducedMotion();

  useEffect(() => {
    if (defaultInterest) {
      setInterests((prev) => (prev.includes(defaultInterest) ? prev : [...prev, defaultInterest]));
    }
  }, [defaultInterest]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const toggleInterest = (id: EnterpriseInterest) => {
    setInterests((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const payload = {
        email: email.trim(),
        org: org.trim(),
        stack,
        interests,
        source: sourceLabel,
        submittedAt: new Date().toISOString(),
      };
      window.localStorage.setItem("redhand_design_partner_waitlist", JSON.stringify(payload));
    } catch {
      // Storage unavailable in private mode; continue with UI confirmation.
    }
    setSubmitted(true);
  };

  const handleResetAndClose = () => {
    setSubmitted(false);
    onClose();
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          role="dialog"
          aria-modal="true"
          aria-labelledby="early-access-title"
          initial={reducedMotion ? false : { opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: MOTION_TIMING.fast, ease: EASE_OUT_EXPO }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-rh-scrim p-4 backdrop-blur-sm"
        >
          <motion.div
            initial={reducedMotion ? false : { opacity: 0, y: 12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: 8, scale: 0.98 }}
            transition={{ duration: MOTION_TIMING.normal, ease: EASE_OUT_EXPO }}
            className="rh-glass relative w-full max-w-lg rounded-rh-xl border border-control-borderStrong bg-control-elevated p-6 shadow-rh-glass"
          >
            <button
              type="button"
              onClick={handleResetAndClose}
              aria-label="Close waitlist modal"
              className="absolute right-4 top-4 flex h-8 w-8 items-center justify-center rounded-lg text-rh-text-2 transition-colors hover:bg-control-glassHover hover:text-rh-text"
            >
              <X className="h-4 w-4" />
            </button>

            <AnimatePresence mode="wait">
              {submitted ? (
                <motion.div
                  key="submitted"
                  initial={reducedMotion ? false : { opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: MOTION_TIMING.fast, ease: EASE_OUT_EXPO }}
                  className="flex flex-col items-center py-4 text-center"
                >
                  <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full border border-rh-teal-border bg-rh-teal-wash text-rh-teal-text">
                    <CheckCircle2 className="h-6 w-6" />
                  </div>
                  <h2 id="early-access-title" className="text-lg font-bold text-rh-text">
                    Design Partner Request Recorded
                  </h2>
                  <p className="mt-2 max-w-md text-xs leading-relaxed text-rh-text-2">
                    Thank you — <span className="font-semibold text-rh-text">{email}</span> is queued for{" "}
                    <span className="text-rh-ochre">{sourceLabel}</span> early access. Our engineering team
                    provisions design-partner tenants in weekly cohorts with dedicated onboarding.
                  </p>
                  <div className="mt-5 flex items-center gap-3">
                    <button
                      type="button"
                      onClick={handleResetAndClose}
                      className="inline-flex h-9 items-center rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-5 text-xs font-semibold text-white shadow-rh-crimson transition-colors duration-rh-fast hover:from-control-crimson hover:to-control-crimsonDeep"
                    >
                      Return to Console
                    </button>
                  </div>
                </motion.div>
              ) : (
                <motion.div
                  key="form"
                  initial={reducedMotion ? false : { opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: MOTION_TIMING.fast }}
                >
                  <div className="flex items-center gap-2">
                    <span className="inline-flex items-center gap-1 rounded-full border border-rh-ochre-border bg-rh-ochre-wash px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-rh-ochre">
                      <Lock className="h-3 w-3" />
                      Design Partner Waitlist
                    </span>
                    <span className="text-[11px] text-rh-text-muted">{sourceLabel}</span>
                  </div>

                  <h2 id="early-access-title" className="mt-2.5 text-lg font-bold tracking-tight text-rh-text">
                    Request Early Access to 10x Enterprise Native
                  </h2>
                  <p className="mt-1 text-xs leading-relaxed text-rh-text-2">
                    Deploy ephemeral 60s cloud IAM, async cyber-model escalation, and SIEM threat feeds
                    without adding latency to your Open-Source Core gateway.
                  </p>

                  <form onSubmit={handleSubmit} className="mt-4 flex flex-col gap-3.5">
                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                      <div>
                        <label htmlFor="waitlist-email" className="block text-[11px] font-semibold text-rh-text-2">
                          Work Email
                        </label>
                        <input
                          id="waitlist-email"
                          type="email"
                          required
                          placeholder="ciso@company.com"
                          value={email}
                          onChange={(e) => setEmail(e.target.value)}
                          className="mt-1 h-9 w-full rounded-rh-sm border border-control-border bg-rh-subtle px-3 text-xs text-rh-text placeholder:text-rh-text-muted focus:border-control-crimson focus:outline-none"
                        />
                      </div>
                      <div>
                        <label htmlFor="waitlist-org" className="block text-[11px] font-semibold text-rh-text-2">
                          Organization
                        </label>
                        <input
                          id="waitlist-org"
                          type="text"
                          required
                          placeholder="Acme Security"
                          value={org}
                          onChange={(e) => setOrg(e.target.value)}
                          className="mt-1 h-9 w-full rounded-rh-sm border border-control-border bg-rh-subtle px-3 text-xs text-rh-text placeholder:text-rh-text-muted focus:border-control-crimson focus:outline-none"
                        />
                      </div>
                    </div>

                    <div>
                      <label htmlFor="waitlist-stack" className="block text-[11px] font-semibold text-rh-text-2">
                        Primary Agent Stack
                      </label>
                      <select
                        id="waitlist-stack"
                        value={stack}
                        onChange={(e) => setStack(e.target.value)}
                        className="mt-1 h-9 w-full rounded-rh-sm border border-control-border bg-rh-subtle px-3 text-xs text-rh-text focus:border-control-crimson focus:outline-none"
                      >
                        {STACK_OPTIONS.map((opt) => (
                          <option key={opt} value={opt}>
                            {opt}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <span className="block text-[11px] font-semibold text-rh-text-2">
                        Enterprise Capabilities Needed
                      </span>
                      <div className="mt-1.5 grid grid-cols-1 gap-2 sm:grid-cols-2">
                        {INTEREST_OPTIONS.map((opt) => {
                          const checked = interests.includes(opt.id);
                          return (
                            <button
                              key={opt.id}
                              type="button"
                              onClick={() => toggleInterest(opt.id)}
                              className={`flex flex-col rounded-rh-sm border px-2.5 py-2 text-left transition-colors duration-rh-fast ${
                                checked
                                  ? "border-rh-ochre-border bg-rh-ochre-wash text-rh-text"
                                  : "border-control-border bg-rh-subtle text-rh-text-2 hover:border-control-borderStrong"
                              }`}
                            >
                              <span className="text-[11px] font-semibold text-rh-text">{opt.label}</span>
                              <span className="mt-0.5 text-[10px] text-rh-text-muted">{opt.detail}</span>
                            </button>
                          );
                        })}
                      </div>
                    </div>

                    <div className="mt-2 flex items-center justify-between gap-3 border-t border-control-border pt-3">
                      <span className="flex items-center gap-1.5 text-[11px] text-rh-text-muted">
                        <ShieldCheck className="h-3.5 w-3.5 text-rh-teal-text" />
                        No pricing commitments yet · Early access cohort
                      </span>
                      <button
                        type="submit"
                        className="inline-flex h-9 shrink-0 items-center gap-1.5 rounded-full bg-gradient-to-r from-control-crimsonDeep to-control-crimson px-5 text-xs font-semibold text-white shadow-rh-crimson transition-colors duration-rh-fast hover:from-control-crimson hover:to-control-crimsonDeep"
                      >
                        Join Waitlist
                      </button>
                    </div>
                  </form>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
