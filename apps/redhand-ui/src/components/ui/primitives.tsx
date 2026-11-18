/**
 * Small building blocks for the Matte Executive Dark dashboard. Flat surfaces, 1px hairline borders, no shadows, glow or gradients.
 * Every value shown here comes from a caller; nothing is rendered as HTML (CLAUDE.md section 5.4).
 */

import React from "react";

export type Tone = "teal" | "steel" | "ochre" | "crimson" | "purple" | "neutral";

const DOT: Record<Tone, string> = {
  teal: "bg-rh-teal",
  steel: "bg-rh-steel",
  ochre: "bg-rh-ochre",
  crimson: "bg-rh-crimson",
  purple: "bg-rh-purple",
  neutral: "bg-rh-text-2",
};
const WASH: Record<Tone, string> = {
  teal: "bg-rh-teal-wash",
  steel: "bg-rh-steel-wash",
  ochre: "bg-rh-ochre-wash",
  crimson: "bg-rh-crimson-wash",
  purple: "bg-rh-purple-wash",
  neutral: "bg-rh-elevated",
};

export function toneClasses(tone: Tone): { dot: string; wash: string } {
  return { dot: DOT[tone], wash: WASH[tone] };
}

export function Card({ title, subtitle, actions, children, className = "" }: {
  title?: string;
  subtitle?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-[10px] border border-rh-hairline bg-rh-card p-4 ${className}`}>
      {(title || actions) && (
        <div className="mb-3 flex items-start justify-between gap-3">
          <div className="min-w-0">
            {title && <h2 className="text-[13px] font-semibold text-rh-text">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-[12px] text-rh-text-2">{subtitle}</p>}
          </div>
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function KpiTile({ label, value, note, tone }: { label: string; value: string; note?: string; tone?: Tone }) {
  return (
    <div className="rounded-[10px] border border-rh-hairline bg-rh-card px-4 py-3">
      <div className="flex items-center gap-1.5 text-[12px] text-rh-text-2">
        {tone && <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${DOT[tone]}`} />}
        {label}
      </div>
      <div className="rh-tabular mt-1 text-[26px] font-semibold leading-none text-rh-text">{value}</div>
      {note && <div className="mt-1.5 text-[12px] text-rh-text-2">{note}</div>}
    </div>
  );
}

/** A status chip: primary text on a wash with a coloured dot (the accent colours alone are below 4.5:1 on their washes). */
export function Chip({ tone = "neutral", children }: { tone?: Tone; children: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium text-rh-text ${WASH[tone]}`}>
      <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${DOT[tone]}`} />
      {children}
    </span>
  );
}

const BUTTON: Record<"primary" | "secondary" | "danger", string> = {
  primary: "bg-rh-teal text-rh-canvas hover:opacity-90",
  secondary: "border border-rh-strong bg-rh-card text-rh-text hover:bg-rh-elevated",
  danger: "border border-rh-crimson bg-rh-crimson-wash text-rh-text hover:bg-rh-crimson hover:text-rh-canvas",
};

export function Button({ variant = "secondary", className = "", ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" }) {
  return (
    <button
      {...rest}
      className={`inline-flex items-center gap-1.5 rounded-[8px] px-3 py-1.5 text-[13px] font-medium disabled:cursor-not-allowed disabled:opacity-50 ${BUTTON[variant]} ${className}`}
    />
  );
}

export function EmptyState({ title, detail }: { title: string; detail?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 rounded-[8px] border border-dashed border-rh-hairline px-4 py-8 text-center">
      <p className="text-[13px] font-medium text-rh-text">{title}</p>
      {detail && <p className="text-[12px] text-rh-text-2">{detail}</p>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-center justify-between gap-3 rounded-[8px] border border-rh-crimson bg-rh-crimson-wash px-4 py-3 text-[13px] text-rh-text">
      <span>{message}</span>
      {onRetry && <Button onClick={onRetry}>Try again</Button>}
    </div>
  );
}
