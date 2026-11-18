/**
 * Small building blocks for the Dark Navy Glass + Crimson dashboard. Translucent glass surfaces with 1px hairline borders,
 * subtle backdrop blur, and crimson primary/danger CTAs. Every value shown here comes from a caller; nothing is rendered as HTML
 * (CLAUDE.md section 5.4).
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
const CHIP_BORDER: Record<Tone, string> = {
  teal: "border-control-border",
  steel: "border-control-steelBorder",
  ochre: "border-control-ochreBorder",
  crimson: "border-control-crimsonBorder",
  purple: "border-control-border",
  neutral: "border-control-border",
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
    <section className={`rh-glass rounded-rh-lg p-4 ${className}`}>
      {(title || actions) && (
        <div className="mb-3 flex items-start justify-between gap-3">
          <div className="min-w-0">
            {title && <h2 className="text-[13px] font-semibold tracking-tight text-rh-text">{title}</h2>}
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
    <div className="rh-glass rounded-rh-md px-4 py-3">
      <div className="flex items-center gap-2 text-[11px] font-medium tracking-wide text-rh-text-2">
        {tone && <span aria-hidden className={`inline-block h-2 w-2 shrink-0 rounded-[3px] ${DOT[tone]}`} />}
        {label}
      </div>
      <div className="rh-tabular mt-1.5 text-[24px] font-semibold leading-none tracking-tight text-rh-text">{value}</div>
      {note && <div className="mt-1.5 text-[12px] text-rh-text-2">{note}</div>}
    </div>
  );
}

/** A status chip: primary text on a wash with a coloured dot (the accent colours alone are below 4.5:1 on their washes). */
export function Chip({ tone = "neutral", children }: { tone?: Tone; children: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium text-rh-text backdrop-blur-md ${WASH[tone]} ${CHIP_BORDER[tone]}`}>
      <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${DOT[tone]}`} />
      {children}
    </span>
  );
}

const BUTTON: Record<"primary" | "secondary" | "danger", string> = {
  primary: "bg-gradient-to-r from-control-crimsonDeep to-control-crimson text-white shadow-rh-crimson ring-1 ring-control-borderStrong hover:to-control-crimsonDeep active:scale-[0.98]",
  secondary: "border border-control-borderStrong bg-control-glass text-rh-text backdrop-blur-md hover:bg-control-glassHover",
  danger: "border border-control-crimsonBorder bg-control-crimsonSoft text-rh-crimson-text hover:bg-control-crimsonDeep hover:text-white",
};

export function Button({ variant = "secondary", className = "", ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" }) {
  return (
    <button
      {...rest}
      className={`inline-flex items-center justify-center gap-1.5 rounded-rh-sm px-3 py-1.5 text-[13px] font-medium transition-[background-color,border-color,transform,filter] duration-rh-fast ease-rh-out disabled:cursor-not-allowed disabled:opacity-50 ${BUTTON[variant]} ${className}`}
    />
  );
}

export function EmptyState({ title, detail }: { title: string; detail?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 rounded-rh-md border border-dashed border-control-borderStrong bg-control-elevated px-4 py-8 text-center">
      <p className="text-[13px] font-medium text-rh-text">{title}</p>
      {detail && <p className="text-[12px] text-rh-text-2">{detail}</p>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-center justify-between gap-3 rounded-rh-md border border-control-crimsonBorder bg-control-crimsonSoft px-4 py-3 text-[13px] text-rh-text shadow-rh-crimson backdrop-blur-md">
      <span>{message}</span>
      {onRetry && <Button onClick={onRetry}>Try again</Button>}
    </div>
  );
}
