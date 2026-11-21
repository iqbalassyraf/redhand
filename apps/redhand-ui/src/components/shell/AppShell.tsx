"use client";

/**
 * The dashboard frame: a floating Dark Navy Glass + Crimson left IconRail (with tooltips, and a top header + collapsible drawer
 * on phones), a glass header band with the page title, organization and role, and sign-out. Pages render their own content inside it.
 * Which links show is a convenience; core authorizes every request (CLAUDE.md section 6.4).
 */

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Archive,
  Building2,
  Cpu,
  Hand,
  IdCard,
  KeyRound,
  LayoutDashboard,
  Lock,
  LogOut,
  Menu,
  Radar,
  Radio,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";

import { useAuth } from "@/lib/auth";
import { activeNavHref, NAV_ITEMS, roleLabel, type NavItem } from "@/lib/nav";

const ICONS: Record<NavItem["icon"], React.ComponentType<{ className?: string }>> = {
  insights: LayoutDashboard,
  passports: IdCard,
  blackbox: Archive,
  radar: Radar,
  scanner: ScanSearch,
  honeytokens: KeyRound,
  coverage: ShieldCheck,
  organization: Building2,
  ephemeral_iam: Lock,
  cyber_escalation: Cpu,
  siem_intel: Radio,
};

interface AppShellProps {
  title: string;
  /** Organization name and role, once known (`GET /v1/me`). */
  organization?: string | null;
  role?: string | null;
  actions?: React.ReactNode;
  children: React.ReactNode;
}

const TOOLTIP_CLASS =
  "pointer-events-none absolute left-[calc(100%+12px)] top-1/2 z-50 -translate-y-1/2 flex items-center gap-2 whitespace-nowrap rounded-rh-sm border border-control-borderStrong bg-control-elevated px-3 py-1.5 text-xs font-semibold text-rh-text shadow-rh-glass";

function MobileNavLinks({ active, onNavigate }: { active: string | null; onNavigate?: () => void }) {
  const coreItems = NAV_ITEMS.filter((i) => i.tier !== "enterprise");
  const enterpriseItems = NAV_ITEMS.filter((i) => i.tier === "enterprise");

  const renderItem = (item: NavItem) => {
    const Icon = ICONS[item.icon];
    const isActive = item.href === active;
    return (
      <Link
        key={item.href}
        href={item.href}
        onClick={onNavigate}
        aria-current={isActive ? "page" : undefined}
        className={`relative flex items-center justify-between gap-2 rounded-rh-sm px-3 py-2 text-[13px] font-medium transition-colors duration-rh-fast ${
          isActive
            ? "border border-control-crimsonBorder bg-control-crimsonSoft text-rh-text"
            : "text-rh-text-2 hover:bg-control-glassHover hover:text-rh-text"
        }`}
      >
        {isActive && <span aria-hidden className="absolute inset-y-1.5 left-0 w-[2px] rounded-full bg-control-crimsonBright" />}
        <span className="flex items-center gap-3">
          <Icon className="h-4 w-4 shrink-0" />
          <span>{item.label}</span>
        </span>
        {item.badge && (
          <span className="rounded-full border border-rh-ochre-border bg-rh-ochre-wash px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-rh-ochre">
            {item.badge}
          </span>
        )}
      </Link>
    );
  };

  return (
    <nav aria-label="Main" className="flex flex-col gap-1">
      {coreItems.map(renderItem)}
      <div className="my-1.5 flex items-center gap-2 px-3">
        <div className="h-px flex-1 bg-control-border" />
        <span className="text-[9px] font-bold uppercase tracking-widest text-rh-ochre">Enterprise</span>
        <div className="h-px flex-1 bg-control-border" />
      </div>
      {enterpriseItems.map(renderItem)}
    </nav>
  );
}

export function AppShell({ title, organization, role, actions, children }: AppShellProps) {
  const pathname = usePathname() ?? "/";
  const { session, signOut } = useAuth();
  const [open, setOpen] = useState(false);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const active = activeNavHref(pathname);
  const who = [session?.email, organization, roleLabel(role ?? session?.role)].filter(Boolean).join(" · ");

  const doSignOut = () => {
    signOut("/login");
  };

  return (
    <div className="rh-dark min-h-screen lg:flex lg:gap-3 lg:p-3">
      <aside
        aria-label="Primary navigation"
        className="rh-glass sticky top-3 z-30 hidden h-[calc(100vh-24px)] w-[64px] shrink-0 flex-col items-center justify-between rounded-rh-xl py-3.5 lg:flex"
      >
        <div className="flex w-full flex-col items-center gap-4">
          <div className="relative">
            <Link
              href="/"
              aria-label="RedHand Control Room"
              onMouseEnter={() => setHoveredId("brand")}
              onMouseLeave={() => setHoveredId((prev) => (prev === "brand" ? null : prev))}
              onFocus={() => setHoveredId("brand")}
              onBlur={() => setHoveredId((prev) => (prev === "brand" ? null : prev))}
              className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-control-crimsonBright to-control-crimsonDeep text-white shadow-rh-crimson ring-1 ring-control-borderStrong transition-transform duration-rh-fast ease-rh-out hover:scale-105"
            >
              <Hand className="h-5 w-5" />
            </Link>
            {hoveredId === "brand" && (
              <div role="tooltip" className={TOOLTIP_CLASS}>
                RedHand Control Room
              </div>
            )}
          </div>

          <nav aria-label="Main" className="flex w-full flex-col items-center gap-1.5 px-2">
            {NAV_ITEMS.map((item, idx) => {
              const Icon = ICONS[item.icon];
              const isActive = item.href === active;
              const isFirstEnterprise = item.tier === "enterprise" && NAV_ITEMS[idx - 1]?.tier !== "enterprise";
              return (
                <React.Fragment key={item.href}>
                  {isFirstEnterprise && <div className="my-1 h-px w-8 bg-control-border" role="separator" />}
                  <div className="relative flex w-full justify-center">
                    <Link
                      href={item.href}
                      aria-label={item.label}
                      aria-current={isActive ? "page" : undefined}
                      onMouseEnter={() => setHoveredId(item.href)}
                      onMouseLeave={() => setHoveredId((prev) => (prev === item.href ? null : prev))}
                      onFocus={() => setHoveredId(item.href)}
                      onBlur={() => setHoveredId((prev) => (prev === item.href ? null : prev))}
                      className={`relative flex h-10 w-10 items-center justify-center rounded-xl transition-colors duration-rh-fast ${
                        isActive
                          ? "border border-control-crimsonBorder bg-control-crimsonSoft text-rh-text shadow-rh-crimson"
                          : "text-rh-text-2 hover:bg-control-glassHover hover:text-rh-text"
                      }`}
                    >
                      <Icon className="h-[18px] w-[18px]" />
                      {item.badge && (
                        <span
                          aria-hidden
                          className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-rh-ochre"
                        />
                      )}
                    </Link>
                    {hoveredId === item.href && (
                      <div role="tooltip" className={TOOLTIP_CLASS}>
                        <span>{item.label}</span>
                        {item.badge && (
                          <span className="rounded-full border border-rh-ochre-border bg-rh-ochre-wash px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-rh-ochre">
                            {item.badge}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </React.Fragment>
              );
            })}
          </nav>
        </div>

        <div className="relative flex w-full justify-center px-2">
          <button
            type="button"
            onClick={doSignOut}
            aria-label="Sign out"
            onMouseEnter={() => setHoveredId("signout")}
            onMouseLeave={() => setHoveredId((prev) => (prev === "signout" ? null : prev))}
            onFocus={() => setHoveredId("signout")}
            onBlur={() => setHoveredId((prev) => (prev === "signout" ? null : prev))}
            className="flex h-10 w-10 items-center justify-center rounded-xl text-rh-text-2 transition-colors duration-rh-fast hover:bg-control-crimsonSoft hover:text-rh-crimson-text"
          >
            <LogOut className="h-4 w-4" />
            <span className="sr-only">Sign out</span>
          </button>
          {hoveredId === "signout" && (
            <div role="tooltip" className={TOOLTIP_CLASS}>
              Sign out
            </div>
          )}
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col gap-4 p-3 lg:p-0">
        <header className="rh-glass relative z-20 flex min-h-[58px] w-full flex-wrap items-center justify-between gap-3 rounded-rh-xl px-4 py-2">
          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              aria-label={open ? "Close menu" : "Open menu"}
              aria-expanded={open}
              onClick={() => setOpen((v) => !v)}
              className="rounded-rh-sm p-1.5 text-rh-text-2 transition-colors hover:bg-control-glassHover hover:text-rh-text lg:hidden"
            >
              {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
            <Link
              href="/"
              aria-label="RedHand Control Room"
              className="flex h-7 w-7 items-center justify-center rounded-lg bg-gradient-to-br from-control-crimsonBright to-control-crimsonDeep text-white shadow-rh-crimson lg:hidden"
            >
              <Hand className="h-4 w-4" />
            </Link>
            <h1 className="truncate text-[18px] font-semibold tracking-tight text-rh-text">{title}</h1>
          </div>
          <div className="flex min-w-0 items-center gap-3 text-[12px] text-rh-text-2">
            {who && <span className="hidden truncate md:inline">{who}</span>}
            {actions}
          </div>
        </header>

        {open && (
          <div className="rh-glass rounded-rh-xl p-3 lg:hidden">
            <MobileNavLinks active={active} onNavigate={() => setOpen(false)} />
            <button
              type="button"
              onClick={doSignOut}
              className="mt-2 flex w-full items-center gap-3 rounded-rh-sm px-3 py-2 text-[13px] font-medium text-rh-text-2 transition-colors hover:bg-control-crimsonSoft hover:text-rh-crimson-text"
            >
              <LogOut className="h-4 w-4" /> Sign out
            </button>
          </div>
        )}

        <main className="mx-auto w-full max-w-[1280px] flex-1 px-1 py-2">{children}</main>
      </div>
    </div>
  );
}
