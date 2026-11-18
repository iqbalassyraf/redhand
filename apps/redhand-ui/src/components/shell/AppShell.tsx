"use client";

/**
 * The dashboard frame: a pine-slate rail on the left (a top bar with a menu on phones), a header band with the page title, the
 * organization and role, and sign-out. Pages render their own content inside it. Which links show is a convenience; core authorizes
 * every request (CLAUDE.md section 6.4).
 */

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Archive, Building2, Hand, IdCard, KeyRound, LayoutDashboard, LogOut, Menu, Radar, ScanSearch, ShieldCheck, X } from "lucide-react";

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
};

interface AppShellProps {
  title: string;
  /** Organization name and role, once known (`GET /v1/me`). */
  organization?: string | null;
  role?: string | null;
  actions?: React.ReactNode;
  children: React.ReactNode;
}

function NavLinks({ active, onNavigate }: { active: string | null; onNavigate?: () => void }) {
  return (
    <nav aria-label="Main" className="flex flex-col gap-1">
      {NAV_ITEMS.map((item) => {
        const Icon = ICONS[item.icon];
        const isActive = item.href === active;
        return (
          <Link
            key={item.href}
            href={item.href}
            onClick={onNavigate}
            aria-current={isActive ? "page" : undefined}
            className={`relative flex items-center gap-3 rounded-[8px] px-3 py-2 text-[13px] font-medium ${
              isActive ? "bg-rh-chrome-active text-rh-text" : "text-rh-text-2 hover:bg-rh-chrome-hover hover:text-rh-text"
            }`}
          >
            {isActive && <span aria-hidden className="absolute inset-y-1.5 left-0 w-[2px] rounded-full bg-rh-teal" />}
            <Icon className="h-4 w-4 shrink-0" />
            <span>{item.label}</span>
          </Link>
        );
      })}
    </nav>
  );
}

export function AppShell({ title, organization, role, actions, children }: AppShellProps) {
  const pathname = usePathname() ?? "/";
  const { session, signOut } = useAuth();
  const [open, setOpen] = useState(false);
  const active = activeNavHref(pathname);
  const who = [session?.email, organization, roleLabel(role ?? session?.role)].filter(Boolean).join(" · ");

  const doSignOut = () => {
    signOut();
    window.location.href = "/login";
  };

  return (
    <div className="rh-dark min-h-screen lg:flex">
      <aside className="hidden w-[220px] shrink-0 flex-col justify-between border-r border-rh-chrome-border bg-rh-chrome px-3 py-4 lg:flex">
        <div className="flex flex-col gap-6">
          <Link href="/" className="flex items-center gap-2 px-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-[8px] bg-rh-chrome-active">
              <Hand className="h-4 w-4 text-rh-text" />
            </span>
            <span className="text-[16px] font-semibold tracking-tight text-rh-text">RedHand</span>
          </Link>
          <NavLinks active={active} />
        </div>
        <button
          onClick={doSignOut}
          className="flex items-center gap-3 rounded-[8px] px-3 py-2 text-[13px] font-medium text-rh-text-2 hover:bg-rh-chrome-hover hover:text-rh-text"
        >
          <LogOut className="h-4 w-4" /> Sign out
        </button>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-[56px] items-center justify-between gap-3 border-b border-rh-chrome-border bg-rh-chrome px-4">
          <div className="flex min-w-0 items-center gap-3">
            <button
              aria-label={open ? "Close menu" : "Open menu"}
              aria-expanded={open}
              onClick={() => setOpen((v) => !v)}
              className="rounded-[8px] p-1.5 text-rh-text-2 hover:bg-rh-chrome-hover lg:hidden"
            >
              {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
            <h1 className="truncate text-[18px] font-semibold tracking-tight text-rh-text">{title}</h1>
          </div>
          <div className="flex min-w-0 items-center gap-3 text-[12px] text-rh-text-2">
            <span className="hidden truncate md:inline">{who}</span>
            {actions}
          </div>
        </header>

        {open && (
          <div className="border-b border-rh-chrome-border bg-rh-chrome px-3 py-3 lg:hidden">
            <NavLinks active={active} onNavigate={() => setOpen(false)} />
            <button
              onClick={doSignOut}
              className="mt-2 flex w-full items-center gap-3 rounded-[8px] px-3 py-2 text-[13px] font-medium text-rh-text-2 hover:bg-rh-chrome-hover"
            >
              <LogOut className="h-4 w-4" /> Sign out
            </button>
          </div>
        )}

        <main className="mx-auto w-full max-w-[1280px] flex-1 bg-rh-canvas px-4 py-6">{children}</main>
      </div>
    </div>
  );
}
