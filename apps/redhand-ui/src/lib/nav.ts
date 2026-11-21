/**
 * The dashboard's navigation, in one place. Which items a role sees is a convenience only: core authorizes every request, and a page
 * still explains itself if its role cannot use it (the UI is never a security boundary, CLAUDE.md section 6.4).
 */

export type Role = "owner" | "admin" | "security_operator" | "viewer";

export interface NavItem {
  href: string;
  label: string;
  icon:
    | "insights"
    | "passports"
    | "blackbox"
    | "radar"
    | "scanner"
    | "honeytokens"
    | "coverage"
    | "organization"
    | "ephemeral_iam"
    | "cyber_escalation"
    | "siem_intel";
  tier?: "core" | "enterprise";
  badge?: "PREVIEW" | "ENTERPRISE";
}

export const NAV_ITEMS: readonly NavItem[] = [
  { href: "/", label: "Insights", icon: "insights", tier: "core" },
  { href: "/passports", label: "Passports", icon: "passports", tier: "core" },
  { href: "/blackbox", label: "Black Box", icon: "blackbox", tier: "core" },
  { href: "/radar", label: "Radar", icon: "radar", tier: "core" },
  { href: "/scanner", label: "MCP Scanner", icon: "scanner", tier: "core" },
  { href: "/honeytokens", label: "Honeytokens", icon: "honeytokens", tier: "core" },
  { href: "/coverage", label: "Coverage", icon: "coverage", tier: "core" },
  { href: "/organization", label: "Organization", icon: "organization", tier: "core" },
  { href: "/ephemeral-iam", label: "Ephemeral IAM", icon: "ephemeral_iam", tier: "enterprise", badge: "ENTERPRISE" },
  { href: "/cyber-escalation", label: "Cyber-Model Escalation", icon: "cyber_escalation", tier: "enterprise", badge: "PREVIEW" },
  { href: "/siem-intel", label: "SIEM & Threat Intel", icon: "siem_intel", tier: "enterprise", badge: "ENTERPRISE" },
];

/** The nav item for a pathname: the longest href that is the path or a parent of it ("/" only matches exactly). */
export function activeNavHref(pathname: string): string | null {
  let best: string | null = null;
  for (const item of NAV_ITEMS) {
    const hit = item.href === "/" ? pathname === "/" : pathname === item.href || pathname.startsWith(`${item.href}/`);
    if (hit && (best === null || item.href.length > best.length)) best = item.href;
  }
  return best;
}

export function roleLabel(role: string | null | undefined): string {
  return role ? role.replace("_", " ") : "";
}
