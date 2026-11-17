/**
 * Onboarding helpers (Phase 4.5 D1): pure functions and fixed texts for creating an organization with a sign-up code, joining with an invite link,
 * and managing the team. redhand-core authorizes every action; nothing here is a security boundary, it only keeps the screens honest and the forms tidy.
 */

export const CODE_PATTERN = /^rh_inv_[A-Za-z0-9_-]{20,64}$/;
export const INVITE_PATTERN = /^rh_join_[A-Za-z0-9_-]{20,64}$/;
export const PENDING_INVITE_KEY = "redhand.pending-invite";

export type Role = "owner" | "admin" | "security_operator" | "viewer";
export const ROLE_RANK: Record<Role, number> = { viewer: 1, security_operator: 2, admin: 3, owner: 4 };
export const ROLE_LABEL: Record<Role, string> = { owner: "Owner", admin: "Admin", security_operator: "Security operator", viewer: "Viewer" };
export const ROLE_HELP: Record<Role, string> = {
  viewer: "Sees agents, spend and the audit log. Cannot change anything.",
  security_operator: "Investigates and stops: freeze, unfreeze, Radar, timelines. Cannot issue credentials or change settings.",
  admin: "Everything above, plus registering agents, issuing keys, scopes, settings and the team.",
  owner: "Everything, including making other owners. An organization always keeps at least one owner.",
};

export const CREATE_TEXT = {
  title: "Create your organization",
  intro: "RedHand is invite-only for now. Paste the sign-up code you were given. You become the owner of the new organization.",
  noOrganization: "This account does not belong to an organization yet.",
  refused: "That sign-up code cannot be used. It may be wrong, already used or expired.",
};
export const JOIN_TEXT = {
  title: "Join an organization",
  intro: "You were invited to an organization. Accepting adds this account to it at the role the invite names.",
  signInFirst: "Sign in or create an account first. Your invite will be waiting.",
  refused: "That invite cannot be used. It may be wrong, already used, revoked or expired.",
};
export const INVITE_SHOWN_TEXT = "Copy this link now. It will not be shown again: RedHand keeps only a hash. Anyone who has it can join at this role until it is used, revoked or expires, so send it privately.";
export const LAST_OWNER_TEXT = "An organization always keeps at least one owner.";
export const TEAM_TEXT = "Invite links are single-use and expire. You can grant a role up to your own; only an owner can make another owner.";

export function parseCode(value: string): string | "invalid" {
  const trimmed = value.trim();
  return CODE_PATTERN.test(trimmed) ? trimmed : "invalid";
}

export function parseInviteToken(value: string | null | undefined): string | "invalid" {
  const trimmed = (value ?? "").trim();
  return INVITE_PATTERN.test(trimmed) ? trimmed : "invalid";
}

export function parseOrgName(value: string): string | "invalid" {
  const trimmed = value.trim();
  return trimmed.length >= 1 && trimmed.length <= 100 ? trimmed : "invalid";
}

/** The token inside an invite link or a bare token someone pasted ("https://app/join?token=rh_join_..." or "rh_join_..."). */
export function tokenFromPasted(value: string): string | "invalid" {
  const text = value.trim();
  const fromQuery = /[?&]token=([^&#\s]+)/.exec(text);
  return parseInviteToken(fromQuery ? decodeURIComponent(fromQuery[1]) : text);
}

export function isAdmin(role: string | null | undefined): boolean {
  return role !== null && role !== undefined && (ROLE_RANK as Record<string, number>)[role] >= ROLE_RANK.admin;
}

export function isSecurityOperator(role: string | null | undefined): boolean {
  return role !== null && role !== undefined && (ROLE_RANK as Record<string, number>)[role] >= ROLE_RANK.security_operator;
}

/** Roles the signed-in person may give: up to their own. Owner is offered only to an owner. */
export function grantableRoles(own: string | null | undefined): Role[] {
  if (own === null || own === undefined || !(own in ROLE_RANK)) return [];
  const rank = ROLE_RANK[own as Role];
  if (rank < ROLE_RANK.admin) return [];
  return (Object.keys(ROLE_RANK) as Role[]).filter((r) => ROLE_RANK[r] <= rank).sort((a, b) => ROLE_RANK[a] - ROLE_RANK[b]);
}

/** Roles an invite can carry: never owner. */
export function invitableRoles(own: string | null | undefined): Role[] {
  return grantableRoles(own).filter((r) => r !== "owner");
}

/** Whether the person may change or remove this member: admin or owner, and not someone above them. */
export function canManageMember(own: string | null | undefined, target: Role): boolean {
  if (!isAdmin(own)) return false;
  return ROLE_RANK[own as Role] >= ROLE_RANK[target];
}

export function inviteStateLabel(state: string): string {
  return { pending: "Waiting", used: "Used", revoked: "Revoked", expired: "Expired" }[state] ?? state;
}

export function joinUrl(origin: string, joinPath: string): string {
  return `${origin.replace(/\/+$/, "")}${joinPath}`;
}

/** "Not a member of any organization" from core means: send the person to the create-or-join screen. */
export function isNoOrganizationMessage(message: string): boolean {
  return /not a member/i.test(message);
}
