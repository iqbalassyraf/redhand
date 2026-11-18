"use client";

/**
 * The team (Phase 4.5 D1): members with their roles, and single-use invite links. Admins only (core refuses anyone else). A new invite link is shown exactly
 * once, from the create response held in this component's state; it is never written to storage or logs, and leaving or refreshing the page forgets it.
 */

import React, { useCallback, useEffect, useState } from "react";

import { ApiError, onboardingApi, type TeamInvite, type TeamMember } from "@/lib/api";
import {
  INVITE_SHOWN_TEXT, LAST_OWNER_TEXT, ROLE_HELP, ROLE_LABEL, TEAM_TEXT, canManageMember, grantableRoles, invitableRoles, inviteStateLabel, joinUrl, type Role,
} from "@/lib/onboarding";

const button = "rounded-full border border-rh-hairline bg-rh-card px-3 py-1 text-[12px] font-semibold hover:bg-rh-elevated disabled:opacity-50";

export function TeamCard(props: { token: string; ownRole: string; ownUserId: string; onUnauthorized: () => void }) {
  const { token, ownRole, ownUserId } = props;
  const [members, setMembers] = useState<TeamMember[] | null>(null);
  const [invites, setInvites] = useState<TeamInvite[]>([]);
  const [role, setRole] = useState<Role>("viewer");
  const [days, setDays] = useState("7");
  const [shown, setShown] = useState<{ url: string; role: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const fail = useCallback((err: unknown) => {
    if (err instanceof ApiError && err.status === 401) {
      props.onUnauthorized();
      return;
    }
    setError(err instanceof Error ? err.message : "Something went wrong.");
  }, [props]);

  const load = useCallback(async () => {
    try {
      const [m, i] = await Promise.all([onboardingApi.members(token), onboardingApi.invites(token)]);
      setMembers(m.members);
      setInvites(i.invites);
    } catch (err) {
      fail(err);
    }
  }, [token, fail]);

  useEffect(() => { void load(); }, [load]);

  async function act(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      await load();
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  }

  const days1to30 = /^\d+$/.test(days.trim()) && Number(days) >= 1 && Number(days) <= 30;
  const canInvite = invitableRoles(ownRole).length > 0;
  const pending = invites.filter((i) => i.state === "pending");

  return (
    <section className="rh-glass rounded-rh-md p-4" aria-label="Team">
      <h2 className="text-[15px] font-semibold">Team</h2>
      <p className="mb-3 mt-1 text-[12px] text-rh-text-2">{TEAM_TEXT}</p>
      {error && <div role="alert" className="mb-3 rounded-[8px] bg-rh-crimson-wash p-2 text-[12px] text-rh-crimson-text">{error}</div>}

      {shown && (
        <div role="status" className="mb-3 rounded-[8px] bg-rh-ochre-wash p-3 text-[12px] text-rh-ochre">
          <p>{INVITE_SHOWN_TEXT}</p>
          <p className="mt-1">Role: {shown.role}</p>
          <code className="mt-2 block break-all rounded-[6px] bg-rh-card p-2 font-mono text-[11px] text-rh-text">{shown.url}</code>
          <div className="mt-2 flex gap-2">
            <button className={button} onClick={async () => { await navigator.clipboard.writeText(shown.url).catch(() => undefined); setCopied(true); }}>{copied ? "Copied" : "Copy link"}</button>
            <button className={button} onClick={() => { setShown(null); setCopied(false); }}>Done</button>
          </div>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full min-w-[420px] text-left text-[13px]">
          <thead>
            <tr className="text-[11px] uppercase tracking-wide text-rh-text-2"><th className="p-2">Member</th><th className="p-2">Role</th><th className="p-2" /></tr>
          </thead>
          <tbody>
            {(members ?? []).map((m) => {
              const manage = canManageMember(ownRole, m.role) && m.user_id !== ownUserId;
              return (
                <tr key={m.user_id} className="border-t border-rh-hairline">
                  <td className="p-2">{m.email ?? m.user_id.slice(0, 8)}{m.user_id === ownUserId ? " (you)" : ""}</td>
                  <td className="p-2">
                    {manage ? (
                      <select
                        aria-label={`Role of ${m.email ?? m.user_id}`}
                        className="rounded-[6px] border border-rh-hairline px-2 py-1 text-[12px]"
                        value={m.role}
                        disabled={busy}
                        onChange={(e) => {
                          const next = e.target.value as Role;
                          if (next === "owner" && !window.confirm(`Make ${m.email ?? "this person"} an owner? Owners can do everything, including removing you.`)) return;
                          void act(() => onboardingApi.setRole(token, m.user_id, next, next === "owner"));
                        }}
                      >
                        {grantableRoles(ownRole).map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
                      </select>
                    ) : ROLE_LABEL[m.role]}
                  </td>
                  <td className="p-2 text-right">
                    {manage && (
                      <button
                        className={`${button} text-rh-crimson-text`}
                        disabled={busy}
                        onClick={() => {
                          if (!window.confirm(`Remove ${m.email ?? "this person"} from the organization? They lose access at once. ${m.role === "owner" ? LAST_OWNER_TEXT : ""}`)) return;
                          void act(() => onboardingApi.removeMember(token, m.user_id));
                        }}
                      >
                        Remove
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {canInvite && (
        <form
          className="mt-4 flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (!days1to30) { setError("Days must be a whole number from 1 to 30."); return; }
            void act(async () => {
              const created = await onboardingApi.createInvite(token, { role, expires_in_days: Number(days) });
              setShown({ url: joinUrl(window.location.origin, created.join_path), role: ROLE_LABEL[created.invite.role] });
              setCopied(false);
            });
          }}
        >
          <label className="flex flex-col gap-1 text-[12px] font-semibold text-rh-text-2">
            Invite as
            <select className="rounded-[6px] border border-rh-hairline px-2 py-1 text-[13px] font-normal" value={role} onChange={(e) => setRole(e.target.value as Role)}>
              {invitableRoles(ownRole).map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-[12px] font-semibold text-rh-text-2">
            Valid for (days)
            <input className="w-[80px] rounded-[6px] border border-rh-hairline px-2 py-1 text-[13px] font-normal" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />
          </label>
          <button className={button} disabled={busy}>Create invite link</button>
          <p className="basis-full text-[11px] text-rh-text-2">{ROLE_HELP[role]}</p>
        </form>
      )}

      {pending.length > 0 && (
        <div className="mt-4">
          <h3 className="mb-1 text-[12px] font-semibold text-rh-text-2">Invites waiting</h3>
          <ul className="flex flex-col gap-1 text-[12px]">
            {invites.map((i) => (
              <li key={i.id} className="flex items-center justify-between rounded-[6px] bg-rh-subtle px-2 py-1">
                <span>{ROLE_LABEL[i.role]} · {inviteStateLabel(i.state)}{i.expires_at ? ` · until ${new Date(i.expires_at).toLocaleDateString()}` : ""}</span>
                {i.state === "pending" && (
                  <button className={button} disabled={busy} onClick={() => { if (window.confirm("Revoke this invite? The link stops working at once.")) void act(() => onboardingApi.revokeInvite(token, i.id)); }}>Revoke</button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
