# Support and status (to fill in)

Nothing here is decided. Replace every `<...>` before launch.

- **Support contact:** `<address or form>`; hours `<hours and time zone>`; first reply within `<target>` (only promise what you will keep).
- **Security reports:** GitHub private vulnerability reporting on this repository (owner checklist item 3). `SECURITY.md` says so.
- **Status page:** `<URL>` (a free hosted status page is enough at first). Components: dashboard, core API, gateway.
- **Who is on call:** `<name>`; they are told by `<channel that reaches a phone>` when `/health` fails (owner checklist item 15).

## Incident text (copy and edit)
- *Investigating:* "We are investigating a problem with `<component>` that began at `<time UTC>`. Agents protected by RedHand are `<still refused when they should be / being refused calls they should be allowed>`. We will update at `<time>`."
- *Resolved:* "The problem with `<component>` is fixed as of `<time UTC>`. Cause: `<one plain sentence>`. Effect on your agents: `<what they could and could not do>`. What we are changing: `<one line>`."
Tell customers the truth about the direction of failure: RedHand fails closed, so an outage means agents are refused, not left unprotected.
