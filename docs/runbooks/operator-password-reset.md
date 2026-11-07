# Operator password reset

Operators sign in to the dashboard with a Supabase Auth email and password. The login page has a **Forgot password?**
link; the emailed link opens `/reset-password`, where the operator sets a new password (12 to 128 characters).

## Supabase settings it depends on (Authentication -> URL Configuration)
- **Site URL**: the dashboard's https origin, for example `https://redhand.archtificial.com`. If it still says
  `http://localhost:3000`, every emailed link goes to the operator's own machine and fails.
- **Redirect URLs**: include `https://redhand.archtificial.com/**` (and any other dashboard origin you use).

## How it behaves
- The request always answers the same way, whether or not the email has an account.
- The link works once and expires quickly. The recovery tokens arrive in the URL fragment and are removed from the
  address bar as soon as the page loads.
- After a successful change, all of that user's sessions are signed out.

## If it fails
| Symptom | Cause | Fix |
|---|---|---|
| Link opens `localhost` and "site can't be reached" | Site URL is still localhost | Set Site URL, request a new link |
| "invalid or has expired" | Link already used, expired, or opened by a mail scanner | Request a new link; open it once, in the same browser |
| No email arrives | Supabase email rate limit, or the address has no account | Wait a few minutes; check Authentication -> Users |
| Lost access to the only owner account | | Recover through the Supabase dashboard (project owner), never by pasting a password into chat or SQL |
