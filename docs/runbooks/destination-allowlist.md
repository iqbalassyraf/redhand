# Runbook: per-agent destination allowlist

**Product truth (shown in the dashboard):** RedHand reads the web and email addresses an agent writes into a call that goes through the RedHand gateway. It does not see what a tool does with the data afterwards, an address written as a plain word, encoded or split across fields, or anything an agent does outside the gateway.

## What it does
For each agent you keep a list of up to 100 hosts (exact names or addresses, nothing else) and a mode.
- **Off (default):** nothing is checked.
- **Watch:** every address in a call that is not on the list is recorded as a finding (rule `RAD-DST-001`, "Address outside the list" on the Radar page) and you get one Telegram alert per agent per 10 minutes. Nothing is refused. Findings show only the last two parts of the address.
- **Enforce:** the call is also refused ("this call contains an address that is not on this agent's allowed list") and never reaches the tool. A call too large to read is refused too. Refused calls use no budget and are not counted as loops.

## Turn it on safely
1. Passports, **Destinations** on the agent's row. Leave it on **Watch** with a short list of the hosts you know it needs (admin: type the host, tick the box, **Allow**). Hosts are stored in one canonical form: `Files.Example.COM.` becomes `files.example.com`, an umlaut becomes `xn--...`, `0x7f.1` becomes `127.0.0.1`.
2. Watch for a few days. Open Radar, kind **Address outside the list**: each finding names the agent, the tool and the last two parts of the address. Add what is legitimate; investigate what is not.
3. Switch to **Enforce** (admin, tick the confirmation). It needs at least one host, and the last host cannot be removed while enforcing. The change reaches the gateway within a few seconds.
4. To go back: choose Watch (no confirmation) or Off (confirmation needed). Every change is in the audit log (`passport.destination_added`, `_removed`, `_mode_changed`).

## Reading the list
- **Exact match:** `good.com` does not allow `sub.good.com`, `good.com.evil.com` or `evilgood.com`. List each host the agent needs (up to 100). Wildcards are not supported.
- **Scheme and port are ignored:** `http` and `https`, any port, count as the same host.
- **IP addresses** can be listed (any form is stored as dotted decimal or compressed IPv6).
- **An address that is ambiguous** (for example `http://a@b@good.com/`, or `http://good.com\@evil.com/`, which parsers read differently) counts as outside the list.

## If something is wrong
- **A legitimate call is refused after enforcing:** the address is not on the list. Add it (or switch the agent to Watch while you find out what it is). Note that a **URL that is not a destination** (a search tool whose query contains a link, a summarizer given a page to read) is also an address in the call.
- **"too large to read to check":** an argument is over 64 KiB, or the call holds more than 200 addresses or 50 distinct hosts. Shrink the call, or use Watch for that agent.
- **Gateway-wide switch, no deploy:** set `AGENTWALL_DESTINATION_CHECK_ENABLED=false` on the gateway service (Cloud Run: update the environment variable, new revision). The check is skipped for every agent whatever its mode. `deploy/cloudrun/deploy.sh` replaces environment values, so write it in `docs/handoff.md` the same day.
- **All calls fail with "Passport service unavailable" right after a gateway deploy:** the gateway was deployed before core. It requires `destination_mode` and `allowed_destinations` and denies when they are missing. Deploy core first (or roll the gateway back).
- **All calls of one agent fail with "Passport service unavailable":** core could not read that agent's list (a database problem); it denies rather than check against nothing. See core's logs ("Destination list lookup failed").
- **No alert arrived:** one alert per agent per 10 minutes; later findings are still recorded. The gateway sends at most one finding per agent, tool and server every 30 seconds, so a finding's count is "at least".

## Reading the numbers
Gateway `/metrics`: `redhand_gateway_destination_checks_total{outcome=ok|flagged|refused|untracked|error|report_throttled}` and the stage `redhand_gateway_stage_ms{stage="destination_check"}`. `flagged` counts calls with an address outside the list (in Watch and in Enforce); `refused` counts enforced refusals; `untracked` means part of a call was past the scan budget; `error` means the check failed (Watch: the call carried on; Enforce: it was refused).

## Limits
Not found: an address written as a bare word, encoded, split across fields or built by the tool; scheme and port are ignored; a subdomain of a listed host is not allowed; findings keep only the last two labels (for `a.b.example.co.uk`, `co.uk`). With several gateway instances the check is the same on each (the list comes from core), unlike the loop and budget counters.

## Deploy and rollback
Order: apply `20261121000000_destination_allowlist.sql` (after the loop migration), deploy core, deploy the gateway, then the dashboard. Rollback: run `supabase/rollbacks/20261121000000_destination_allowlist.down.sql` (it deletes every allowlist, destination findings and `RAD-DST` suppressions), after redeploying the previous gateway if the new one is running (an older core cannot satisfy it).
