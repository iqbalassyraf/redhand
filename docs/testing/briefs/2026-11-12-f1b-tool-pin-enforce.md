# Test brief: tool pinning in enforce mode (F1b, Phase 4 done test 4)

- **Date:** 2026-11-12. **Written by:** Claude Code. **Run by:** Antigravity with the owner. Steps marked *owner-assisted* need the owner (keys, terminal).
- **Why:** F1 left step 11, step 12 and the "tool hidden until approved" behaviour unproven on staging (`docs/testing/results/2026-11-09-f1-phase4-staging-sweep.md`, correction section). This brief proves them **without redeploying the helpdesk demo**, using a second DeepWiki tool that has never been approved. The "a changed description is detected" case (F1 steps 13 and 14) is not covered here and stays for the F2 closeout.
- **Standing rules from the owner:** do NOT create sessions as the owner, do NOT read shell history, do NOT deploy anything, do NOT change settings, agents or scopes that this brief does not name. Never paste a key or token anywhere; say "set", "worked", "refused". List every change you make to staging and undo the ones this brief names.
- **Rules about evidence:** quote every on-screen text you rely on **exactly, in quotation marks**, attach a screenshot for every step marked *screenshot*, and for terminal steps paste the printed output (it contains no secrets). Do **not** mark a step PASS unless you saw it in this run. If you could not do a step, write NOT RUN and why. Do not write GOOD if any step is NOT RUN.
- **Environment:** dashboard `https://redhand.archtificial.com`; core and gateway as in `docs/handoff.md`. Both services are at zero minimum instances, so the first call after a quiet period is slow: wait about 10 seconds and retry before calling it a failure. Nothing needs deploying.
- **Prerequisite (owner, in Passports):** register an agent `pin-test`, framework custom, with **two** scopes: server `deepwiki`, tool `read_wiki_structure`, access `read`, and server `deepwiki`, tool `read_wiki_contents`, access `read`. Terminal: `cd /Users/testing/Documents/project-redhand`; `export RH_INTERNAL_TOKEN="$(gcloud secrets versions access latest --secret redhand-internal-service-token)"`; `read -s RH_AGENT_KEY; export RH_AGENT_KEY` (paste the `pin-test` key).

## Steps
| # | Do | Expected | Type |
|---|---|---|---|
| 0 | *Owner-assisted, mode is still alert:* `python3 scripts/staging_agent.py run --server deepwiki --ok-tool read_wiki_contents --ok-args '{"repoName": "facebook/react"}'`. Paste the output | Both tools are visible and the call works, in alert mode (the baseline). If DeepWiki is slow or errors, say exactly what happened | normal |
| 1 | As the **owner (admin)** open `/scanner`, **Tool pins** on `deepwiki`. *Screenshot*. Write down each tool and its status | `read_wiki_structure` approved. `read_wiki_contents` appears as pending ("new tool") because step 0 listed it. Mode shows **alert** | normal |
| 2 | Try to switch the mode to **enforce** **without** ticking the confirmation. *Screenshot*. Quote the message | Refused with a message about confirming. The mode stays alert | abuse |
| 3 | Tick the confirmation and set **enforce**. *Screenshot* | Banner "Tool pinning is now enforce." (quote it) | normal |
| 4 | *Owner-assisted:* run `python3 scripts/staging_agent.py run --server deepwiki --ok-tool read_wiki_structure`. Paste the output | All checks pass. The visible tools list contains only `read_wiki_structure` (the approved one). The unapproved `read_wiki_contents` is **not** listed | normal |
| 5 | *Owner-assisted:* run the step 0 command again (`--ok-tool read_wiki_contents ...`). Paste the output | The in-scope call to `read_wiki_contents` is **refused** with a message that the tool is not approved. This script line printing FAIL is the **expected** result. The call never reaches DeepWiki | abuse |
| 6 | Reload **Tool pins**. *Screenshot* | `read_wiki_contents` still pending. One Telegram alert may have arrived about a new or changed tool, with counts only and no tool text. Report whether one arrived and quote it | normal |
| 7 | As **security operator** (`iassyraf+operator@gmail.com`) try **Approve** on `read_wiki_contents`. *Screenshot* | Refused: "This action requires the 'admin' role or higher." (quote it). Nothing changes | abuse |
| 8 | As the owner approve `read_wiki_contents`. *Owner-assisted:* run the step 0 command again | The tool is listed and the call works again | normal |
| 9 | As the owner set the mode back to **alert** (confirmation needed). *Screenshot* | Mode shows alert | normal |

## Cleanup (owner and Antigravity)
Set the mode back to alert (step 9), revoke the `pin-test` agent, `unset RH_AGENT_KEY RH_INTERNAL_TOKEN`. Note: **`read_wiki_contents` stays approved** after this test (an approval cannot be taken back from the page); say so in the report. Do not change anything else. Also list the honeytoken create and retire from F1 if it was yours.

## Report back (simple English first)
One line: **GOOD** or **NOT GOOD** (with the steps that failed or were not run). Then each step PASS, FAIL or NOT RUN with the quoted text, terminal output and screenshot names. List every change to staging and whether it was undone.

## How Claude Code will check your report
Against the staging database: `mcp_server.pin_mode_changed` audit rows (there must be an enforce period long enough for steps 4 to 8), the pin rows in `mcp_tool_pins` for `read_wiki_contents`, the agent's final status, and the gateway events for the refused call.
