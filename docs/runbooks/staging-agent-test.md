# Runbook: test a real agent against staging

Runs the four Phase 1 "done" tests on the staging stack with `scripts/staging_agent.py`, a small
stand-in for an AI agent that speaks MCP through the RedHand gateway to a real, public MCP server
(DeepWiki, `https://mcp.deepwiki.com/mcp`, no login needed). Standard library only; Python 3 is all
you need.

The script was checked against a local copy of the whole stack (run mode: 6 of 6 checks; watch
mode: freeze 1.2 s, unfreeze 0.2 s, freeze-all 1.3 s, revoke 1.8 s until the agent was stopped).
Against staging and DeepWiki it has **not** been run yet. DeepWiki's tool names
(`read_wiki_structure`, `read_wiki_contents`, `ask_question`) are from its public documentation and
unverified here; the script prints what it finds, so a mismatch is easy to correct.

## 1. In the dashboard (browser): https://redhand-dashboard.vercel.app/passports

1. **MCP servers** box: slug `deepwiki`, name `DeepWiki`, URL `https://mcp.deepwiki.com/mcp` →
   *Register server (admin)*. Expect "MCP server deepwiki registered."
2. **Register an agent** box (do this twice, for two agents):
   - Name `Test agent 1` (then `Test agent 2`), framework anything, expires 90 days.
   - *Add scope*: server `deepwiki`, tool `read_wiki_structure`, access `read`.
   - *Register and issue key*. A box shows the key (`rh_agent_...`) **once**: click *Copy* and keep
     it for step 2. Do not paste it into chat.

## 2. Checks in action (Terminal, in the repository folder)

```bash
python3 scripts/staging_agent.py run
```

Paste Test agent 1's key at the hidden prompt. Expect six PASS lines: token issued, MCP initialize,
tools/list shows only the allowed tool, the allowed call works, `ask_question` is refused, an
unknown server is refused. Then open Google Cloud console → Cloud Run → `redhand-gateway` → Logs and
search `BLOCK`: the refused call is recorded there (done test 2: "denied and logged").

## 3. Revoke and freeze-all (Terminal, then dashboard)

```bash
python3 scripts/staging_agent.py watch --agents 2
```

Paste both keys. Both agents report "calls are allowed". Now, in the dashboard, one at a time:

| In the dashboard | Expect in Terminal | Done test |
|---|---|---|
| *Freeze* on Test agent 1 | `agent 1 ... STOPPED ... passport is frozen` within about 2 s | |
| *Unfreeze* on Test agent 1 (confirm) | `agent 1 ... RESUMED` | |
| *Freeze all agents* (type FREEZE) | both agents `STOPPED` | 4 |
| *Unfreeze* each agent (confirm) | both `RESUMED` | |
| *Revoke* on Test agent 1 (confirm) | `STOPPED ... passport is revoked`, and it never resumes | 3 |

After each action the dashboard's *Control audit log* shows who did what and when. Press Ctrl+C in
Terminal to stop watching.

## If something fails

| Symptom | Likely cause |
|---|---|
| `token refused (HTTP 401)` | wrong key, or the agent was revoked |
| `token refused (HTTP 403)` | the passport is frozen, revoked or expired |
| in-scope call fails with an upstream error | DeepWiki is down, rate-limiting, or the tool name differs: run the script with `--ok-tool <name>` after checking `tools/list` |
| `Unknown MCP server` | the slug in the dashboard is not `deepwiki`, or pass `--server <slug>` |
| first run is very slow | Cloud Run cold starts (min instances 0); retry |
