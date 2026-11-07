# Testing handoff

Claude Code builds and writes the automated tests for every change (`CLAUDE.md` section 7). Antigravity independently
verifies each change on staging and in a browser. The owner connects the two by telling Antigravity which brief to run.

## Flow
1. Claude Code finishes a change and writes `briefs/<date>-<change>.md` (copy `TEMPLATE-brief.md`).
2. Owner tells Antigravity: "Test `docs/testing/briefs/<file>.md`".
3. Antigravity runs every step, writes `results/<date>-<change>.md` (copy `TEMPLATE-result.md`), and adds a short entry
   to `docs/handoff.md`.
4. Claude Code reads the result and fixes any failure, then adds a note under the brief's "Follow-up".

## When to test (cadence)
1. **Always, per change:** Claude Code writes and runs the automated tests (`CLAUDE.md` section 7).
2. **Per milestone:** one brief and one staging test for each batch that can be deployed (for example "M4 Radar and output
   checks", or "M5 and M6 together"). Not after every small edit, and not only at the end of a phase.
3. **Riskier work first:** anything touching the gateway, migrations, credentials or tenant isolation gets its staging test
   before Claude Code builds the next thing that depends on it. At most one untested milestone is ever stacked up.
4. **Small fixes ride along:** trivial UI or docs fixes go into the next brief as their own step.
5. **Never skip silently:** if a milestone moves on untested, say so in `docs/handoff.md`.
6. **Testing does not block building:** Antigravity can test milestone N on staging while Claude Code builds N+1, as long as
   N+1 does not build on N's code when N touched enforcement. Bugs found go into the result file; Claude Code fixes them.

## Rules for the tester
- Staging only (dashboard `https://redhand.archtificial.com`, core and gateway Cloud Run URLs in `docs/briefing.md`
  and `docs/runbooks/cloud-run-staging.md`). Never production, never real customer data.
- Never write passwords, tokens, agent keys or honeytoken values into a result, a log or a chat. Say "set", "worked", "rejected".
- Sign-in and anything needing the owner's mailbox or phone is **owner-assisted**: ask the owner to do that step and
  report what they saw. Do not create accounts or reset credentials yourself.
- Do each step as written and record what actually happened. If the actual result differs from the expected one, that is a
  FAIL, even if the difference looks harmless. Do not adjust the expectation to match.
- Do not fix bugs in the RedHand repo. Report them with steps to reproduce; Claude Code fixes them.
- Mark a step NOT RUN, with the reason, rather than guessing.
- Keep claims honest: a result says what was exercised, not that "everything works".
