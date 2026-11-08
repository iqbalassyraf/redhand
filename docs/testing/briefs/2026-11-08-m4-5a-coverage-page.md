# Test brief: the Coverage page (M4.5a)

- **Date:** 2026-11-08. **Written by:** Claude Code. **Run by:** Antigravity with the owner, after the Vercel production deploy of `main` has finished.
- **Standing rules from the owner:** do NOT create sessions as the owner, do NOT read shell history, do NOT deploy anything, do NOT change settings that this brief does not name. If you need a login, ask the owner and wait. List every change you make to staging (this brief should need none).
- **Environment:** `https://redhand.archtificial.com/coverage`. Sign-in is owner-assisted.

## What changed
A **Coverage** page (link in every header) that shows measured detection results, language badges and known gaps. It is static data (`/coverage.json`). The header menu now scrolls sideways on phones. No backend change.

## Already verified by Claude Code (local only)
Data and tests, a local browser run, and phone width on three pages. **Not verified:** staging, the other pages at phone width, other browsers.

## Steps
| # | Do | Expected |
|---|---|---|
| 1 | Open any page, click **Coverage** in the header | The page opens; the link is highlighted |
| 2 | Read the top of the page | Known gaps come first, in a shaded box. No sentence claims RedHand blocks everything or protects things outside the gateway |
| 3 | Open `https://redhand.archtificial.com/coverage.json` | JSON loads; it has no attack or sample text, only counts and names |
| 4 | Compare the three blind round tables with `docs/security/blind-round-1.md`, `-2.md`, `-3.md` (owner or Claude Code provides) | Every number matches the record (round 3: 34 of 94, 36%, 10 of 146 false alarms) |
| 5 | Languages block | Four languages, each "not native-reviewed". Indonesian shows attacks "not measured". Chinese shows "not covered" and nothing measured |
| 6 | Held-out and development tables | Ratings use the words covered / partial / weak; "Development samples" is collapsed by default and says it flatters the rules |
| 7 | Compare one row of each table with `docs/security/coverage-matrix.md` | Same numbers |
| 8 | Look for any text a person would take as a promise (for example "100%", "fully protected", "guaranteed") | None. Report the exact words if you find any |
| 9 | Emulate 375 px wide on `/coverage`, `/radar`, `/passports`, `/blackbox`, `/honeytokens`, `/scanner` | On each: the page does not scroll sideways, the header menu scrolls sideways, **Sign out** stays visible, tables scroll inside their box |
| 10 | Block the file (browser dev tools: block `/coverage.json`) and reload `/coverage` | A clear "could not be loaded" message, no blank page or crash |
| 11 | Sign out and open `/coverage` | You are sent to the login page |

## Report back
PASS / FAIL / NOT RUN per step, with what you saw (numbers, exact words for step 8). List every change you made to staging.
