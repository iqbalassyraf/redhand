# ADR 0031: Dashboard design system (Matte Executive Dark) and the Insights summary

**Status:** Accepted by the owner (2026-11-18: whole app in slices, real Insights home page, new summary endpoint). Slices S1 to S5 are merged or in review; the design rules are in `docs/design/matte-executive-dark.md`.

## Context
The dashboard was light-themed with about 1,400 hard-coded colours in 29 files, no shared navigation (each page drew its own header) and a home page that was a sample-data canvas. The owner supplied a dark design system and a reference layout (an analytics page: rail, KPI tiles, charts).

## Decision
1. **One design system.** Colour tokens as CSS variables, mapped to Tailwind `rh-*`; Inter and JetBrains Mono through Next.js's built-in loader (no new dependency, CSP unchanged); a shared `AppShell`; small UI primitives. A test fails on raw colours, shadows, gradients or a page without the shell.
2. **Insights as the home page**, built only from real data. The sample canvas moved to `/demo`.
3. **A new read-only endpoint** `GET /v1/insights/summary?window=1h|24h|7d` (viewer and above), computed in SQL (`insights_summary`, migration `20261202000000`) from the Black Box. Only aggregates leave core; refusal reasons are mapped in SQL to a fixed set of categories, because the gateway's raw reason sentences carry tool, server and address names. A failed read is a 503, never zeros.
4. **Charts are hand-drawn SVG**, no chart library (a dependency needs approval and the shapes are simple); geometry is pure and tested.

## Alternatives considered
- Restyle only the new page and leave the rest light: a mixed product for weeks.
- Aggregate in the browser from the last 200 Black Box events: approximate numbers on busy tenants.
- A chart library: new dependency and bundle weight for six chart shapes.

## Consequences
- Latency on the page is the whole call as the gateway saw it (tool time included) and is labelled so; the gateway's 50 ms budget is drawn only as a scale reference.
- The page needs core with the endpoint and the migration applied; an older core shows "This core does not serve Insights yet".
- The accent colours carry RedHand meanings (teal allowed, crimson refused, ochre attention, purple detective), not the owner's original labels such as "17 ms fast path", which RedHand makes no claim about.
- Cost: one indexed range query per page load and per 30 s refresh while the tab is visible.
