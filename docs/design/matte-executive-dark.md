# Dashboard design system: Matte Executive Dark

The one visual system for `apps/redhand-ui`. Owner-specified tokens (2026-11-18); implemented in `apps/redhand-ui/src/app/globals.css` and mapped to Tailwind `rh-*` colours in `tailwind.config.ts`. Guarded by `tests/tokens.test.mjs` and `tests/no-raw-colours.test.mjs`.

## Rules (strict)
- No pure black or white, no shadows, glows, neon borders, gradients, glassmorphism or blur. Depth comes from matte surface steps and 1px hairline borders.
- Every colour comes from a token. A raw hex colour, a `shadow`, a `blur`, a gradient, the old palette or a page that draws its own chrome fails the `no-raw-colours` test.
- Labels in Inter; figures (counts, latency, sizes, ids) in JetBrains Mono with tabular numbers (`.rh-tabular`). Both load through Next.js's built-in font loader, served from our own origin (CSP `font-src 'self'` unchanged).
- The UI is never a security boundary: hiding a link only saves a click; core authorizes every request.

## Surfaces
| Token | Use |
|---|---|
| `rh-chrome` (and `-hover`, `-active`, `-border`) | Left rail and header band only (deep pine-slate) |
| `rh-canvas` | Page background |
| `rh-card` | Cards and panels |
| `rh-elevated` | Controls, hovered rows, tracks |
| `rh-subtle` | Wells and inset areas, form controls |
| `rh-hairline` / `rh-strong` | 1px borders; stronger divider |

## Text
`rh-text` (primary), `rh-text-2` (secondary, 4.5:1 or better on every surface), `rh-muted` (placeholders and separators only: below AA on purpose, never for information).

## Accent meanings (claims discipline: each colour means something RedHand really does)
| Accent | Means | Text-safe sibling |
|---|---|---|
| teal | allowed, active, primary action, focus outline | `rh-teal-text` |
| steel | volume and traffic | `rh-steel-text` |
| ochre | needs attention: frozen, Safe Mode, review pending, Watch mode, unpriced spend | `rh-ochre` (already AA) |
| crimson | refused, revoked, honeytoken trip, failed verification | `rh-crimson-text` |
| slate-purple | detective findings (Radar, scanner, behaviour), never enforcement | `rh-purple-text` |

The accents themselves are for dots, bars and chart marks (3:1 against the card). Small text uses the text-safe sibling. A chip puts primary text on the wash with a coloured dot. Your original token names mention a "17 ms fast path" and "async cyber-model escalation": RedHand publishes no such claim and has no such feature, so the colours kept their values and took real meanings.

## Components
`AppShell` (rail, header band, phone menu), `Card`, `KpiTile`, `Chip`, `Button` (primary teal, secondary hairline, danger crimson), `EmptyState`, `ErrorState` (`src/components/shell`, `src/components/ui`). Charts are hand-drawn SVG (`src/components/charts`, geometry in `src/lib/chartGeometry.ts`, tested). Every chart has a text summary for screen readers and a "View as table" toggle. Empty and failed reads say so: never a zero passed off as data.

## Accessibility
WCAG AA is checked by test for every text-on-surface pair the system uses (4.5:1 for text, 3:1 for chart marks). Focus is a crisp 1px teal outline, never a glow. Known near-miss: canvas-coloured text on a crimson fill (primary danger buttons) is 4.44:1; it is bold 13px button text.

## Adding to it
Use an existing token. If none fits, add one to `globals.css`, map it in `tailwind.config.ts`, and extend `tokens.test.mjs` (the test fails if a token is not mapped or a text pair drops below AA).
