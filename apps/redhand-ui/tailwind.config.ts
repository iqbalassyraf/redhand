import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/lib/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Unified Dark Navy Glass + Crimson: every value is a CSS variable in src/app/globals.css (one source of colour).
        rh: {
          chrome: "var(--rh-chrome-bg)",
          "chrome-hover": "var(--rh-chrome-hover)",
          "chrome-active": "var(--rh-chrome-active)",
          "chrome-border": "var(--rh-chrome-border)",
          canvas: "var(--rh-canvas-bg)",
          card: "var(--rh-surface-card)",
          elevated: "var(--rh-surface-elevated)",
          subtle: "var(--rh-surface-subtle)",
          hairline: "var(--rh-border-hairline)",
          strong: "var(--rh-border-strong)",
          text: "var(--rh-text-primary)",
          "text-2": "var(--rh-text-secondary)",
          muted: "var(--rh-text-muted)",
          teal: "var(--rh-teal)",
          "teal-wash": "var(--rh-teal-wash)",
          steel: "var(--rh-steel)",
          "steel-wash": "var(--rh-steel-wash)",
          ochre: "var(--rh-ochre)",
          "ochre-wash": "var(--rh-ochre-wash)",
          crimson: "var(--rh-crimson)",
          "crimson-wash": "var(--rh-crimson-wash)",
          purple: "var(--rh-slate-purple)",
          "purple-wash": "var(--rh-slate-purple-wash)",
          "teal-text": "var(--rh-teal-text)",
          "crimson-text": "var(--rh-crimson-text)",
          "steel-text": "var(--rh-steel-text)",
          "purple-text": "var(--rh-purple-text)",
        },
        // Dark Navy Glass & Crimson control surface tokens (src/app/globals.css).
        control: {
          base: "var(--rh-bg-base)",
          elevated: "var(--rh-bg-elevated)",
          rail: "var(--rh-bg-rail)",
          glass: "var(--rh-glass-bg)",
          glassHover: "var(--rh-glass-bg-hover)",
          border: "var(--rh-glass-border)",
          borderStrong: "var(--rh-glass-border-strong)",
          scrim: "var(--rh-scrim)",
          crimson: "var(--rh-accent-crimson)",
          crimsonBright: "var(--rh-accent-crimson-bright)",
          crimsonDeep: "var(--rh-accent-crimson-deep)",
          crimsonSoft: "var(--rh-accent-crimson-soft)",
          crimsonBorder: "var(--rh-accent-crimson-border)",
          steelBorder: "var(--rh-steel-border)",
          ochreBorder: "var(--rh-ochre-border)",
          allowed: "var(--rh-status-allowed)",
          flagged: "var(--rh-status-flagged)",
          blocked: "var(--rh-status-blocked)",
          pending: "var(--rh-status-pending)",
          text: "var(--rh-text-primary)",
          muted: "var(--rh-text-secondary)",
          subtle: "var(--rh-text-muted)",
        },
      },
      borderRadius: {
        "rh-sm": "var(--rh-radius-sm)",
        "rh-md": "var(--rh-radius-md)",
        "rh-lg": "var(--rh-radius-lg)",
        "rh-xl": "var(--rh-radius-xl)",
      },
      boxShadow: {
        "rh-glass": "var(--rh-glass-glow)",
        "rh-crimson": "var(--rh-glow-crimson)",
        "rh-allowed": "var(--rh-glow-allowed)",
        "rh-flagged": "var(--rh-glow-flagged)",
        "rh-blocked": "var(--rh-glow-blocked)",
      },
      transitionTimingFunction: {
        "rh-out": "var(--rh-ease-out)",
      },
      transitionDuration: {
        "rh-fast": "var(--rh-duration-fast)",
        "rh-normal": "var(--rh-duration-normal)",
      },
      fontFamily: {
        sans: ["var(--font-rh-sans)", "system-ui", "-apple-system", "sans-serif"],
        mono: ["var(--font-rh-mono)", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
