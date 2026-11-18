import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Matte Executive Dark: every value is a CSS variable in src/app/globals.css (one source of colour).
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
