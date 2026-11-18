/** Clerk's screens in the Dark Navy Glass + Crimson tokens: glass surfaces, hairline borders, crimson primary CTAs. Values are the CSS variables, so the tokens stay the one source of colour. */
export const clerkAppearance = {
  variables: {
    colorPrimary: "var(--rh-accent-crimson)",
    colorBackground: "var(--rh-bg-elevated)",
    colorInputBackground: "var(--rh-bg-base)",
    colorInputText: "var(--rh-text-primary)",
    colorText: "var(--rh-text-primary)",
    colorTextSecondary: "var(--rh-text-secondary)",
    colorDanger: "var(--rh-crimson)",
    colorNeutral: "var(--rh-text-primary)",
    borderRadius: "12px",
    fontFamily: "var(--font-rh-sans), system-ui, sans-serif",
  },
  elements: {
    card: {
      boxShadow: "var(--rh-glass-glow)",
      border: "1px solid var(--rh-glass-border)",
      backgroundColor: "var(--rh-glass-bg)",
      backdropFilter: "blur(20px)",
      WebkitBackdropFilter: "blur(20px)",
    },
    formButtonPrimary: {
      backgroundColor: "var(--rh-accent-crimson)",
      boxShadow: "var(--rh-glow-crimson)",
    },
    rootBox: { width: "100%" },
    footer: { background: "transparent" },
  },
} as const;
