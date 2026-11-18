/** Clerk's screens in the Matte Executive Dark tokens (docs/design/matte-executive-dark.md): flat, hairline borders, no shadows. Values are the CSS variables, so the tokens stay the one source of colour. */
export const clerkAppearance = {
  variables: {
    colorPrimary: "var(--rh-teal)",
    colorBackground: "var(--rh-surface-card)",
    colorInputBackground: "var(--rh-surface-subtle)",
    colorInputText: "var(--rh-text-primary)",
    colorText: "var(--rh-text-primary)",
    colorTextSecondary: "var(--rh-text-secondary)",
    colorDanger: "var(--rh-crimson)",
    colorNeutral: "var(--rh-text-primary)",
    borderRadius: "8px",
    fontFamily: "var(--font-rh-sans), system-ui, sans-serif",
  },
  elements: {
    card: { boxShadow: "none", border: "1px solid var(--rh-border-hairline)", backgroundColor: "var(--rh-surface-card)" },
    rootBox: { width: "100%" },
    footer: { background: "transparent" },
  },
} as const;
