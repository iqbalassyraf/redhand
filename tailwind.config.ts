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
        broadcast: {
          red: "#FF0000",
          redHover: "#CC0000",
          blue: "#065FD4",
          neutral: "#606060",
          bg: "#FFFFFF",
          surface: "#F2F2F2",
          surfaceHover: "#E5E5E5",
          text: "#0F0F0F",
          border: "#E5E5E5",
          success: "#2BA640",
          warning: "#FB8C00",
        },
      },
      fontFamily: {
        sans: ["Roboto", "system-ui", "-apple-system", "sans-serif"],
        mono: ["Roboto Mono", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
