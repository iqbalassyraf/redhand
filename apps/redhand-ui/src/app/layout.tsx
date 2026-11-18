import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import { connection } from "next/server";
import "./globals.css";
import { AuthProvider } from "@/lib/auth";

// Downloaded at build time and served from this site, so the CSP keeps font-src 'self' (no request to Google from the browser).
const sans = Inter({ subsets: ["latin"], variable: "--font-rh-sans", display: "swap" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-rh-mono", display: "swap" });

export const metadata: Metadata = {
  title: "RedHand | Agent Passports & Control",
  description:
    "Identify every AI agent, control which MCP tools it can use, and stop it instantly.",
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Every page is rendered per request so Next.js can stamp the Content-Security-Policy nonce (src/middleware.ts) on its scripts.
  await connection();
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body className="rh-dark bg-control-base text-rh-text font-sans antialiased">
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
