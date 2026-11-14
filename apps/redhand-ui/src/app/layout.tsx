import type { Metadata } from "next";
import { connection } from "next/server";
import "./globals.css";
import { AuthProvider } from "@/lib/auth";

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
    <html lang="en">
      <body className="bg-[#FFFFFF] text-[#0F0F0F] font-sans antialiased">
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
