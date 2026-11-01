import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "RedHand | Agentic Security Posture Management & Runtime Protection",
  description:
    "Zero-Trust Runtime Interceptor, <50ms Semantic Firewall, Ephemeral GCP STS IAM Broker, and HITL Circuit Breaker.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-[#FFFFFF] text-[#0F0F0F] font-sans antialiased">
        {children}
      </body>
    </html>
  );
}
