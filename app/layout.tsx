import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DNS Guard - Network Security Dashboard",
  description: "Real-time Network Vulnerabilities Checker",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body style={{ fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif' }}>
        {children}
      </body>
    </html>
  );
}
