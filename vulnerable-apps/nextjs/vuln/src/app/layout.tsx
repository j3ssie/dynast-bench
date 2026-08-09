import "./globals.css";
import type { ReactNode } from "react";
import { PUBLIC_RUNTIME_CONFIG, RUNTIME_CONFIG } from "@/lib/config";

export const metadata = { title: "TaskFlow (vulnerable)", description: "DAST benchmark app" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang={PUBLIC_RUNTIME_CONFIG.locale}>
      <body>
        {/*
          VULN CONFIG-LEAK-001 (CWE-200/CWE-215): the bootstrap blob every page
          embeds is the FULL server runtime config — internal service base URL,
          SMTP credentials and the internal admin token — not the public subset
          sitting right next to it. Rendered into every route, pre-auth included.
        */}
        <script
          id="app-config"
          type="application/json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(RUNTIME_CONFIG) }}
        />
        <div className="banner">
          ⚠️ INTENTIONALLY VULNERABLE benchmark app — do not deploy on a public network.
        </div>
        <nav style={{ padding: "12px 24px", borderBottom: "1px solid #223" }}>
          <a href="/">Home</a>
          <a href="/posts">Posts</a>
          <a href="/posts/search">Search</a>
          <a href="/login">Login</a>
          <a href="/profile">Profile</a>
          <a href="/integrations">Integrations</a>
          <a href="/admin/users">Admin</a>
        </nav>
        {children}
      </body>
    </html>
  );
}
