import "./globals.css";
import type { ReactNode } from "react";
import { PUBLIC_RUNTIME_CONFIG } from "@/lib/config";
import AppNav from "./_components/AppNav";

export const metadata = { title: "TaskFlow (vulnerable)", description: "DAST benchmark app" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang={PUBLIC_RUNTIME_CONFIG.locale}>
      <body>
        {/*
          FIXED CONFIG-LEAK-001: the bootstrap blob is built from the explicit
          public allow-list. The internal API base, SMTP credentials and the
          internal admin token stay on the server.
        */}
        <script
          id="app-config"
          type="application/json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(PUBLIC_RUNTIME_CONFIG) }}
        />
        <div className="banner">
          ⚠️ INTENTIONALLY VULNERABLE benchmark app — do not deploy on a public network.
        </div>
        <AppNav />
        {children}
      </body>
    </html>
  );
}
