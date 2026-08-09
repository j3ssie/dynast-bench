"use client";
import { useEffect, useState } from "react";
import { decodeWidgetTheme, fetchSyncToken } from "@/lib/integrations";

// "Connected apps" widget. Client component, so everything it imports from
// @/lib/integrations ends up in the public browser bundle.
export default function IntegrationsPage() {
  const [msg, setMsg] = useState("");
  const [theme, setTheme] = useState<{ theme: string; density: string } | null>(null);

  useEffect(() => setTheme(decodeWidgetTheme()), []);

  async function sync() {
    // FIXED CREDS-BUNDLE-001: authenticate as the caller (session cookie), not
    // with a service credential embedded in the bundle.
    const r = await fetch("/api/integrations/sync", { method: "POST" });
    const j = await r.json();
    setMsg(r.ok ? `synced ${j.synced} items as ${j.as}` : `Error: ${j.error}`);
  }

  async function rotate() {
    const t = await fetchSyncToken();
    setMsg(t ? `issued a fresh sync token (${t.slice(0, 8)}…)` : "log in first");
  }

  return (
    <main>
      <h1>Connected apps</h1>
      <div className="card">
        <h3>Object store</h3>
        {/* FIXED SECRET-002: no credential is bundled or rendered. */}
        <small>bucket credential: configured on the server</small>
      </div>
      <div className="card">
        <h3>Sync</h3>
        <button onClick={sync}>Sync now</button>
        <button onClick={rotate}>Rotate token</button>
        <p>{msg}</p>
      </div>
      <p>
        <small>widget theme: {theme ? `${theme.theme}/${theme.density}` : "…"}</small>
      </p>
    </main>
  );
}
