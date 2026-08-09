"use client";
import { useEffect, useState } from "react";
import {
  OBJECT_STORE_KEY_B64,
  SYNC_BASIC_AUTH,
  decodeWidgetTheme,
  fetchSyncToken,
} from "@/lib/integrations";

// "Connected apps" widget. Client component, so everything it imports from
// @/lib/integrations ends up in the public browser bundle.
export default function IntegrationsPage() {
  const [msg, setMsg] = useState("");
  const [theme, setTheme] = useState<{ theme: string; density: string } | null>(null);

  useEffect(() => setTheme(decodeWidgetTheme()), []);

  async function sync() {
    // VULN CREDS-BUNDLE-001: the widget authenticates with the hardcoded service
    // credential instead of the caller's own session.
    const r = await fetch("/api/integrations/sync", {
      method: "POST",
      headers: { authorization: SYNC_BASIC_AUTH },
    });
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
        {/* VULN SECRET-002: the bundled credential, echoed into the DOM. */}
        <small>bucket credential: {OBJECT_STORE_KEY_B64}</small>
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
