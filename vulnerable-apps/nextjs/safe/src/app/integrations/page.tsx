"use client";
import { useEffect, useState } from "react";
import { WIDGET_APP_KEY, decodeWidgetTheme, fetchSyncToken } from "@/lib/integrations";

// "Connected apps" widget. Client component, so everything it imports from
// @/lib/integrations ends up in the public browser bundle.
export default function IntegrationsPage() {
  const [msg, setMsg] = useState("");
  const [theme, setTheme] = useState<{ theme: string; density: string } | null>(null);
  const [panel, setPanel] = useState("");
  const [status, setStatus] = useState("");

  useEffect(() => setTheme(decodeWidgetTheme()), []);

  // FIXED POSTMSG-003: a key that ships in the bundle proves nothing about who
  // sent the message, so the bridge checks where it came from instead - and the
  // payload it accepts is rendered as text rather than as HTML.
  useEffect(() => {
    function onWidgetMessage(ev: MessageEvent) {
      const data: any = ev.data;
      if (ev.origin !== window.location.origin) return;
      if (!data || data.type !== "taskflow:widget") return;
      setPanel(String(data.text ?? ""));
    }
    window.addEventListener("message", onWidgetMessage);
    return () => window.removeEventListener("message", onWidgetMessage);
  }, []);

  // NEAR-MISS NM-POSTMSG-003: the same shape - a window message handler on the
  // same page, driven by the same widget - but it is gated on the origin rather
  // than on a bundled constant, and what it accepts only ever becomes text.
  useEffect(() => {
    function onWidgetStatus(ev: MessageEvent) {
      const data: any = ev.data;
      if (ev.origin !== window.location.origin) return;
      if (!data || data.type !== "taskflow:widget-status") return;
      setStatus(String(data.text ?? ""));
    }
    window.addEventListener("message", onWidgetStatus);
    return () => window.removeEventListener("message", onWidgetStatus);
  }, []);

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
      <div className="card">
        <h3>Widget</h3>
        <div data-widget-panel>{panel}</div>
        <p data-widget-status>{status}</p>
      </div>
      <p>
        <small>widget theme: {theme ? `${theme.theme}/${theme.density}` : "…"}</small>
      </p>
    </main>
  );
}
