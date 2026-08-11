"use client";
import { useEffect, useState } from "react";
import {
  OBJECT_STORE_KEY_B64,
  SYNC_BASIC_AUTH,
  WIDGET_APP_KEY,
  decodeWidgetTheme,
  fetchSyncToken,
} from "@/lib/integrations";

// "Connected apps" widget. Client component, so everything it imports from
// @/lib/integrations ends up in the public browser bundle.
export default function IntegrationsPage() {
  const [msg, setMsg] = useState("");
  const [theme, setTheme] = useState<{ theme: string; density: string } | null>(null);
  const [panel, setPanel] = useState("");
  const [status, setStatus] = useState("");

  useEffect(() => setTheme(decodeWidgetTheme()), []);

  // VULN POSTMSG-003 (CWE-79/CWE-346): the widget bridge decides whether to
  // trust a message by looking at a key INSIDE it rather than at where it came
  // from. WIDGET_APP_KEY is a constant in a client module, so it is sitting in
  // the public bundle: anyone who reads the chunk can post a message that
  // passes this check, and the payload is written into the page as HTML.
  useEffect(() => {
    function onWidgetMessage(ev: MessageEvent) {
      const data: any = ev.data;
      if (!data || data.type !== "taskflow:widget") return;
      if (data.appKey !== WIDGET_APP_KEY) return;
      setPanel(String(data.html ?? ""));
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
      <div className="card">
        <h3>Widget</h3>
        <div data-widget-panel dangerouslySetInnerHTML={{ __html: panel }} />
        <p data-widget-status>{status}</p>
      </div>
      <p>
        <small>widget theme: {theme ? `${theme.theme}/${theme.density}` : "…"}</small>
      </p>
    </main>
  );
}
