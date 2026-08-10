"use client";
import { useEffect, useState } from "react";
import dynamicImport from "next/dynamic";
import { api } from "@/lib/routes";

// Code-split and client-only: the browser does not request this chunk until the
// Advanced button is pressed, so nothing it references is visible to a crawler
// that only reads what the page loads on arrival.
const DevTools = dynamicImport(() => import("../_components/DevTools"), { ssr: false });

export default function ProfilePage() {
  const [me, setMe] = useState<any>(null);
  const [displayName, setDisplayName] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [notice, setNotice] = useState("");

  async function load() {
    const r = await fetch(api("me"));
    if (r.ok) { const j = await r.json(); setMe(j); setDisplayName(j.displayName || ""); }
    else setMe({ error: "not logged in" });
  }
  useEffect(() => { load(); }, []);

  // VULN POSTMSG-001 (CWE-346/CWE-79): the companion-widget bridge handles any
  // message that arrives, from any window, without ever looking at
  // event.origin — and then writes the payload it is handed into the page as
  // HTML. Any frame or opener that can reach this window scripts it.
  useEffect(() => {
    function onMessage(ev: MessageEvent) {
      const data: any = ev.data;
      if (data && data.type === "taskflow:notice") {
        setNotice(String(data.html ?? ""));
      }
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    await fetch(api("me"), {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ displayName }),
    });
    load();
  }

  return (
    <main>
      <h1>Profile</h1>
      <pre className="card">{JSON.stringify(me, null, 2)}</pre>
      <form onSubmit={save}>
        <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="display name" />
        <button type="submit">Save</button>
      </form>

      <div data-notice dangerouslySetInnerHTML={{ __html: notice }} />

      <button type="button" onClick={() => setAdvanced((v) => !v)} data-advanced-toggle>
        {advanced ? "Hide advanced" : "Advanced"}
      </button>
      {advanced && <DevTools />}
    </main>
  );
}
