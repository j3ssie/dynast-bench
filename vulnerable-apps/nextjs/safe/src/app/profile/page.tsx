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

  // FIXED POSTMSG-001: the bridge rejects any message whose origin is not this
  // app's own, and the payload it accepts is rendered as text, not HTML — so a
  // message from another frame can neither be trusted nor script the page.
  useEffect(() => {
    function onMessage(ev: MessageEvent) {
      if (ev.origin !== window.location.origin) return;
      const data: any = ev.data;
      if (data && data.type === "taskflow:notice") {
        setNotice(String(data.text ?? ""));
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

      <div data-notice>{notice}</div>

      <button type="button" onClick={() => setAdvanced((v) => !v)} data-advanced-toggle>
        {advanced ? "Hide advanced" : "Advanced"}
      </button>
      {advanced && <DevTools />}
    </main>
  );
}
