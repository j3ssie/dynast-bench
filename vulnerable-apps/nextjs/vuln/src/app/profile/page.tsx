"use client";
import { useEffect, useState } from "react";

export default function ProfilePage() {
  const [me, setMe] = useState<any>(null);
  const [displayName, setDisplayName] = useState("");

  async function load() {
    const r = await fetch("/api/users/me");
    if (r.ok) { const j = await r.json(); setMe(j); setDisplayName(j.displayName || ""); }
    else setMe({ error: "not logged in" });
  }
  useEffect(() => { load(); }, []);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    await fetch("/api/users/me", {
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
    </main>
  );
}
