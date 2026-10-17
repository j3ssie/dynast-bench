"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/routes";

type Org = { slug: string; name: string; role: string; current: boolean };

/** Workspaces: the ones you belong to, a switcher, and a way to ask to join another. */
export default function OrgsPage() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [slug, setSlug] = useState("");
  const [note, setNote] = useState("");

  async function load() {
    const r = await fetch(api("myOrgs"));
    if (r.ok) setOrgs((await r.json()).orgs ?? []);
    else setNote("sign in to see your workspaces");
  }
  useEffect(() => { load(); }, []);

  async function switchTo(target: string) {
    const r = await fetch(api("switchOrg"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ slug: target }),
    });
    const j = await r.json().catch(() => ({}));
    setNote(j.error ?? `now in ${j.org}`);
    load();
  }

  async function requestJoin(e: React.FormEvent) {
    e.preventDefault();
    const r = await fetch(api("joinRequests", slug), { method: "POST" });
    const j = await r.json().catch(() => ({}));
    setNote(j.error ?? `request ${j.status}`);
  }

  return (
    <main>
      <h1>Workspaces</h1>
      {orgs.map((o) => (
        <div key={o.slug} className="card">
          <strong>{o.name}</strong> <small>{o.role}</small>{" "}
          {o.current ? <em>current</em> : <button type="button" onClick={() => switchTo(o.slug)}>Switch</button>}
        </div>
      ))}
      <form onSubmit={requestJoin}>
        <input value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="workspace slug" />
        <button type="submit">Ask to join</button>
      </form>
      {note && <p><small>{note}</small></p>}
    </main>
  );
}
