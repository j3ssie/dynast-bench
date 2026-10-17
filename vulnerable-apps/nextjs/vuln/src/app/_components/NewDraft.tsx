"use client";
import { useState } from "react";
import { api } from "@/lib/routes";

/** Start a draft in the current workspace and jump straight into the editor. */
export default function NewDraft() {
  const [title, setTitle] = useState("");
  const [note, setNote] = useState("");

  async function create(e: React.FormEvent) {
    e.preventDefault();
    const r = await fetch(api("posts"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ title, body: "" }),
    });
    const j = await r.json().catch(() => ({}));
    if (j.id) window.location.href = `/posts/${j.id}/edit`;
    else setNote(j.error ?? "could not create");
  }

  return (
    <form onSubmit={create} data-new-draft>
      <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="new draft title" />
      <button type="submit">New draft</button>
      {note && <small> {note}</small>}
    </form>
  );
}
