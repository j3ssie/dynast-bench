"use client";
import { useState } from "react";
import { api } from "@/lib/routes";
import DevAutofill from "../_components/DevAutofill";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const r = await fetch(api("login"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const j = await r.json();
    setMsg(r.ok ? `Logged in as ${j.role}` : `Error: ${j.error}`);
  }

  return (
    <main>
      <h1>Sign in</h1>
      <form onSubmit={submit}>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email" />
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" />
        <button type="submit">Sign in</button>
      </form>
      <p>{msg}</p>
      <DevAutofill
        onPick={(e, p) => {
          setEmail(e);
          setPassword(p);
        }}
      />
      <p>
        <small>
          No account? <a href="/signup">Create one</a>.
        </small>
      </p>
    </main>
  );
}
