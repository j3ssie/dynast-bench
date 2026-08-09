"use client";
import { useState } from "react";

export default function LoginPage() {
  const [email, setEmail] = useState("user1@bench.local");
  const [password, setPassword] = useState("User123!");
  const [msg, setMsg] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const r = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const j = await r.json();
    setMsg(r.ok ? `Logged in as ${j.role}` : `Error: ${j.error}`);
  }

  return (
    <main>
      <h1>Login</h1>
      <form onSubmit={submit}>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email" />
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" />
        <button type="submit">Login</button>
      </form>
      <p>{msg}</p>
    </main>
  );
}
