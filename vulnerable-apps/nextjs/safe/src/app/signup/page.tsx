"use client";
import { useState } from "react";
import { api } from "@/lib/routes";

type Step = "start" | "verify" | "profile" | "complete" | "done";

/**
 * Four-step registration. Each step is its own request against its own endpoint,
 * and only the step the wizard is currently on is ever issued — so the later
 * endpoints exist nowhere in the served HTML, and are not reached at all until
 * a client has typed an address and submitted.
 */
export default function SignupPage() {
  const [step, setStep] = useState<Step>("start");
  const [draftId, setDraftId] = useState<number | null>(null);
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState("");

  const post = async (route: Parameters<typeof api>[0], body: unknown) => {
    const r = await fetch(api(route), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { ok: r.ok, json: await r.json().catch(() => ({})) };
  };

  async function start(e: React.FormEvent) {
    e.preventDefault();
    const { ok, json } = await post("signupStart", { email });
    if (!ok) return setMsg(json.error ?? "could not start");
    setDraftId(json.draftId);
    setMsg("We emailed you a 6-digit code.");
    setStep("verify");
  }

  async function verify(e: React.FormEvent) {
    e.preventDefault();
    const { ok, json } = await post("signupVerify", { draftId, code });
    if (!ok) return setMsg(json.error ?? "could not verify");
    setMsg("");
    setStep("profile");
  }

  async function profile(e: React.FormEvent) {
    e.preventDefault();
    const { ok, json } = await post("signupProfile", { draftId, displayName });
    if (!ok) return setMsg(json.error ?? "could not save");
    setMsg("");
    setStep("complete");
  }

  async function complete(e: React.FormEvent) {
    e.preventDefault();
    const { ok, json } = await post("signupComplete", { draftId, password });
    if (!ok) return setMsg(json.error ?? "could not finish");
    setMsg(`Welcome, ${json.email} (${json.role}).`);
    setStep("done");
  }

  async function resend() {
    await post("signupResend", { email });
    setMsg("If that signup exists, a code is on its way.");
  }

  return (
    <main>
      <h1>Create your account</h1>
      <p>
        <small data-step={step}>step {["start", "verify", "profile", "complete"].indexOf(step) + 1} of 4</small>
      </p>

      {step === "start" && (
        <form onSubmit={start}>
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="work email" />
          <button type="submit">Continue</button>
        </form>
      )}

      {step === "verify" && (
        <form onSubmit={verify}>
          <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="6-digit code" />
          <button type="submit">Verify</button>
          <button type="button" onClick={resend}>Resend code</button>
        </form>
      )}

      {step === "profile" && (
        <form onSubmit={profile}>
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="display name" />
          <button type="submit">Continue</button>
        </form>
      )}

      {step === "complete" && (
        <form onSubmit={complete}>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="choose a password" />
          <button type="submit">Finish</button>
        </form>
      )}

      <p>{msg}</p>
    </main>
  );
}
