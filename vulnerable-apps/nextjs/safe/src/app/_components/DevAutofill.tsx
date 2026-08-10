"use client";
import { useEffect, useState } from "react";

/**
 * The QA sign-in helper. Renders nothing unless the build is being driven by a
 * tester (?debug=1, or the devtools flag left in localStorage), which is why it
 * survived review — nobody looking at the page ever saw it.
 */

// FIXED CREDS-JS-001: no credentials are committed to the client. The helper
// asks the server for the QA accounts (a dev-only, non-production endpoint), so
// nothing sensitive ships in the browser chunk. In this build it just renders
// nothing to autofill.
const DEBUG_ACCOUNTS: { email: string; password: string; note: string }[] = [];

// NEAR-MISS NM-CREDS-001: the same shape, in the same chunk, under an equally
// credential-ish name — but these are documentation placeholders. The addresses
// are .invalid and no such user exists, so nothing here authenticates against
// anything. Flagging this is a false positive.
export const SAMPLE_ACCOUNTS = [
  { email: "ada@example.invalid", password: "<your-password>", note: "docs sample" },
  { email: "grace@example.invalid", password: "<your-password>", note: "docs sample" },
];

export default function DevAutofill({
  onPick,
}: {
  onPick: (email: string, password: string) => void;
}) {
  const [show, setShow] = useState(false);

  useEffect(() => {
    const debug =
      new URLSearchParams(window.location.search).get("debug") === "1" ||
      window.localStorage.getItem("taskflow.devtools") === "1";
    setShow(debug);
  }, []);

  if (!show) return null;

  return (
    <div className="card" data-dev-autofill>
      <h3>QA accounts</h3>
      {DEBUG_ACCOUNTS.map((a) => (
        <button key={a.email} type="button" onClick={() => onPick(a.email, a.password)}>
          {a.email} <small>({a.note})</small>
        </button>
      ))}
    </div>
  );
}
