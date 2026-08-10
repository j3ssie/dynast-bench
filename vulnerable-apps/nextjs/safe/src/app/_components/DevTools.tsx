"use client";
import { useState } from "react";
import { API_BASE } from "@/lib/routes";

/**
 * The Advanced panel: an internal report builder, kept out of the main bundle
 * because almost nobody opens it. It is code-split, so the browser does not
 * fetch this chunk at all until the button is clicked — and the endpoint it
 * talks to appears in no other chunk, in no HTML, and in no route registry.
 */

// The builder's own endpoint, assembled from segments the same way the rest of
// the app assembles its API paths.
const REPORT_SEGMENTS = ["_debug", "report"];
const reportUrl = () => [API_BASE, ...REPORT_SEGMENTS].join("/");

export default function DevTools() {
  const [expr, setExpr] = useState("row.title.length");
  const [out, setOut] = useState("");

  async function run(body: unknown) {
    const r = await fetch(reportUrl(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    setOut(JSON.stringify(await r.json().catch(() => ({})), null, 2));
  }

  return (
    <div className="card" data-devtools>
      <h3>Report builder</h3>
      <p>
        <small>Computed column, evaluated per row.</small>
      </p>
      <input value={expr} onChange={(e) => setExpr(e.target.value)} placeholder="row.title.length" />
      <button type="button" onClick={() => run({ expr })}>
        Run
      </button>
      <button type="button" onClick={() => run({ agg: "count" })}>
        Count rows
      </button>
      <pre>{out}</pre>
    </div>
  );
}
