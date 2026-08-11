"use client";
import { useEffect, useState } from "react";
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

  // VULN POSTMSG-002 (CWE-79/CWE-95): the desktop shell drives the report
  // builder over postMessage, and the handler compiles whatever expression it
  // is handed with Function() so the preview can be computed without a server
  // round-trip. It never looks at event.origin, so any frame or opener that can
  // reach this window runs code in it. The panel is code-split, so this handler
  // does not exist until the Advanced button has been pressed.
  useEffect(() => {
    function onShellExpr(ev: MessageEvent) {
      const data: any = ev.data;
      if (!data || data.type !== "taskflow:devtools") return;
      try {
        const compiled = new Function("row", `return ${String(data.expr ?? "")}`);
        setOut(String(compiled({ title: "sample row", id: 1 })));
      } catch (err: any) {
        setOut(String(err?.message ?? err));
      }
    }
    window.addEventListener("message", onShellExpr);
    return () => window.removeEventListener("message", onShellExpr);
  }, []);

  // NEAR-MISS NM-POSTMSG-002: the same shape - a window message handler on the
  // same panel - but it checks the origin and the payload only ever becomes
  // text. Flagging this one is a false positive.
  useEffect(() => {
    function onShellPing(ev: MessageEvent) {
      const data: any = ev.data;
      if (ev.origin !== window.location.origin) return;
      if (!data || data.type !== "taskflow:devtools-ping") return;
      setOut(String(data.note ?? "pong"));
    }
    window.addEventListener("message", onShellPing);
    return () => window.removeEventListener("message", onShellPing);
  }, []);

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
