"use client";
import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/routes";
import { autosaveDraft } from "./actions";

type Props = { id: string; title: string; body: string; status: string; mine: boolean };

/**
 * The post editor. The body autosaves through a Server Action a moment after
 * the author stops typing; the review workflow buttons go through the API.
 */
export default function Editor(props: Props) {
  const [body, setBody] = useState(props.body);
  const [status, setStatus] = useState(props.status);
  const [note, setNote] = useState("");
  const first = useRef(true);

  useEffect(() => {
    if (first.current) { first.current = false; return; }
    if (!props.mine) return;
    const t = setTimeout(async () => {
      const r = await autosaveDraft(props.id, body);
      if (r.ok) { setStatus(r.status ?? status); setNote("saved"); } else setNote(r.error ?? "not saved");
    }, 800);
    return () => clearTimeout(t);
  }, [body]);

  async function step(name: "postSubmit" | "postApprove" | "postPublish") {
    const r = await fetch(api(name, props.id), { method: "POST" });
    const j = await r.json().catch(() => ({}));
    if (j.status) setStatus(j.status);
    setNote(j.error ?? j.status ?? "");
  }

  return (
    <div className="card" data-editor>
      <h2>{props.title}</h2>
      <p><small>status: <span data-status>{status}</span> {note && <>· {note}</>}</small></p>
      <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={10} cols={70} disabled={!props.mine} />
      <div>
        {props.mine && status === "draft" && <button type="button" onClick={() => step("postSubmit")}>Submit for review</button>}
        {!props.mine && status === "in_review" && <button type="button" onClick={() => step("postApprove")}>Approve</button>}
        {status === "approved" && <button type="button" onClick={() => step("postPublish")}>Publish</button>}
      </div>
    </div>
  );
}
