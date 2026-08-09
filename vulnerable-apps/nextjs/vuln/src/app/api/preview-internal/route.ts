import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// NM-FETCH (near-miss, safe): a server-side fetch that takes NO user-controlled
// URL — it only calls a fixed, allow-listed internal endpoint. Present in both
// variants; a scanner that flags this as SSRF is producing a false positive.
const ALLOWED = "http://localhost:3000/api/_verify/health";

export async function GET() {
  try {
    const r = await fetch(ALLOWED);
    return NextResponse.json({ status: r.status, body: (await r.text()).slice(0, 500) });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 502 });
  }
}
