import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// VULN SSRF-001 (CWE-918): fetches an arbitrary user-supplied URL server-side.
// Reaches internal-only services (mailpit, redis, postgres) and cloud metadata
// (169.254.169.254) that are not exposed to the client.
export async function GET(req: Request) {
  const url = new URL(req.url).searchParams.get("url") ?? "";
  if (!url) return NextResponse.json({ error: "url required" }, { status: 400 });
  try {
    const r = await fetch(url, { redirect: "follow" });
    const body = (await r.text()).slice(0, 4000);
    return NextResponse.json({ status: r.status, body });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 502 });
  }
}
