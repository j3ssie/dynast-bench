import { NextResponse } from "next/server";
import { lookup } from "dns/promises";
import net from "net";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;      // link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  if (ip === "::1" || ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe80")) return true;
  return false;
}

// FIXED SSRF-001: only http/https to a PUBLIC host is allowed; the resolved IP
// is checked so it cannot reach internal services or cloud metadata.
export async function GET(req: Request) {
  const raw = new URL(req.url).searchParams.get("url") ?? "";
  if (!raw) return NextResponse.json({ error: "url required" }, { status: 400 });
  let target: URL;
  try { target = new URL(raw); } catch { return NextResponse.json({ error: "bad url" }, { status: 400 }); }
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    return NextResponse.json({ error: "scheme not allowed" }, { status: 400 });
  }
  try {
    const { address } = await lookup(target.hostname);
    if (isPrivateIp(address)) {
      return NextResponse.json({ error: "destination not allowed" }, { status: 400 });
    }
  } catch {
    return NextResponse.json({ error: "resolution failed" }, { status: 400 });
  }
  try {
    const r = await fetch(target, { redirect: "error" });
    const body = (await r.text()).slice(0, 4000);
    return NextResponse.json({ status: r.status, body });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 502 });
  }
}
