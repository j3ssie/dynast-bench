import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// FIXED REDIRECT-001: only same-site relative paths are allowed. Protocol-
// relative (`//evil`) and absolute external URLs fall back to "/".
export async function GET(req: Request) {
  const next = new URL(req.url).searchParams.get("next") ?? "/";
  const safe = next.startsWith("/") && !next.startsWith("//") ? next : "/";
  return NextResponse.redirect(new URL(safe, req.url));
}
