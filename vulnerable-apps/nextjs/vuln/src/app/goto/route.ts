import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// VULN REDIRECT-001 (CWE-601): redirects to a fully attacker-controlled URL
// (this models the login `?next=` parameter). `?next=https://evil.example`
// sends the victim off-site.
export async function GET(req: Request) {
  const next = new URL(req.url).searchParams.get("next") ?? "/";
  return NextResponse.redirect(next);
}
