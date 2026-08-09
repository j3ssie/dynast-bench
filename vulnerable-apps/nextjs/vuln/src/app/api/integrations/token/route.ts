import { NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// NEAR-MISS NM-TOKEN-001 support: mints a short-lived sync token for the caller's
// OWN session using a CSPRNG. Nothing is committed and nothing is shared between
// users — this is the correct shape that SYNC_BASIC_AUTH gets wrong.
export async function GET(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  return NextResponse.json({ token: randomUUID(), expiresIn: 300 });
}
