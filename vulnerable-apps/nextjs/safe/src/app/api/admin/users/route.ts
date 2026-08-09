import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// FIXED MW-BYPASS-001 (defense-in-depth): the handler independently verifies the
// caller is an admin, so even a request that slipped past middleware is denied.
export async function GET(req: Request) {
  const me = await getIdentity(req);
  if (!me || (me.role !== "admin" && me.role !== "service")) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const users = await prisma.user.findMany({
    select: { id: true, email: true, role: true, isAdmin: true, orgId: true },
  });
  return NextResponse.json({ users });
}
