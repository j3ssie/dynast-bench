import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Admin-only report, authenticated via the API Bearer JWT path. Because
// verifyJwt (JWT-001) accepts `alg: none` and a hardcoded secret, an attacker
// can forge a token with role="admin" and reach this endpoint.
export async function GET(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  if (me.role !== "admin" && me.role !== "service") {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const totalUsers = await prisma.user.count();
  const totalPosts = await prisma.post.count();
  return NextResponse.json({ report: "admin-summary", totalUsers, totalPosts });
}
