import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// NEAR-MISS NM-MEMBERSHIP-001: the workspace switcher's list. Same "which orgs
// does this user belong to" question the switch endpoint asks, answered
// correctly - a pending request is not a seat, so it is never listed.
export async function GET(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const seats = await prisma.membership.findMany({
    where: { userId: me.userId, status: "active" },
    include: { org: true },
    orderBy: { createdAt: "asc" },
  });
  return NextResponse.json({
    current: me.orgId,
    orgs: seats.map((m) => ({ slug: m.org.slug, name: m.org.name, role: m.role, current: m.orgId === me.orgId })),
  });
}
