import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";
import { rank, RANKS } from "@/lib/roles";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// An admin of the workspace turns a pending request into an active seat.
export async function POST(req: Request, { params }: { params: Promise<{ slug: string; id: string }> }) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { slug, id } = await params;
  const org = await prisma.organization.findUnique({ where: { slug } });
  if (!org || org.id !== me.orgId || rank(me.role) < RANKS.admin) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const { count } = await prisma.membership.updateMany({
    where: { id, orgId: org.id, status: "pending" },
    data: { status: "active" },
  });
  if (count === 0) return NextResponse.json({ error: "no such pending request" }, { status: 404 });
  return NextResponse.json({ ok: true, id, status: "active" });
}
