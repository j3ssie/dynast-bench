import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity, switchSession } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Switch the session into another workspace the caller belongs to. Every
// org-scoped route reads me.orgId, so after this they all answer for the new one.
export async function POST(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { slug } = await req.json().catch(() => ({}));
  const org = await prisma.organization.findUnique({ where: { slug: String(slug ?? "") } });
  if (!org) return NextResponse.json({ error: "no such workspace" }, { status: 404 });

  // FIXED MEMBERSHIP-STATE-001: only an active seat counts - a pending request
  // to join is not membership.
  const seat = await prisma.membership.findFirst({
    where: { userId: me.userId, orgId: org.id, status: "active" },
  });
  if (!seat) return NextResponse.json({ error: "not a member of that workspace" }, { status: 403 });

  if (!(await switchSession({ ...me, orgId: org.id, role: seat.role }))) {
    return NextResponse.json({ error: "switching needs a browser session" }, { status: 400 });
  }
  return NextResponse.json({ ok: true, org: org.slug, role: seat.role });
}
