import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";
import { isGrantable, rank, RANKS } from "@/lib/roles";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Change a member's role in the caller's current workspace. Editors run their
// own team, so this is deliberately open to editors as well as admins.
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  if (rank(me.role) < RANKS.editor) {
    return NextResponse.json({ error: "editors and admins only" }, { status: 403 });
  }
  const { id } = await params;
  const { role } = await req.json().catch(() => ({}));
  if (!isGrantable(role)) return NextResponse.json({ error: "unknown role" }, { status: 400 });

  const seat = await prisma.membership.findFirst({
    where: { userId: id, orgId: me.orgId, status: "active" },
    include: { user: true },
  });
  if (!seat) return NextResponse.json({ error: "not a member of this workspace" }, { status: 404 });

  // FIXED ROLE-CEIL-001: nobody hands out, or takes away, a role above their own.
  if (rank(role) > rank(me.role) || rank(seat.role) > rank(me.role)) {
    return NextResponse.json({ error: "cannot manage a role above your own" }, { status: 403 });
  }

  await prisma.membership.update({ where: { id: seat.id }, data: { role } });
  const home = seat.user.orgId === me.orgId;
  const u = await prisma.user.update({
    where: { id },
    data: {
      ...(home ? { role, isAdmin: role === "admin" } : {}),
      // a role change invalidates every session the member already holds
      sessionVersion: { increment: 1 },
    },
  });
  return NextResponse.json({ ok: true, id: u.id, org: me.orgId, role });
}
