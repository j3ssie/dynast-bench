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

  // VULN ROLE-CEIL-001 (CWE-269): the gate above asks "may this caller manage
  // roles at all?" and stops there. It never asks whether the role being handed
  // out - or the role being taken away - sits above the caller's own, so an
  // editor can mint admins (themselves included) and demote the admins above
  // them.

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
