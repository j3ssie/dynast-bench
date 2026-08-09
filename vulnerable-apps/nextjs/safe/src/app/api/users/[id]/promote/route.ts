import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// FIXED AUTHZ-001: requires an admin/service caller before promoting anyone.
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  if (me.role !== "admin" && me.role !== "service") {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const { id } = await params;
  const u = await prisma.user.update({ where: { id }, data: { role: "admin", isAdmin: true } });
  return NextResponse.json({ ok: true, id: u.id, role: u.role });
}
