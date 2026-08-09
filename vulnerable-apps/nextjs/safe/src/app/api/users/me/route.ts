import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const u = await prisma.user.findUnique({ where: { id: me.userId } });
  return NextResponse.json({ id: u?.id, email: u?.email, role: u?.role, isAdmin: u?.isAdmin, displayName: u?.displayName });
}

// FIXED MASSASSIGN-001: only explicitly-allowed fields are updatable. Privileged
// columns (role, isAdmin) can never be set from the request body.
export async function PATCH(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const body = await req.json().catch(() => ({}));
  const data: { displayName?: string } = {};
  if (typeof body.displayName === "string") data.displayName = body.displayName;
  const updated = await prisma.user.update({ where: { id: me.userId }, data });
  return NextResponse.json({ ok: true, role: updated.role, isAdmin: updated.isAdmin });
}
