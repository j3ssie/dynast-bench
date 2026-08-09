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

// VULN MASSASSIGN-001 (CWE-915): the entire request body is spread into the
// Prisma update, so a client can set privileged columns (role, isAdmin) that
// were never meant to be user-writable.
export async function PATCH(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const body = await req.json().catch(() => ({}));
  const updated = await prisma.user.update({ where: { id: me.userId }, data: { ...body } });
  return NextResponse.json({ ok: true, role: updated.role, isAdmin: updated.isAdmin });
}
