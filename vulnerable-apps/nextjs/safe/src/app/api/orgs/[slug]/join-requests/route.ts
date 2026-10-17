import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";
import { rank, RANKS } from "@/lib/roles";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

type Ctx = { params: Promise<{ slug: string }> };

// Ask to join a workspace. Anyone signed in may ask; the request sits as a
// pending membership until an admin of that workspace approves it.
export async function POST(req: Request, { params }: Ctx) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const org = await prisma.organization.findUnique({ where: { slug: (await params).slug } });
  if (!org) return NextResponse.json({ error: "no such workspace" }, { status: 404 });
  const existing = await prisma.membership.findUnique({
    where: { userId_orgId: { userId: me.userId, orgId: org.id } },
  });
  if (existing) {
    return NextResponse.json({ error: `already ${existing.status}`, status: existing.status }, { status: 409 });
  }
  const m = await prisma.membership.create({
    data: { userId: me.userId, orgId: org.id, role: "user", status: "pending" },
  });
  return NextResponse.json({ ok: true, id: m.id, status: m.status }, { status: 201 });
}

// Withdraw your own pending request.
export async function DELETE(req: Request, { params }: Ctx) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const org = await prisma.organization.findUnique({ where: { slug: (await params).slug } });
  if (!org) return NextResponse.json({ error: "no such workspace" }, { status: 404 });
  const { count } = await prisma.membership.deleteMany({
    where: { userId: me.userId, orgId: org.id, status: "pending" },
  });
  return NextResponse.json({ ok: true, withdrawn: count });
}

// The approval queue, for admins of that workspace.
export async function GET(req: Request, { params }: Ctx) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const org = await prisma.organization.findUnique({ where: { slug: (await params).slug } });
  if (!org || org.id !== me.orgId || rank(me.role) < RANKS.admin) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const pending = await prisma.membership.findMany({
    where: { orgId: org.id, status: "pending" },
    include: { user: { select: { email: true, displayName: true } } },
    orderBy: { createdAt: "asc" },
  });
  return NextResponse.json({
    requests: pending.map((m) => ({ id: m.id, email: m.user.email, name: m.user.displayName, createdAt: m.createdAt })),
  });
}
