import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// FIXED RACE-001: the seat is reserved atomically with a conditional update
// (updateMany WHERE seatsUsed < seatsLimit). Concurrent requests that lose the
// race match zero rows and are rejected, so the limit can never be exceeded.
export async function POST(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { email } = await req.json().catch(() => ({}));

  const reserved = await prisma.organization.updateMany({
    where: { id: me.orgId, seatsUsed: { lt: prisma.organization.fields.seatsLimit } },
    data: { seatsUsed: { increment: 1 } },
  });
  if (reserved.count === 0) {
    return NextResponse.json({ error: "seat limit reached" }, { status: 409 });
  }
  await prisma.invitation.create({ data: { orgId: me.orgId, email: email || "invitee@bench.local", token: crypto.randomUUID() } });
  const org = await prisma.organization.findUnique({ where: { id: me.orgId } });
  return NextResponse.json({ ok: true, seatsUsed: org?.seatsUsed, seatsLimit: org?.seatsLimit });
}
