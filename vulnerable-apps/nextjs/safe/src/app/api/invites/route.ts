import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";
import { isGrantable, rank } from "@/lib/roles";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// NEAR-MISS NM-ROLE-CEIL-001: an invite carries the role the invitee will get,
// and this is the ceiling the member-role endpoint forgets - nobody can invite
// someone into a role above their own.
function inviteRoleAllowed(myRole: string, role: unknown): boolean {
  return isGrantable(role) && rank(role) <= rank(myRole);
}

// FIXED RACE-001: the seat is reserved atomically with a conditional update
// (updateMany WHERE seatsUsed < seatsLimit). Concurrent requests that lose the
// race match zero rows and are rejected, so the limit can never be exceeded.
export async function POST(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { email, role = "user" } = await req.json().catch(() => ({}));
  if (!inviteRoleAllowed(me.role, role)) {
    return NextResponse.json({ error: "cannot invite above your own role" }, { status: 403 });
  }

  const reserved = await prisma.organization.updateMany({
    where: { id: me.orgId, seatsUsed: { lt: prisma.organization.fields.seatsLimit } },
    data: { seatsUsed: { increment: 1 } },
  });
  if (reserved.count === 0) {
    return NextResponse.json({ error: "seat limit reached" }, { status: 409 });
  }
  await prisma.invitation.create({ data: { orgId: me.orgId, email: email || "invitee@bench.local", role, token: crypto.randomUUID() } });
  const org = await prisma.organization.findUnique({ where: { id: me.orgId } });
  return NextResponse.json({ ok: true, seatsUsed: org?.seatsUsed, seatsLimit: org?.seatsLimit });
}
