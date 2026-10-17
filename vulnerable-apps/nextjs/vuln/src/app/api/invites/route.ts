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

// VULN RACE-001 (CWE-362): the seat-limit check and the seat increment are not
// atomic. Concurrent requests all read the same seatsUsed before any of them
// writes, so N parallel invites blow past the seat limit.
export async function POST(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { email, role = "user" } = await req.json().catch(() => ({}));
  if (!inviteRoleAllowed(me.role, role)) {
    return NextResponse.json({ error: "cannot invite above your own role" }, { status: 403 });
  }

  const org = await prisma.organization.findUnique({ where: { id: me.orgId } });
  if (!org) return NextResponse.json({ error: "no org" }, { status: 400 });
  if (org.seatsUsed >= org.seatsLimit) {
    return NextResponse.json({ error: "seat limit reached" }, { status: 409 });
  }
  // Widen the race window (a real read-modify-write gap does the same).
  await new Promise((r) => setTimeout(r, 20));
  await prisma.invitation.create({ data: { orgId: me.orgId, email: email || "invitee@bench.local", role, token: Math.random().toString(36).slice(2) } });
  const updated = await prisma.organization.update({ where: { id: me.orgId }, data: { seatsUsed: { increment: 1 } } });
  return NextResponse.json({ ok: true, seatsUsed: updated.seatsUsed, seatsLimit: updated.seatsLimit });
}
