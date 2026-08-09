import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// VULN BILLING-001 (CWE-840): no validation of `quantity`. Negative or absurdly
// large values are accepted, corrupting the seat limit (and, in a real billing
// system, the amount charged).
export async function POST(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { quantity } = await req.json().catch(() => ({}));
  const org = await prisma.organization.update({
    where: { id: me.orgId },
    data: { seatsLimit: quantity },
  });
  return NextResponse.json({ ok: true, seatsLimit: org.seatsLimit });
}
