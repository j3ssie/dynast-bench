import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// FIXED BILLING-001: quantity is validated to a sane positive range before use.
export async function POST(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { quantity } = await req.json().catch(() => ({}));
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 1000) {
    return NextResponse.json({ error: "quantity must be an integer between 1 and 1000" }, { status: 400 });
  }
  const org = await prisma.organization.update({
    where: { id: me.orgId },
    data: { seatsLimit: quantity },
  });
  return NextResponse.json({ ok: true, seatsLimit: org.seatsLimit });
}
