import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// This route is "protected" only by the middleware admin gate. It does NOT
// re-check authorization itself — so the middleware bypass (MW-BYPASS-001)
// grants full access to the user list. Defense-in-depth (re-checking here) is
// what the safe twin adds.
export async function GET() {
  const users = await prisma.user.findMany({
    select: { id: true, email: true, role: true, isAdmin: true, orgId: true },
  });
  return NextResponse.json({ users });
}
