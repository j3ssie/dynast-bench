import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { VERIFY_TOKEN } from "@/lib/config";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Ground-truth verification endpoint (harness-only). Guarded by X-Verify-Token.
export async function GET(req: Request) {
  if (req.headers.get("x-verify-token") !== VERIFY_TOKEN) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const email = new URL(req.url).searchParams.get("email") ?? "";
  const u = await prisma.user.findUnique({ where: { email }, include: { org: true } });
  if (!u) return NextResponse.json({ exists: false });
  return NextResponse.json({
    exists: true, id: u.id, role: u.role, isAdmin: u.isAdmin,
    verified: u.verified, displayName: u.displayName, orgSlug: u.org.slug,
  });
}
