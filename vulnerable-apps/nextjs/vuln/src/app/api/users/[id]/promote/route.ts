import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// VULN AUTHZ-001 (CWE-862): a privileged action (promote to admin) with no
// function-level authorization check. It lives OUTSIDE the /api/admin prefix, so
// the middleware gate never applies and any logged-in user can call it.
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  // Missing: require me.role === "admin"
  const { id } = await params;
  const u = await prisma.user.update({ where: { id }, data: { role: "admin", isAdmin: true } });
  return NextResponse.json({ ok: true, id: u.id, role: u.role });
}
